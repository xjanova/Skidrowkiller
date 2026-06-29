using System;
using System.Diagnostics;
using System.Linq;
using System.Management;
using System.Security.Principal;
using System.Threading.Tasks;
using Serilog;

namespace SkidrowKiller.Services
{
    /// <summary>
    /// Safe, legitimate Windows Defender coexistence.
    ///
    /// IMPORTANT: this service NEVER disables Windows Defender's protection. Forcibly turning Defender
    /// off (Set-MpPreference -DisableRealtimeMonitoring, killing WinDefend, registry DisableAntiSpyware)
    /// is exactly what malware does — it is blocked by Tamper Protection, and doing it would get THIS app
    /// flagged as malware. The professional way for a third-party AV to make Defender stand down is to
    /// register with the Windows Security Center (which requires joining the Microsoft Virus Initiative,
    /// shipping an ELAM driver, and EV code-signing) — not a registry hack.
    ///
    /// What we DO here is the safe, common installer behavior: add OUR OWN app folder to Defender's
    /// exclusion list so Defender stops quarantining our (legitimately-malware-string-containing) binary,
    /// and surface read-only status so the user can see what is protecting the machine.
    /// </summary>
    public class DefenderIntegrationService
    {
        private readonly ILogger _logger;
        private readonly string _selfDirectory;

        public DefenderIntegrationService()
        {
            _logger = LoggingService.ForContext<DefenderIntegrationService>();
            _selfDirectory = AppDomain.CurrentDomain.BaseDirectory.TrimEnd('\\');
        }

        public static bool IsElevated()
        {
            try
            {
                using var identity = WindowsIdentity.GetCurrent();
                return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch { return false; }
        }

        /// <summary>Read-only snapshot of Defender + which AV products are registered with Windows.</summary>
        public async Task<DefenderStatus> GetStatusAsync()
        {
            var status = new DefenderStatus { RegisteredAntiviruses = GetRegisteredAntiviruses() };

            await Task.Run(() =>
            {
                var raw = RunPowerShell(
                    "$s=Get-MpComputerStatus; \"$($s.RealTimeProtectionEnabled)|$($s.AntivirusEnabled)|$($s.IsTamperProtected)\"");
                var parts = raw.Split('|');
                if (parts.Length == 3)
                {
                    status.DefenderRealtimeEnabled = ParseBool(parts[0]);
                    status.DefenderAntivirusEnabled = ParseBool(parts[1]);
                    status.TamperProtectionEnabled = ParseBool(parts[2]);
                    status.Queried = true;
                }

                status.SelfExcluded = IsSelfExcluded();
            });

            return status;
        }

        /// <summary>
        /// Ensure our own folder is in Defender's exclusion list so Defender stops blocking us.
        /// Requires admin; returns true if excluded (already or newly). Does NOT touch Defender protection.
        /// </summary>
        public async Task<bool> EnsureSelfExclusionAsync()
        {
            if (!IsElevated())
            {
                _logger.Information("Defender self-exclusion skipped (not elevated)");
                return false;
            }

            return await Task.Run(() =>
            {
                try
                {
                    if (IsSelfExcluded()) return true;
                    // Single-quoted path is literal to PowerShell; our dir contains no single quotes.
                    RunPowerShell($"Add-MpPreference -ExclusionPath '{_selfDirectory}'");
                    var ok = IsSelfExcluded();
                    if (ok) _logger.Information("Added Defender exclusion for {Dir}", _selfDirectory);
                    else _logger.Warning("Defender exclusion not applied (Tamper Protection or policy?) for {Dir}", _selfDirectory);
                    return ok;
                }
                catch (Exception ex)
                {
                    _logger.Warning(ex, "Failed to add Defender self-exclusion");
                    return false;
                }
            });
        }

        public string[] GetRegisteredAntiviruses()
        {
            try
            {
                using var searcher = new ManagementObjectSearcher(@"root\SecurityCenter2",
                    "SELECT displayName FROM AntiVirusProduct");
                return searcher.Get()
                    .Cast<ManagementObject>()
                    .Select(mo => mo["displayName"] as string ?? "")
                    .Where(s => !string.IsNullOrWhiteSpace(s))
                    .Distinct()
                    .ToArray();
            }
            catch
            {
                return Array.Empty<string>();
            }
        }

        private bool IsSelfExcluded()
        {
            var raw = RunPowerShell("(Get-MpPreference).ExclusionPath -join '||'");
            if (string.IsNullOrWhiteSpace(raw)) return false;
            return raw.Split(new[] { "||" }, StringSplitOptions.RemoveEmptyEntries)
                      .Any(p => string.Equals(p.Trim().TrimEnd('\\'), _selfDirectory, StringComparison.OrdinalIgnoreCase));
        }

        private static bool ParseBool(string s) => bool.TryParse(s.Trim(), out var b) && b;

        private static string RunPowerShell(string command)
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = $"-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"{command}\"",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                using var p = Process.Start(psi);
                if (p == null) return "";
                var output = p.StandardOutput.ReadToEnd();
                p.WaitForExit(15000);
                return output.Trim();
            }
            catch
            {
                return "";
            }
        }
    }

    public class DefenderStatus
    {
        public bool Queried { get; set; }
        public bool DefenderRealtimeEnabled { get; set; }
        public bool DefenderAntivirusEnabled { get; set; }
        public bool TamperProtectionEnabled { get; set; }
        public bool SelfExcluded { get; set; }
        public string[] RegisteredAntiviruses { get; set; } = Array.Empty<string>();
    }
}
