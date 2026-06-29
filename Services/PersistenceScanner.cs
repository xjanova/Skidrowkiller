using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Microsoft.Win32;
using SkidrowKiller.Models;
using Serilog;

namespace SkidrowKiller.Services
{
    /// <summary>
    /// Enumerates the Auto-Start Extensibility Points (ASEPs) that malware most often abuses for
    /// persistence — far beyond the basic Run/RunOnce keys. This is how a real AV / Sysinternals
    /// Autoruns finds the thing that keeps coming back after a reboot:
    ///   • Run / RunOnce (HKCU, HKLM, and the 32-bit Wow6432Node view)
    ///   • Startup folders (per-user and all-users)
    ///   • Winlogon Shell / Userinit hijacks
    ///   • AppInit_DLLs (loaded into nearly every process)
    ///   • Image File Execution Options "Debugger" hijacks (run X → silently runs malware)
    /// Each discovered target is run through the normal ThreatAnalyzer, and inherently-dangerous
    /// configurations (IFEO debugger, AppInit DLLs, Winlogon tampering) are flagged on their own.
    /// </summary>
    public class PersistenceScanner
    {
        private readonly ThreatAnalyzer _analyzer;
        private readonly ILogger _logger;

        public PersistenceScanner(ThreatAnalyzer analyzer)
        {
            _analyzer = analyzer;
            _logger = LoggingService.ForContext<PersistenceScanner>();
        }

        public List<ThreatInfo> Scan()
        {
            var threats = new List<ThreatInfo>();
            try
            {
                ScanRunKeys(threats);
                ScanStartupFolders(threats);
                ScanWinlogon(threats);
                ScanAppInitDlls(threats);
                ScanImageFileExecutionOptions(threats);
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Persistence scan failed");
            }
            return threats;
        }

        private void ScanRunKeys(List<ThreatInfo> threats)
        {
            var locations = new (RegistryHive Hive, RegistryView View, string Path)[]
            {
                (RegistryHive.CurrentUser,  RegistryView.Default,  @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
                (RegistryHive.CurrentUser,  RegistryView.Default,  @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
                (RegistryHive.LocalMachine, RegistryView.Registry64, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
                (RegistryHive.LocalMachine, RegistryView.Registry64, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
                (RegistryHive.LocalMachine, RegistryView.Registry32, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
                (RegistryHive.LocalMachine, RegistryView.Registry32, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
            };

            foreach (var (hive, view, path) in locations)
            {
                try
                {
                    using var baseKey = RegistryKey.OpenBaseKey(hive, view);
                    using var key = baseKey.OpenSubKey(path, false);
                    if (key == null) continue;

                    foreach (var valueName in key.GetValueNames())
                    {
                        var command = key.GetValue(valueName)?.ToString();
                        if (string.IsNullOrWhiteSpace(command)) continue;

                        var exe = ExtractExecutablePath(command);
                        var threat = AnalyzeTarget(exe);
                        if (threat != null)
                        {
                            Decorate(threat, $"{hive}\\{path}\\{valueName}", valueName, "Run key autostart", command);
                            threats.Add(threat);
                        }
                    }
                }
                catch { }
            }
        }

        private void ScanStartupFolders(List<ThreatInfo> threats)
        {
            var folders = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.Startup),
                Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup)
            };

            foreach (var folder in folders.Distinct())
            {
                try
                {
                    if (string.IsNullOrEmpty(folder) || !Directory.Exists(folder)) continue;
                    foreach (var file in Directory.GetFiles(folder))
                    {
                        var threat = _analyzer.AnalyzePath(file);
                        if (threat != null)
                        {
                            Decorate(threat, file, Path.GetFileName(file), "Startup folder autostart", file);
                            threats.Add(threat);
                        }
                    }
                }
                catch { }
            }
        }

        private void ScanWinlogon(List<ThreatInfo> threats)
        {
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
                using var key = baseKey.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", false);
                if (key == null) return;

                var shell = key.GetValue("Shell")?.ToString() ?? "";
                if (!string.IsNullOrEmpty(shell) && !shell.Trim().Equals("explorer.exe", StringComparison.OrdinalIgnoreCase))
                {
                    threats.Add(MakeThreat(
                        @"HKLM\...\Winlogon\Shell", "Shell",
                        $"Winlogon Shell hijacked (expected 'explorer.exe', found '{shell}')", 75, shell));
                }

                var userinit = key.GetValue("Userinit")?.ToString() ?? "";
                // Normal value is "<sysdir>\userinit.exe," — anything extra after the comma is suspicious.
                var extra = userinit.Split(',').Select(s => s.Trim()).Where(s => s.Length > 0 &&
                            !s.EndsWith("userinit.exe", StringComparison.OrdinalIgnoreCase)).ToList();
                if (extra.Count > 0)
                {
                    threats.Add(MakeThreat(
                        @"HKLM\...\Winlogon\Userinit", "Userinit",
                        $"Winlogon Userinit has extra entries: {string.Join(" ; ", extra)}", 80, userinit));
                }
            }
            catch { }
        }

        private void ScanAppInitDlls(List<ThreatInfo> threats)
        {
            foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
            {
                try
                {
                    using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);
                    using var key = baseKey.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows", false);
                    var appInit = key?.GetValue("AppInit_DLLs")?.ToString();
                    if (!string.IsNullOrWhiteSpace(appInit))
                    {
                        // AppInit_DLLs forces a DLL into nearly every GUI process — almost always abuse today.
                        threats.Add(MakeThreat(
                            @"HKLM\...\Windows\AppInit_DLLs", "AppInit_DLLs",
                            $"AppInit_DLLs injects a DLL system-wide: {appInit}", 70, appInit));
                    }
                }
                catch { }
            }
        }

        private void ScanImageFileExecutionOptions(List<ThreatInfo> threats)
        {
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
                using var ifeo = baseKey.OpenSubKey(
                    @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options", false);
                if (ifeo == null) return;

                foreach (var subName in ifeo.GetSubKeyNames())
                {
                    try
                    {
                        using var sub = ifeo.OpenSubKey(subName, false);
                        var debugger = sub?.GetValue("Debugger")?.ToString();
                        if (!string.IsNullOrWhiteSpace(debugger))
                        {
                            // A "Debugger" here means: launching <subName> silently runs <debugger> instead.
                            threats.Add(MakeThreat(
                                $@"HKLM\...\Image File Execution Options\{subName}\Debugger", subName,
                                $"IFEO debugger hijack: running '{subName}' launches '{debugger}'", 85, debugger));
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }

        // ---- helpers ----

        private ThreatInfo? AnalyzeTarget(string? exePath)
        {
            if (string.IsNullOrWhiteSpace(exePath)) return null;
            try { return _analyzer.AnalyzePath(exePath); } catch { return null; }
        }

        private static void Decorate(ThreatInfo threat, string regPath, string name, string how, string command)
        {
            threat.Type = ThreatType.Registry;
            threat.Path = regPath;
            threat.Name = name;
            threat.MatchedPatterns.Add($"[PERSIST] {how}");
            if (!string.IsNullOrEmpty(command))
                threat.MatchedPatterns.Add($"[PERSIST] cmd: {Truncate(command, 80)}");
            threat.Description = $"Persistence ({how}): {threat.Description}";
        }

        private static ThreatInfo MakeThreat(string regPath, string name, string description, int score, string command)
        {
            var severity = score >= 80 ? ThreatSeverity.Critical
                         : score >= 60 ? ThreatSeverity.High
                         : ThreatSeverity.Medium;
            return new ThreatInfo
            {
                Type = ThreatType.Registry,
                Category = ThreatCategory.Suspicious,
                Severity = severity,
                Score = score,
                Path = regPath,
                Name = name,
                MalwareName = "Persistence." + name.Replace(" ", ""),
                Description = description,
                DetectionReason = "Suspicious autostart / persistence configuration",
                Recommendation = "Review this autostart entry. Remove it if you do not recognize the program it launches.",
                CanIgnore = false,
                MatchedPatterns = new List<string> { "[PERSIST] " + description, "[PERSIST] cmd: " + Truncate(command, 80) }
            };
        }

        /// <summary>Pull the executable path out of a command line (handles quotes and arguments).</summary>
        public static string ExtractExecutablePath(string commandLine)
        {
            if (string.IsNullOrWhiteSpace(commandLine)) return "";
            var s = Environment.ExpandEnvironmentVariables(commandLine.Trim());

            if (s.StartsWith("\""))
            {
                var end = s.IndexOf('"', 1);
                return end > 1 ? s[1..end] : s.Trim('"');
            }

            // Unquoted: take up to the first space that ends a real path (best-effort).
            var space = s.IndexOf(' ');
            return space > 0 ? s[..space] : s;
        }

        private static string Truncate(string s, int max) => s.Length <= max ? s : s[..max] + "…";
    }
}
