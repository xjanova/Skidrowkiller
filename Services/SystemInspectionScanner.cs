using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management;
using System.Threading;
using System.Xml.Linq;
using Microsoft.Win32;
using SkidrowKiller.Models;
using Serilog;

namespace SkidrowKiller.Services
{
    /// <summary>
    /// "Live system" inspection — the checks a real AV runs against a running machine, not just files:
    ///   • LOLBins: running processes whose command line abuses living-off-the-land binaries
    ///     (powershell -enc, mshta http, regsvr32 scrobj, certutil -decode, wmic shadowcopy delete …)
    ///   • Scheduled Tasks that silently launch suspicious payloads
    ///   • Windows Services running from temp/AppData or impersonating system processes
    ///   • hosts-file tampering that redirects/blocks AV, Windows Update or banking domains
    /// Everything is conservative (cross-checked with ThreatAnalyzer / location) to avoid false alarms.
    /// </summary>
    public class SystemInspectionScanner
    {
        private readonly ThreatAnalyzer _analyzer;
        private readonly WhitelistManager? _whitelist;
        private readonly ILogger _logger;

        public SystemInspectionScanner(ThreatAnalyzer analyzer, WhitelistManager? whitelist = null)
        {
            _analyzer = analyzer;
            _whitelist = whitelist;
            _logger = LoggingService.ForContext<SystemInspectionScanner>();
        }

        // (binary, any-of-these-args, score, description)
        private static readonly (string Bin, string[] AnyOf, int Score, string Desc)[] LolbinRules =
        {
            ("powershell", new[] { "-enc", "-encodedcommand", "frombase64string", "downloadstring", "downloadfile",
                                   "-w hidden", "-windowstyle hidden", "-nop", "invoke-expression", "iex(", "-ep bypass", "bypass" }, 55, "Obfuscated/hidden PowerShell"),
            ("pwsh", new[] { "-enc", "-encodedcommand", "frombase64string", "downloadstring", "-w hidden", "bypass" }, 55, "Obfuscated/hidden PowerShell"),
            ("mshta", new[] { "javascript:", "vbscript:", "http://", "https://" }, 60, "mshta remote/script execution"),
            ("rundll32", new[] { "javascript:", "http", ",#1", "url.dll,fileprotocolhandler" }, 50, "rundll32 abuse"),
            ("regsvr32", new[] { "/i:http", "scrobj.dll", "/s /n /u /i:" }, 60, "regsvr32 scriptlet (Squiblydoo)"),
            ("certutil", new[] { "-decode", "-urlcache", "-encode", "-f -split" }, 55, "certutil download/decode"),
            ("bitsadmin", new[] { "/transfer", "/addfile", "/create" }, 45, "bitsadmin download"),
            ("wscript", new[] { ".vbs", ".js", ".jse", ".wsf", "http" }, 35, "Windows Script Host"),
            ("cscript", new[] { ".vbs", ".js", ".jse", ".wsf", "http" }, 35, "Windows Script Host"),
            ("installutil", new[] { "/logfile=", "/u " }, 40, "InstallUtil AppLocker bypass"),
            ("msbuild", new[] { "inline", ".xml", ".csproj" }, 35, "MSBuild inline-task bypass"),
            ("wmic", new[] { "process call create", "shadowcopy delete", "/node:" }, 45, "WMIC abuse"),
        };

        private static readonly string[] AntiRecovery =
        {
            "vssadmin delete shadows", "vssadmin resize shadowstorage", "wmic shadowcopy delete",
            "wbadmin delete catalog", "wbadmin delete systemstatebackup", "recoveryenabled no",
            "bootstatuspolicy ignoreallfailures", "cipher /w", "fsutil usn deletejournal"
        };

        // Domains malware loves to block (AV/OS update) or redirect (banks). Conservative, well-known set.
        private static readonly string[] SensitiveHosts =
        {
            "windowsupdate", "update.microsoft", "microsoft.com", "defender", "mpa.one.microsoft",
            "avast", "avg.com", "kaspersky", "bitdefender", "mcafee", "norton", "symantec",
            "malwarebytes", "eset", "sophos", "trendmicro", "virustotal", "abuse.ch"
        };

        public List<ThreatInfo> Scan(CancellationToken token = default)
        {
            var results = new List<ThreatInfo>();
            TryRun(() => ScanProcessCommandLines(results, token), "process command lines");
            TryRun(() => ScanScheduledTasks(results, token), "scheduled tasks");
            TryRun(() => ScanServices(results, token), "services");
            TryRun(() => ScanHostsFile(results), "hosts file");
            return results;
        }

        private void TryRun(Action a, string what)
        {
            try { a(); } catch (Exception ex) { _logger.Debug(ex, "System inspection step failed: {What}", what); }
        }

        // ---- 1. Running process command lines (LOLBins + anti-recovery) ----
        private void ScanProcessCommandLines(List<ThreatInfo> results, CancellationToken token)
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT ProcessId, Name, CommandLine, ExecutablePath FROM Win32_Process");
            foreach (ManagementObject mo in searcher.Get())
            {
                if (token.IsCancellationRequested) break;
                try
                {
                    var name = (mo["Name"] as string ?? "").ToLowerInvariant();
                    var cmd = (mo["CommandLine"] as string ?? "");
                    var exe = mo["ExecutablePath"] as string ?? "";
                    var pid = mo["ProcessId"] is uint p ? (int)p : 0;
                    if (string.IsNullOrEmpty(cmd)) continue;

                    if (!string.IsNullOrEmpty(exe) && _whitelist?.IsWhitelisted(exe) == true) continue;

                    var threat = EvaluateProcessCommandLine(pid, name, exe, cmd);
                    if (threat != null) results.Add(threat);
                }
                catch { }
                finally { mo.Dispose(); }
            }
        }

        /// <summary>
        /// Evaluate a single process command line for LOLBin abuse / anti-recovery commands.
        /// Shared by the on-demand scan and the real-time process guard. Returns null if clean.
        /// </summary>
        public static ThreatInfo? EvaluateProcessCommandLine(int pid, string nameLower, string exe, string cmd)
        {
            if (string.IsNullOrEmpty(cmd)) return null;
            var lower = cmd.ToLowerInvariant();
            nameLower = (nameLower ?? "").ToLowerInvariant();

            var ar = AntiRecovery.FirstOrDefault(a => lower.Contains(a));
            if (ar != null)
                return MakeProcThreat(pid, nameLower, exe, cmd,
                    $"Anti-recovery command in running process: {ar}", 85, ThreatCategory.Ransomware);

            foreach (var rule in LolbinRules)
            {
                if (!nameLower.Contains(rule.Bin) && !lower.Contains(rule.Bin + " ") && !lower.Contains(rule.Bin + ".exe")) continue;
                if (rule.AnyOf.Any(a => lower.Contains(a)))
                    return MakeProcThreat(pid, nameLower, exe, cmd, $"LOLBin abuse: {rule.Desc}", rule.Score, ThreatCategory.Suspicious);
            }
            return null;
        }

        // ---- 2. Scheduled tasks ----
        private void ScanScheduledTasks(List<ThreatInfo> results, CancellationToken token)
        {
            var tasksRoot = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "Tasks");
            if (!Directory.Exists(tasksRoot)) return;

            XNamespace ns = "http://schemas.microsoft.com/windows/2004/02/mit/task";

            foreach (var file in Directory.EnumerateFiles(tasksRoot, "*", SearchOption.AllDirectories))
            {
                if (token.IsCancellationRequested) break;
                try
                {
                    var doc = XDocument.Load(file);
                    foreach (var exec in doc.Descendants(ns + "Exec"))
                    {
                        var command = (exec.Element(ns + "Command")?.Value ?? "").Trim().Trim('"');
                        var args = exec.Element(ns + "Arguments")?.Value ?? "";
                        if (string.IsNullOrEmpty(command)) continue;

                        var resolved = Environment.ExpandEnvironmentVariables(command);
                        var lowerAll = (resolved + " " + args).ToLowerInvariant();
                        var taskName = Path.GetFileName(file);

                        var antiRec = AntiRecovery.FirstOrDefault(a => lowerAll.Contains(a));
                        var lolbin = LolbinRules.FirstOrDefault(r =>
                            (resolved.ToLowerInvariant().Contains(r.Bin) || lowerAll.Contains(r.Bin + " ")) &&
                            r.AnyOf.Any(a => lowerAll.Contains(a)));

                        var inUserland = lowerAll.Contains(@"\temp\") || lowerAll.Contains(@"\appdata\") ||
                                         lowerAll.Contains(@"\users\public\") || lowerAll.Contains(@"\downloads\");

                        var fileThreat = File.Exists(resolved) ? SafeAnalyze(resolved) : null;

                        if (antiRec != null || lolbin.Bin != null || inUserland || fileThreat != null)
                        {
                            var score = antiRec != null ? 85 : lolbin.Bin != null ? Math.Max(lolbin.Score, 55) : fileThreat?.Score ?? 45;
                            var reason = antiRec != null ? $"anti-recovery ({antiRec})"
                                       : lolbin.Bin != null ? $"LOLBin ({lolbin.Desc})"
                                       : fileThreat != null ? "suspicious target binary"
                                       : "launches from a user-writable location";
                            results.Add(MakeConfigThreat(
                                File.Exists(resolved) ? resolved : file, taskName,
                                $"Scheduled task '{taskName}' is suspicious — {reason}: {command} {args}".Trim(),
                                score, ThreatType.File));
                        }
                    }
                }
                catch { }
            }
        }

        // ---- 3. Services ----
        private void ScanServices(List<ThreatInfo> results, CancellationToken token)
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT Name, DisplayName, PathName, StartMode, State FROM Win32_Service");
            foreach (ManagementObject mo in searcher.Get())
            {
                if (token.IsCancellationRequested) break;
                try
                {
                    var name = mo["Name"] as string ?? "";
                    var pathName = mo["PathName"] as string ?? "";
                    if (string.IsNullOrEmpty(pathName)) continue;

                    var exe = PersistenceScanner.ExtractExecutablePath(pathName);
                    if (string.IsNullOrEmpty(exe)) continue;
                    var lowerExe = exe.ToLowerInvariant();

                    if (_whitelist?.IsWhitelisted(exe) == true) continue;

                    var inUserland = lowerExe.Contains(@"\temp\") || lowerExe.Contains(@"\appdata\") ||
                                     lowerExe.Contains(@"\users\public\") || lowerExe.Contains(@"\downloads\") ||
                                     lowerExe.Contains(@"\programdata\");

                    // svchost should only ever live in System32/SysWOW64.
                    var fakeSvchost = Path.GetFileName(lowerExe) == "svchost.exe" &&
                                      !lowerExe.Contains(@"\windows\system32\") && !lowerExe.Contains(@"\windows\syswow64\");

                    var fileThreat = File.Exists(exe) ? SafeAnalyze(exe) : null;

                    if (inUserland || fakeSvchost || fileThreat != null)
                    {
                        var score = fakeSvchost ? 85 : fileThreat?.Score ?? 55;
                        var reason = fakeSvchost ? "svchost.exe running from a non-system location (impersonation)"
                                   : fileThreat != null ? "suspicious service binary"
                                   : "service runs from a user-writable location";
                        results.Add(MakeConfigThreat(exe, name,
                            $"Service '{name}' is suspicious — {reason}: {pathName}", score, ThreatType.File));
                    }
                }
                catch { }
                finally { mo.Dispose(); }
            }
        }

        // ---- 4. hosts file ----
        private void ScanHostsFile(List<ThreatInfo> results)
        {
            var hosts = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "drivers", "etc", "hosts");
            if (!File.Exists(hosts)) return;

            foreach (var raw in File.ReadAllLines(hosts))
            {
                var line = raw.Trim();
                if (line.Length == 0 || line.StartsWith("#")) continue;

                var parts = line.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length < 2) continue;

                var ip = parts[0];
                for (var i = 1; i < parts.Length; i++)
                {
                    var host = parts[i].ToLowerInvariant();
                    if (host.StartsWith("#")) break;
                    if (SensitiveHosts.Any(s => host.Contains(s)))
                    {
                        var blocked = ip is "0.0.0.0" or "127.0.0.1" or "::1";
                        var verb = blocked ? "BLOCKS" : "REDIRECTS";
                        results.Add(MakeConfigThreat(hosts, host,
                            $"hosts file {verb} a security/update domain: {host} → {ip} (malware often disables AV/updates this way)",
                            blocked ? 70 : 80, ThreatType.File));
                    }
                }
            }
        }

        // ---- helpers ----
        private ThreatInfo? SafeAnalyze(string path)
        {
            try { return _analyzer.AnalyzePath(path); } catch { return null; }
        }

        private static ThreatInfo MakeProcThreat(int pid, string name, string exe, string cmd, string reason, int score, ThreatCategory cat)
        {
            return new ThreatInfo
            {
                Type = ThreatType.Process,
                Category = cat,
                Severity = ScoreToSeverity(score),
                Score = score,
                ProcessId = pid,
                Path = string.IsNullOrEmpty(exe) ? name : exe,
                Name = name,
                MalwareName = (cat == ThreatCategory.Ransomware ? "Ransom.AntiRecovery" : "LOLBin." + name.Replace(".exe", "")),
                Description = reason,
                DetectionReason = "Living-off-the-land / anti-recovery command line",
                Recommendation = "Investigate this running process. Terminate it if you did not start it intentionally.",
                CanIgnore = false,
                MatchedPatterns = new List<string> { "[LOLBIN] " + reason, "[CMD] " + Truncate(cmd, 100) }
            };
        }

        private static ThreatInfo MakeConfigThreat(string path, string name, string reason, int score, ThreatType type)
        {
            return new ThreatInfo
            {
                Type = type,
                Category = ThreatCategory.Suspicious,
                Severity = ScoreToSeverity(score),
                Score = score,
                Path = path,
                Name = name,
                MalwareName = "Suspicious.SystemConfig",
                Description = reason,
                DetectionReason = "Suspicious system configuration",
                Recommendation = "Review this entry. Remove it if you do not recognize it.",
                CanIgnore = false,
                MatchedPatterns = new List<string> { "[SYSTEM] " + Truncate(reason, 140) }
            };
        }

        private static ThreatSeverity ScoreToSeverity(int score) =>
            score >= 80 ? ThreatSeverity.Critical :
            score >= 60 ? ThreatSeverity.High :
            score >= 40 ? ThreatSeverity.Medium : ThreatSeverity.Low;

        private static string Truncate(string s, int max) => s.Length <= max ? s : s[..max] + "…";
    }
}
