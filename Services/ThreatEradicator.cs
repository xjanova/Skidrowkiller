using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using System.Xml.Linq;
using Microsoft.Win32;
using SkidrowKiller.Models;
using Serilog;

namespace SkidrowKiller.Services
{
    public enum EradicationMode
    {
        /// <summary>Wipe the file (backup first if requested).</summary>
        Delete,

        /// <summary>Move the file into encrypted quarantine so it can be restored.</summary>
        Quarantine
    }

    /// <summary>
    /// Honest account of what a removal actually achieved. A bool could not express "the process is
    /// dead and the Run key is gone but the file is locked until reboot" - and that is the common case.
    /// </summary>
    public sealed class EradicationResult
    {
        public bool Succeeded { get; set; }
        public bool DeferredToReboot { get; set; }
        public bool BackedUp { get; set; }
        public string? BackupId { get; set; }
        public bool FileRemoved { get; set; }
        public bool FileQuarantined { get; set; }
        public int ProcessesKilled { get; set; }
        public int ProcessesSurvived { get; set; }
        public int RunEntriesRemoved { get; set; }
        public int TasksRemoved { get; set; }
        public int ServicesDisabled { get; set; }
        public List<string> Actions { get; } = new();
        public List<string> Failures { get; } = new();

        public string Summary
        {
            get
            {
                var parts = new List<string>();
                if (ProcessesKilled > 0) parts.Add($"{ProcessesKilled} process(es) killed");
                if (ProcessesSurvived > 0) parts.Add($"{ProcessesSurvived} process(es) survived");
                if (RunEntriesRemoved > 0) parts.Add($"{RunEntriesRemoved} autorun entry(ies) removed");
                if (TasksRemoved > 0) parts.Add($"{TasksRemoved} scheduled task(s) removed");
                if (ServicesDisabled > 0) parts.Add($"{ServicesDisabled} service(s) disabled");
                if (FileQuarantined) parts.Add("file quarantined");
                else if (FileRemoved) parts.Add("file wiped");
                else if (DeferredToReboot) parts.Add("file locked - removal scheduled for next reboot");
                if (Failures.Count > 0) parts.Add("failed: " + string.Join("; ", Failures));
                return parts.Count == 0 ? "nothing to do" : string.Join(", ", parts);
            }
        }
    }

    /// <summary>
    /// Removes a threat's whole footprint, not just the thing that was clicked on.
    ///
    /// The old removal path did one action per threat type: kill the PID, or delete the file. Killing a
    /// process left its image and its Run key behind, so it was back at the next logon; deleting a file
    /// that was still running failed silently and was reported as "securely wiped" anyway. This class
    /// does what an eradication has to do, in the only order that works, and reports what happened:
    ///
    ///   1. refuse to touch whitelisted files or Windows' own binaries (a false positive there bricks
    ///      the machine - being "smart" starts with knowing what not to kill),
    ///   2. back the file up,
    ///   3. kill EVERY process running that image (not just the one PID), with their process trees,
    ///   4. remove the persistence that would bring it back: Run/RunOnce values, scheduled tasks,
    ///      services pointing at the image,
    ///   5. wipe or quarantine the file - retrying while handles are released, and if it is still
    ///      locked, schedule deletion at next boot instead of pretending,
    ///   6. verify, and feed the confirmed removal into the reputation memory so the same bytes score
    ///      higher next time.
    /// </summary>
    public sealed class ThreatEradicator
    {
        private readonly BackupManager _backup;
        private readonly QuarantineService? _quarantine;
        private readonly ThreatAnalyzer _analyzer;
        private readonly WhitelistManager _whitelist;
        private readonly ILogger _logger;

        public event EventHandler<string>? LogAdded;

        private const int MOVEFILE_DELAY_UNTIL_REBOOT = 0x4;

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool MoveFileEx(string lpExistingFileName, string? lpNewFileName, int dwFlags);

        public ThreatEradicator(BackupManager backup, QuarantineService? quarantine,
            ThreatAnalyzer analyzer, WhitelistManager whitelist)
        {
            _backup = backup;
            _quarantine = quarantine;
            _analyzer = analyzer;
            _whitelist = whitelist;
            _logger = LoggingService.ForContext<ThreatEradicator>();
        }

        public async Task<EradicationResult> EradicateAsync(ThreatInfo threat, bool backup,
            EradicationMode mode, CancellationToken ct = default)
        {
            var result = new EradicationResult();

            try
            {
                var imagePath = ResolveImagePath(threat);

                // Nothing on disk and nothing running: the threat is already gone (a second click on
                // "Remove", or a sample that deleted itself). That is a success, not "nothing to do".
                if (imagePath == null && !IsProcessAlive(threat.ProcessId))
                {
                    result.FileRemoved = true;
                    result.Succeeded = true;
                    result.Actions.Add("already removed");
                    return Finish(threat, result);
                }

                // ---- 1. Safety rails ----------------------------------------------------------
                if (imagePath != null && _whitelist.IsWhitelisted(imagePath))
                {
                    result.Failures.Add("file is whitelisted");
                    return Finish(threat, result);
                }

                if (imagePath != null && IsProtectedSystemFile(imagePath))
                {
                    // Do not become the thing we are hunting: a scanner that deletes files out of
                    // System32 on a heuristic hit is worse than the malware.
                    result.Failures.Add("refusing to remove a Windows system file - review manually");
                    Log($"🛑 [SAFETY] Not removing Windows system file: {imagePath}");
                    return Finish(threat, result);
                }

                // Capture the hash BEFORE the bytes disappear so the learning signal binds to content.
                if (string.IsNullOrEmpty(threat.Hash) && imagePath != null && File.Exists(imagePath))
                {
                    try
                    {
                        if (new FileInfo(imagePath).Length <= 256L * 1024 * 1024)
                            threat.Hash = await _analyzer.SignatureDatabase.ComputeSHA256Async(imagePath);
                    }
                    catch { /* hashing is best-effort */ }
                }

                // ---- 2. Backup --------------------------------------------------------------
                if (backup && imagePath != null && File.Exists(imagePath))
                {
                    var id = _backup.BackupFile(imagePath);
                    if (id != null)
                    {
                        result.BackedUp = true;
                        result.BackupId = id;
                        threat.IsBackedUp = true;
                        threat.BackupPath = id;
                        result.Actions.Add("backed up");
                    }
                }

                // ---- 3. Kill every process running this image --------------------------------
                KillProcesses(threat, imagePath, result);

                // ---- 4. Remove persistence -----------------------------------------------------
                if (imagePath != null)
                {
                    result.RunEntriesRemoved = RemoveRunKeyReferences(imagePath, result);
                    result.TasksRemoved = RemoveScheduledTasksReferencing(imagePath, result);
                    result.ServicesDisabled = DisableServicesReferencing(imagePath, result);
                }

                // ---- 5. Deal with the file itself -------------------------------------------
                if (imagePath != null && File.Exists(imagePath))
                {
                    if (mode == EradicationMode.Quarantine && _quarantine != null)
                        await QuarantineWithRetryAsync(threat, imagePath, result, ct);
                    else
                        await WipeWithRetryAsync(imagePath, result, ct);
                }
                else if (imagePath != null)
                {
                    result.FileRemoved = true; // already gone
                }

                // ---- 6. Verdict ---------------------------------------------------------------
                var fileHandled = result.FileRemoved || result.FileQuarantined;
                result.Succeeded = fileHandled && result.ProcessesSurvived == 0
                                   && (imagePath != null || result.ProcessesKilled > 0);

                if (result.Succeeded)
                {
                    // LEARNING: a confirmed, completed removal is a true positive for these bytes.
                    try
                    {
                        _analyzer.Reputation?.RecordConfirmedRemoval(threat.Hash, imagePath ?? threat.Path,
                            threat.MatchedPatterns, threat.Score);
                    }
                    catch (Exception ex) { _logger.Debug(ex, "Reputation feedback failed"); }
                }

                return Finish(threat, result);
            }
            catch (OperationCanceledException)
            {
                result.Failures.Add("cancelled");
                return Finish(threat, result);
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Eradication failed for {Path}", threat.Path);
                result.Failures.Add(ex.Message);
                return Finish(threat, result);
            }
        }

        private EradicationResult Finish(ThreatInfo threat, EradicationResult result)
        {
            threat.RemovalNote = result.Summary;

            var icon = result.Succeeded ? "✅" : result.DeferredToReboot ? "⏳" : "❌";
            var verb = result.Succeeded ? "ERADICATED" : result.DeferredToReboot ? "PENDING REBOOT" : "INCOMPLETE";
            Log($"{icon} [{verb}] {threat.Name}: {result.Summary}");
            return result;
        }

        // ------------------------------------------------------------------------------------------
        // Resolution + safety
        // ------------------------------------------------------------------------------------------

        private static string? ResolveImagePath(ThreatInfo threat)
        {
            if (threat.ProcessId.HasValue)
            {
                try
                {
                    using var p = Process.GetProcessById(threat.ProcessId.Value);
                    var main = p.MainModule?.FileName;
                    if (!string.IsNullOrEmpty(main)) return main;
                }
                catch { /* exited, or access denied to its modules */ }
            }

            return File.Exists(threat.Path) ? Path.GetFullPath(threat.Path) : null;
        }

        private static bool IsProcessAlive(int? pid)
        {
            if (!pid.HasValue) return false;
            try
            {
                using var p = Process.GetProcessById(pid.Value);
                return !p.HasExited;
            }
            catch { return false; }
        }

        private static bool IsProtectedSystemFile(string path)
        {
            try
            {
                var full = Path.GetFullPath(path);
                var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);

                bool Under(string root) => full.StartsWith(root.TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase);

                // Our own binary must never be a removal target either.
                var self = AppDomain.CurrentDomain.BaseDirectory;
                if (!string.IsNullOrEmpty(self) && Under(self)) return true;

                // Binaries that live directly in %SystemRoot% (explorer.exe, regedit.exe, notepad.exe,
                // winhlp32.exe) are not under System32 - protect the root level explicitly. Deeper
                // folders such as Windows\Temp are deliberately NOT protected: they are drop sites.
                var parent = Path.GetDirectoryName(full) ?? "";
                if (string.Equals(parent.TrimEnd('\\'), windows.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase))
                    return true;

                return Under(Path.Combine(windows, "System32"))
                    || Under(Path.Combine(windows, "SysWOW64"))
                    || Under(Path.Combine(windows, "WinSxS"))
                    || Under(Path.Combine(windows, "servicing"))
                    || Under(Path.Combine(windows, "Boot"));
            }
            catch { return false; }
        }

        // ------------------------------------------------------------------------------------------
        // Processes
        // ------------------------------------------------------------------------------------------

        private void KillProcesses(ThreatInfo threat, string? imagePath, EradicationResult result)
        {
            var targets = new Dictionary<int, Process>();

            if (threat.ProcessId.HasValue)
            {
                try { targets[threat.ProcessId.Value] = Process.GetProcessById(threat.ProcessId.Value); }
                catch { /* already gone */ }
            }

            // Every OTHER process running the same image - malware frequently runs as a pair that
            // restarts whichever half is killed.
            if (imagePath != null)
            {
                foreach (var p in Process.GetProcesses())
                {
                    try
                    {
                        if (p.Id == Environment.ProcessId) { p.Dispose(); continue; }
                        var main = p.MainModule?.FileName;
                        if (!string.IsNullOrEmpty(main) &&
                            string.Equals(Path.GetFullPath(main), imagePath, StringComparison.OrdinalIgnoreCase))
                        {
                            targets[p.Id] = p;
                            continue;
                        }
                    }
                    catch { /* protected or exited */ }
                    p.Dispose();
                }
            }

            foreach (var (pid, proc) in targets)
            {
                try
                {
                    using (proc)
                    {
                        if (proc.HasExited) continue;
                        proc.Kill(entireProcessTree: true);
                        if (proc.WaitForExit(5000))
                        {
                            result.ProcessesKilled++;
                            Log($"💀 [KILLED] PID {pid} ({proc.ProcessName}) and its child processes");
                        }
                        else
                        {
                            result.ProcessesSurvived++;
                            result.Failures.Add($"PID {pid} did not exit");
                        }
                    }
                }
                catch (Exception ex)
                {
                    result.ProcessesSurvived++;
                    result.Failures.Add($"PID {pid}: {ex.Message}");
                }
            }
        }

        // ------------------------------------------------------------------------------------------
        // Persistence
        // ------------------------------------------------------------------------------------------

        private static readonly (RegistryHive Hive, RegistryView View, string Path)[] RunKeyLocations =
        {
            (RegistryHive.CurrentUser,  RegistryView.Default,    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (RegistryHive.CurrentUser,  RegistryView.Default,    @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
            (RegistryHive.LocalMachine, RegistryView.Registry64, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (RegistryHive.LocalMachine, RegistryView.Registry64, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
            (RegistryHive.LocalMachine, RegistryView.Registry32, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (RegistryHive.LocalMachine, RegistryView.Registry32, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
        };

        private int RemoveRunKeyReferences(string imagePath, EradicationResult result)
        {
            var removed = 0;

            foreach (var (hive, view, path) in RunKeyLocations)
            {
                try
                {
                    using var baseKey = RegistryKey.OpenBaseKey(hive, view);
                    using var key = baseKey.OpenSubKey(path, writable: true);
                    if (key == null) continue;

                    foreach (var valueName in key.GetValueNames())
                    {
                        var command = key.GetValue(valueName)?.ToString();
                        if (!CommandReferences(command, imagePath)) continue;

                        key.DeleteValue(valueName, throwOnMissingValue: false);
                        removed++;
                        Log($"🧹 [PERSISTENCE] Removed autorun '{valueName}' from {hive}\\{path}");
                    }
                }
                catch (Exception ex)
                {
                    result.Failures.Add($"autorun cleanup ({hive}): {ex.Message}");
                }
            }

            return removed;
        }

        private int RemoveScheduledTasksReferencing(string imagePath, EradicationResult result)
        {
            var removed = 0;
            var tasksRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "Tasks");
            if (!Directory.Exists(tasksRoot)) return 0;

            XNamespace ns = "http://schemas.microsoft.com/windows/2004/02/mit/task";

            foreach (var file in SafeEnumerateFiles(tasksRoot))
            {
                try
                {
                    var doc = XDocument.Load(file);
                    var hit = doc.Descendants(ns + "Exec").Any(exec =>
                    {
                        var cmd = Environment.ExpandEnvironmentVariables(exec.Element(ns + "Command")?.Value ?? "");
                        var args = exec.Element(ns + "Arguments")?.Value ?? "";
                        return CommandReferences(cmd + " " + args, imagePath);
                    });
                    if (!hit) continue;

                    // Task name = path relative to the Tasks root, e.g. "\Vendor\Updater".
                    var taskName = "\\" + Path.GetRelativePath(tasksRoot, file);

                    var psi = new ProcessStartInfo("schtasks.exe", $"/Delete /TN \"{taskName}\" /F")
                    {
                        UseShellExecute = false, CreateNoWindow = true,
                        RedirectStandardOutput = true, RedirectStandardError = true
                    };
                    using var p = Process.Start(psi);
                    p?.WaitForExit(10000);

                    if (p?.ExitCode == 0)
                    {
                        removed++;
                        Log($"🧹 [PERSISTENCE] Deleted scheduled task {taskName}");
                    }
                    else
                    {
                        result.Failures.Add($"scheduled task {taskName} could not be deleted");
                    }
                }
                catch { /* unreadable task - skip */ }
            }

            return removed;
        }

        private int DisableServicesReferencing(string imagePath, EradicationResult result)
        {
            var disabled = 0;
            try
            {
                using var searcher = new ManagementObjectSearcher("SELECT Name, PathName FROM Win32_Service");
                foreach (ManagementObject mo in searcher.Get())
                {
                    using (mo)
                    {
                        var name = mo["Name"] as string ?? "";
                        var pathName = mo["PathName"] as string ?? "";
                        if (name.Length == 0 || !CommandReferences(pathName, imagePath)) continue;

                        // Stop + disable rather than delete: reversible, and enough to break the
                        // persistence. Deleting arbitrary services on a heuristic is not something a
                        // security tool should do without a human in the loop.
                        RunSc($"stop \"{name}\"");
                        if (RunSc($"config \"{name}\" start= disabled"))
                        {
                            disabled++;
                            Log($"🧹 [PERSISTENCE] Stopped and disabled service '{name}'");
                        }
                        else
                        {
                            result.Failures.Add($"service '{name}' could not be disabled");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                result.Failures.Add($"service cleanup: {ex.Message}");
            }
            return disabled;
        }

        private static bool RunSc(string args)
        {
            try
            {
                var psi = new ProcessStartInfo("sc.exe", args)
                {
                    UseShellExecute = false, CreateNoWindow = true,
                    RedirectStandardOutput = true, RedirectStandardError = true
                };
                using var p = Process.Start(psi);
                p?.WaitForExit(10000);
                return p?.ExitCode == 0;
            }
            catch { return false; }
        }

        /// <summary>Does a command line / value data point at this image?</summary>
        private static bool CommandReferences(string? command, string imagePath)
        {
            if (string.IsNullOrWhiteSpace(command)) return false;
            var expanded = Environment.ExpandEnvironmentVariables(command);
            return expanded.IndexOf(imagePath, StringComparison.OrdinalIgnoreCase) >= 0;
        }

        private static IEnumerable<string> SafeEnumerateFiles(string root)
        {
            IEnumerable<string> files;
            try { files = Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories); }
            catch { yield break; }

            using var e = files.GetEnumerator();
            while (true)
            {
                try { if (!e.MoveNext()) yield break; }
                catch { yield break; }
                yield return e.Current;
            }
        }

        // ------------------------------------------------------------------------------------------
        // File
        // ------------------------------------------------------------------------------------------

        private async Task WipeWithRetryAsync(string path, EradicationResult result, CancellationToken ct)
        {
            // Handles can take a moment to be released after a kill; retry before giving up.
            for (var attempt = 1; attempt <= 4; attempt++)
            {
                if (SecureDelete(path))
                {
                    result.FileRemoved = true;
                    result.Actions.Add("wiped");
                    Log($"🧨 [WIPED] {path}");
                    return;
                }
                await Task.Delay(250 * attempt, ct);
            }

            if (!File.Exists(path))
            {
                result.FileRemoved = true;
                return;
            }

            // Still locked. Do what real AV does: have Windows delete it before anything can load it
            // again, and SAY SO instead of claiming success.
            if (MoveFileEx(path, null, MOVEFILE_DELAY_UNTIL_REBOOT))
            {
                result.DeferredToReboot = true;
                Log($"⏳ [DEFERRED] {path} is locked - Windows will delete it at the next reboot");
            }
            else
            {
                result.Failures.Add($"file locked and reboot-delete could not be scheduled (error {Marshal.GetLastWin32Error()})");
            }
        }

        private async Task QuarantineWithRetryAsync(ThreatInfo threat, string path, EradicationResult result, CancellationToken ct)
        {
            string lastMessage = "";
            for (var attempt = 1; attempt <= 4; attempt++)
            {
                var q = _quarantine!.QuarantineFile(path, threat);
                if (q.Success)
                {
                    result.FileQuarantined = true;
                    result.Actions.Add("quarantined");
                    Log($"🔒 [QUARANTINED] {path}");
                    return;
                }
                lastMessage = q.Message;
                await Task.Delay(250 * attempt, ct);
            }

            result.Failures.Add($"quarantine failed: {lastMessage}");
        }

        /// <summary>
        /// Overwrite then delete. Returns whether the file is actually gone - the previous version
        /// swallowed every exception and the caller reported "securely wiped" regardless.
        /// </summary>
        private static bool SecureDelete(string path)
        {
            try
            {
                File.SetAttributes(path, FileAttributes.Normal);
                var length = new FileInfo(path).Length;
                if (length > 0)
                {
                    var toWipe = Math.Min(length, 100L * 1024 * 1024);
                    using var rng = System.Security.Cryptography.RandomNumberGenerator.Create();
                    using var fs = new FileStream(path, FileMode.Open, FileAccess.Write, FileShare.None);
                    var buffer = new byte[64 * 1024];
                    long written = 0;
                    while (written < toWipe)
                    {
                        rng.GetBytes(buffer);
                        var n = (int)Math.Min(buffer.Length, toWipe - written);
                        fs.Write(buffer, 0, n);
                        written += n;
                    }
                    fs.Flush(true);
                }
            }
            catch
            {
                // Could not overwrite (locked). Fall through and try a plain delete anyway.
            }

            try { File.Delete(path); } catch { }
            return !File.Exists(path);
        }

        private void Log(string message) => LogAdded?.Invoke(this, message);
    }
}
