using System.Diagnostics;
using System.IO;
using System.Management;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32;
using SkidrowKiller.Models;
using Serilog;

namespace SkidrowKiller.Services
{
    public class SafeScanner : IDisposable
    {
        private readonly ThreatAnalyzer _analyzer;
        private readonly WhitelistManager _whitelist;
        private readonly BackupManager _backup;
        private readonly ILogger _logger;
        private CancellationTokenSource? _cts;
        private bool _isPaused;
        private bool _disposed;
        private readonly ManualResetEventSlim _pauseEvent = new(true);

        public event EventHandler<string>? LogAdded;
        public event EventHandler<ThreatInfo>? ThreatFound;
        public event EventHandler<ProgressEventArgs>? ProgressChanged;
        public event EventHandler<ScanResult>? ScanCompleted;
        public event EventHandler<string>? PreScanStatusChanged;

        public bool IsPaused => _isPaused;
        public bool IsScanning => _cts != null && !_cts.IsCancellationRequested;

        // Pre-scan counting
        private long _totalFilesToScan;
        private long _totalRegistryToScan;
        private long _totalProcessesToScan;
        private long _totalItemsToScan;
        private int _currentSectionIndex;
        private int _totalSections;
        private string _currentSection = string.Empty;
        private long _sectionScanned;
        private long _sectionTotal;

        // Scan mode parameters
        private Views.ScanMode _currentScanMode = Views.ScanMode.Quick;
        private List<string> _selectedDrives = new();

        [DllImport("kernel32.dll")]
        private static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
        [DllImport("kernel32.dll")]
        private static extern bool CloseHandle(IntPtr handle);
        [DllImport("psapi.dll")]
        private static extern bool EnumProcessModules(IntPtr hProcess, IntPtr[] modules, uint cb, out uint needed);
        [DllImport("psapi.dll", CharSet = CharSet.Unicode)]
        private static extern uint GetModuleFileNameEx(IntPtr hProcess, IntPtr hModule, StringBuilder name, uint size);

        private const uint PROCESS_QUERY_INFORMATION = 0x0400;
        private const uint PROCESS_VM_READ = 0x0010;

        public SafeScanner(ThreatAnalyzer analyzer, WhitelistManager whitelist, BackupManager backup)
        {
            _analyzer = analyzer ?? throw new ArgumentNullException(nameof(analyzer));
            _whitelist = whitelist ?? throw new ArgumentNullException(nameof(whitelist));
            _backup = backup ?? throw new ArgumentNullException(nameof(backup));
            _logger = LoggingService.ForContext<SafeScanner>();
            _backup.LogAdded += (s, msg) => RaiseLog(msg);
        }

        public async Task<ScanResult> ScanAsync(bool scanFiles, bool scanRegistry, bool scanProcesses,
            Views.ScanMode scanMode = Views.ScanMode.Quick, List<string>? selectedDrives = null)
        {
            _cts = new CancellationTokenSource();
            var token = _cts.Token;
            var startTime = DateTime.Now;
            var result = new ScanResult();

            // Store scan parameters
            _currentScanMode = scanMode;
            _selectedDrives = selectedDrives ?? new List<string>();

            try
            {
                var modeText = scanMode switch
                {
                    Views.ScanMode.Quick => "QUICK SCAN",
                    Views.ScanMode.Deep => "DEEP SCAN",
                    _ => "CUSTOM SCAN"
                };

                RaiseLog("=" + new string('=', 60));
                RaiseLog($"🔍 Starting {modeText} with Threat Analysis");
                RaiseLog("=" + new string('=', 60));

                if (scanMode == Views.ScanMode.Quick)
                {
                    RaiseLog("   Mode: Quick - Scanning common malware locations only");
                }
                else if (scanMode == Views.ScanMode.Deep)
                {
                    RaiseLog("   Mode: Deep - Full system scan");
                }

                if (_selectedDrives.Any())
                {
                    RaiseLog($"   Drives: {string.Join(", ", _selectedDrives)}");
                }

                // Pre-scan: Count items first
                RaiseLog("\n📊 [PRE-SCAN] Counting items to scan...");
                await PreScanCountAsync(scanFiles, scanRegistry, scanProcesses, token);

                // Calculate total sections
                _totalSections = 0;
                if (scanFiles) _totalSections++;
                if (scanRegistry) _totalSections++;
                if (scanProcesses) _totalSections++;
                _currentSectionIndex = 0;

                RaiseLog($"   Total items to scan: {_totalItemsToScan:N0}");
                RaiseLog($"   Files: {_totalFilesToScan:N0} | Registry: {_totalRegistryToScan:N0} | Processes: {_totalProcessesToScan:N0}");

                if (scanFiles && !token.IsCancellationRequested)
                {
                    _currentSectionIndex++;
                    _currentSection = "Files";
                    _sectionTotal = _totalFilesToScan;
                    _sectionScanned = 0;
                    RaiseLog("\n📁 [FILE SCAN] Scanning file system...");
                    await ScanFilesAsync(result, token);
                }

                if (scanRegistry && !token.IsCancellationRequested)
                {
                    _currentSectionIndex++;
                    _currentSection = "Registry";
                    _sectionTotal = _totalRegistryToScan;
                    _sectionScanned = 0;
                    RaiseLog("\n📋 [REGISTRY SCAN] Scanning registry...");
                    await ScanRegistryAsync(result, token);
                }

                if (scanProcesses && !token.IsCancellationRequested)
                {
                    _currentSectionIndex++;
                    _currentSection = "Memory";
                    _sectionTotal = _totalProcessesToScan;
                    _sectionScanned = 0;
                    RaiseLog("\n💾 [MEMORY SCAN] Scanning processes...");
                    await ScanProcessesAsync(result, token);
                }

                result.Duration = DateTime.Now - startTime;

                RaiseLog("\n" + new string('=', 60));
                RaiseLog("📊 Scan Summary:");
                RaiseLog($"  Total Scanned: {result.TotalScanned:N0}");
                RaiseLog($"  Threats Found: {result.ThreatsFound}");
                RaiseLog($"  Backed Up: {result.ThreatsBackedUp}");
                RaiseLog($"  Removed: {result.ThreatsRemoved}");
                RaiseLog($"  Skipped: {result.ThreatsSkipped}");
                RaiseLog($"  Duration: {result.Duration.TotalSeconds:F1}s");
                RaiseLog(new string('=', 60));

                ScanCompleted?.Invoke(this, result);
            }
            catch (OperationCanceledException)
            {
                RaiseLog("\n⚠️ [CANCELLED] Scan stopped by user");
            }
            catch (Exception ex)
            {
                RaiseLog($"\n❌ [ERROR] {ex.Message}");
            }

            return result;
        }

        private async Task PreScanCountAsync(bool scanFiles, bool scanRegistry, bool scanProcesses, CancellationToken token)
        {
            _totalFilesToScan = 0;
            _totalRegistryToScan = 0;
            _totalProcessesToScan = 0;

            if (scanFiles)
            {
                PreScanStatusChanged?.Invoke(this, "Counting files...");
                await Task.Run(() =>
                {
                    var drivesToScan = GetDrivesToScan();

                    if (_currentScanMode == Views.ScanMode.Quick)
                    {
                        // Quick scan: only count common malware locations
                        foreach (var drive in drivesToScan)
                        {
                            if (token.IsCancellationRequested) break;
                            foreach (var path in GetQuickScanPaths(drive))
                            {
                                if (token.IsCancellationRequested) break;
                                if (Directory.Exists(path))
                                {
                                    CountFilesInDirectory(path, token, maxDepth: 3);
                                }
                            }
                        }
                    }
                    else
                    {
                        // Deep/Custom scan: count all files
                        foreach (var drive in drivesToScan)
                        {
                            if (token.IsCancellationRequested) break;
                            CountFilesInDirectory(drive, token);
                        }
                    }
                }, token);
            }

            if (scanRegistry)
            {
                PreScanStatusChanged?.Invoke(this, "Counting registry entries...");
                await Task.Run(() =>
                {
                    _totalRegistryToScan = CountRegistryEntries(token);
                }, token);
            }

            if (scanProcesses)
            {
                PreScanStatusChanged?.Invoke(this, "Counting processes...");
                _totalProcessesToScan = Process.GetProcesses().Length;
            }

            _totalItemsToScan = _totalFilesToScan + _totalRegistryToScan + _totalProcessesToScan;
            PreScanStatusChanged?.Invoke(this, $"Found {_totalItemsToScan:N0} items");
        }

        private List<string> GetDrivesToScan()
        {
            if (_selectedDrives.Any())
            {
                return _selectedDrives;
            }

            // Default: all fixed and removable drives
            return DriveInfo.GetDrives()
                .Where(d => d.IsReady && (d.DriveType == DriveType.Fixed || d.DriveType == DriveType.Removable))
                .Select(d => d.RootDirectory.FullName)
                .ToList();
        }

        private static List<string> GetQuickScanPaths(string drive)
        {
            var paths = new List<string>();
            var driveLetter = Path.GetPathRoot(drive) ?? drive;

            // Common malware hiding spots
            paths.Add(Path.Combine(driveLetter, "Windows", "Temp"));
            paths.Add(Path.Combine(driveLetter, "Windows", "System32", "drivers"));
            paths.Add(Path.Combine(driveLetter, "Windows", "System32", "Tasks"));
            paths.Add(Path.Combine(driveLetter, "ProgramData"));
            paths.Add(Path.Combine(driveLetter, "Program Files"));
            paths.Add(Path.Combine(driveLetter, "Program Files (x86)"));

            // User profile locations
            var usersPath = Path.Combine(driveLetter, "Users");
            if (Directory.Exists(usersPath))
            {
                try
                {
                    foreach (var userDir in Directory.GetDirectories(usersPath))
                    {
                        paths.Add(Path.Combine(userDir, "AppData", "Local", "Temp"));
                        paths.Add(Path.Combine(userDir, "AppData", "Roaming"));
                        paths.Add(Path.Combine(userDir, "AppData", "Local"));
                        paths.Add(Path.Combine(userDir, "Downloads"));
                        paths.Add(Path.Combine(userDir, "Desktop"));
                    }
                }
                catch { }
            }

            return paths.Where(p => Directory.Exists(p)).ToList();
        }

        private void CountFilesInDirectory(string path, CancellationToken token, int maxDepth = -1, int currentDepth = 0)
        {
            try
            {
                if (token.IsCancellationRequested) return;
                if (maxDepth != -1 && currentDepth > maxDepth) return;

                // Count files
                try
                {
                    _totalFilesToScan += Directory.GetFiles(path).Length;
                }
                catch { }

                // Recurse subdirectories
                try
                {
                    foreach (var dir in Directory.GetDirectories(path))
                    {
                        if (token.IsCancellationRequested) return;
                        CountFilesInDirectory(dir, token, maxDepth, currentDepth + 1);
                    }
                }
                catch { }
            }
            catch { }
        }

        private long CountRegistryEntries(CancellationToken token)
        {
            long count = 0;
            var rootKeys = new[] { Registry.CurrentUser, Registry.LocalMachine };
            var scanPaths = new[]
            {
                @"Software\Microsoft\Windows\CurrentVersion\Run",
                @"Software\Microsoft\Windows\CurrentVersion\RunOnce",
                @"Software"
            };

            foreach (var rootKey in rootKeys)
            {
                foreach (var path in scanPaths)
                {
                    if (token.IsCancellationRequested) break;
                    count += CountRegistryKey(rootKey, path, token);
                }
            }
            return count;
        }

        private long CountRegistryKey(RegistryKey rootKey, string path, CancellationToken token)
        {
            long count = 0;
            try
            {
                if (token.IsCancellationRequested) return count;

                using var key = rootKey.OpenSubKey(path, false);
                if (key == null) return count;

                count++; // Count the key itself
                count += key.GetValueNames().Length;

                foreach (var subKeyName in key.GetSubKeyNames())
                {
                    if (token.IsCancellationRequested) break;
                    count += CountRegistryKey(rootKey, $"{path}\\{subKeyName}", token);
                }
            }
            catch { }
            return count;
        }

        private async Task ScanFilesAsync(ScanResult result, CancellationToken token)
        {
            var drivesToScan = GetDrivesToScan();

            if (_currentScanMode == Views.ScanMode.Quick)
            {
                // Quick scan: only scan common malware locations
                RaiseLog("   Scanning common malware locations...");
                foreach (var drive in drivesToScan)
                {
                    if (token.IsCancellationRequested) break;
                    foreach (var path in GetQuickScanPaths(drive))
                    {
                        if (token.IsCancellationRequested) break;
                        if (Directory.Exists(path))
                        {
                            RaiseLog($"   📁 {path}");
                            await Task.Run(() => ScanDirectory(path, result, token, maxDepth: 3), token);
                        }
                    }
                }
            }
            else
            {
                // Deep/Custom scan: scan all files on selected drives
                foreach (var drive in drivesToScan)
                {
                    if (token.IsCancellationRequested) break;
                    RaiseLog($"   📁 Scanning drive: {drive}");
                    await Task.Run(() => ScanDirectory(drive, result, token), token);
                }
            }
        }

        private void ScanDirectory(string path, ScanResult result, CancellationToken token, int maxDepth = -1, int currentDepth = 0)
        {
            try
            {
                _pauseEvent.Wait(token);
                if (token.IsCancellationRequested) return;
                if (maxDepth != -1 && currentDepth > maxDepth) return;

                // Analyze directory itself
                var dirThreat = _analyzer.AnalyzePath(path);
                if (dirThreat != null)
                {
                    result.Threats.Add(dirThreat);
                    result.ThreatsFound++;
                    ThreatFound?.Invoke(this, dirThreat);
                    RaiseLog($"🔴 [THREAT] {dirThreat.SeverityDisplay}: {path}");
                    RaiseLog($"   Score: {dirThreat.Score} | Patterns: {string.Join(", ", dirThreat.MatchedPatterns)}");
                }

                // Scan files in directory
                foreach (var file in Directory.GetFiles(path))
                {
                    if (token.IsCancellationRequested) return;
                    _pauseEvent.Wait(token);

                    result.TotalScanned++;
                    _sectionScanned++;

                    // Report progress every 100 files for smoother UI
                    if (result.TotalScanned % 100 == 0)
                    {
                        RaiseProgress(file, result);
                    }

                    var threat = _analyzer.AnalyzePath(file);
                    if (threat != null)
                    {
                        result.Threats.Add(threat);
                        result.ThreatsFound++;
                        ThreatFound?.Invoke(this, threat);
                        RaiseLog($"🔴 [THREAT] {threat.SeverityDisplay}: {file}");
                        RaiseLog($"   Score: {threat.Score} | Patterns: {string.Join(", ", threat.MatchedPatterns)}");
                    }
                }

                // Recurse into subdirectories
                foreach (var dir in Directory.GetDirectories(path))
                {
                    if (token.IsCancellationRequested) return;
                    ScanDirectory(dir, result, token, maxDepth, currentDepth + 1);
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (Exception) { }
        }

        private void RaiseProgress(string currentItem, ScanResult result)
        {
            ProgressChanged?.Invoke(this, new ProgressEventArgs
            {
                CurrentItem = currentItem,
                ScannedCount = result.TotalScanned,
                FoundCount = result.ThreatsFound,
                CurrentSection = _currentSection,
                SectionIndex = _currentSectionIndex,
                TotalSections = _totalSections,
                SectionScanned = _sectionScanned,
                SectionTotal = _sectionTotal,
                TotalItems = _totalItemsToScan
            });
        }

        private async Task ScanRegistryAsync(ScanResult result, CancellationToken token)
        {
            var rootKeys = new[] { Registry.CurrentUser, Registry.LocalMachine };
            var scanPaths = new[]
            {
                @"Software\Microsoft\Windows\CurrentVersion\Run",
                @"Software\Microsoft\Windows\CurrentVersion\RunOnce",
                @"Software"
            };

            foreach (var rootKey in rootKeys)
            {
                foreach (var path in scanPaths)
                {
                    if (token.IsCancellationRequested) break;
                    await Task.Run(() => ScanRegistryKey(rootKey, path, result, token), token);
                }
            }
        }

        private void ScanRegistryKey(RegistryKey rootKey, string path, ScanResult result, CancellationToken token)
        {
            try
            {
                _pauseEvent.Wait(token);
                if (token.IsCancellationRequested) return;

                using var key = rootKey.OpenSubKey(path, false);
                if (key == null) return;

                result.TotalScanned++;
                _sectionScanned++;

                // Report progress every 50 registry entries
                if (_sectionScanned % 50 == 0)
                {
                    RaiseProgress($"{rootKey.Name}\\{path}", result);
                }

                // Check values
                foreach (var valueName in key.GetValueNames())
                {
                    if (token.IsCancellationRequested) return;

                    var value = key.GetValue(valueName)?.ToString() ?? "";
                    var fullPath = $"{rootKey.Name}\\{path}\\{valueName}";

                    var threat = _analyzer.AnalyzePath(value);
                    if (threat != null)
                    {
                        threat.Type = ThreatType.Registry;
                        threat.Path = fullPath;
                        threat.Name = valueName;
                        result.Threats.Add(threat);
                        result.ThreatsFound++;
                        ThreatFound?.Invoke(this, threat);
                        RaiseLog($"🔴 [REGISTRY] {threat.SeverityDisplay}: {fullPath}");
                    }
                }

                // Check subkeys
                foreach (var subKeyName in key.GetSubKeyNames())
                {
                    if (token.IsCancellationRequested) return;

                    var threat = _analyzer.AnalyzePath(subKeyName);
                    if (threat != null)
                    {
                        threat.Type = ThreatType.Registry;
                        threat.Path = $"{rootKey.Name}\\{path}\\{subKeyName}";
                        threat.Name = subKeyName;
                        result.Threats.Add(threat);
                        result.ThreatsFound++;
                        ThreatFound?.Invoke(this, threat);
                        RaiseLog($"🔴 [REGISTRY KEY] {threat.SeverityDisplay}: {threat.Path}");
                    }

                    ScanRegistryKey(rootKey, $"{path}\\{subKeyName}", result, token);
                }
            }
            catch { }
        }

        private async Task ScanProcessesAsync(ScanResult result, CancellationToken token)
        {
            var processes = Process.GetProcesses();
            RaiseLog($"Analyzing {processes.Length} processes...");

            var processIndex = 0;
            foreach (var process in processes)
            {
                if (token.IsCancellationRequested) break;

                try
                {
                    result.TotalScanned++;
                    _sectionScanned++;
                    processIndex++;

                    // Report progress for each process
                    RaiseProgress(process.ProcessName, result);

                    string? execPath = null;
                    try { execPath = process.MainModule?.FileName; } catch { }

                    var loadedDlls = GetLoadedModules(process);
                    var threat = _analyzer.AnalyzeProcess(process.Id, process.ProcessName, execPath, loadedDlls);

                    if (threat != null)
                    {
                        result.Threats.Add(threat);
                        result.ThreatsFound++;
                        ThreatFound?.Invoke(this, threat);
                        RaiseLog($"🔴 [PROCESS] {threat.SeverityDisplay}: {process.ProcessName} (PID: {process.Id})");
                        RaiseLog($"   Score: {threat.Score} | Path: {execPath ?? "N/A"}");
                        if (loadedDlls?.Any() == true)
                        {
                            RaiseLog($"   Suspicious DLLs: {string.Join(", ", loadedDlls.Select(Path.GetFileName))}");
                        }
                    }
                }
                catch { }
                finally
                {
                    try { process.Dispose(); } catch { }
                }

                await Task.Delay(10, token); // Small delay to prevent UI freeze
            }
        }

        private List<string>? GetLoadedModules(Process process)
        {
            try
            {
                var modules = process.Modules;
                return modules.Cast<ProcessModule>()
                    .Select(m => m.FileName)
                    .Where(f => !string.IsNullOrEmpty(f))
                    .ToList();
            }
            catch
            {
                return GetModulesNative(process);
            }
        }

        private List<string>? GetModulesNative(Process process)
        {
            var result = new List<string>();
            var hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, process.Id);
            if (hProcess == IntPtr.Zero) return null;

            try
            {
                var modules = new IntPtr[1024];
                if (EnumProcessModules(hProcess, modules, (uint)(modules.Length * IntPtr.Size), out var needed))
                {
                    var count = (int)(needed / IntPtr.Size);
                    for (var i = 0; i < count; i++)
                    {
                        var sb = new StringBuilder(260);
                        if (GetModuleFileNameEx(hProcess, modules[i], sb, (uint)sb.Capacity) > 0)
                        {
                            result.Add(sb.ToString());
                        }
                    }
                }
            }
            finally
            {
                CloseHandle(hProcess);
            }

            return result.Count > 0 ? result : null;
        }

        public async Task<bool> RemoveThreatAsync(ThreatInfo threat, bool backup = true)
        {
            try
            {
                // Backup first if requested
                if (backup)
                {
                    string? backupId = null;
                    switch (threat.Type)
                    {
                        case ThreatType.File:
                            backupId = _backup.BackupFile(threat.Path);
                            break;
                        case ThreatType.Directory:
                            backupId = _backup.BackupDirectory(threat.Path);
                            break;
                        case ThreatType.Registry:
                            // Registry backup handled separately
                            break;
                    }

                    if (backupId != null)
                    {
                        threat.IsBackedUp = true;
                        threat.BackupPath = backupId;
                    }
                }

                // Remove threat
                switch (threat.Type)
                {
                    case ThreatType.File:
                        if (File.Exists(threat.Path))
                        {
                            File.SetAttributes(threat.Path, FileAttributes.Normal);
                            File.Delete(threat.Path);
                            RaiseLog($"✅ [REMOVED] File: {threat.Path}");
                            return true;
                        }
                        break;

                    case ThreatType.Directory:
                        if (Directory.Exists(threat.Path))
                        {
                            Directory.Delete(threat.Path, true);
                            RaiseLog($"✅ [REMOVED] Directory: {threat.Path}");
                            return true;
                        }
                        break;

                    case ThreatType.Process:
                        if (threat.ProcessId.HasValue)
                        {
                            var proc = Process.GetProcessById(threat.ProcessId.Value);
                            proc.Kill(true);
                            proc.WaitForExit(5000);
                            RaiseLog($"✅ [KILLED] Process: {threat.Name} (PID: {threat.ProcessId})");
                            return true;
                        }
                        break;

                    case ThreatType.Registry:
                        // Parse and delete registry entry
                        return DeleteRegistryEntry(threat.Path);
                }
            }
            catch (Exception ex)
            {
                RaiseLog($"❌ [ERROR] Failed to remove {threat.Path}: {ex.Message}");
            }

            return false;
        }

        private bool DeleteRegistryEntry(string fullPath)
        {
            try
            {
                RegistryKey? rootKey = null;
                var path = fullPath;

                if (path.StartsWith("HKEY_CURRENT_USER"))
                {
                    rootKey = Registry.CurrentUser;
                    path = path.Substring("HKEY_CURRENT_USER\\".Length);
                }
                else if (path.StartsWith("HKEY_LOCAL_MACHINE"))
                {
                    rootKey = Registry.LocalMachine;
                    path = path.Substring("HKEY_LOCAL_MACHINE\\".Length);
                }

                if (rootKey == null) return false;

                var lastSlash = path.LastIndexOf('\\');
                if (lastSlash > 0)
                {
                    var keyPath = path.Substring(0, lastSlash);
                    var valueName = path.Substring(lastSlash + 1);

                    using var key = rootKey.OpenSubKey(keyPath, true);
                    if (key != null)
                    {
                        key.DeleteValue(valueName, false);
                        RaiseLog($"✅ [REMOVED] Registry: {fullPath}");
                        return true;
                    }
                }
            }
            catch { }
            return false;
        }

        public void Pause()
        {
            _isPaused = true;
            _pauseEvent.Reset();
            RaiseLog("⏸️ [PAUSED] Scan paused");
        }

        public void Resume()
        {
            _isPaused = false;
            _pauseEvent.Set();
            RaiseLog("▶️ [RESUMED] Scan resumed");
        }

        public void Stop()
        {
            _logger.Information("Scan stop requested");
            _cts?.Cancel();
            _pauseEvent.Set(); // Unblock if paused
        }

        private void RaiseLog(string message)
        {
            LogAdded?.Invoke(this, message);
            _logger.Debug("Scan log: {Message}", message);
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (_disposed) return;

            if (disposing)
            {
                _logger.Debug("Disposing SafeScanner");
                _cts?.Cancel();
                _cts?.Dispose();
                _pauseEvent.Dispose();
            }

            _disposed = true;
        }

        ~SafeScanner()
        {
            Dispose(false);
        }
    }

    public class ProgressEventArgs : EventArgs
    {
        public string CurrentItem { get; set; } = string.Empty;
        public long ScannedCount { get; set; }
        public int FoundCount { get; set; }

        // Section progress (Files, Registry, Processes)
        public string CurrentSection { get; set; } = string.Empty;
        public int SectionIndex { get; set; }
        public int TotalSections { get; set; }
        public long SectionScanned { get; set; }
        public long SectionTotal { get; set; }
        public double SectionPercent => SectionTotal > 0 ? (double)SectionScanned / SectionTotal * 100 : 0;

        // Overall progress
        public long TotalItems { get; set; }
        public double TotalPercent => TotalItems > 0 ? (double)ScannedCount / TotalItems * 100 : 0;
    }

    public class ScanPhase
    {
        public string Name { get; set; } = string.Empty;
        public long ItemCount { get; set; }
        public bool IsCompleted { get; set; }
    }
}
