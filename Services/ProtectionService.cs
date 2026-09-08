using System.Diagnostics;
using System.IO;
using System.Net.NetworkInformation;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using System.Threading;
using Microsoft.Win32;
using SkidrowKiller.Models;

namespace SkidrowKiller.Services
{
    public enum ProtectionStatus
    {
        Safe,
        Warning,
        Critical
    }

    public class ProtectionAlert
    {
        public DateTime Timestamp { get; set; } = DateTime.Now;
        public ProtectionStatus Status { get; set; }
        public string ProcessName { get; set; } = string.Empty;
        public int ProcessId { get; set; }
        public string Description { get; set; } = string.Empty;
        public string Details { get; set; } = string.Empty;
        public ThreatInfo? Threat { get; set; }
    }

    /// <summary>
    /// Real-time protection service with file monitoring, process monitoring, and network monitoring.
    /// </summary>
    public class ProtectionService : IDisposable
    {
        private readonly ThreatAnalyzer _analyzer;
        private readonly WhitelistManager _whitelist;
        private CancellationTokenSource? _cts;
        private Task? _monitorTask;
        private readonly HashSet<int> _knownProcessIds = new();
        private readonly List<FileSystemWatcher> _fileWatchers = new();
        private readonly HashSet<string> _alertedConnections = new();
        private ProtectionStatus _currentStatus = ProtectionStatus.Safe;
        private DateTime _lastWarningAt = DateTime.MinValue;
        private int _alertCount;

        private static readonly TimeSpan _monitorInterval =
            TimeSpan.FromSeconds(Math.Clamp(SafeProtectionSetting(s => s.MonitorIntervalSeconds, 2), 1, 60));

        private static readonly TimeSpan _autoResetAfter =
            TimeSpan.FromSeconds(Math.Clamp(SafeProtectionSetting(s => s.AutoResetStatusSeconds, 30), 5, 600));

        private static int SafeProtectionSetting(Func<ProtectionSettings, int> selector, int fallback)
        {
            try
            {
                var value = selector(AppConfiguration.Settings.Protection);
                return value > 0 ? value : fallback;
            }
            catch { return fallback; }
        }

        // Real stats
        private int _processesScanned;
        private int _filesWatched;
        private int _networkConnections;
        private int _registryKeysChecked;
        private int _blockedThreats;
        private int _threatsDetected;

        public event EventHandler<ProtectionAlert>? AlertRaised;
        public event EventHandler<ProtectionStatus>? StatusChanged;
        public event EventHandler<string>? LogAdded;

        public bool IsRunning { get; private set; }
        public ProtectionStatus CurrentStatus => _currentStatus;
        public int AlertCount => _alertCount;

        // Per-layer switches driven by Settings -> Real-time Protection. Changing one takes effect on
        // the next monitor tick; file watchers are (re)built when the flag flips while running.
        public bool ProcessMonitoringEnabled { get; set; } = true;
        public bool NetworkMonitoringEnabled { get; set; } = true;
        public bool RegistryMonitoringEnabled { get; set; } = true;

        /// <summary>
        /// Back off while a game is in the foreground: poll less often and skip the registry sweep.
        /// Drives Gaming Mode's "Reduce scan intensity" option, which previously changed nothing.
        /// </summary>
        public bool LowIntensityMode { get; set; }

        private bool _fileMonitoringEnabled = true;
        public bool FileMonitoringEnabled
        {
            get => _fileMonitoringEnabled;
            set
            {
                if (_fileMonitoringEnabled == value) return;
                _fileMonitoringEnabled = value;
                if (!IsRunning) return;

                if (value) SetupFileSystemWatchers();
                else DisposeFileWatchers();
            }
        }

        // Real stats properties
        public int ProcessesScanned => _processesScanned;
        public int FilesWatched => _filesWatched;
        public int NetworkConnections => _networkConnections;
        public int RegistryKeysChecked => _registryKeysChecked;

        /// <summary>Threats this service has flagged. Flagging is not blocking.</summary>
        public int ThreatsDetected => _threatsDetected;

        /// <summary>
        /// Threats that were actually neutralised in response to an alert. This used to be bumped on
        /// every detection while nothing in this class ever killed, quarantined or deleted anything -
        /// it is now only incremented by <see cref="ReportBlocked"/> from whoever really acted.
        /// </summary>
        public int BlockedThreats => _blockedThreats;

        public void ReportBlocked() => Interlocked.Increment(ref _blockedThreats);

        // Base list plus whatever Protection:SuspiciousPorts adds in appsettings.json (that key used to be dead).
        private readonly HashSet<int> _suspiciousPorts = BuildSuspiciousPorts();

        private static HashSet<int> BuildSuspiciousPorts()
        {
            var ports = new HashSet<int>
            {
                4444, 5555, 6666, 7777, 8888, 9999, 31337, 12345, 65535,
                1337, 4443, 8443, 6667, 6668, 6669, 1080, 9050
            };

            try
            {
                foreach (var p in AppConfiguration.Settings.Protection.SuspiciousPorts)
                    ports.Add(p);
            }
            catch { /* configuration unavailable - defaults are enough */ }

            return ports;
        }

        private readonly string[] _monitoredExtensions = {
            ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js",
            ".scr", ".pif", ".msi", ".jar", ".hta", ".wsf"
        };

        private readonly string[] _persistenceKeys = {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        };

        public ProtectionService(ThreatAnalyzer analyzer, WhitelistManager whitelist)
        {
            _analyzer = analyzer;
            _whitelist = whitelist;
        }

        public void Start()
        {
            if (IsRunning) return;

            _cts = new CancellationTokenSource();
            IsRunning = true;
            _alertCount = 0;
            _processesScanned = 0;
            _filesWatched = 0;
            _networkConnections = 0;
            _registryKeysChecked = 0;
            _blockedThreats = 0;
            _threatsDetected = 0;
            _alertedConnections.Clear();

            InitializeKnownProcesses();
            if (FileMonitoringEnabled) SetupFileSystemWatchers();
            _monitorTask = Task.Run(() => MonitorLoop(_cts.Token));

            static string State(bool on) => on ? "Active" : "Disabled in settings";

            RaiseLog("🛡️ [PROTECTION] Real-time monitoring started");
            RaiseLog($"   ├─ Process monitoring: {State(ProcessMonitoringEnabled)}");
            RaiseLog($"   ├─ File system monitoring: {State(FileMonitoringEnabled)}");
            RaiseLog($"   ├─ Network monitoring: {State(NetworkMonitoringEnabled)}");
            RaiseLog($"   └─ Registry monitoring: {State(RegistryMonitoringEnabled)}");
            UpdateStatus(ProtectionStatus.Safe);
        }

        public void Stop()
        {
            if (!IsRunning) return;

            _cts?.Cancel();
            IsRunning = false;

            DisposeFileWatchers();

            RaiseLog("🛡️ [PROTECTION] Real-time monitoring stopped");
            RaiseLog($"   📊 Session: {_processesScanned} processes, {_filesWatched} files, {_blockedThreats} blocked");
        }

        #region File System Monitoring

        private void DisposeFileWatchers()
        {
            lock (_fileWatchers)
            {
                foreach (var watcher in _fileWatchers)
                {
                    try
                    {
                        watcher.EnableRaisingEvents = false;
                        watcher.Dispose();
                    }
                    catch { /* already torn down */ }
                }
                _fileWatchers.Clear();
            }
        }

        private void SetupFileSystemWatchers()
        {
            var watchPaths = new List<string>();

            var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            var downloads = Path.Combine(userProfile, "Downloads");
            var desktop = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
            var temp = Path.GetTempPath();
            var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

            if (Directory.Exists(downloads)) watchPaths.Add(downloads);
            if (Directory.Exists(desktop)) watchPaths.Add(desktop);
            if (Directory.Exists(temp)) watchPaths.Add(temp);
            if (Directory.Exists(appData)) watchPaths.Add(appData);

            foreach (var path in watchPaths)
            {
                try
                {
                    var watcher = new FileSystemWatcher(path)
                    {
                        NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.CreationTime,
                        IncludeSubdirectories = true,
                        InternalBufferSize = 64 * 1024,
                        EnableRaisingEvents = true
                    };

                    watcher.Created += OnFileCreated;
                    watcher.Renamed += OnFileRenamed;
                    watcher.Error += OnWatcherError;

                    _fileWatchers.Add(watcher);
                    _filesWatched++;
                    RaiseLog($"👁️ [WATCH] Monitoring: {Path.GetFileName(path)}");
                }
                catch (Exception ex)
                {
                    RaiseLog($"⚠️ [WATCH] Failed: {Path.GetFileName(path)} - {ex.Message}");
                }
            }
        }

        private void OnWatcherError(object sender, ErrorEventArgs e)
        {
            RaiseLog($"⚠️ [WATCH] Monitoring degraded — some file events may have been missed ({e.GetException()?.Message}).");
        }

        private void OnFileCreated(object sender, FileSystemEventArgs e)
        {
            if (_cts?.Token.IsCancellationRequested ?? true) return;
            Task.Run(() => AnalyzeNewFile(e.FullPath));
        }

        private void OnFileRenamed(object sender, RenamedEventArgs e)
        {
            if (_cts?.Token.IsCancellationRequested ?? true) return;
            var ext = Path.GetExtension(e.FullPath).ToLower();
            if (_monitoredExtensions.Contains(ext))
            {
                Task.Run(() => AnalyzeNewFile(e.FullPath));
            }
        }

        private async Task AnalyzeNewFile(string filePath)
        {
            try
            {
                if (!File.Exists(filePath)) return;
                if (_whitelist.IsWhitelisted(filePath)) return;

                Interlocked.Increment(ref _filesWatched);

                var ext = Path.GetExtension(filePath).ToLower();
                if (!_monitoredExtensions.Contains(ext)) return;

                // Wait for file to be fully written
                await Task.Delay(500);

                // Content analysis, not just the filename. Real-time protection used to call
                // AnalyzePath, which never consults the hash database, the YARA rules or the PE
                // layers - so a dropper landing in Downloads under a harmless name was ignored.
                var threat = await _analyzer.AnalyzeFileAsync(filePath, DetectionDepth.Full);
                if (threat != null && threat.Severity >= ThreatSeverity.Medium)
                {
                    _alertCount++;
                    _threatsDetected++;

                    var alert = new ProtectionAlert
                    {
                        Status = threat.Severity >= ThreatSeverity.High
                            ? ProtectionStatus.Critical
                            : ProtectionStatus.Warning,
                        ProcessName = Path.GetFileName(filePath),
                        Description = $"🔍 Suspicious file detected: {Path.GetFileName(filePath)}",
                        Details = $"Path: {filePath}\nScore: {threat.Score}\nPatterns: {string.Join(", ", threat.MatchedPatterns)}",
                        Threat = threat
                    };

                    RaiseAlert(alert);
                }
            }
            catch { }
        }

        #endregion

        #region Process Monitoring

        private void InitializeKnownProcesses()
        {
            _knownProcessIds.Clear();
            foreach (var process in Process.GetProcesses())
            {
                try
                {
                    _knownProcessIds.Add(process.Id);
                    process.Dispose();
                }
                catch { }
            }
            _processesScanned = _knownProcessIds.Count;
        }

        private async Task MonitorLoop(CancellationToken token)
        {
            while (!token.IsCancellationRequested)
            {
                try
                {
                    // Low-intensity mode stretches the poll interval fourfold instead of stopping.
                    await Task.Delay(LowIntensityMode ? _monitorInterval * 4 : _monitorInterval, token);

                    if (ProcessMonitoringEnabled)
                        await MonitorNewProcesses(token);

                    if (NetworkMonitoringEnabled)
                        await MonitorNetwork(token);

                    // Monitor registry (less frequently, and not at all while backing off)
                    if (RegistryMonitoringEnabled && !LowIntensityMode && _processesScanned % 5 == 0)
                    {
                        await MonitorRegistry(token);
                    }

                    // Auto-reset status once the warning has aged out. This used to `await Task.Delay(30000)`
                    // inline, which stalled ALL monitoring for 30s after every single warning.
                    if (_currentStatus == ProtectionStatus.Warning &&
                        DateTime.UtcNow - _lastWarningAt >= _autoResetAfter)
                    {
                        UpdateStatus(ProtectionStatus.Safe);
                    }
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    RaiseLog($"⚠️ [MONITOR] Error: {ex.Message}");
                }
            }
        }

        private async Task MonitorNewProcesses(CancellationToken token)
        {
            Process[] currentProcesses;
            try
            {
                currentProcesses = Process.GetProcesses();
            }
            catch
            {
                return;
            }

            var newProcesses = new List<Process>();
            var currentIds = new HashSet<int>();

            foreach (var process in currentProcesses)
            {
                try
                {
                    var pid = process.Id;
                    currentIds.Add(pid);

                    if (!_knownProcessIds.Contains(pid))
                    {
                        newProcesses.Add(process);
                        _knownProcessIds.Add(pid);
                    }
                    else
                    {
                        process.Dispose();
                    }
                }
                catch
                {
                    try { process.Dispose(); } catch { }
                }
            }

            // Update process count
            _processesScanned = currentIds.Count;

            // Clean up exited processes from known list
            var exitedIds = _knownProcessIds.Where(id => !currentIds.Contains(id)).ToList();
            foreach (var id in exitedIds)
            {
                _knownProcessIds.Remove(id);
            }

            // Analyze new processes
            foreach (var process in newProcesses)
            {
                if (token.IsCancellationRequested) break;

                try
                {
                    if (!process.HasExited)
                    {
                        await AnalyzeProcess(process, token);
                    }
                }
                catch (InvalidOperationException) { }
                catch (Exception) { }
                finally
                {
                    try { process.Dispose(); } catch { }
                }
            }
        }

        private async Task AnalyzeProcess(Process process, CancellationToken token)
        {
            try
            {
                string? execPath = null;
                try { execPath = process.MainModule?.FileName; } catch { }

                if (!string.IsNullOrEmpty(execPath) && _whitelist.IsWhitelisted(execPath))
                    return;

                var threat = _analyzer.AnalyzeProcess(
                    process.Id,
                    process.ProcessName,
                    execPath,
                    null
                );

                if (threat != null)
                {
                    _alertCount++;
                    _threatsDetected++;

                    var alert = new ProtectionAlert
                    {
                        Status = threat.Severity >= ThreatSeverity.High
                            ? ProtectionStatus.Critical
                            : ProtectionStatus.Warning,
                        ProcessName = process.ProcessName,
                        ProcessId = process.Id,
                        Description = $"Suspicious process detected: {process.ProcessName}",
                        Details = $"Path: {execPath ?? "Unknown"}\nScore: {threat.Score}\nPatterns: {string.Join(", ", threat.MatchedPatterns)}",
                        Threat = threat
                    };

                    RaiseAlert(alert);
                }
            }
            catch { }
        }

        #endregion

        #region Network Monitoring

        private async Task MonitorNetwork(CancellationToken token)
        {
            try
            {
                await Task.Run(() =>
                {
                    var connections = IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpConnections();
                    _networkConnections = connections.Length;

                    foreach (var conn in connections)
                    {
                        if (token.IsCancellationRequested) break;

                        if (conn.State == TcpState.Established)
                        {
                            if (_suspiciousPorts.Contains(conn.RemoteEndPoint.Port))
                            {
                                var connKey = $"{conn.RemoteEndPoint.Address}:{conn.RemoteEndPoint.Port}";

                                // Only alert once per connection
                                if (!_alertedConnections.Contains(connKey))
                                {
                                    _alertedConnections.Add(connKey);
                                    _alertCount++;

                                    var alert = new ProtectionAlert
                                    {
                                        Status = ProtectionStatus.Warning,
                                        ProcessName = "Network",
                                        Description = "Suspicious network connection detected",
                                        Details = $"Remote: {conn.RemoteEndPoint.Address}:{conn.RemoteEndPoint.Port}\nPort {conn.RemoteEndPoint.Port} is commonly used by malware"
                                    };

                                    RaiseAlert(alert);
                                }
                            }
                        }
                    }
                }, token);
            }
            catch { }
        }

        #endregion

        #region Registry Monitoring

        private async Task MonitorRegistry(CancellationToken token)
        {
            try
            {
                foreach (var keyPath in _persistenceKeys)
                {
                    if (token.IsCancellationRequested) break;
                    await CheckRegistryKey(keyPath);
                }
            }
            catch { }
        }

        private async Task CheckRegistryKey(string keyPath)
        {
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(keyPath);
                if (key == null) return;

                _registryKeysChecked++;

                foreach (var valueName in key.GetValueNames())
                {
                    var value = key.GetValue(valueName)?.ToString();
                    if (string.IsNullOrEmpty(value)) continue;

                    var path = ExtractPath(value);
                    if (string.IsNullOrEmpty(path)) continue;
                    if (_whitelist.IsWhitelisted(path)) continue;

                    var threat = _analyzer.AnalyzePath(path);
                    if (threat != null && threat.Severity >= ThreatSeverity.Medium)
                    {
                        _alertCount++;

                        var alert = new ProtectionAlert
                        {
                            Status = ProtectionStatus.Warning,
                            ProcessName = "Registry",
                            Description = "Suspicious startup entry detected",
                            Details = $"Key: {keyPath}\\{valueName}\nPath: {path}\nScore: {threat.Score}"
                        };

                        RaiseAlert(alert);
                    }
                }
            }
            catch { }

            await Task.CompletedTask;
        }

        private string? ExtractPath(string value)
        {
            value = value.Trim('"', ' ');
            var match = Regex.Match(value, @"([A-Za-z]:\\[^\s""]+\.(exe|dll|bat|cmd|vbs|ps1))", RegexOptions.IgnoreCase);
            return match.Success ? match.Groups[1].Value : null;
        }

        #endregion

        #region Alert Handling

        private void RaiseAlert(ProtectionAlert alert)
        {
            AlertRaised?.Invoke(this, alert);

            var icon = alert.Status == ProtectionStatus.Critical ? "🚨" : "⚠️";
            RaiseLog($"{icon} [{alert.Status.ToString().ToUpper()}] {alert.Description}");
            RaiseLog($"   {alert.Details.Replace("\n", "\n   ")}");

            if (alert.Status == ProtectionStatus.Critical ||
                (_currentStatus != ProtectionStatus.Critical && alert.Status == ProtectionStatus.Warning))
            {
                UpdateStatus(alert.Status);
            }
        }

        private void UpdateStatus(ProtectionStatus status)
        {
            // Refresh the timestamp on every warning (even a repeat) so the auto-reset window
            // measures time since the LAST alert, not since the first one.
            if (status == ProtectionStatus.Warning || status == ProtectionStatus.Critical)
                _lastWarningAt = DateTime.UtcNow;

            if (_currentStatus != status)
            {
                _currentStatus = status;
                StatusChanged?.Invoke(this, status);
            }
        }

        public void ResetStatus()
        {
            UpdateStatus(ProtectionStatus.Safe);
        }

        private void RaiseLog(string message)
        {
            LogAdded?.Invoke(this, message);
        }

        #endregion

        public void Dispose()
        {
            Stop();
            _cts?.Dispose();
        }
    }
}
