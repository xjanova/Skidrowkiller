using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32;
using SkidrowKiller.Models;

namespace SkidrowKiller.Services
{
    /// <summary>
    /// Advanced real-time protection service with enterprise-grade threat detection.
    /// </summary>
    public class AdvancedProtectionService : IDisposable
    {
        private readonly ThreatAnalyzer _analyzer;
        private readonly WhitelistManager _whitelist;
        private readonly QuarantineService _quarantine;
        private CancellationTokenSource? _cts;
        private Task? _monitorTask;

        private readonly List<FileSystemWatcher> _fileWatchers = new();
        private readonly HashSet<int> _knownProcessIds = new();
        private readonly ConcurrentDictionary<int, ProcessInfo> _processCache = new();
        private readonly ConcurrentDictionary<string, ConnectionInfo> _connectionHistory = new();
        private readonly HashSet<string> _maliciousHashes = new(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _knownC2Domains = new(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<IPAddress> _knownC2IPs = new();

        private ProtectionStatus _currentStatus = ProtectionStatus.Safe;
        private int _alertCount;
        private int _blockedThreats;
        private int _filesScanned;
        private int _processesAnalyzed;

        public event EventHandler<ProtectionAlert>? AlertRaised;
        public event EventHandler<ProtectionStatus>? StatusChanged;
        public event EventHandler<string>? LogAdded;
        public event EventHandler<ThreatInfo>? ThreatBlocked;

        public bool IsRunning { get; private set; }
        public ProtectionStatus CurrentStatus => _currentStatus;
        public int AlertCount => _alertCount;
        public int BlockedThreats => _blockedThreats;
        public int FilesScanned => _filesScanned;
        public int ProcessesAnalyzed => _processesAnalyzed;

        public bool AutoQuarantine { get; set; } = false;
        public bool MonitorRegistry { get; set; } = true;
        public bool MonitorFileSystem { get; set; } = true;
        public bool DeepScan { get; set; } = true;
        public int ScanIntervalMs { get; set; } = 2000;

        private readonly int[] _suspiciousPorts = {
            4444, 5555, 6666, 7777, 8888, 9999, 31337, 12345, 65535,
            1337, 1338, 4443, 8443, 8080, 6667, 6668, 6669, 1080, 9050, 9150
        };

        private readonly string[] _monitoredExtensions = {
            ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js",
            ".scr", ".pif", ".msi", ".jar", ".hta", ".wsf"
        };

        private readonly string[] _persistenceKeys = {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
        };

        public AdvancedProtectionService(ThreatAnalyzer analyzer, WhitelistManager whitelist, QuarantineService quarantine)
        {
            _analyzer = analyzer;
            _whitelist = whitelist;
            _quarantine = quarantine;
            LoadThreatDatabase();
        }

        private void LoadThreatDatabase()
        {
            _maliciousHashes.Add("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
            _knownC2Domains.Add("malware.com");
            RaiseLog("📚 [DATABASE] Threat database loaded");
        }

        public void Start()
        {
            if (IsRunning) return;

            _cts = new CancellationTokenSource();
            IsRunning = true;
            _alertCount = 0;
            _blockedThreats = 0;

            InitializeKnownProcesses();
            if (MonitorFileSystem) SetupFileSystemWatchers();

            _monitorTask = Task.Run(() => MonitorLoop(_cts.Token));

            RaiseLog("🛡️ [PROTECTION] Advanced protection started");
            UpdateStatus(ProtectionStatus.Safe);
        }

        public void Stop()
        {
            if (!IsRunning) return;

            _cts?.Cancel();
            IsRunning = false;

            foreach (var watcher in _fileWatchers)
            {
                watcher.EnableRaisingEvents = false;
                watcher.Dispose();
            }
            _fileWatchers.Clear();

            RaiseLog("🛡️ [PROTECTION] Protection stopped");
        }

        private void SetupFileSystemWatchers()
        {
            var paths = new[] {
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                Path.GetTempPath()
            };

            foreach (var path in paths.Where(Directory.Exists))
            {
                try
                {
                    var watcher = new FileSystemWatcher(path)
                    {
                        NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite,
                        IncludeSubdirectories = true,
                        EnableRaisingEvents = true
                    };
                    watcher.Created += OnFileCreated;
                    _fileWatchers.Add(watcher);
                    RaiseLog($"👁️ [WATCH] Monitoring: {path}");
                }
                catch { }
            }
        }

        private void OnFileCreated(object sender, FileSystemEventArgs e)
        {
            if (_cts?.Token.IsCancellationRequested ?? true) return;
            Task.Run(() => AnalyzeNewFile(e.FullPath));
        }

        private async Task AnalyzeNewFile(string filePath)
        {
            try
            {
                if (!File.Exists(filePath) || _whitelist.IsWhitelisted(filePath)) return;

                Interlocked.Increment(ref _filesScanned);
                var ext = Path.GetExtension(filePath).ToLower();
                if (!_monitoredExtensions.Contains(ext)) return;

                await Task.Delay(500);

                var hash = await ComputeFileHash(filePath);
                if (!string.IsNullOrEmpty(hash) && _maliciousHashes.Contains(hash))
                {
                    await HandleMaliciousFile(filePath, $"Known malicious hash: {hash[..16]}...");
                    return;
                }

                var threat = _analyzer.AnalyzePath(filePath);
                if (threat != null && threat.Severity >= ThreatSeverity.Medium)
                {
                    RaiseLog($"🔍 [FILE] Suspicious: {Path.GetFileName(filePath)}");
                    await HandleThreat(threat);
                }
            }
            catch { }
        }

        private async Task<string?> ComputeFileHash(string filePath)
        {
            try
            {
                using var sha256 = SHA256.Create();
                using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read);
                var hashBytes = await sha256.ComputeHashAsync(stream);
                return BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
            }
            catch { return null; }
        }

        private async Task HandleMaliciousFile(string filePath, string reason)
        {
            _alertCount++;
            _blockedThreats++;

            var alert = new ProtectionAlert
            {
                Status = ProtectionStatus.Critical,
                ProcessName = Path.GetFileName(filePath),
                Description = "🚨 MALICIOUS FILE DETECTED",
                Details = $"Path: {filePath}\nReason: {reason}"
            };
            RaiseAlert(alert);

            if (AutoQuarantine)
            {
                try
                {
                    var threat = new ThreatInfo
                    {
                        Type = ThreatType.File,
                        Path = filePath,
                        Name = Path.GetFileName(filePath),
                        Severity = ThreatSeverity.Critical,
                        Description = reason
                    };
                    await Task.Run(() => _quarantine.QuarantineFile(filePath, threat));
                    RaiseLog($"🔒 [QUARANTINE] File quarantined: {Path.GetFileName(filePath)}");
                    ThreatBlocked?.Invoke(this, threat);
                }
                catch (Exception ex)
                {
                    RaiseLog($"⚠️ [QUARANTINE] Failed: {ex.Message}");
                }
            }
        }

        private void InitializeKnownProcesses()
        {
            _knownProcessIds.Clear();
            _processCache.Clear();

            foreach (var process in Process.GetProcesses())
            {
                try
                {
                    _knownProcessIds.Add(process.Id);
                    _processCache[process.Id] = new ProcessInfo { Id = process.Id, Name = process.ProcessName };
                    process.Dispose();
                }
                catch { }
            }
        }

        private async Task MonitorLoop(CancellationToken token)
        {
            while (!token.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(ScanIntervalMs, token);
                    await MonitorNewProcesses(token);
                    await MonitorNetwork(token);
                    if (MonitorRegistry) await MonitorRegistryPersistence(token);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    RaiseLog($"⚠️ [MONITOR] Error: {ex.Message}");
                }
            }
        }

        private async Task MonitorNewProcesses(CancellationToken token)
        {
            Process[] currentProcesses;
            try { currentProcesses = Process.GetProcesses(); }
            catch { return; }

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
                        _processCache[pid] = new ProcessInfo { Id = pid, Name = process.ProcessName };
                    }
                    else
                    {
                        process.Dispose();
                    }
                }
                catch { try { process.Dispose(); } catch { } }
            }

            var exitedIds = _knownProcessIds.Where(id => !currentIds.Contains(id)).ToList();
            foreach (var id in exitedIds)
            {
                _knownProcessIds.Remove(id);
                _processCache.TryRemove(id, out _);
            }

            foreach (var process in newProcesses)
            {
                if (token.IsCancellationRequested) break;

                try
                {
                    if (!process.HasExited)
                    {
                        Interlocked.Increment(ref _processesAnalyzed);
                        await AnalyzeProcess(process, token);
                    }
                }
                catch { }
                finally { try { process.Dispose(); } catch { } }
            }
        }

        private async Task AnalyzeProcess(Process process, CancellationToken token)
        {
            try
            {
                string? execPath = null;
                try { execPath = process.MainModule?.FileName; } catch { }

                if (!string.IsNullOrEmpty(execPath) && _whitelist.IsWhitelisted(execPath)) return;

                var threat = _analyzer.AnalyzeProcess(process.Id, process.ProcessName, execPath, null);
                if (threat != null)
                {
                    await HandleThreat(threat);
                }
            }
            catch { }
        }

        private async Task MonitorNetwork(CancellationToken token)
        {
            try
            {
                await Task.Run(() =>
                {
                    var connections = IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpConnections();

                    foreach (var conn in connections)
                    {
                        if (token.IsCancellationRequested) break;

                        if (conn.State == TcpState.Established && _suspiciousPorts.Contains(conn.RemoteEndPoint.Port))
                        {
                            var endpoint = $"{conn.RemoteEndPoint.Address}:{conn.RemoteEndPoint.Port}";
                            if (!_connectionHistory.ContainsKey(endpoint))
                            {
                                _connectionHistory[endpoint] = new ConnectionInfo { RemoteAddress = endpoint };
                                _alertCount++;

                                var alert = new ProtectionAlert
                                {
                                    Status = ProtectionStatus.Warning,
                                    ProcessName = "Network",
                                    Description = "Suspicious network connection",
                                    Details = $"Remote: {endpoint}\nSuspicious port detected"
                                };
                                RaiseAlert(alert);
                            }
                        }
                    }
                }, token);
            }
            catch { }
        }

        private async Task MonitorRegistryPersistence(CancellationToken token)
        {
            try
            {
                foreach (var keyPath in _persistenceKeys)
                {
                    if (token.IsCancellationRequested) break;
                    await CheckRegistryKey(Registry.CurrentUser, keyPath);
                }
            }
            catch { }
        }

        private async Task CheckRegistryKey(RegistryKey root, string keyPath)
        {
            try
            {
                using var key = root.OpenSubKey(keyPath);
                if (key == null) return;

                foreach (var valueName in key.GetValueNames())
                {
                    var value = key.GetValue(valueName)?.ToString();
                    if (string.IsNullOrEmpty(value)) continue;

                    var path = ExtractPath(value);
                    if (string.IsNullOrEmpty(path) || _whitelist.IsWhitelisted(path)) continue;

                    var threat = _analyzer.AnalyzePath(path);
                    if (threat != null && threat.Severity >= ThreatSeverity.Medium)
                    {
                        var alert = new ProtectionAlert
                        {
                            Status = ProtectionStatus.Warning,
                            ProcessName = "Registry",
                            Description = "Suspicious persistence entry",
                            Details = $"Key: {keyPath}\nValue: {valueName}\nPath: {path}"
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

        private async Task HandleThreat(ThreatInfo threat)
        {
            _alertCount++;

            var alert = new ProtectionAlert
            {
                Status = threat.Severity >= ThreatSeverity.High ? ProtectionStatus.Critical : ProtectionStatus.Warning,
                ProcessName = threat.Name,
                ProcessId = threat.ProcessId ?? 0,
                Description = threat.Description,
                Details = $"Path: {threat.Path}\nScore: {threat.Score}",
                Threat = threat
            };
            RaiseAlert(alert);

            if (AutoQuarantine && threat.Severity >= ThreatSeverity.Critical && threat.Type == ThreatType.File)
            {
                try
                {
                    await Task.Run(() => _quarantine.QuarantineFile(threat.Path, threat));
                    _blockedThreats++;
                    RaiseLog($"🔒 [QUARANTINE] Threat quarantined: {threat.Name}");
                    ThreatBlocked?.Invoke(this, threat);
                }
                catch (Exception ex)
                {
                    RaiseLog($"⚠️ [QUARANTINE] Failed: {ex.Message}");
                }
            }
        }

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
            if (_currentStatus != status)
            {
                _currentStatus = status;
                StatusChanged?.Invoke(this, status);
            }
        }

        public void ResetStatus() => UpdateStatus(ProtectionStatus.Safe);

        private void RaiseLog(string message) => LogAdded?.Invoke(this, message);

        public void AddMaliciousHash(string hash) => _maliciousHashes.Add(hash.ToLower());

        public void Dispose()
        {
            Stop();
            _cts?.Dispose();
        }

        private class ProcessInfo
        {
            public int Id { get; set; }
            public string Name { get; set; } = string.Empty;
        }

        private class ConnectionInfo
        {
            public string RemoteAddress { get; set; } = string.Empty;
        }
    }
}
