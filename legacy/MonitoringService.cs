using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.NetworkInformation;
using System.Threading;
using System.Threading.Tasks;

namespace SkidrowKiller
{
    public enum ThreatLevel
    {
        Safe,
        Warning,
        Critical
    }

    public class ThreatAlert
    {
        public DateTime Timestamp { get; set; }
        public ThreatLevel Level { get; set; }
        public string ProcessName { get; set; } = string.Empty;
        public int ProcessId { get; set; }
        public string Description { get; set; } = string.Empty;
        public string Details { get; set; } = string.Empty;
    }

    public class MonitoringService : IDisposable
    {
        private CancellationTokenSource? cancellationTokenSource;
        private Task? monitoringTask;
        private readonly ProcessScanner processScanner;
        private readonly HashSet<int> knownProcessIds = new HashSet<int>();
        private bool isRunning;
        private DateTime lastCheckTime = DateTime.Now;
        private ThreatLevel currentThreatLevel = ThreatLevel.Safe;

        public event EventHandler<ThreatAlert>? ThreatDetected;
        public event EventHandler<ThreatLevel>? ThreatLevelChanged;
        public event EventHandler<string>? StatusChanged;
        public event EventHandler<string>? LogAdded;

        public bool IsRunning => isRunning;
        public ThreatLevel CurrentThreatLevel => currentThreatLevel;

        private readonly string[] skidrowPatterns = new[]
        {
            "skidrow", "crack", "keygen", "reloaded", "codex",
            "plaza", "cpy", "3dm", "ali213", "smartsteam", "nosteam"
        };

        public MonitoringService()
        {
            processScanner = new ProcessScanner();
            processScanner.LogAdded += (s, msg) => RaiseLogAdded(msg);
        }

        public void Start()
        {
            if (isRunning) return;

            cancellationTokenSource = new CancellationTokenSource();
            isRunning = true;

            // Initialize known processes
            InitializeKnownProcesses();

            monitoringTask = Task.Run(() => MonitoringLoop(cancellationTokenSource.Token));

            RaiseStatusChanged("Real-time monitoring started");
            RaiseLogAdded($"[MONITOR] Started at {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
        }

        public void Stop()
        {
            if (!isRunning) return;

            cancellationTokenSource?.Cancel();
            isRunning = false;

            RaiseStatusChanged("Real-time monitoring stopped");
            RaiseLogAdded($"[MONITOR] Stopped at {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
        }

        private void InitializeKnownProcesses()
        {
            try
            {
                var processes = Process.GetProcesses();
                foreach (var process in processes)
                {
                    try
                    {
                        knownProcessIds.Add(process.Id);
                        process.Dispose();
                    }
                    catch { }
                }
            }
            catch { }
        }

        private async Task MonitoringLoop(CancellationToken token)
        {
            while (!token.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(2000, token); // Check every 2 seconds

                    // Monitor for new processes
                    await MonitorNewProcesses(token);

                    // Monitor network connections
                    await MonitorNetworkActivity(token);

                    lastCheckTime = DateTime.Now;
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    RaiseLogAdded($"[MONITOR ERROR] {ex.Message}");
                }
            }
        }

        private async Task MonitorNewProcesses(CancellationToken token)
        {
            try
            {
                var currentProcesses = Process.GetProcesses();
                var newProcesses = new List<Process>();

                foreach (var process in currentProcesses)
                {
                    try
                    {
                        if (!knownProcessIds.Contains(process.Id))
                        {
                            newProcesses.Add(process);
                            knownProcessIds.Add(process.Id);
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

                if (newProcesses.Any())
                {
                    foreach (var process in newProcesses)
                    {
                        try
                        {
                            await CheckProcessThreat(process, token);
                        }
                        finally
                        {
                            try { process.Dispose(); } catch { }
                        }
                    }
                }
            }
            catch { }
        }

        private async Task CheckProcessThreat(Process process, CancellationToken token)
        {
            try
            {
                string processName = process.ProcessName.ToLower();
                string executablePath = string.Empty;

                try
                {
                    executablePath = process.MainModule?.FileName ?? string.Empty;
                }
                catch { }

                // Check if process name matches patterns
                if (skidrowPatterns.Any(p => processName.Contains(p)))
                {
                    var alert = new ThreatAlert
                    {
                        Timestamp = DateTime.Now,
                        Level = ThreatLevel.Critical,
                        ProcessName = process.ProcessName,
                        ProcessId = process.Id,
                        Description = "Suspicious process detected",
                        Details = $"Process '{process.ProcessName}' matches malware pattern. Path: {executablePath}"
                    };

                    RaiseThreatDetected(alert);
                    UpdateThreatLevel(ThreatLevel.Critical);
                    return;
                }

                // Check executable path
                if (!string.IsNullOrEmpty(executablePath) &&
                    skidrowPatterns.Any(p => executablePath.ToLower().Contains(p)))
                {
                    var alert = new ThreatAlert
                    {
                        Timestamp = DateTime.Now,
                        Level = ThreatLevel.Critical,
                        ProcessName = process.ProcessName,
                        ProcessId = process.Id,
                        Description = "Suspicious executable path",
                        Details = $"Process path contains malware signature: {executablePath}"
                    };

                    RaiseThreatDetected(alert);
                    UpdateThreatLevel(ThreatLevel.Critical);
                    return;
                }

                // Deep scan with ProcessScanner
                var threats = await processScanner.ScanProcessesAsync(token);
                var threat = threats.FirstOrDefault(t => t.ProcessId == process.Id);

                if (threat != null)
                {
                    var alert = new ThreatAlert
                    {
                        Timestamp = DateTime.Now,
                        Level = ThreatLevel.Critical,
                        ProcessName = threat.ProcessName,
                        ProcessId = threat.ProcessId,
                        Description = threat.Reason,
                        Details = $"DLLs: {string.Join(", ", threat.SuspiciousModules)}"
                    };

                    RaiseThreatDetected(alert);
                    UpdateThreatLevel(ThreatLevel.Critical);
                }
            }
            catch { }
        }

        private async Task MonitorNetworkActivity(CancellationToken token)
        {
            try
            {
                await Task.Run(() =>
                {
                    var properties = IPGlobalProperties.GetIPGlobalProperties();
                    var connections = properties.GetActiveTcpConnections();

                    foreach (var connection in connections)
                    {
                        if (token.IsCancellationRequested) break;

                        // Check for suspicious outbound connections
                        if (connection.State == TcpState.Established)
                        {
                            try
                            {
                                var remoteEndpoint = connection.RemoteEndPoint;

                                // Check if connection is to suspicious ports or addresses
                                if (IsSuspiciousConnection(connection))
                                {
                                    var alert = new ThreatAlert
                                    {
                                        Timestamp = DateTime.Now,
                                        Level = ThreatLevel.Warning,
                                        ProcessName = "Unknown",
                                        ProcessId = 0,
                                        Description = "Suspicious network connection",
                                        Details = $"Connection to {remoteEndpoint.Address}:{remoteEndpoint.Port}"
                                    };

                                    RaiseThreatDetected(alert);

                                    if (currentThreatLevel == ThreatLevel.Safe)
                                    {
                                        UpdateThreatLevel(ThreatLevel.Warning);
                                    }
                                }
                            }
                            catch { }
                        }
                    }
                }, token);
            }
            catch { }
        }

        private bool IsSuspiciousConnection(TcpConnectionInformation connection)
        {
            // Check for suspicious ports commonly used by malware
            int[] suspiciousPorts = { 4444, 5555, 6666, 7777, 8888, 9999, 31337, 12345 };

            if (suspiciousPorts.Contains(connection.RemoteEndPoint.Port))
            {
                return true;
            }

            // Add more sophisticated checks here if needed
            return false;
        }

        private void UpdateThreatLevel(ThreatLevel newLevel)
        {
            if (currentThreatLevel != newLevel)
            {
                currentThreatLevel = newLevel;
                ThreatLevelChanged?.Invoke(this, newLevel);

                RaiseLogAdded($"[THREAT LEVEL] Changed to {newLevel}");
            }
        }

        public void ResetThreatLevel()
        {
            UpdateThreatLevel(ThreatLevel.Safe);
        }

        private void RaiseThreatDetected(ThreatAlert alert)
        {
            ThreatDetected?.Invoke(this, alert);

            string levelText = alert.Level switch
            {
                ThreatLevel.Critical => "CRITICAL",
                ThreatLevel.Warning => "WARNING",
                _ => "INFO"
            };

            RaiseLogAdded($"[{levelText}] {alert.Description}");
            RaiseLogAdded($"  Process: {alert.ProcessName} (PID: {alert.ProcessId})");
            RaiseLogAdded($"  Details: {alert.Details}");
        }

        private void RaiseStatusChanged(string status)
        {
            StatusChanged?.Invoke(this, status);
        }

        private void RaiseLogAdded(string message)
        {
            LogAdded?.Invoke(this, message);
        }

        public void Dispose()
        {
            Stop();
            cancellationTokenSource?.Dispose();
        }
    }
}
