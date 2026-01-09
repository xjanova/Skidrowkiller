using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace SkidrowKiller.Services;

/// <summary>
/// Real-time file system monitor that watches for new/modified files in high-risk locations
/// and automatically scans them for threats.
/// </summary>
public class RealTimeMonitorService : IDisposable
{
    private readonly ILogger<RealTimeMonitorService>? _logger;
    private readonly List<FileSystemWatcher> _watchers = new();
    private readonly ConcurrentDictionary<string, DateTime> _recentlyScanned = new();
    private readonly ConcurrentQueue<string> _scanQueue = new();
    private CancellationTokenSource? _cts;
    private Task? _processingTask;
    private bool _isRunning;
    private bool _disposed;

    // Debounce settings
    private readonly TimeSpan _debounceInterval = TimeSpan.FromMilliseconds(500);
    private readonly TimeSpan _scanCooldown = TimeSpan.FromSeconds(5);

    // Events
    public event EventHandler<ThreatDetectedEventArgs>? ThreatDetected;
    public event EventHandler<FileScannedEventArgs>? FileScanned;
    public event EventHandler<MonitorStatusEventArgs>? StatusChanged;

    // High-risk directories to monitor
    private static readonly string[] DefaultMonitorPaths =
    {
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile) + "\\Downloads",
        Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData) + "\\Temp",
        Path.GetTempPath(),
        Environment.GetFolderPath(Environment.SpecialFolder.Startup),
        Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup),
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
    };

    // Extensions to monitor
    private static readonly HashSet<string> MonitoredExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".scr", ".sys", ".drv",
        ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jse", ".wsf", ".wsh",
        ".msi", ".msp", ".msu",
        ".jar", ".class",
        ".hta", ".cpl",
        ".lnk", ".pif",
        ".reg",
        ".zip", ".rar", ".7z", ".tar", ".gz",
        ".iso", ".img",
    };

    // Scan function delegate
    private Func<string, Task<RTScanResult>>? _scanFunction;

    public bool IsRunning => _isRunning;
    public int QueuedFiles => _scanQueue.Count;

    public RealTimeMonitorService(ILogger<RealTimeMonitorService>? logger = null)
    {
        _logger = logger;
    }

    /// <summary>
    /// Sets the scan function to use for checking files
    /// </summary>
    public void SetScanFunction(Func<string, Task<RTScanResult>> scanFunction)
    {
        _scanFunction = scanFunction;
    }

    /// <summary>
    /// Starts monitoring with default paths
    /// </summary>
    public void Start()
    {
        Start(DefaultMonitorPaths);
    }

    /// <summary>
    /// Starts monitoring specified paths
    /// </summary>
    public void Start(IEnumerable<string> paths)
    {
        if (_isRunning)
        {
            _logger?.LogWarning("Real-time monitor is already running");
            return;
        }

        _cts = new CancellationTokenSource();
        _isRunning = true;

        foreach (var path in paths)
        {
            if (Directory.Exists(path))
            {
                try
                {
                    var watcher = CreateWatcher(path);
                    _watchers.Add(watcher);
                    watcher.EnableRaisingEvents = true;
                    _logger?.LogInformation("Monitoring: {Path}", path);
                }
                catch (Exception ex)
                {
                    _logger?.LogWarning(ex, "Failed to create watcher for {Path}", path);
                }
            }
        }

        // Start the processing task
        _processingTask = Task.Run(ProcessQueueAsync);

        StatusChanged?.Invoke(this, new MonitorStatusEventArgs
        {
            IsRunning = true,
            MonitoredPaths = _watchers.Count,
            Message = $"Monitoring {_watchers.Count} locations"
        });

        _logger?.LogInformation("Real-time monitor started with {Count} watchers", _watchers.Count);
    }

    /// <summary>
    /// Stops monitoring
    /// </summary>
    public void Stop()
    {
        if (!_isRunning) return;

        _cts?.Cancel();
        _isRunning = false;

        foreach (var watcher in _watchers)
        {
            try
            {
                watcher.EnableRaisingEvents = false;
                watcher.Dispose();
            }
            catch { }
        }
        _watchers.Clear();

        try
        {
            _processingTask?.Wait(TimeSpan.FromSeconds(5));
        }
        catch { }

        StatusChanged?.Invoke(this, new MonitorStatusEventArgs
        {
            IsRunning = false,
            MonitoredPaths = 0,
            Message = "Real-time monitor stopped"
        });

        _logger?.LogInformation("Real-time monitor stopped");
    }

    private FileSystemWatcher CreateWatcher(string path)
    {
        var watcher = new FileSystemWatcher(path)
        {
            NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.CreationTime,
            IncludeSubdirectories = true,
            EnableRaisingEvents = false
        };

        watcher.Created += OnFileCreated;
        watcher.Changed += OnFileChanged;
        watcher.Renamed += OnFileRenamed;
        watcher.Error += OnWatcherError;

        return watcher;
    }

    private void OnFileCreated(object sender, FileSystemEventArgs e)
    {
        QueueFileForScan(e.FullPath, "Created");
    }

    private void OnFileChanged(object sender, FileSystemEventArgs e)
    {
        QueueFileForScan(e.FullPath, "Modified");
    }

    private void OnFileRenamed(object sender, RenamedEventArgs e)
    {
        QueueFileForScan(e.FullPath, "Renamed");
    }

    private void OnWatcherError(object sender, ErrorEventArgs e)
    {
        _logger?.LogError(e.GetException(), "File system watcher error");

        // Try to recover
        if (sender is FileSystemWatcher watcher)
        {
            try
            {
                watcher.EnableRaisingEvents = false;
                watcher.EnableRaisingEvents = true;
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Failed to recover watcher");
            }
        }
    }

    private void QueueFileForScan(string filePath, string reason)
    {
        try
        {
            // Check if we should monitor this file
            var extension = Path.GetExtension(filePath);
            if (!MonitoredExtensions.Contains(extension))
            {
                return;
            }

            // Check debounce
            if (_recentlyScanned.TryGetValue(filePath, out var lastScan))
            {
                if (DateTime.Now - lastScan < _scanCooldown)
                {
                    return;
                }
            }

            _recentlyScanned[filePath] = DateTime.Now;
            _scanQueue.Enqueue(filePath);

            _logger?.LogDebug("Queued for scan ({Reason}): {Path}", reason, filePath);
        }
        catch (Exception ex)
        {
            _logger?.LogWarning(ex, "Error queueing file: {Path}", filePath);
        }
    }

    private async Task ProcessQueueAsync()
    {
        var token = _cts?.Token ?? CancellationToken.None;

        while (!token.IsCancellationRequested)
        {
            try
            {
                if (_scanQueue.TryDequeue(out var filePath))
                {
                    await ScanFileAsync(filePath);
                }
                else
                {
                    await Task.Delay(100, token);
                }
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Error processing scan queue");
            }
        }
    }

    private async Task ScanFileAsync(string filePath)
    {
        try
        {
            // Wait for file to be available
            if (!await WaitForFileAsync(filePath, TimeSpan.FromSeconds(5)))
            {
                _logger?.LogDebug("File not available: {Path}", filePath);
                return;
            }

            if (!File.Exists(filePath)) return;

            // Use custom scan function if provided
            if (_scanFunction != null)
            {
                var result = await _scanFunction(filePath);

                FileScanned?.Invoke(this, new FileScannedEventArgs
                {
                    FilePath = filePath,
                    IsThreat = result.HasThreats,
                    ThreatCount = result.ThreatCount
                });

                if (result.HasThreats)
                {
                    ThreatDetected?.Invoke(this, new ThreatDetectedEventArgs
                    {
                        FilePath = filePath,
                        ThreatName = result.ThreatName ?? "Unknown Threat",
                        Severity = result.Severity,
                        Action = result.RecommendedAction
                    });
                }
            }
            else
            {
                // Basic scan using file name patterns
                var basicResult = PerformBasicScan(filePath);

                FileScanned?.Invoke(this, new FileScannedEventArgs
                {
                    FilePath = filePath,
                    IsThreat = basicResult.IsThreat,
                    ThreatCount = basicResult.IsThreat ? 1 : 0
                });

                if (basicResult.IsThreat)
                {
                    ThreatDetected?.Invoke(this, new ThreatDetectedEventArgs
                    {
                        FilePath = filePath,
                        ThreatName = basicResult.ThreatName,
                        Severity = basicResult.Severity,
                        Action = "Quarantine recommended"
                    });
                }
            }
        }
        catch (Exception ex)
        {
            _logger?.LogWarning(ex, "Error scanning file: {Path}", filePath);
        }
    }

    private async Task<bool> WaitForFileAsync(string filePath, TimeSpan timeout)
    {
        var deadline = DateTime.Now + timeout;

        while (DateTime.Now < deadline)
        {
            try
            {
                using var stream = File.Open(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                return true;
            }
            catch (IOException)
            {
                await Task.Delay(100);
            }
            catch
            {
                return false;
            }
        }

        return false;
    }

    private BasicScanResult PerformBasicScan(string filePath)
    {
        var fileName = Path.GetFileName(filePath).ToLower();
        var result = new BasicScanResult();

        // Check for known malicious patterns
        var suspiciousPatterns = new Dictionary<string, string>
        {
            ["njrat"] = "NjRAT Trojan",
            ["darkcomet"] = "DarkComet RAT",
            ["cryptolocker"] = "CryptoLocker Ransomware",
            ["wannacry"] = "WannaCry Ransomware",
            ["emotet"] = "Emotet Botnet",
            ["mimikatz"] = "Mimikatz Credential Tool",
            ["metasploit"] = "Metasploit Payload",
            ["cobalt"] = "Cobalt Strike Beacon",
            ["redline"] = "RedLine Stealer",
        };

        foreach (var (pattern, threatName) in suspiciousPatterns)
        {
            if (fileName.Contains(pattern))
            {
                result.IsThreat = true;
                result.ThreatName = threatName;
                result.Severity = "Critical";
                return result;
            }
        }

        // Check for double extensions
        if (fileName.Contains(".pdf.exe") || fileName.Contains(".doc.exe") ||
            fileName.Contains(".jpg.exe") || fileName.Contains(".txt.exe"))
        {
            result.IsThreat = true;
            result.ThreatName = "Suspicious double extension";
            result.Severity = "High";
            return result;
        }

        // Check for suspicious locations
        var dirPath = Path.GetDirectoryName(filePath)?.ToLower() ?? "";
        if (dirPath.Contains("\\temp\\") && Path.GetExtension(filePath).Equals(".exe", StringComparison.OrdinalIgnoreCase))
        {
            // Executable in temp - moderately suspicious
            result.IsThreat = false; // Don't flag as threat by default, just log
            _logger?.LogDebug("Executable in temp folder: {Path}", filePath);
        }

        return result;
    }

    /// <summary>
    /// Adds a custom path to monitor
    /// </summary>
    public void AddMonitorPath(string path)
    {
        if (!_isRunning)
        {
            _logger?.LogWarning("Cannot add path - monitor not running");
            return;
        }

        if (!Directory.Exists(path))
        {
            _logger?.LogWarning("Path does not exist: {Path}", path);
            return;
        }

        try
        {
            var watcher = CreateWatcher(path);
            _watchers.Add(watcher);
            watcher.EnableRaisingEvents = true;
            _logger?.LogInformation("Added monitor path: {Path}", path);
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to add monitor path: {Path}", path);
        }
    }

    /// <summary>
    /// Clears the recently scanned cache
    /// </summary>
    public void ClearCache()
    {
        _recentlyScanned.Clear();
    }

    /// <summary>
    /// Gets statistics about the monitor
    /// </summary>
    public MonitorStatistics GetStatistics()
    {
        return new MonitorStatistics
        {
            IsRunning = _isRunning,
            MonitoredPaths = _watchers.Count,
            QueuedFiles = _scanQueue.Count,
            CachedFiles = _recentlyScanned.Count
        };
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        Stop();
        _cts?.Dispose();
        GC.SuppressFinalize(this);
    }

    private class BasicScanResult
    {
        public bool IsThreat { get; set; }
        public string ThreatName { get; set; } = "";
        public string Severity { get; set; } = "Low";
    }
}

#region Event Args and Models

public class ThreatDetectedEventArgs : EventArgs
{
    public string FilePath { get; set; } = "";
    public string ThreatName { get; set; } = "";
    public string Severity { get; set; } = "";
    public string Action { get; set; } = "";
}

public class FileScannedEventArgs : EventArgs
{
    public string FilePath { get; set; } = "";
    public bool IsThreat { get; set; }
    public int ThreatCount { get; set; }
}

public class MonitorStatusEventArgs : EventArgs
{
    public bool IsRunning { get; set; }
    public int MonitoredPaths { get; set; }
    public string Message { get; set; } = "";
}

public class MonitorStatistics
{
    public bool IsRunning { get; set; }
    public int MonitoredPaths { get; set; }
    public int QueuedFiles { get; set; }
    public int CachedFiles { get; set; }
}

public class RTScanResult
{
    public bool HasThreats { get; set; }
    public int ThreatCount { get; set; }
    public string? ThreatName { get; set; }
    public string Severity { get; set; } = "Unknown";
    public string RecommendedAction { get; set; } = "";
}

#endregion
