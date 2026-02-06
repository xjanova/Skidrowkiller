using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management;
using System.Threading;
using System.Threading.Tasks;
using SkidrowKiller.Models;
using SkidrowKiller.Views;

namespace SkidrowKiller.Services
{
    /// <summary>
    /// USB Auto-Scan Service - Automatically detects and scans USB drives and external devices.
    /// Provides protection against autorun malware and infected removable media.
    /// </summary>
    public class UsbScanService : IDisposable
    {
        private readonly SafeScanner _scanner;
        private readonly ThreatAnalyzer _analyzer;
        private ManagementEventWatcher? _insertWatcher;
        private ManagementEventWatcher? _removeWatcher;
        private readonly HashSet<string> _scannedDrives = new();
        private readonly Dictionary<string, UsbDeviceInfo> _connectedDevices = new();
        private bool _isEnabled = true;
        private bool _autoScanEnabled = true;
        private bool _blockAutorun = true;
        private bool _isDisposed;

        public event EventHandler<UsbDeviceEventArgs>? DeviceConnected;
        public event EventHandler<UsbDeviceEventArgs>? DeviceRemoved;
        public event EventHandler<UsbScanEventArgs>? ScanStarted;
        public event EventHandler<UsbScanEventArgs>? ScanCompleted;
        public event EventHandler<UsbScanProgressEventArgs>? ScanProgress;
        public event EventHandler<UsbThreatEventArgs>? ThreatFound;
        public event EventHandler<string>? LogAdded;

        public bool IsEnabled
        {
            get => _isEnabled;
            set
            {
                _isEnabled = value;
                if (value) Start(); else Stop();
            }
        }

        public bool AutoScanEnabled
        {
            get => _autoScanEnabled;
            set => _autoScanEnabled = value;
        }

        public bool BlockAutorun
        {
            get => _blockAutorun;
            set => _blockAutorun = value;
        }

        public IReadOnlyDictionary<string, UsbDeviceInfo> ConnectedDevices => _connectedDevices;

        // Dangerous autorun files to check
        private static readonly string[] AutorunFiles = {
            "autorun.inf", "autorun.exe", "autorun.bat", "autorun.cmd",
            "desktop.ini", "folder.htt"
        };

        // Suspicious file patterns on USB
        private static readonly string[] SuspiciousPatterns = {
            "*.exe", "*.scr", "*.pif", "*.bat", "*.cmd", "*.vbs",
            "*.js", "*.jse", "*.wsf", "*.wsh", "*.ps1", "*.lnk"
        };

        public UsbScanService(SafeScanner scanner, ThreatAnalyzer analyzer)
        {
            _scanner = scanner;
            _analyzer = analyzer;
        }

        public void Start()
        {
            if (_insertWatcher != null) return;

            try
            {
                // Watch for USB insert
                var insertQuery = new WqlEventQuery(
                    "SELECT * FROM __InstanceCreationEvent WITHIN 2 WHERE TargetInstance ISA 'Win32_LogicalDisk' AND TargetInstance.DriveType = 2"
                );
                _insertWatcher = new ManagementEventWatcher(insertQuery);
                _insertWatcher.EventArrived += OnDeviceInserted;
                _insertWatcher.Start();

                // Watch for USB remove
                var removeQuery = new WqlEventQuery(
                    "SELECT * FROM __InstanceDeletionEvent WITHIN 2 WHERE TargetInstance ISA 'Win32_LogicalDisk' AND TargetInstance.DriveType = 2"
                );
                _removeWatcher = new ManagementEventWatcher(removeQuery);
                _removeWatcher.EventArrived += OnDeviceRemoved;
                _removeWatcher.Start();

                // Scan existing removable drives
                ScanExistingDrives();

                RaiseLog("🔌 USB monitoring started");
            }
            catch (Exception ex)
            {
                RaiseLog($"USB monitoring error: {ex.Message}");
            }
        }

        public void Stop()
        {
            _insertWatcher?.Stop();
            _insertWatcher?.Dispose();
            _insertWatcher = null;

            _removeWatcher?.Stop();
            _removeWatcher?.Dispose();
            _removeWatcher = null;

            RaiseLog("🔌 USB monitoring stopped");
        }

        private void ScanExistingDrives()
        {
            foreach (var drive in DriveInfo.GetDrives())
            {
                if (drive.DriveType == DriveType.Removable && drive.IsReady)
                {
                    RegisterDevice(drive.Name);
                }
            }
        }

        private void OnDeviceInserted(object sender, EventArrivedEventArgs e)
        {
            try
            {
                var target = (ManagementBaseObject)e.NewEvent["TargetInstance"];
                var driveLetter = target["DeviceID"]?.ToString();

                if (!string.IsNullOrEmpty(driveLetter))
                {
                    RegisterDevice(driveLetter);

                    if (_autoScanEnabled)
                    {
                        Task.Run(() => ScanDriveAsync(driveLetter, CancellationToken.None));
                    }
                }
            }
            catch (Exception ex)
            {
                RaiseLog($"USB insert error: {ex.Message}");
            }
        }

        private void OnDeviceRemoved(object sender, EventArrivedEventArgs e)
        {
            try
            {
                var target = (ManagementBaseObject)e.NewEvent["TargetInstance"];
                var driveLetter = target["DeviceID"]?.ToString();

                if (!string.IsNullOrEmpty(driveLetter))
                {
                    UnregisterDevice(driveLetter);
                }
            }
            catch { }
        }

        private void RegisterDevice(string driveLetter)
        {
            try
            {
                var drive = new DriveInfo(driveLetter);
                if (!drive.IsReady) return;

                var device = new UsbDeviceInfo
                {
                    DriveLetter = driveLetter,
                    VolumeLabel = drive.VolumeLabel,
                    TotalSize = drive.TotalSize,
                    FreeSpace = drive.AvailableFreeSpace,
                    FileSystem = drive.DriveFormat,
                    ConnectedAt = DateTime.Now
                };

                _connectedDevices[driveLetter] = device;
                RaiseLog($"🔌 USB connected: {driveLetter} ({device.VolumeLabel})");

                DeviceConnected?.Invoke(this, new UsbDeviceEventArgs(device));

                // Check for autorun immediately
                if (_blockAutorun)
                {
                    CheckAndBlockAutorun(driveLetter);
                }
            }
            catch { }
        }

        private void UnregisterDevice(string driveLetter)
        {
            if (_connectedDevices.TryGetValue(driveLetter, out var device))
            {
                _connectedDevices.Remove(driveLetter);
                _scannedDrives.Remove(driveLetter);
                RaiseLog($"🔌 USB removed: {driveLetter}");
                DeviceRemoved?.Invoke(this, new UsbDeviceEventArgs(device));
            }
        }

        private void CheckAndBlockAutorun(string driveLetter)
        {
            try
            {
                foreach (var autorunFile in AutorunFiles)
                {
                    var path = Path.Combine(driveLetter, autorunFile);
                    if (File.Exists(path))
                    {
                        RaiseLog($"⚠️ Autorun file detected: {path}");

                        // Analyze the autorun file
                        var threat = _analyzer.AnalyzePath(path);
                        if (threat != null)
                        {
                            ThreatFound?.Invoke(this, new UsbThreatEventArgs(driveLetter, threat));
                        }

                        // Attempt to remove/rename autorun.inf
                        if (autorunFile.Equals("autorun.inf", StringComparison.OrdinalIgnoreCase))
                        {
                            try
                            {
                                var blockedPath = path + ".blocked";
                                if (File.Exists(blockedPath)) File.Delete(blockedPath);
                                File.Move(path, blockedPath);
                                RaiseLog($"🛡️ Autorun blocked: {path}");
                            }
                            catch
                            {
                                // Try to delete instead
                                try
                                {
                                    File.SetAttributes(path, FileAttributes.Normal);
                                    File.Delete(path);
                                    RaiseLog($"🛡️ Autorun deleted: {path}");
                                }
                                catch { }
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                RaiseLog($"Autorun check error: {ex.Message}");
            }
        }

        public async Task<UsbScanResult> ScanDriveAsync(string driveLetter, CancellationToken cancellationToken)
        {
            var result = new UsbScanResult
            {
                DriveLetter = driveLetter,
                StartTime = DateTime.Now
            };

            if (!_connectedDevices.TryGetValue(driveLetter, out var device))
            {
                result.Error = "Device not found";
                return result;
            }

            RaiseLog($"🔍 Scanning USB: {driveLetter}");
            ScanStarted?.Invoke(this, new UsbScanEventArgs(device, result));

            try
            {
                var threats = new List<ThreatInfo>();

                // Count total files first for progress calculation
                int totalFiles = 0;
                int processedFiles = 0;

                // Quick count of root files
                var rootFiles = Directory.GetFiles(driveLetter, "*.*", SearchOption.TopDirectoryOnly);
                totalFiles += rootFiles.Length;

                // Estimate files for each pattern
                foreach (var pattern in SuspiciousPatterns)
                {
                    try
                    {
                        var files = Directory.GetFiles(driveLetter, pattern, SearchOption.AllDirectories);
                        totalFiles += files.Length;
                    }
                    catch { }
                }

                // Ensure minimum total for progress
                if (totalFiles == 0) totalFiles = 1;

                // Report initial progress
                ScanProgress?.Invoke(this, new UsbScanProgressEventArgs(driveLetter, 0, totalFiles, "Starting scan..."));

                // Quick scan: Check root and common locations first
                foreach (var file in rootFiles)
                {
                    if (cancellationToken.IsCancellationRequested) break;

                    var threat = _analyzer.AnalyzePath(file);
                    if (threat != null)
                    {
                        threats.Add(threat);
                        ThreatFound?.Invoke(this, new UsbThreatEventArgs(driveLetter, threat));
                    }
                    result.FilesScanned++;
                    processedFiles++;

                    // Report progress every 10 files
                    if (processedFiles % 10 == 0 || processedFiles == totalFiles)
                    {
                        ScanProgress?.Invoke(this, new UsbScanProgressEventArgs(driveLetter, processedFiles, totalFiles, file));
                    }
                }

                // Scan for suspicious file types
                foreach (var pattern in SuspiciousPatterns)
                {
                    if (cancellationToken.IsCancellationRequested) break;

                    try
                    {
                        var files = Directory.GetFiles(driveLetter, pattern, SearchOption.AllDirectories);
                        foreach (var file in files)
                        {
                            if (cancellationToken.IsCancellationRequested) break;

                            var threat = _analyzer.AnalyzePath(file);
                            if (threat != null && !threats.Any(t => t.Path == file))
                            {
                                threats.Add(threat);
                                ThreatFound?.Invoke(this, new UsbThreatEventArgs(driveLetter, threat));
                            }
                            result.FilesScanned++;
                            processedFiles++;

                            // Report progress every 10 files
                            if (processedFiles % 10 == 0 || processedFiles >= totalFiles)
                            {
                                ScanProgress?.Invoke(this, new UsbScanProgressEventArgs(driveLetter, processedFiles, totalFiles, file));
                            }
                        }
                    }
                    catch { }
                }

                // Final progress report
                ScanProgress?.Invoke(this, new UsbScanProgressEventArgs(driveLetter, totalFiles, totalFiles, "Scan complete"));

                result.Threats = threats;
                result.EndTime = DateTime.Now;
                result.Success = true;

                _scannedDrives.Add(driveLetter);
                device.LastScanned = DateTime.Now;
                device.ThreatsFound = threats.Count;

                RaiseLog($"✅ USB scan complete: {driveLetter} - {result.FilesScanned} files, {threats.Count} threats");
            }
            catch (Exception ex)
            {
                result.Error = ex.Message;
                RaiseLog($"❌ USB scan error: {ex.Message}");
            }

            ScanCompleted?.Invoke(this, new UsbScanEventArgs(device, result));
            return result;
        }

        public async Task<UsbScanResult> DeepScanDriveAsync(string driveLetter, IProgress<(int scanned, int threats, string current)>? progress, CancellationToken cancellationToken)
        {
            var result = new UsbScanResult
            {
                DriveLetter = driveLetter,
                StartTime = DateTime.Now
            };

            if (!_connectedDevices.TryGetValue(driveLetter, out var device))
            {
                result.Error = "Device not found";
                return result;
            }

            RaiseLog($"🔍 Deep scanning USB: {driveLetter}");
            ScanStarted?.Invoke(this, new UsbScanEventArgs(device, result));

            try
            {
                // Use full scanner for deep scan
                var scanResult = await _scanner.ScanAsync(
                    scanFiles: true,
                    scanRegistry: false,
                    scanProcesses: false,
                    scanMode: Views.ScanMode.Custom,
                    customFolders: new List<string> { driveLetter }
                );

                result.Threats = scanResult.Threats;
                result.FilesScanned = (int)scanResult.TotalScanned;
                result.EndTime = DateTime.Now;
                result.Success = true;

                _scannedDrives.Add(driveLetter);
                device.LastScanned = DateTime.Now;
                device.ThreatsFound = result.Threats.Count;

                RaiseLog($"✅ USB deep scan complete: {driveLetter} - {result.FilesScanned} files, {result.Threats.Count} threats");
            }
            catch (Exception ex)
            {
                result.Error = ex.Message;
                RaiseLog($"❌ USB deep scan error: {ex.Message}");
            }

            ScanCompleted?.Invoke(this, new UsbScanEventArgs(device, result));
            return result;
        }

        public bool IsDriveScanned(string driveLetter) => _scannedDrives.Contains(driveLetter);

        private void RaiseLog(string message)
        {
            LogAdded?.Invoke(this, message);
        }

        public void Dispose()
        {
            if (_isDisposed) return;
            _isDisposed = true;
            Stop();
        }
    }

    public class UsbDeviceInfo
    {
        public string DriveLetter { get; set; } = string.Empty;
        public string VolumeLabel { get; set; } = string.Empty;
        public long TotalSize { get; set; }
        public long FreeSpace { get; set; }
        public string FileSystem { get; set; } = string.Empty;
        public DateTime ConnectedAt { get; set; }
        public DateTime? LastScanned { get; set; }
        public int ThreatsFound { get; set; }

        public string FormattedSize => $"{TotalSize / (1024 * 1024 * 1024.0):F1} GB";
    }

    public class UsbScanResult
    {
        public string DriveLetter { get; set; } = string.Empty;
        public DateTime StartTime { get; set; }
        public DateTime EndTime { get; set; }
        public int FilesScanned { get; set; }
        public List<ThreatInfo> Threats { get; set; } = new();
        public bool Success { get; set; }
        public string? Error { get; set; }

        public TimeSpan Duration => EndTime - StartTime;
    }

    public class UsbDeviceEventArgs : EventArgs
    {
        public UsbDeviceInfo Device { get; }

        public UsbDeviceEventArgs(UsbDeviceInfo device)
        {
            Device = device;
        }
    }

    public class UsbScanEventArgs : EventArgs
    {
        public UsbDeviceInfo Device { get; }
        public UsbScanResult Result { get; }

        public UsbScanEventArgs(UsbDeviceInfo device, UsbScanResult result)
        {
            Device = device;
            Result = result;
        }
    }

    public class UsbThreatEventArgs : EventArgs
    {
        public string DriveLetter { get; }
        public ThreatInfo Threat { get; }

        public UsbThreatEventArgs(string driveLetter, ThreatInfo threat)
        {
            DriveLetter = driveLetter;
            Threat = threat;
        }
    }

    public class UsbScanProgressEventArgs : EventArgs
    {
        public string DriveLetter { get; }
        public int ProcessedFiles { get; }
        public int TotalFiles { get; }
        public string CurrentFile { get; }
        public int ProgressPercent => TotalFiles > 0 ? (int)((ProcessedFiles * 100.0) / TotalFiles) : 0;

        public UsbScanProgressEventArgs(string driveLetter, int processedFiles, int totalFiles, string currentFile)
        {
            DriveLetter = driveLetter;
            ProcessedFiles = processedFiles;
            TotalFiles = totalFiles;
            CurrentFile = currentFile;
        }
    }
}
