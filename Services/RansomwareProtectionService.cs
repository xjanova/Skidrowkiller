using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace SkidrowKiller.Services
{
    /// <summary>
    /// Ransomware Protection Service - Protects important folders from unauthorized encryption/modification.
    /// Uses honeypot files, behavioral detection, and folder protection.
    /// </summary>
    public class RansomwareProtectionService : IDisposable
    {
        private readonly List<FileSystemWatcher> _watchers = new();
        private readonly ConcurrentDictionary<string, FileSnapshot> _fileSnapshots = new();
        private readonly ConcurrentDictionary<string, int> _processModificationCount = new();
        private readonly HashSet<string> _protectedFolders = new();
        private readonly HashSet<string> _trustedProcesses = new();
        private readonly SettingsDatabase? _db;
        private readonly string _configPath;
        private readonly string _honeypotFolder;
        private CancellationTokenSource? _cts;
        private bool _isEnabled;
        private bool _isDisposed;
        private DateTime _lastAlertTime = DateTime.MinValue;

        // Ransomware detection thresholds
        private const int ModificationThreshold = 10; // Modifications per process before alert
        private const int TimeWindowSeconds = 5;
        private const double EntropyThreshold = 7.5; // High entropy indicates encryption

        // Common ransomware extensions
        private static readonly HashSet<string> RansomwareExtensions = new(StringComparer.OrdinalIgnoreCase)
        {
            ".encrypted", ".locked", ".crypto", ".crypt", ".enc", ".crypted",
            ".locky", ".cerber", ".zepto", ".thor", ".aaa", ".abc", ".xyz",
            ".zzz", ".micro", ".xxx", ".ttt", ".ecc", ".ezz", ".exx",
            ".wncry", ".wcry", ".wannacry", ".petya", ".notpetya",
            ".dharma", ".phobos", ".ryuk", ".sodinokibi", ".revil",
            ".lockbit", ".conti", ".maze", ".ragnar", ".darkside"
        };

        // Protected file types (documents, photos, etc.)
        private static readonly HashSet<string> ProtectedExtensions = new(StringComparer.OrdinalIgnoreCase)
        {
            // Documents
            ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf", ".odt", ".ods", ".odp",
            ".txt", ".rtf", ".csv", ".xml", ".json", ".html", ".htm",
            // Images
            ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".psd", ".ai", ".svg", ".raw",
            // Videos
            ".mp4", ".avi", ".mkv", ".mov", ".wmv", ".flv", ".webm",
            // Audio
            ".mp3", ".wav", ".flac", ".aac", ".ogg", ".wma",
            // Archives
            ".zip", ".rar", ".7z", ".tar", ".gz",
            // Code
            ".cs", ".js", ".py", ".java", ".cpp", ".h", ".php", ".rb", ".go", ".rs",
            // Database
            ".sql", ".db", ".mdb", ".accdb", ".sqlite"
        };

        public event EventHandler<RansomwareAlertEventArgs>? AlertRaised;
        public event EventHandler<string>? LogAdded;

        public bool IsEnabled => _isEnabled;
        public IReadOnlySet<string> ProtectedFolders => _protectedFolders;

        public RansomwareProtectionService(SettingsDatabase? db = null)
        {
            _db = db;

            var appData = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "SkidrowKiller"
            );
            _configPath = Path.Combine(appData, "ransomware_config.json");
            _honeypotFolder = Path.Combine(appData, "Honeypots");

            LoadConfig();
        }

        public void Start()
        {
            if (_isEnabled) return;

            _isEnabled = true;
            _cts = new CancellationTokenSource();

            // Setup default protected folders if none configured
            if (_protectedFolders.Count == 0)
            {
                AddDefaultProtectedFolders();
            }

            // Create honeypot files
            CreateHoneypotFiles();

            // Setup watchers for protected folders
            SetupWatchers();

            // Take initial snapshots
            Task.Run(() => TakeSnapshots());

            RaiseLog("🛡️ Ransomware protection started");
            RaiseLog($"   Protecting {_protectedFolders.Count} folders");
        }

        public void Stop()
        {
            if (!_isEnabled) return;

            _isEnabled = false;
            _cts?.Cancel();

            foreach (var watcher in _watchers)
            {
                watcher.EnableRaisingEvents = false;
                watcher.Dispose();
            }
            _watchers.Clear();

            RaiseLog("🛡️ Ransomware protection stopped");
        }

        private void AddDefaultProtectedFolders()
        {
            var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

            // Add common user folders
            AddProtectedFolder(Path.Combine(userProfile, "Documents"));
            AddProtectedFolder(Path.Combine(userProfile, "Pictures"));
            AddProtectedFolder(Path.Combine(userProfile, "Videos"));
            AddProtectedFolder(Path.Combine(userProfile, "Music"));
            AddProtectedFolder(Path.Combine(userProfile, "Desktop"));
            AddProtectedFolder(Path.Combine(userProfile, "Downloads"));

            SaveConfig();
        }

        public void AddProtectedFolder(string path)
        {
            if (Directory.Exists(path))
            {
                _protectedFolders.Add(path);
                if (_isEnabled)
                {
                    SetupWatcherForFolder(path);
                }

                // Save to SQLite
                _db?.AddProtectedFolder(path);
                SaveConfig();
                RaiseLog($"📁 Protected folder added: {path}");
            }
        }

        public void RemoveProtectedFolder(string path)
        {
            _protectedFolders.Remove(path);
            // Remove from SQLite
            _db?.RemoveProtectedFolder(path);
            SaveConfig();
            RaiseLog($"📁 Protected folder removed: {path}");
        }

        public void AddTrustedProcess(string processName)
        {
            _trustedProcesses.Add(processName.ToLower());
            SaveConfig();
        }

        private void SetupWatchers()
        {
            foreach (var folder in _protectedFolders)
            {
                SetupWatcherForFolder(folder);
            }
        }

        private void SetupWatcherForFolder(string folder)
        {
            if (!Directory.Exists(folder)) return;

            try
            {
                var watcher = new FileSystemWatcher(folder)
                {
                    NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite |
                                   NotifyFilters.Size | NotifyFilters.CreationTime,
                    IncludeSubdirectories = true,
                    EnableRaisingEvents = true
                };

                watcher.Changed += OnFileChanged;
                watcher.Renamed += OnFileRenamed;
                watcher.Deleted += OnFileDeleted;
                watcher.Created += OnFileCreated;

                _watchers.Add(watcher);
            }
            catch (Exception ex)
            {
                RaiseLog($"Watcher setup error for {folder}: {ex.Message}");
            }
        }

        private void OnFileChanged(object sender, FileSystemEventArgs e)
        {
            if (!_isEnabled) return;
            Task.Run(() => AnalyzeFileChange(e.FullPath, "Modified"));
        }

        private void OnFileRenamed(object sender, RenamedEventArgs e)
        {
            if (!_isEnabled) return;

            // Check if renamed to ransomware extension
            var newExt = Path.GetExtension(e.FullPath);
            if (RansomwareExtensions.Contains(newExt))
            {
                RaiseAlert(new RansomwareAlertEventArgs
                {
                    AlertType = RansomwareAlertType.SuspiciousRename,
                    FilePath = e.FullPath,
                    OldPath = e.OldFullPath,
                    Description = $"File renamed to ransomware extension: {newExt}",
                    Severity = AlertSeverity.Critical
                });
            }

            Task.Run(() => AnalyzeFileChange(e.FullPath, "Renamed"));
        }

        private void OnFileDeleted(object sender, FileSystemEventArgs e)
        {
            if (!_isEnabled) return;

            // Check if honeypot was deleted
            if (e.FullPath.Contains(_honeypotFolder))
            {
                RaiseAlert(new RansomwareAlertEventArgs
                {
                    AlertType = RansomwareAlertType.HoneypotTriggered,
                    FilePath = e.FullPath,
                    Description = "Honeypot file was deleted - possible ransomware activity!",
                    Severity = AlertSeverity.Critical
                });
            }

            // Track mass deletion
            TrackProcessModification("deletion");
        }

        private void OnFileCreated(object sender, FileSystemEventArgs e)
        {
            if (!_isEnabled) return;

            // Check for ransom note patterns
            var fileName = Path.GetFileName(e.FullPath).ToLower();
            if (IsRansomNote(fileName))
            {
                RaiseAlert(new RansomwareAlertEventArgs
                {
                    AlertType = RansomwareAlertType.RansomNoteDetected,
                    FilePath = e.FullPath,
                    Description = $"Possible ransom note detected: {fileName}",
                    Severity = AlertSeverity.Critical
                });
            }
        }

        private bool IsRansomNote(string fileName)
        {
            var ransomNotePatterns = new[] {
                "readme", "decrypt", "recover", "restore", "help_decrypt",
                "how_to_decrypt", "your_files", "ransom", "payment", "bitcoin",
                "!readme", "_readme", "-readme", "read_me", "read_it"
            };

            return ransomNotePatterns.Any(p => fileName.Contains(p)) &&
                   (fileName.EndsWith(".txt") || fileName.EndsWith(".html") || fileName.EndsWith(".hta"));
        }

        private async Task AnalyzeFileChange(string filePath, string changeType)
        {
            try
            {
                if (!File.Exists(filePath)) return;

                var ext = Path.GetExtension(filePath);
                if (!ProtectedExtensions.Contains(ext)) return;

                // Check for high-entropy content (indicates encryption)
                var entropy = await CalculateFileEntropy(filePath);
                if (entropy > EntropyThreshold)
                {
                    // Check if we have a snapshot to compare
                    if (_fileSnapshots.TryGetValue(filePath, out var snapshot))
                    {
                        // File was previously low entropy, now high = likely encrypted
                        if (snapshot.Entropy < EntropyThreshold - 1)
                        {
                            RaiseAlert(new RansomwareAlertEventArgs
                            {
                                AlertType = RansomwareAlertType.FileEncrypted,
                                FilePath = filePath,
                                Description = $"File appears to be encrypted (entropy: {entropy:F2})",
                                Severity = AlertSeverity.High
                            });
                        }
                    }
                }

                // Track modification rate
                TrackProcessModification(filePath);
            }
            catch { }
        }

        private void TrackProcessModification(string context)
        {
            var key = $"{DateTime.Now:HHmmss}"; // Group by second
            _processModificationCount.AddOrUpdate(key, 1, (_, count) => count + 1);

            // Check if too many modifications in time window
            var recentCount = _processModificationCount
                .Where(kvp => DateTime.TryParseExact(kvp.Key, "HHmmss", null, System.Globalization.DateTimeStyles.None, out var time) &&
                              (DateTime.Now - DateTime.Today.Add(time.TimeOfDay)).TotalSeconds < TimeWindowSeconds)
                .Sum(kvp => kvp.Value);

            if (recentCount > ModificationThreshold)
            {
                // Rate limit alerts
                if ((DateTime.Now - _lastAlertTime).TotalSeconds > 30)
                {
                    _lastAlertTime = DateTime.Now;
                    RaiseAlert(new RansomwareAlertEventArgs
                    {
                        AlertType = RansomwareAlertType.MassModification,
                        Description = $"Suspicious mass file modification detected ({recentCount} files in {TimeWindowSeconds}s)",
                        Severity = AlertSeverity.High
                    });
                }
            }

            // Cleanup old entries
            var cutoff = DateTime.Now.AddMinutes(-1).ToString("HHmmss");
            foreach (var key2 in _processModificationCount.Keys.Where(k => string.Compare(k, cutoff) < 0).ToList())
            {
                _processModificationCount.TryRemove(key2, out _);
            }
        }

        private async Task<double> CalculateFileEntropy(string filePath)
        {
            try
            {
                var bytes = await File.ReadAllBytesAsync(filePath);
                if (bytes.Length == 0) return 0;

                // Use sample for large files
                if (bytes.Length > 1024 * 1024)
                {
                    var sample = new byte[1024 * 1024];
                    Array.Copy(bytes, sample, sample.Length);
                    bytes = sample;
                }

                var frequencies = new int[256];
                foreach (var b in bytes)
                {
                    frequencies[b]++;
                }

                double entropy = 0;
                var length = (double)bytes.Length;
                for (int i = 0; i < 256; i++)
                {
                    if (frequencies[i] > 0)
                    {
                        var probability = frequencies[i] / length;
                        entropy -= probability * Math.Log2(probability);
                    }
                }

                return entropy;
            }
            catch
            {
                return 0;
            }
        }

        #region Honeypot Files

        private void CreateHoneypotFiles()
        {
            try
            {
                if (!Directory.Exists(_honeypotFolder))
                {
                    Directory.CreateDirectory(_honeypotFolder);
                    File.SetAttributes(_honeypotFolder, FileAttributes.Hidden);
                }

                // Create honeypot files in protected folders
                foreach (var folder in _protectedFolders)
                {
                    CreateHoneypotInFolder(folder);
                }

                // Also create in honeypot folder
                CreateHoneypotFile(Path.Combine(_honeypotFolder, "important_document.docx"));
                CreateHoneypotFile(Path.Combine(_honeypotFolder, "financial_records.xlsx"));
                CreateHoneypotFile(Path.Combine(_honeypotFolder, "passwords.txt"));

                // Setup honeypot watcher
                SetupWatcherForFolder(_honeypotFolder);
            }
            catch (Exception ex)
            {
                RaiseLog($"Honeypot creation error: {ex.Message}");
            }
        }

        private void CreateHoneypotInFolder(string folder)
        {
            try
            {
                // Create a hidden honeypot file
                var honeypotPath = Path.Combine(folder, ".~important_backup.docx");
                CreateHoneypotFile(honeypotPath);
            }
            catch { }
        }

        private void CreateHoneypotFile(string path)
        {
            try
            {
                if (File.Exists(path)) return;

                // Create file with low-entropy content
                var content = "This is an important document. Please do not modify or delete this file.\n";
                content += string.Concat(Enumerable.Repeat(content, 100));

                File.WriteAllText(path, content);
                File.SetAttributes(path, FileAttributes.Hidden | FileAttributes.System);
            }
            catch { }
        }

        #endregion

        #region Snapshots

        private async Task TakeSnapshots()
        {
            foreach (var folder in _protectedFolders)
            {
                try
                {
                    var files = Directory.GetFiles(folder, "*.*", SearchOption.TopDirectoryOnly)
                        .Where(f => ProtectedExtensions.Contains(Path.GetExtension(f)))
                        .Take(100); // Limit for performance

                    foreach (var file in files)
                    {
                        try
                        {
                            var entropy = await CalculateFileEntropy(file);
                            var hash = await ComputeFileHash(file);

                            _fileSnapshots[file] = new FileSnapshot
                            {
                                Path = file,
                                Hash = hash,
                                Entropy = entropy,
                                Size = new FileInfo(file).Length,
                                LastModified = File.GetLastWriteTime(file)
                            };
                        }
                        catch { }
                    }
                }
                catch { }
            }
        }

        private async Task<string> ComputeFileHash(string filePath)
        {
            using var sha256 = SHA256.Create();
            using var stream = File.OpenRead(filePath);
            var hash = await sha256.ComputeHashAsync(stream);
            return BitConverter.ToString(hash).Replace("-", "").ToLower();
        }

        #endregion

        #region Persistence

        private void LoadConfig()
        {
            try
            {
                // First try to load from SQLite database
                if (_db != null)
                {
                    var folders = _db.GetProtectedFolders();
                    foreach (var folder in folders)
                    {
                        if (Directory.Exists(folder))
                        {
                            _protectedFolders.Add(folder);
                        }
                    }
                }

                // Fallback/migrate from JSON config
                if (File.Exists(_configPath))
                {
                    var json = File.ReadAllText(_configPath);
                    var config = JsonSerializer.Deserialize<RansomwareConfig>(json);
                    if (config != null)
                    {
                        foreach (var folder in config.ProtectedFolders)
                        {
                            if (Directory.Exists(folder) && !_protectedFolders.Contains(folder))
                            {
                                _protectedFolders.Add(folder);
                                // Migrate to SQLite
                                _db?.AddProtectedFolder(folder);
                            }
                        }
                        foreach (var proc in config.TrustedProcesses)
                        {
                            _trustedProcesses.Add(proc);
                        }
                    }
                }
            }
            catch { }
        }

        private void SaveConfig()
        {
            try
            {
                var dir = Path.GetDirectoryName(_configPath);
                if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
                {
                    Directory.CreateDirectory(dir);
                }

                var config = new RansomwareConfig
                {
                    ProtectedFolders = _protectedFolders.ToList(),
                    TrustedProcesses = _trustedProcesses.ToList()
                };

                var json = JsonSerializer.Serialize(config, new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(_configPath, json);
            }
            catch { }
        }

        #endregion

        private void RaiseAlert(RansomwareAlertEventArgs args)
        {
            RaiseLog($"🚨 RANSOMWARE ALERT: {args.Description}");
            AlertRaised?.Invoke(this, args);
        }

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

    public class FileSnapshot
    {
        public string Path { get; set; } = string.Empty;
        public string Hash { get; set; } = string.Empty;
        public double Entropy { get; set; }
        public long Size { get; set; }
        public DateTime LastModified { get; set; }
    }

    public class RansomwareConfig
    {
        public List<string> ProtectedFolders { get; set; } = new();
        public List<string> TrustedProcesses { get; set; } = new();
    }

    public enum RansomwareAlertType
    {
        HoneypotTriggered,
        MassModification,
        FileEncrypted,
        SuspiciousRename,
        RansomNoteDetected
    }

    public enum AlertSeverity
    {
        Low,
        Medium,
        High,
        Critical
    }

    public class RansomwareAlertEventArgs : EventArgs
    {
        public RansomwareAlertType AlertType { get; set; }
        public string FilePath { get; set; } = string.Empty;
        public string? OldPath { get; set; }
        public string Description { get; set; } = string.Empty;
        public AlertSeverity Severity { get; set; }
        public DateTime Timestamp { get; set; } = DateTime.Now;
    }
}
