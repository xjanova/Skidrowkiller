using System.IO;
using System.IO.Compression;
using System.Text.Json;
using Microsoft.Win32;

namespace SkidrowKiller.Services
{
    public class BackupEntry
    {
        public string Id { get; set; } = Guid.NewGuid().ToString();
        public string OriginalPath { get; set; } = string.Empty;
        public string BackupPath { get; set; } = string.Empty;
        public string Name { get; set; } = string.Empty;
        public bool IsDirectory { get; set; }
        public long Size { get; set; }
        public DateTime BackedUpAt { get; set; } = DateTime.Now;
        public string? RegistryKey { get; set; }
        public string? RegistryValue { get; set; }
        public object? RegistryData { get; set; }
        public RegistryValueKind? RegistryKind { get; set; }
    }

    public class BackupManager
    {
        private readonly string _backupFolder;
        private readonly string _manifestPath;
        private List<BackupEntry> _backups = new();
        private readonly object _lock = new();

        public event EventHandler<string>? LogAdded;

        public BackupManager()
        {
            _backupFolder = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "SkidrowKiller",
                "Backups"
            );
            _manifestPath = Path.Combine(_backupFolder, "manifest.json");

            EnsureBackupFolder();
            LoadManifest();
        }

        private void EnsureBackupFolder()
        {
            if (!Directory.Exists(_backupFolder))
            {
                Directory.CreateDirectory(_backupFolder);
            }
        }

        private void LoadManifest()
        {
            lock (_lock)
            {
                try
                {
                    if (File.Exists(_manifestPath))
                    {
                        var json = File.ReadAllText(_manifestPath);
                        _backups = JsonSerializer.Deserialize<List<BackupEntry>>(json) ?? new();
                    }
                }
                catch
                {
                    _backups = new();
                }
            }
        }

        private void SaveManifest()
        {
            lock (_lock)
            {
                try
                {
                    var json = JsonSerializer.Serialize(_backups, new JsonSerializerOptions { WriteIndented = true });
                    File.WriteAllText(_manifestPath, json);
                }
                catch { }
            }
        }

        public string? BackupFile(string filePath)
        {
            if (!File.Exists(filePath)) return null;

            lock (_lock)
            {
                try
                {
                    var entry = new BackupEntry
                    {
                        OriginalPath = filePath,
                        Name = Path.GetFileName(filePath),
                        IsDirectory = false,
                        Size = new FileInfo(filePath).Length
                    };

                    var backupName = $"{entry.Id}_{Path.GetFileName(filePath)}";
                    entry.BackupPath = Path.Combine(_backupFolder, backupName);

                    File.Copy(filePath, entry.BackupPath, true);

                    _backups.Add(entry);
                    SaveManifest();

                    RaiseLog($"[BACKUP] Backed up: {filePath}");
                    return entry.Id;
                }
                catch (Exception ex)
                {
                    RaiseLog($"[BACKUP ERROR] Failed to backup {filePath}: {ex.Message}");
                    return null;
                }
            }
        }

        public string? BackupDirectory(string directoryPath)
        {
            if (!Directory.Exists(directoryPath)) return null;

            lock (_lock)
            {
                try
                {
                    var entry = new BackupEntry
                    {
                        OriginalPath = directoryPath,
                        Name = Path.GetFileName(directoryPath),
                        IsDirectory = true
                    };

                    var backupName = $"{entry.Id}_{Path.GetFileName(directoryPath)}.zip";
                    entry.BackupPath = Path.Combine(_backupFolder, backupName);

                    // Calculate size
                    entry.Size = new DirectoryInfo(directoryPath)
                        .EnumerateFiles("*", SearchOption.AllDirectories)
                        .Sum(f => f.Length);

                    // Create zip backup
                    ZipFile.CreateFromDirectory(directoryPath, entry.BackupPath, CompressionLevel.Fastest, true);

                    _backups.Add(entry);
                    SaveManifest();

                    RaiseLog($"[BACKUP] Backed up directory: {directoryPath}");
                    return entry.Id;
                }
                catch (Exception ex)
                {
                    RaiseLog($"[BACKUP ERROR] Failed to backup directory {directoryPath}: {ex.Message}");
                    return null;
                }
            }
        }

        public string? BackupRegistry(RegistryKey rootKey, string path, string valueName)
        {
            lock (_lock)
            {
                try
                {
                    using var key = rootKey.OpenSubKey(path, false);
                    if (key == null) return null;

                    var value = key.GetValue(valueName);
                    var kind = key.GetValueKind(valueName);

                    var entry = new BackupEntry
                    {
                        OriginalPath = $"{rootKey.Name}\\{path}",
                        Name = valueName,
                        IsDirectory = false,
                        RegistryKey = $"{rootKey.Name}\\{path}",
                        RegistryValue = valueName,
                        RegistryData = value,
                        RegistryKind = kind
                    };

                    _backups.Add(entry);
                    SaveManifest();

                    RaiseLog($"[BACKUP] Backed up registry: {entry.RegistryKey}\\{valueName}");
                    return entry.Id;
                }
                catch (Exception ex)
                {
                    RaiseLog($"[BACKUP ERROR] Failed to backup registry {path}\\{valueName}: {ex.Message}");
                    return null;
                }
            }
        }

        public bool Restore(string backupId)
        {
            lock (_lock)
            {
                var entry = _backups.FirstOrDefault(b => b.Id == backupId);
                if (entry == null) return false;

                try
                {
                    bool success;
                    if (entry.RegistryKey != null)
                    {
                        success = RestoreRegistry(entry);
                    }
                    else if (entry.IsDirectory)
                    {
                        success = RestoreDirectory(entry);
                    }
                    else
                    {
                        success = RestoreFile(entry);
                    }

                    // Delete backup entry after successful restore
                    if (success)
                    {
                        // Delete the backup file
                        if (!string.IsNullOrEmpty(entry.BackupPath) && File.Exists(entry.BackupPath))
                        {
                            try
                            {
                                File.Delete(entry.BackupPath);
                            }
                            catch { }
                        }

                        // Remove from list and save
                        _backups.Remove(entry);
                        SaveManifest();
                        RaiseLog($"[BACKUP] Removed backup entry after successful restore: {entry.Name}");
                    }

                    return success;
                }
                catch (Exception ex)
                {
                    RaiseLog($"[RESTORE ERROR] {ex.Message}");
                    return false;
                }
            }
        }

        private bool RestoreFile(BackupEntry entry)
        {
            if (!File.Exists(entry.BackupPath)) return false;

            var directory = Path.GetDirectoryName(entry.OriginalPath);
            if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
            {
                Directory.CreateDirectory(directory);
            }

            File.Copy(entry.BackupPath, entry.OriginalPath, true);
            RaiseLog($"[RESTORE] Restored file: {entry.OriginalPath}");
            return true;
        }

        private bool RestoreDirectory(BackupEntry entry)
        {
            if (!File.Exists(entry.BackupPath)) return false;

            if (Directory.Exists(entry.OriginalPath))
            {
                Directory.Delete(entry.OriginalPath, true);
            }

            ZipFile.ExtractToDirectory(entry.BackupPath, Path.GetDirectoryName(entry.OriginalPath)!, true);
            RaiseLog($"[RESTORE] Restored directory: {entry.OriginalPath}");
            return true;
        }

        private bool RestoreRegistry(BackupEntry entry)
        {
            if (entry.RegistryKey == null || entry.RegistryValue == null || entry.RegistryData == null)
                return false;

            // Parse root key
            RegistryKey? rootKey = null;
            var keyPath = entry.RegistryKey;

            if (keyPath.StartsWith("HKEY_CURRENT_USER"))
            {
                rootKey = Registry.CurrentUser;
                keyPath = keyPath.Substring("HKEY_CURRENT_USER\\".Length);
            }
            else if (keyPath.StartsWith("HKEY_LOCAL_MACHINE"))
            {
                rootKey = Registry.LocalMachine;
                keyPath = keyPath.Substring("HKEY_LOCAL_MACHINE\\".Length);
            }
            else if (keyPath.StartsWith("HKEY_USERS"))
            {
                rootKey = Registry.Users;
                keyPath = keyPath.Substring("HKEY_USERS\\".Length);
            }

            if (rootKey == null) return false;

            using var key = rootKey.OpenSubKey(keyPath, true) ?? rootKey.CreateSubKey(keyPath);
            if (key == null) return false;

            key.SetValue(entry.RegistryValue, entry.RegistryData, entry.RegistryKind ?? RegistryValueKind.String);
            RaiseLog($"[RESTORE] Restored registry: {entry.RegistryKey}\\{entry.RegistryValue}");
            return true;
        }

        public void DeleteBackup(string backupId)
        {
            lock (_lock)
            {
                var entry = _backups.FirstOrDefault(b => b.Id == backupId);
                if (entry == null) return;

                try
                {
                    if (!string.IsNullOrEmpty(entry.BackupPath) && File.Exists(entry.BackupPath))
                    {
                        File.Delete(entry.BackupPath);
                    }

                    _backups.Remove(entry);
                    SaveManifest();
                }
                catch { }
            }
        }

        public List<BackupEntry> GetBackups()
        {
            lock (_lock)
            {
                return _backups.OrderByDescending(b => b.BackedUpAt).ToList();
            }
        }

        public long GetTotalBackupSize()
        {
            lock (_lock)
            {
                return _backups.Sum(b => b.Size);
            }
        }

        public void CleanOldBackups(int keepDays = 7)
        {
            lock (_lock)
            {
                var cutoff = DateTime.Now.AddDays(-keepDays);
                var oldBackups = _backups.Where(b => b.BackedUpAt < cutoff).ToList();

                foreach (var backup in oldBackups)
                {
                    DeleteBackup(backup.Id);
                }
            }
        }

        private void RaiseLog(string message)
        {
            LogAdded?.Invoke(this, message);
        }
    }
}
