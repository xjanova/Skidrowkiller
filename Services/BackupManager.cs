using System.IO;
using System.IO.Compression;
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
        public bool IsRestored { get; set; }
    }

    public class BackupManager
    {
        private readonly string _backupFolder;
        private readonly SettingsDatabase? _db;
        private readonly object _lock = new();

        public event EventHandler<string>? LogAdded;

        /// <summary>
        /// Days a backup is kept before <see cref="CleanOldBackups()"/> removes it.
        /// 0 (or less) means "never delete". Seeded from Backup:RetentionDays, overridden by Settings.
        /// </summary>
        public int RetentionDays { get; set; }

        /// <summary>
        /// Cap on the total size of the backup folder in MB. 0 (or less) means unlimited.
        /// When a new backup would exceed it, the oldest backups are evicted first; if it still
        /// does not fit, the backup is refused rather than blowing past the user's limit.
        /// </summary>
        public int MaxBackupSizeMB { get; set; }

        public BackupManager(SettingsDatabase? db = null)
        {
            _db = db;

            // Backup:RetentionDays and Backup:MaxBackupSizeMB used to be read by nothing at all.
            try
            {
                var cfg = AppConfiguration.Settings.Backup;
                RetentionDays = cfg.RetentionDays;
                MaxBackupSizeMB = cfg.MaxBackupSizeMB;
            }
            catch
            {
                RetentionDays = 7;
                MaxBackupSizeMB = 1024;
            }

            _backupFolder = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "SkidrowKiller",
                "Backups"
            );

            EnsureBackupFolder();
        }

        private void EnsureBackupFolder()
        {
            if (!Directory.Exists(_backupFolder))
            {
                Directory.CreateDirectory(_backupFolder);
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

                    if (!MakeRoomFor(entry.Size))
                        return null;

                    var backupName = $"{entry.Id}_{Path.GetFileName(filePath)}";
                    entry.BackupPath = Path.Combine(_backupFolder, backupName);

                    File.Copy(filePath, entry.BackupPath, true);

                    // Save to database
                    _db?.AddBackupEntry(entry);

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

                    if (!MakeRoomFor(entry.Size))
                        return null;

                    // Create zip backup
                    ZipFile.CreateFromDirectory(directoryPath, entry.BackupPath, CompressionLevel.Fastest, true);

                    // Save to database
                    _db?.AddBackupEntry(entry);

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

                    // Save to database
                    _db?.AddBackupEntry(entry);

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
                var backups = GetBackups();
                var entry = backups.FirstOrDefault(b => b.Id == backupId);
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

                        // Mark as restored in database
                        _db?.MarkBackupRestored(backupId);
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

            var targetDir = Path.GetDirectoryName(entry.OriginalPath);
            if (targetDir == null) return false;
            ZipFile.ExtractToDirectory(entry.BackupPath, targetDir, true);
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
                var backups = GetBackups();
                var entry = backups.FirstOrDefault(b => b.Id == backupId);
                if (entry == null) return;

                try
                {
                    if (!string.IsNullOrEmpty(entry.BackupPath) && File.Exists(entry.BackupPath))
                    {
                        File.Delete(entry.BackupPath);
                    }

                    // Mark as restored (deleted) in database
                    _db?.MarkBackupRestored(backupId);
                }
                catch { }
            }
        }

        public List<BackupEntry> GetBackups()
        {
            lock (_lock)
            {
                if (_db == null) return new List<BackupEntry>();

                return _db.GetBackupEntries()
                    .OrderByDescending(b => b.BackedUpAt)
                    .ToList();
            }
        }

        public long GetTotalBackupSize()
        {
            lock (_lock)
            {
                return GetBackups().Sum(b => b.Size);
            }
        }

        /// <summary>Apply the configured <see cref="RetentionDays"/>.</summary>
        public void CleanOldBackups() => CleanOldBackups(RetentionDays);

        public void CleanOldBackups(int keepDays)
        {
            // A non-positive retention means "never delete" (the "Never delete" option in Settings).
            if (keepDays <= 0) return;

            lock (_lock)
            {
                var cutoff = DateTime.Now.AddDays(-keepDays);
                var oldBackups = GetBackups().Where(b => b.BackedUpAt < cutoff).ToList();

                foreach (var backup in oldBackups)
                {
                    DeleteBackup(backup.Id);
                }

                if (oldBackups.Count > 0)
                    RaiseLog($"[BACKUP] Removed {oldBackups.Count} backup(s) older than {keepDays} day(s)");
            }
        }

        /// <summary>
        /// Evict oldest backups until <paramref name="incomingBytes"/> fits inside the size cap.
        /// Returns false when even an empty folder could not hold it - the caller must not proceed.
        /// Caller already holds <see cref="_lock"/>.
        /// </summary>
        private bool MakeRoomFor(long incomingBytes)
        {
            if (MaxBackupSizeMB <= 0) return true; // Unlimited

            var limit = (long)MaxBackupSizeMB * 1024 * 1024;

            if (incomingBytes > limit)
            {
                RaiseLog($"[BACKUP] Skipped: item is {incomingBytes / (1024 * 1024)} MB, over the {MaxBackupSizeMB} MB backup limit");
                return false;
            }

            var current = GetBackups().Sum(b => b.Size);
            if (current + incomingBytes <= limit) return true;

            foreach (var oldest in GetBackups().OrderBy(b => b.BackedUpAt).ToList())
            {
                DeleteBackup(oldest.Id);
                current -= oldest.Size;
                RaiseLog($"[BACKUP] Evicted old backup '{oldest.Name}' to stay under the {MaxBackupSizeMB} MB limit");

                if (current + incomingBytes <= limit) return true;
            }

            return current + incomingBytes <= limit;
        }

        private void RaiseLog(string message)
        {
            LogAdded?.Invoke(this, message);
        }
    }
}
