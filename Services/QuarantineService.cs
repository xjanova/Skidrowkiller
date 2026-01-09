using System;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using SkidrowKiller.Models;
using Serilog;

namespace SkidrowKiller.Services
{
    /// <summary>
    /// Service for quarantining threats instead of permanent deletion.
    /// Quarantined files are encrypted and stored safely, allowing restoration if needed.
    /// </summary>
    public class QuarantineService
    {
        private readonly string _quarantinePath;
        private readonly SettingsDatabase? _db;
        private readonly ILogger _logger;
        private readonly object _lock = new();

        // Encryption key derived from machine-specific data
        private static readonly byte[] EncryptionKey = DeriveKey();

        public event EventHandler<string>? LogAdded;
        public event EventHandler<QuarantineEntry>? ItemQuarantined;
        public event EventHandler<QuarantineEntry>? ItemRestored;

        public QuarantineService(SettingsDatabase? db = null)
        {
            _logger = LoggingService.ForContext<QuarantineService>();
            _db = db;

            _quarantinePath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "SkidrowKiller",
                "Quarantine"
            );

            EnsureDirectoryExists();
        }

        private void EnsureDirectoryExists()
        {
            if (!Directory.Exists(_quarantinePath))
            {
                Directory.CreateDirectory(_quarantinePath);
                _logger.Information("Created quarantine directory: {Path}", _quarantinePath);
            }
        }

        /// <summary>
        /// Quarantine a file - move it to quarantine and encrypt it
        /// </summary>
        public QuarantineResult QuarantineFile(string filePath, ThreatInfo? threatInfo = null)
        {
            lock (_lock)
            {
                try
                {
                    if (!File.Exists(filePath))
                    {
                        return new QuarantineResult
                        {
                            Success = false,
                            Message = "File not found"
                        };
                    }

                    var fileInfo = new FileInfo(filePath);
                    var fileHash = ComputeFileHash(filePath);
                    var entryId = Guid.NewGuid().ToString();

                    // Create quarantine file path
                    var quarantineFilePath = Path.Combine(_quarantinePath, $"{entryId}.qtn");

                    // Read, encrypt, and save the file
                    var fileContent = File.ReadAllBytes(filePath);
                    var encryptedContent = EncryptData(fileContent);
                    File.WriteAllBytes(quarantineFilePath, encryptedContent);

                    // Delete original file
                    File.Delete(filePath);

                    var entry = new QuarantineEntry
                    {
                        Id = entryId,
                        OriginalPath = filePath,
                        FileName = fileInfo.Name,
                        FileSize = fileInfo.Length,
                        QuarantinedAt = DateTime.Now,
                        ThreatName = threatInfo?.Name ?? "Unknown Threat",
                        ThreatScore = threatInfo?.Score ?? 0,
                        Severity = threatInfo?.Severity.ToString() ?? "Unknown",
                        QuarantineFilePath = quarantineFilePath,
                        FileHash = fileHash
                    };

                    // Save to database
                    if (_db != null)
                    {
                        _db.AddQuarantineEntry(entry);
                    }

                    var message = $"Quarantined: {fileInfo.Name}";
                    RaiseLog(message);
                    _logger.Information("File quarantined: {Path} -> {QuarantinePath}", filePath, quarantineFilePath);
                    ItemQuarantined?.Invoke(this, entry);

                    return new QuarantineResult
                    {
                        Success = true,
                        Message = message,
                        Entry = entry
                    };
                }
                catch (UnauthorizedAccessException ex)
                {
                    _logger.Error(ex, "Access denied when quarantining file: {Path}", filePath);
                    return new QuarantineResult
                    {
                        Success = false,
                        Message = $"Access denied: {ex.Message}"
                    };
                }
                catch (Exception ex)
                {
                    _logger.Error(ex, "Failed to quarantine file: {Path}", filePath);
                    return new QuarantineResult
                    {
                        Success = false,
                        Message = $"Error: {ex.Message}"
                    };
                }
            }
        }

        /// <summary>
        /// Quarantine a directory - compress, encrypt, and store it
        /// </summary>
        public QuarantineResult QuarantineDirectory(string directoryPath, ThreatInfo? threatInfo = null)
        {
            lock (_lock)
            {
                try
                {
                    if (!Directory.Exists(directoryPath))
                    {
                        return new QuarantineResult
                        {
                            Success = false,
                            Message = "Directory not found"
                        };
                    }

                    var dirInfo = new DirectoryInfo(directoryPath);
                    var entryId = Guid.NewGuid().ToString();
                    var quarantineFilePath = Path.Combine(_quarantinePath, $"{entryId}.qtn");
                    var tempZipPath = Path.Combine(Path.GetTempPath(), $"{entryId}.zip");

                    try
                    {
                        // Compress directory
                        ZipFile.CreateFromDirectory(directoryPath, tempZipPath);

                        // Read, encrypt, and save
                        var zipContent = File.ReadAllBytes(tempZipPath);
                        var encryptedContent = EncryptData(zipContent);
                        File.WriteAllBytes(quarantineFilePath, encryptedContent);

                        var fileHash = ComputeFileHash(tempZipPath);

                        // Delete original directory
                        Directory.Delete(directoryPath, true);

                        var entry = new QuarantineEntry
                        {
                            Id = entryId,
                            OriginalPath = directoryPath,
                            FileName = dirInfo.Name,
                            FileSize = GetDirectorySize(dirInfo),
                            QuarantinedAt = DateTime.Now,
                            ThreatName = threatInfo?.Name ?? "Unknown Threat",
                            ThreatScore = threatInfo?.Score ?? 0,
                            Severity = threatInfo?.Severity.ToString() ?? "Unknown",
                            IsDirectory = true,
                            QuarantineFilePath = quarantineFilePath,
                            FileHash = fileHash
                        };

                        // Save to database
                        if (_db != null)
                        {
                            _db.AddQuarantineEntry(entry);
                        }

                        var message = $"Quarantined directory: {dirInfo.Name}";
                        RaiseLog(message);
                        _logger.Information("Directory quarantined: {Path}", directoryPath);
                        ItemQuarantined?.Invoke(this, entry);

                        return new QuarantineResult
                        {
                            Success = true,
                            Message = message,
                            Entry = entry
                        };
                    }
                    finally
                    {
                        // Clean up temp file
                        if (File.Exists(tempZipPath))
                            File.Delete(tempZipPath);
                    }
                }
                catch (Exception ex)
                {
                    _logger.Error(ex, "Failed to quarantine directory: {Path}", directoryPath);
                    return new QuarantineResult
                    {
                        Success = false,
                        Message = $"Error: {ex.Message}"
                    };
                }
            }
        }

        /// <summary>
        /// Restore a quarantined item to its original location
        /// </summary>
        public QuarantineResult RestoreItem(string entryId)
        {
            lock (_lock)
            {
                try
                {
                    var entries = GetAllEntries();
                    var entry = entries.FirstOrDefault(e => e.Id == entryId);
                    if (entry == null)
                    {
                        return new QuarantineResult
                        {
                            Success = false,
                            Message = "Entry not found in quarantine"
                        };
                    }

                    if (!File.Exists(entry.QuarantineFilePath))
                    {
                        return new QuarantineResult
                        {
                            Success = false,
                            Message = "Quarantine file not found"
                        };
                    }

                    // Read and decrypt
                    var encryptedContent = File.ReadAllBytes(entry.QuarantineFilePath);
                    var decryptedContent = DecryptData(encryptedContent);

                    // Ensure parent directory exists
                    var parentDir = Path.GetDirectoryName(entry.OriginalPath);
                    if (!string.IsNullOrEmpty(parentDir) && !Directory.Exists(parentDir))
                    {
                        Directory.CreateDirectory(parentDir);
                    }

                    if (entry.IsDirectory)
                    {
                        // Extract directory
                        var tempZipPath = Path.Combine(Path.GetTempPath(), $"{entry.Id}_restore.zip");
                        try
                        {
                            File.WriteAllBytes(tempZipPath, decryptedContent);
                            ZipFile.ExtractToDirectory(tempZipPath, entry.OriginalPath);
                        }
                        finally
                        {
                            if (File.Exists(tempZipPath))
                                File.Delete(tempZipPath);
                        }
                    }
                    else
                    {
                        // Restore file
                        File.WriteAllBytes(entry.OriginalPath, decryptedContent);
                    }

                    // Clean up quarantine file
                    File.Delete(entry.QuarantineFilePath);

                    // Mark as restored in database
                    _db?.MarkQuarantineRestored(entry.Id);

                    var message = $"Restored: {entry.FileName} to {entry.OriginalPath}";
                    RaiseLog(message);
                    _logger.Information("Item restored from quarantine: {Path}", entry.OriginalPath);
                    ItemRestored?.Invoke(this, entry);

                    return new QuarantineResult
                    {
                        Success = true,
                        Message = message,
                        Entry = entry
                    };
                }
                catch (Exception ex)
                {
                    _logger.Error(ex, "Failed to restore quarantine item: {Id}", entryId);
                    return new QuarantineResult
                    {
                        Success = false,
                        Message = $"Error: {ex.Message}"
                    };
                }
            }
        }

        /// <summary>
        /// Permanently delete a quarantined item
        /// </summary>
        public QuarantineResult DeletePermanently(string entryId)
        {
            lock (_lock)
            {
                try
                {
                    var entries = GetAllEntries();
                    var entry = entries.FirstOrDefault(e => e.Id == entryId);
                    if (entry == null)
                    {
                        return new QuarantineResult
                        {
                            Success = false,
                            Message = "Entry not found"
                        };
                    }

                    if (File.Exists(entry.QuarantineFilePath))
                    {
                        File.Delete(entry.QuarantineFilePath);
                    }

                    // Mark as deleted in database
                    _db?.MarkQuarantineDeleted(entry.Id);

                    var message = $"Permanently deleted: {entry.FileName}";
                    RaiseLog(message);
                    _logger.Information("Quarantine item permanently deleted: {Path}", entry.OriginalPath);

                    return new QuarantineResult
                    {
                        Success = true,
                        Message = message
                    };
                }
                catch (Exception ex)
                {
                    _logger.Error(ex, "Failed to delete quarantine item: {Id}", entryId);
                    return new QuarantineResult
                    {
                        Success = false,
                        Message = $"Error: {ex.Message}"
                    };
                }
            }
        }

        /// <summary>
        /// Get all quarantine entries
        /// </summary>
        public IReadOnlyList<QuarantineEntry> GetAllEntries()
        {
            lock (_lock)
            {
                if (_db == null) return new List<QuarantineEntry>().AsReadOnly();

                return _db.GetQuarantineEntries().AsReadOnly();
            }
        }

        /// <summary>
        /// Get total quarantine size in bytes
        /// </summary>
        public long GetTotalQuarantineSize()
        {
            try
            {
                var dirInfo = new DirectoryInfo(_quarantinePath);
                return dirInfo.GetFiles("*.qtn").Sum(f => f.Length);
            }
            catch
            {
                return 0;
            }
        }

        /// <summary>
        /// Clean up old quarantine entries based on retention policy
        /// </summary>
        public int CleanupOldEntries(int retentionDays)
        {
            if (retentionDays < 0) return 0; // -1 means never delete

            lock (_lock)
            {
                var cutoffDate = DateTime.Now.AddDays(-retentionDays);
                var entries = GetAllEntries();
                var oldEntries = entries.Where(e => e.QuarantinedAt < cutoffDate).ToList();
                var deletedCount = 0;

                foreach (var entry in oldEntries)
                {
                    try
                    {
                        if (File.Exists(entry.QuarantineFilePath))
                        {
                            File.Delete(entry.QuarantineFilePath);
                        }
                        _db?.MarkQuarantineDeleted(entry.Id);
                        deletedCount++;
                    }
                    catch (Exception ex)
                    {
                        _logger.Error(ex, "Failed to cleanup quarantine entry: {Id}", entry.Id);
                    }
                }

                if (deletedCount > 0)
                {
                    _logger.Information("Cleaned up {Count} old quarantine entries", deletedCount);
                }

                return deletedCount;
            }
        }

        private static byte[] DeriveKey()
        {
            // Derive a key from machine-specific information
            var machineInfo = Environment.MachineName + Environment.UserName + "SkidrowKillerQuarantine";
            using var sha256 = SHA256.Create();
            return sha256.ComputeHash(Encoding.UTF8.GetBytes(machineInfo));
        }

        private static byte[] EncryptData(byte[] data)
        {
            using var aes = Aes.Create();
            aes.Key = EncryptionKey;
            aes.GenerateIV();

            using var ms = new MemoryStream();
            // Write IV first
            ms.Write(aes.IV, 0, aes.IV.Length);

            using (var encryptor = aes.CreateEncryptor())
            using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
            {
                cs.Write(data, 0, data.Length);
            }

            return ms.ToArray();
        }

        private static byte[] DecryptData(byte[] encryptedData)
        {
            using var aes = Aes.Create();
            aes.Key = EncryptionKey;

            // Read IV from beginning
            var iv = new byte[16];
            Array.Copy(encryptedData, 0, iv, 0, 16);
            aes.IV = iv;

            using var ms = new MemoryStream();
            using (var decryptor = aes.CreateDecryptor())
            using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Write))
            {
                cs.Write(encryptedData, 16, encryptedData.Length - 16);
            }

            return ms.ToArray();
        }

        private static string ComputeFileHash(string filePath)
        {
            using var sha256 = SHA256.Create();
            using var stream = File.OpenRead(filePath);
            var hash = sha256.ComputeHash(stream);
            return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
        }

        private static long GetDirectorySize(DirectoryInfo dir)
        {
            try
            {
                return dir.GetFiles("*", SearchOption.AllDirectories).Sum(f => f.Length);
            }
            catch
            {
                return 0;
            }
        }

        private void RaiseLog(string message)
        {
            LogAdded?.Invoke(this, $"🔒 [QUARANTINE] {message}");
        }
    }

    /// <summary>
    /// Quarantine entry record
    /// </summary>
    public class QuarantineEntry
    {
        public string Id { get; set; } = "";
        public string OriginalPath { get; set; } = "";
        public string FileName { get; set; } = "";
        public long FileSize { get; set; }
        public DateTime QuarantinedAt { get; set; }
        public string ThreatName { get; set; } = "";
        public int ThreatScore { get; set; }
        public string Severity { get; set; } = "";
        public string QuarantineFilePath { get; set; } = "";
        public string FileHash { get; set; } = "";
        public bool IsDirectory { get; set; }
    }

    /// <summary>
    /// Result of a quarantine operation
    /// </summary>
    public class QuarantineResult
    {
        public bool Success { get; set; }
        public string Message { get; set; } = "";
        public QuarantineEntry? Entry { get; set; }
    }
}
