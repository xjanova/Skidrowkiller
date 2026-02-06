using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using Serilog;

namespace SkidrowKiller.Services;

/// <summary>
/// SQLite-based settings storage for all application settings
/// Replaces JSON file-based storage with a single database file
/// </summary>
public class SettingsDatabase : IDisposable
{
    private readonly ILogger _logger;
    private readonly string _databasePath;
    private readonly string _connectionString;
    private bool _disposed;

    public SettingsDatabase()
    {
        _logger = LoggingService.ForContext<SettingsDatabase>();

        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var dataFolder = Path.Combine(localAppData, "SkidrowKiller");

        if (!Directory.Exists(dataFolder))
        {
            Directory.CreateDirectory(dataFolder);
        }

        _databasePath = Path.Combine(dataFolder, "settings.db");
        _connectionString = $"Data Source={_databasePath}";

        InitializeDatabase();
        MigrateFromJsonIfNeeded();
    }

    #region Database Initialization

    private void InitializeDatabase()
    {
        try
        {
            using var connection = new SqliteConnection(_connectionString);
            connection.Open();

            // Create settings table (key-value store)
            var createSettingsTable = @"
                CREATE TABLE IF NOT EXISTS Settings (
                    Key TEXT PRIMARY KEY NOT NULL,
                    Value TEXT,
                    Category TEXT DEFAULT 'general',
                    UpdatedAt TEXT DEFAULT CURRENT_TIMESTAMP
                )";

            // Create scan history table
            var createScanHistoryTable = @"
                CREATE TABLE IF NOT EXISTS ScanHistory (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ScanType TEXT NOT NULL,
                    StartTime TEXT NOT NULL,
                    EndTime TEXT,
                    ItemsScanned INTEGER DEFAULT 0,
                    ThreatsFound INTEGER DEFAULT 0,
                    ThreatsRemoved INTEGER DEFAULT 0,
                    Status TEXT DEFAULT 'running'
                )";

            // Create threat log table
            var createThreatLogTable = @"
                CREATE TABLE IF NOT EXISTS ThreatLog (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT,
                    DetectedAt TEXT NOT NULL,
                    ThreatName TEXT NOT NULL,
                    ThreatPath TEXT NOT NULL,
                    Category TEXT,
                    Score INTEGER,
                    Action TEXT,
                    ScanId INTEGER,
                    FOREIGN KEY (ScanId) REFERENCES ScanHistory(Id)
                )";

            // Create quarantine history table
            var createQuarantineTable = @"
                CREATE TABLE IF NOT EXISTS QuarantineHistory (
                    Id TEXT PRIMARY KEY NOT NULL,
                    OriginalPath TEXT NOT NULL,
                    QuarantinedAt TEXT NOT NULL,
                    RestoredAt TEXT,
                    DeletedAt TEXT,
                    ThreatName TEXT,
                    Hash TEXT,
                    FileName TEXT,
                    FileSize INTEGER,
                    ThreatScore INTEGER,
                    Severity TEXT,
                    QuarantineFilePath TEXT,
                    IsDirectory INTEGER DEFAULT 0
                )";

            // Create license info table
            var createLicenseTable = @"
                CREATE TABLE IF NOT EXISTS LicenseInfo (
                    Id INTEGER PRIMARY KEY CHECK (Id = 1),
                    LicenseKey TEXT,
                    Tier TEXT DEFAULT 'Free',
                    IsTrial INTEGER DEFAULT 0,
                    TrialStartDate TEXT,
                    ActivatedAt TEXT,
                    ExpiresAt TEXT,
                    DeviceId TEXT,
                    LastValidated TEXT
                )";

            // Create protection status table
            var createProtectionTable = @"
                CREATE TABLE IF NOT EXISTS ProtectionStatus (
                    Service TEXT PRIMARY KEY NOT NULL,
                    IsEnabled INTEGER DEFAULT 0,
                    LastStateChange TEXT,
                    Configuration TEXT
                )";

            // Create whitelist table
            var createWhitelistTable = @"
                CREATE TABLE IF NOT EXISTS Whitelist (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT,
                    Path TEXT NOT NULL UNIQUE,
                    IsPattern INTEGER DEFAULT 0,
                    Reason TEXT,
                    AddedAt TEXT NOT NULL,
                    AddedBy TEXT DEFAULT 'user'
                )";

            // Create backup records table
            var createBackupTable = @"
                CREATE TABLE IF NOT EXISTS BackupRecords (
                    Id TEXT PRIMARY KEY NOT NULL,
                    OriginalPath TEXT NOT NULL,
                    BackupPath TEXT,
                    Name TEXT,
                    BackupDate TEXT NOT NULL,
                    FileSize INTEGER,
                    IsDirectory INTEGER DEFAULT 0,
                    RegistryKey TEXT,
                    RegistryValue TEXT,
                    RegistryData TEXT,
                    RegistryKind INTEGER,
                    IsRestored INTEGER DEFAULT 0,
                    RestoredAt TEXT
                )";

            // Create scheduled scans table
            var createScheduledScansTable = @"
                CREATE TABLE IF NOT EXISTS ScheduledScans (
                    Id TEXT PRIMARY KEY NOT NULL,
                    Name TEXT NOT NULL,
                    ScanType TEXT NOT NULL,
                    Schedule TEXT NOT NULL,
                    LastRun TEXT,
                    NextRun TEXT,
                    IsEnabled INTEGER DEFAULT 1,
                    Drives TEXT,
                    CreatedAt TEXT NOT NULL
                )";

            // Create ransomware protected folders table
            var createProtectedFoldersTable = @"
                CREATE TABLE IF NOT EXISTS ProtectedFolders (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT,
                    FolderPath TEXT NOT NULL UNIQUE,
                    AddedAt TEXT NOT NULL,
                    IsEnabled INTEGER DEFAULT 1
                )";

            // Create app statistics table
            var createStatsTable = @"
                CREATE TABLE IF NOT EXISTS AppStatistics (
                    Key TEXT PRIMARY KEY NOT NULL,
                    Value INTEGER DEFAULT 0,
                    LastUpdated TEXT
                )";

            using var cmd = connection.CreateCommand();
            cmd.CommandText = createSettingsTable;
            cmd.ExecuteNonQuery();

            cmd.CommandText = createScanHistoryTable;
            cmd.ExecuteNonQuery();

            cmd.CommandText = createThreatLogTable;
            cmd.ExecuteNonQuery();

            cmd.CommandText = createQuarantineTable;
            cmd.ExecuteNonQuery();

            cmd.CommandText = createLicenseTable;
            cmd.ExecuteNonQuery();

            cmd.CommandText = createProtectionTable;
            cmd.ExecuteNonQuery();

            cmd.CommandText = createWhitelistTable;
            cmd.ExecuteNonQuery();

            cmd.CommandText = createBackupTable;
            cmd.ExecuteNonQuery();

            cmd.CommandText = createScheduledScansTable;
            cmd.ExecuteNonQuery();

            cmd.CommandText = createProtectedFoldersTable;
            cmd.ExecuteNonQuery();

            cmd.CommandText = createStatsTable;
            cmd.ExecuteNonQuery();

            _logger.Information("Settings database initialized at {Path}", _databasePath);
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Failed to initialize settings database");
            throw;
        }
    }

    #endregion

    #region Settings CRUD

    /// <summary>
    /// Get a setting value by key
    /// </summary>
    public string? GetSetting(string key, string? defaultValue = null)
    {
        try
        {
            using var connection = new SqliteConnection(_connectionString);
            connection.Open();

            using var cmd = connection.CreateCommand();
            cmd.CommandText = "SELECT Value FROM Settings WHERE Key = @key";
            cmd.Parameters.AddWithValue("@key", key);

            var result = cmd.ExecuteScalar();
            return result?.ToString() ?? defaultValue;
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Failed to get setting {Key}", key);
            return defaultValue;
        }
    }

    /// <summary>
    /// Get a setting as a specific type
    /// </summary>
    public T GetSetting<T>(string key, T defaultValue)
    {
        var value = GetSetting(key);
        if (string.IsNullOrEmpty(value))
            return defaultValue;

        try
        {
            if (typeof(T) == typeof(bool))
                return (T)(object)(value == "1" || value.Equals("true", StringComparison.OrdinalIgnoreCase));

            if (typeof(T) == typeof(int))
                return (T)(object)int.Parse(value);

            if (typeof(T) == typeof(double))
                return (T)(object)double.Parse(value);

            if (typeof(T) == typeof(DateTime))
                return (T)(object)DateTime.Parse(value);

            return (T)(object)value;
        }
        catch
        {
            return defaultValue;
        }
    }

    /// <summary>
    /// Set a setting value
    /// </summary>
    public void SetSetting(string key, object? value, string category = "general")
    {
        try
        {
            using var connection = new SqliteConnection(_connectionString);
            connection.Open();

            using var cmd = connection.CreateCommand();
            cmd.CommandText = @"
                INSERT INTO Settings (Key, Value, Category, UpdatedAt)
                VALUES (@key, @value, @category, @updated)
                ON CONFLICT(Key) DO UPDATE SET
                    Value = @value,
                    Category = @category,
                    UpdatedAt = @updated";

            string? stringValue = value switch
            {
                null => null,
                bool b => b ? "1" : "0",
                DateTime dt => dt.ToString("O"),
                _ => value.ToString()
            };

            cmd.Parameters.AddWithValue("@key", key);
            cmd.Parameters.AddWithValue("@value", stringValue ?? (object)DBNull.Value);
            cmd.Parameters.AddWithValue("@category", category);
            cmd.Parameters.AddWithValue("@updated", DateTime.Now.ToString("O"));

            cmd.ExecuteNonQuery();
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Failed to set setting {Key}", key);
        }
    }

    /// <summary>
    /// Get all settings in a category
    /// </summary>
    public Dictionary<string, string?> GetSettingsByCategory(string category)
    {
        var settings = new Dictionary<string, string?>();

        try
        {
            using var connection = new SqliteConnection(_connectionString);
            connection.Open();

            using var cmd = connection.CreateCommand();
            cmd.CommandText = "SELECT Key, Value FROM Settings WHERE Category = @category";
            cmd.Parameters.AddWithValue("@category", category);

            using var reader = cmd.ExecuteReader();
            while (reader.Read())
            {
                settings[reader.GetString(0)] = reader.IsDBNull(1) ? null : reader.GetString(1);
            }
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Failed to get settings for category {Category}", category);
        }

        return settings;
    }

    /// <summary>
    /// Delete a setting
    /// </summary>
    public void DeleteSetting(string key)
    {
        try
        {
            using var connection = new SqliteConnection(_connectionString);
            connection.Open();

            using var cmd = connection.CreateCommand();
            cmd.CommandText = "DELETE FROM Settings WHERE Key = @key";
            cmd.Parameters.AddWithValue("@key", key);
            cmd.ExecuteNonQuery();
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Failed to delete setting {Key}", key);
        }
    }

    #endregion

    #region Scan History

    /// <summary>
    /// Start a new scan and return its ID
    /// </summary>
    public long StartScan(string scanType)
    {
        try
        {
            using var connection = new SqliteConnection(_connectionString);
            connection.Open();

            using var cmd = connection.CreateCommand();
            cmd.CommandText = @"
                INSERT INTO ScanHistory (ScanType, StartTime, Status)
                VALUES (@type, @start, 'running');
                SELECT last_insert_rowid();";

            cmd.Parameters.AddWithValue("@type", scanType);
            cmd.Parameters.AddWithValue("@start", DateTime.Now.ToString("O"));

            return (long)cmd.ExecuteScalar()!;
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Failed to start scan record");
            return -1;
        }
    }

    /// <summary>
    /// Complete a scan with results
    /// </summary>
    public void CompleteScan(long scanId, int itemsScanned, int threatsFound, int threatsRemoved, string status = "completed")
    {
        try
        {
            using var connection = new SqliteConnection(_connectionString);
            connection.Open();

            using var cmd = connection.CreateCommand();
            cmd.CommandText = @"
                UPDATE ScanHistory SET
                    EndTime = @end,
                    ItemsScanned = @items,
                    ThreatsFound = @found,
                    ThreatsRemoved = @removed,
                    Status = @status
                WHERE Id = @id";

            cmd.Parameters.AddWithValue("@id", scanId);
            cmd.Parameters.AddWithValue("@end", DateTime.Now.ToString("O"));
            cmd.Parameters.AddWithValue("@items", itemsScanned);
            cmd.Parameters.AddWithValue("@found", threatsFound);
            cmd.Parameters.AddWithValue("@removed", threatsRemoved);
            cmd.Parameters.AddWithValue("@status", status);

            cmd.ExecuteNonQuery();
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Failed to complete scan record {ScanId}", scanId);
        }
    }

    /// <summary>
    /// Get recent scan history
    /// </summary>
    public List<ScanHistoryRecord> GetRecentScans(int limit = 10)
    {
        var scans = new List<ScanHistoryRecord>();

        try
        {
            using var connection = new SqliteConnection(_connectionString);
            connection.Open();

            using var cmd = connection.CreateCommand();
            cmd.CommandText = @"
                SELECT Id, ScanType, StartTime, EndTime, ItemsScanned, ThreatsFound, ThreatsRemoved, Status
                FROM ScanHistory
                ORDER BY StartTime DESC
                LIMIT @limit";

            cmd.Parameters.AddWithValue("@limit", limit);

            using var reader = cmd.ExecuteReader();
            while (reader.Read())
            {
                scans.Add(new ScanHistoryRecord
                {
                    Id = reader.GetInt64(0),
                    ScanType = reader.GetString(1),
                    StartTime = DateTime.Parse(reader.GetString(2)),
                    EndTime = reader.IsDBNull(3) ? null : DateTime.Parse(reader.GetString(3)),
                    ItemsScanned = reader.GetInt32(4),
                    ThreatsFound = reader.GetInt32(5),
                    ThreatsRemoved = reader.GetInt32(6),
                    Status = reader.GetString(7)
                });
            }
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Failed to get recent scans");
        }

        return scans;
    }

    #endregion

    #region Threat Log

    /// <summary>
    /// Log a detected threat
    /// </summary>
    public void LogThreat(string threatName, string threatPath, string category, int score, string action, long? scanId = null)
    {
        try
        {
            using var connection = new SqliteConnection(_connectionString);
            connection.Open();

            using var cmd = connection.CreateCommand();
            cmd.CommandText = @"
                INSERT INTO ThreatLog (DetectedAt, ThreatName, ThreatPath, Category, Score, Action, ScanId)
                VALUES (@detected, @name, @path, @category, @score, @action, @scanId)";

            cmd.Parameters.AddWithValue("@detected", DateTime.Now.ToString("O"));
            cmd.Parameters.AddWithValue("@name", threatName);
            cmd.Parameters.AddWithValue("@path", threatPath);
            cmd.Parameters.AddWithValue("@category", category);
            cmd.Parameters.AddWithValue("@score", score);
            cmd.Parameters.AddWithValue("@action", action);
            cmd.Parameters.AddWithValue("@scanId", scanId.HasValue ? scanId.Value : DBNull.Value);

            cmd.ExecuteNonQuery();
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Failed to log threat {ThreatName}", threatName);
        }
    }

    /// <summary>
    /// Get total threats detected
    /// </summary>
    public int GetTotalThreatsDetected()
    {
        try
        {
            using var connection = new SqliteConnection(_connectionString);
            connection.Open();

            using var cmd = connection.CreateCommand();
            cmd.CommandText = "SELECT COUNT(*) FROM ThreatLog";

            return Convert.ToInt32(cmd.ExecuteScalar());
        }
        catch
        {
            return 0;
        }
    }

    #endregion

    #region Protection Status

    /// <summary>
    /// Get protection service status
    /// </summary>
    public bool GetProtectionEnabled(string service, bool defaultValue = false)
    {
        try
        {
            using var connection = new SqliteConnection(_connectionString);
            connection.Open();

            using var cmd = connection.CreateCommand();
            cmd.CommandText = "SELECT IsEnabled FROM ProtectionStatus WHERE Service = @service";
            cmd.Parameters.AddWithValue("@service", service);

            var result = cmd.ExecuteScalar();
            return result != null && Convert.ToInt32(result) == 1;
        }
        catch
        {
            return defaultValue;
        }
    }

    /// <summary>
    /// Set protection service status
    /// </summary>
    public void SetProtectionEnabled(string service, bool enabled, string? configuration = null)
    {
        try
        {
            using var connection = new SqliteConnection(_connectionString);
            connection.Open();

            using var cmd = connection.CreateCommand();
            cmd.CommandText = @"
                INSERT INTO ProtectionStatus (Service, IsEnabled, LastStateChange, Configuration)
                VALUES (@service, @enabled, @changed, @config)
                ON CONFLICT(Service) DO UPDATE SET
                    IsEnabled = @enabled,
                    LastStateChange = @changed,
                    Configuration = COALESCE(@config, Configuration)";

            cmd.Parameters.AddWithValue("@service", service);
            cmd.Parameters.AddWithValue("@enabled", enabled ? 1 : 0);
            cmd.Parameters.AddWithValue("@changed", DateTime.Now.ToString("O"));
            cmd.Parameters.AddWithValue("@config", configuration ?? (object)DBNull.Value);

            cmd.ExecuteNonQuery();
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Failed to set protection status for {Service}", service);
        }
    }

    #endregion

    #region Migration from JSON

    private void MigrateFromJsonIfNeeded()
    {
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var dataFolder = Path.Combine(localAppData, "SkidrowKiller");

        // Check if migration already done
        if (GetSetting("migration_completed") == "1")
            return;

        _logger.Information("Starting migration from JSON to SQLite...");

        try
        {
            // Migrate user_settings.json
            var userSettingsPath = Path.Combine(dataFolder, "user_settings.json");
            if (File.Exists(userSettingsPath))
            {
                var json = File.ReadAllText(userSettingsPath);
                var settings = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(json);

                if (settings != null)
                {
                    foreach (var kvp in settings)
                    {
                        var value = kvp.Value.ValueKind switch
                        {
                            JsonValueKind.True => "1",
                            JsonValueKind.False => "0",
                            JsonValueKind.Number => kvp.Value.GetRawText(),
                            JsonValueKind.String => kvp.Value.GetString(),
                            _ => kvp.Value.GetRawText()
                        };
                        SetSetting(kvp.Key, value, "user");
                    }
                    _logger.Information("Migrated user settings from JSON");
                }

                // Rename old file
                File.Move(userSettingsPath, userSettingsPath + ".migrated", true);
            }

            // Migrate license.json if exists
            var licensePath = Path.Combine(dataFolder, "license.json");
            if (File.Exists(licensePath))
            {
                var json = File.ReadAllText(licensePath);
                SetSetting("license_data", json, "license");
                _logger.Information("Migrated license data from JSON");
                File.Move(licensePath, licensePath + ".migrated", true);
            }

            // Mark migration as complete
            SetSetting("migration_completed", "1", "system");
            SetSetting("migration_date", DateTime.Now.ToString("O"), "system");

            _logger.Information("Migration from JSON to SQLite completed");
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Failed to migrate from JSON to SQLite");
        }
    }

    #endregion

    #region Whitelist

    /// <summary>
    /// Add path to whitelist
    /// </summary>
    public void AddToWhitelist(string path, string? reason = null, bool isPattern = false)
    {
        try
        {
            using var connection = new SqliteConnection(_connectionString);
            connection.Open();

            using var cmd = connection.CreateCommand();
            cmd.CommandText = @"
                INSERT OR REPLACE INTO Whitelist (Path, IsPattern, Reason, AddedAt, AddedBy)
                VALUES (@path, @isPattern, @reason, @added, 'user')";

            cmd.Parameters.AddWithValue("@path", path);
            cmd.Parameters.AddWithValue("@isPattern", isPattern ? 1 : 0);
            cmd.Parameters.AddWithValue("@reason", reason ?? (object)DBNull.Value);
            cmd.Parameters.AddWithValue("@added", DateTime.Now.ToString("O"));

            cmd.ExecuteNonQuery();
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Failed to add {Path} to whitelist", path);
        }
    }

    /// <summary>
    /// Remove path from whitelist
    /// </summary>
    public void RemoveFromWhitelist(string path)
    {
        try
        {
            using var connection = new SqliteConnection(_connectionString);
            connection.Open();

            using var cmd = connection.CreateCommand();
            cmd.CommandText = "DELETE FROM Whitelist WHERE Path = @path";
            cmd.Parameters.AddWithValue("@path", path);
            cmd.ExecuteNonQuery();
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Failed to remove {Path} from whitelist", path);
        }
    }

    /// <summary>
    /// Remove whitelist entry by ID
    /// </summary>
    public void RemoveFromWhitelistById(long id)
    {
        try
        {
            using var connection = new SqliteConnection(_connectionString);
            connection.Open();

            using var cmd = connection.CreateCommand();
            cmd.CommandText = "DELETE FROM Whitelist WHERE Id = @id";
            cmd.Parameters.AddWithValue("@id", id);
            cmd.ExecuteNonQuery();
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Failed to remove whitelist entry {Id}", id);
        }
    }

    /// <summary>
    /// Check if path is whitelisted
    /// </summary>
    public bool IsWhitelisted(string path)
    {
        try
        {
            using var connection = new SqliteConnection(_connectionString);
            connection.Open();

            using var cmd = connection.CreateCommand();
            cmd.CommandText = "SELECT COUNT(*) FROM Whitelist WHERE Path = @path OR (@path LIKE Path AND IsPattern = 1)";
            cmd.Parameters.AddWithValue("@path", path);

            return Convert.ToInt32(cmd.ExecuteScalar()) > 0;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Get all whitelist entries
    /// </summary>
    public List<WhitelistRecord> GetWhitelist()
    {
        var entries = new List<WhitelistRecord>();

        try
        {
            using var connection = new SqliteConnection(_connectionString);
            connection.Open();

            using var cmd = connection.CreateCommand();
            cmd.CommandText = "SELECT Id, Path, IsPattern, Reason, AddedAt FROM Whitelist ORDER BY AddedAt DESC";

            using var reader = cmd.ExecuteReader();
            while (reader.Read())
            {
                entries.Add(new WhitelistRecord
                {
                    Id = reader.GetInt64(0),
                    Path = reader.GetString(1),
                    IsPattern = reader.GetInt32(2) == 1,
                    Reason = reader.IsDBNull(3) ? null : reader.GetString(3),
                    AddedAt = DateTime.Parse(reader.GetString(4))
                });
            }
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Failed to get whitelist");
        }

        return entries;
    }

    #endregion

    #region Backup Records

    /// <summary>
    /// Add backup entry (full details)
    /// </summary>
    public void AddBackupEntry(BackupEntry entry)
    {
        try
        {
            using var connection = new SqliteConnection(_connectionString);
            connection.Open();

            using var cmd = connection.CreateCommand();
            cmd.CommandText = @"
                INSERT INTO BackupRecords (Id, OriginalPath, BackupPath, Name, BackupDate, FileSize, IsDirectory, RegistryKey, RegistryValue, RegistryData, RegistryKind)
                VALUES (@id, @original, @backup, @name, @date, @size, @isDir, @regKey, @regValue, @regData, @regKind)";

            cmd.Parameters.AddWithValue("@id", entry.Id);
            cmd.Parameters.AddWithValue("@original", entry.OriginalPath);
            cmd.Parameters.AddWithValue("@backup", entry.BackupPath ?? (object)DBNull.Value);
            cmd.Parameters.AddWithValue("@name", entry.Name);
            cmd.Parameters.AddWithValue("@date", entry.BackedUpAt.ToString("O"));
            cmd.Parameters.AddWithValue("@size", entry.Size);
            cmd.Parameters.AddWithValue("@isDir", entry.IsDirectory ? 1 : 0);
            cmd.Parameters.AddWithValue("@regKey", entry.RegistryKey ?? (object)DBNull.Value);
            cmd.Parameters.AddWithValue("@regValue", entry.RegistryValue ?? (object)DBNull.Value);
            cmd.Parameters.AddWithValue("@regData", entry.RegistryData?.ToString() ?? (object)DBNull.Value);
            cmd.Parameters.AddWithValue("@regKind", entry.RegistryKind.HasValue ? (int)entry.RegistryKind.Value : DBNull.Value);

            cmd.ExecuteNonQuery();
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Failed to add backup entry");
        }
    }

    /// <summary>
    /// Mark backup as restored by string ID
    /// </summary>
    public void MarkBackupRestored(string id)
    {
        try
        {
            using var connection = new SqliteConnection(_connectionString);
            connection.Open();

            using var cmd = connection.CreateCommand();
            cmd.CommandText = "UPDATE BackupRecords SET IsRestored = 1, RestoredAt = @time WHERE Id = @id";
            cmd.Parameters.AddWithValue("@id", id);
            cmd.Parameters.AddWithValue("@time", DateTime.Now.ToString("O"));
            cmd.ExecuteNonQuery();
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Failed to mark backup {Id} as restored", id);
        }
    }

    /// <summary>
    /// Get all active backup entries (not restored)
    /// </summary>
    public List<BackupEntry> GetBackupEntries()
    {
        var entries = new List<BackupEntry>();

        try
        {
            using var connection = new SqliteConnection(_connectionString);
            connection.Open();

            using var cmd = connection.CreateCommand();
            cmd.CommandText = @"
                SELECT Id, OriginalPath, BackupPath, Name, BackupDate, FileSize, IsDirectory, RegistryKey, RegistryValue, RegistryData, RegistryKind
                FROM BackupRecords
                WHERE IsRestored = 0
                ORDER BY BackupDate DESC";

            using var reader = cmd.ExecuteReader();
            while (reader.Read())
            {
                var entry = new BackupEntry
                {
                    Id = reader.GetString(0),
                    OriginalPath = reader.GetString(1),
                    BackupPath = reader.IsDBNull(2) ? "" : reader.GetString(2),
                    Name = reader.IsDBNull(3) ? "" : reader.GetString(3),
                    BackedUpAt = DateTime.Parse(reader.GetString(4)),
                    Size = reader.IsDBNull(5) ? 0 : reader.GetInt64(5),
                    IsDirectory = !reader.IsDBNull(6) && reader.GetInt32(6) == 1,
                    RegistryKey = reader.IsDBNull(7) ? null : reader.GetString(7),
                    RegistryValue = reader.IsDBNull(8) ? null : reader.GetString(8)
                };

                // Parse registry data if present
                if (!reader.IsDBNull(9))
                {
                    entry.RegistryData = reader.GetString(9);
                }
                if (!reader.IsDBNull(10))
                {
                    entry.RegistryKind = (Microsoft.Win32.RegistryValueKind)reader.GetInt32(10);
                }

                entries.Add(entry);
            }
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Failed to get backup entries");
        }

        return entries;
    }

    /// <summary>
    /// Get all backup records (including restored)
    /// </summary>
    public List<BackupRecord> GetBackupRecords()
    {
        var records = new List<BackupRecord>();

        try
        {
            using var connection = new SqliteConnection(_connectionString);
            connection.Open();

            using var cmd = connection.CreateCommand();
            cmd.CommandText = @"
                SELECT Id, OriginalPath, BackupPath, BackupDate, FileSize, IsRestored, RestoredAt
                FROM BackupRecords
                ORDER BY BackupDate DESC";

            using var reader = cmd.ExecuteReader();
            while (reader.Read())
            {
                records.Add(new BackupRecord
                {
                    Id = reader.IsDBNull(0) ? 0 : long.TryParse(reader.GetString(0), out var id) ? id : 0,
                    OriginalPath = reader.GetString(1),
                    BackupPath = reader.IsDBNull(2) ? "" : reader.GetString(2),
                    BackupDate = DateTime.Parse(reader.GetString(3)),
                    FileSize = reader.IsDBNull(4) ? 0 : reader.GetInt64(4),
                    IsRestored = !reader.IsDBNull(5) && reader.GetInt32(5) == 1,
                    RestoredAt = reader.IsDBNull(6) ? null : DateTime.Parse(reader.GetString(6))
                });
            }
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Failed to get backup records");
        }

        return records;
    }

    /// <summary>
    /// Delete old backup records
    /// </summary>
    public int DeleteOldBackupRecords(int daysOld)
    {
        try
        {
            using var connection = new SqliteConnection(_connectionString);
            connection.Open();

            var cutoffDate = DateTime.Now.AddDays(-daysOld).ToString("O");

            using var cmd = connection.CreateCommand();
            cmd.CommandText = "DELETE FROM BackupRecords WHERE BackupDate < @cutoff";
            cmd.Parameters.AddWithValue("@cutoff", cutoffDate);

            return cmd.ExecuteNonQuery();
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Failed to delete old backup records");
            return 0;
        }
    }

    #endregion

    #region License

    /// <summary>
    /// Save license info
    /// </summary>
    public void SaveLicense(string? licenseKey, string tier, bool isTrial, DateTime? trialStartDate,
        DateTime? activatedAt, DateTime? expiresAt, string deviceId)
    {
        try
        {
            using var connection = new SqliteConnection(_connectionString);
            connection.Open();

            using var cmd = connection.CreateCommand();
            cmd.CommandText = @"
                INSERT INTO LicenseInfo (Id, LicenseKey, Tier, IsTrial, TrialStartDate, ActivatedAt, ExpiresAt, DeviceId, LastValidated)
                VALUES (1, @key, @tier, @trial, @trialStart, @activated, @expires, @device, @validated)
                ON CONFLICT(Id) DO UPDATE SET
                    LicenseKey = @key,
                    Tier = @tier,
                    IsTrial = @trial,
                    TrialStartDate = @trialStart,
                    ActivatedAt = @activated,
                    ExpiresAt = @expires,
                    DeviceId = @device,
                    LastValidated = @validated";

            cmd.Parameters.AddWithValue("@key", licenseKey ?? (object)DBNull.Value);
            cmd.Parameters.AddWithValue("@tier", tier);
            cmd.Parameters.AddWithValue("@trial", isTrial ? 1 : 0);
            cmd.Parameters.AddWithValue("@trialStart", trialStartDate?.ToString("O") ?? (object)DBNull.Value);
            cmd.Parameters.AddWithValue("@activated", activatedAt?.ToString("O") ?? (object)DBNull.Value);
            cmd.Parameters.AddWithValue("@expires", expiresAt?.ToString("O") ?? (object)DBNull.Value);
            cmd.Parameters.AddWithValue("@device", deviceId);
            cmd.Parameters.AddWithValue("@validated", DateTime.Now.ToString("O"));

            cmd.ExecuteNonQuery();
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Failed to save license info");
        }
    }

    /// <summary>
    /// Get license info
    /// </summary>
    public LicenseRecord? GetLicense()
    {
        try
        {
            using var connection = new SqliteConnection(_connectionString);
            connection.Open();

            using var cmd = connection.CreateCommand();
            cmd.CommandText = "SELECT LicenseKey, Tier, IsTrial, TrialStartDate, ActivatedAt, ExpiresAt, DeviceId, LastValidated FROM LicenseInfo WHERE Id = 1";

            using var reader = cmd.ExecuteReader();
            if (reader.Read())
            {
                return new LicenseRecord
                {
                    LicenseKey = reader.IsDBNull(0) ? null : reader.GetString(0),
                    Tier = reader.GetString(1),
                    IsTrial = reader.GetInt32(2) == 1,
                    TrialStartDate = reader.IsDBNull(3) ? null : DateTime.Parse(reader.GetString(3)),
                    ActivatedAt = reader.IsDBNull(4) ? null : DateTime.Parse(reader.GetString(4)),
                    ExpiresAt = reader.IsDBNull(5) ? null : DateTime.Parse(reader.GetString(5)),
                    DeviceId = reader.IsDBNull(6) ? null : reader.GetString(6),
                    LastValidated = reader.IsDBNull(7) ? null : DateTime.Parse(reader.GetString(7))
                };
            }
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Failed to get license info");
        }

        return null;
    }

    #endregion

    #region Quarantine

    /// <summary>
    /// Add quarantine entry (full details)
    /// </summary>
    public void AddQuarantineEntry(QuarantineEntry entry)
    {
        try
        {
            using var connection = new SqliteConnection(_connectionString);
            connection.Open();

            using var cmd = connection.CreateCommand();
            cmd.CommandText = @"
                INSERT INTO QuarantineHistory (Id, OriginalPath, QuarantinedAt, ThreatName, Hash, FileName, FileSize, ThreatScore, Severity, QuarantineFilePath, IsDirectory)
                VALUES (@id, @path, @date, @threat, @hash, @fileName, @fileSize, @score, @severity, @qPath, @isDir)";

            cmd.Parameters.AddWithValue("@id", entry.Id);
            cmd.Parameters.AddWithValue("@path", entry.OriginalPath);
            cmd.Parameters.AddWithValue("@date", entry.QuarantinedAt.ToString("O"));
            cmd.Parameters.AddWithValue("@threat", entry.ThreatName ?? (object)DBNull.Value);
            cmd.Parameters.AddWithValue("@hash", entry.FileHash ?? (object)DBNull.Value);
            cmd.Parameters.AddWithValue("@fileName", entry.FileName);
            cmd.Parameters.AddWithValue("@fileSize", entry.FileSize);
            cmd.Parameters.AddWithValue("@score", entry.ThreatScore);
            cmd.Parameters.AddWithValue("@severity", entry.Severity);
            cmd.Parameters.AddWithValue("@qPath", entry.QuarantineFilePath);
            cmd.Parameters.AddWithValue("@isDir", entry.IsDirectory ? 1 : 0);

            cmd.ExecuteNonQuery();
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Failed to add quarantine entry");
        }
    }

    /// <summary>
    /// Mark quarantine item as restored by string ID
    /// </summary>
    public void MarkQuarantineRestored(string id)
    {
        try
        {
            using var connection = new SqliteConnection(_connectionString);
            connection.Open();

            using var cmd = connection.CreateCommand();
            cmd.CommandText = "UPDATE QuarantineHistory SET RestoredAt = @time WHERE Id = @id";
            cmd.Parameters.AddWithValue("@id", id);
            cmd.Parameters.AddWithValue("@time", DateTime.Now.ToString("O"));
            cmd.ExecuteNonQuery();
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Failed to mark quarantine {Id} as restored", id);
        }
    }

    /// <summary>
    /// Mark quarantine item as deleted by string ID
    /// </summary>
    public void MarkQuarantineDeleted(string id)
    {
        try
        {
            using var connection = new SqliteConnection(_connectionString);
            connection.Open();

            using var cmd = connection.CreateCommand();
            cmd.CommandText = "UPDATE QuarantineHistory SET DeletedAt = @time WHERE Id = @id";
            cmd.Parameters.AddWithValue("@id", id);
            cmd.Parameters.AddWithValue("@time", DateTime.Now.ToString("O"));
            cmd.ExecuteNonQuery();
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Failed to mark quarantine {Id} as deleted", id);
        }
    }

    /// <summary>
    /// Get all active quarantine entries (not restored or deleted)
    /// </summary>
    public List<QuarantineEntry> GetQuarantineEntries()
    {
        var entries = new List<QuarantineEntry>();

        try
        {
            using var connection = new SqliteConnection(_connectionString);
            connection.Open();

            using var cmd = connection.CreateCommand();
            cmd.CommandText = @"
                SELECT Id, OriginalPath, QuarantinedAt, ThreatName, Hash, FileName, FileSize, ThreatScore, Severity, QuarantineFilePath, IsDirectory
                FROM QuarantineHistory
                WHERE RestoredAt IS NULL AND DeletedAt IS NULL
                ORDER BY QuarantinedAt DESC";

            using var reader = cmd.ExecuteReader();
            while (reader.Read())
            {
                entries.Add(new QuarantineEntry
                {
                    Id = reader.GetString(0),
                    OriginalPath = reader.GetString(1),
                    QuarantinedAt = DateTime.Parse(reader.GetString(2)),
                    ThreatName = reader.IsDBNull(3) ? "" : reader.GetString(3),
                    FileHash = reader.IsDBNull(4) ? "" : reader.GetString(4),
                    FileName = reader.IsDBNull(5) ? "" : reader.GetString(5),
                    FileSize = reader.IsDBNull(6) ? 0 : reader.GetInt64(6),
                    ThreatScore = reader.IsDBNull(7) ? 0 : reader.GetInt32(7),
                    Severity = reader.IsDBNull(8) ? "" : reader.GetString(8),
                    QuarantineFilePath = reader.IsDBNull(9) ? "" : reader.GetString(9),
                    IsDirectory = !reader.IsDBNull(10) && reader.GetInt32(10) == 1
                });
            }
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Failed to get quarantine entries");
        }

        return entries;
    }

    /// <summary>
    /// Get quarantine history (including restored/deleted)
    /// </summary>
    public List<QuarantineRecord> GetQuarantineHistory()
    {
        var records = new List<QuarantineRecord>();

        try
        {
            using var connection = new SqliteConnection(_connectionString);
            connection.Open();

            using var cmd = connection.CreateCommand();
            cmd.CommandText = @"
                SELECT Id, OriginalPath, QuarantinedAt, RestoredAt, DeletedAt, ThreatName, Hash
                FROM QuarantineHistory
                ORDER BY QuarantinedAt DESC";

            using var reader = cmd.ExecuteReader();
            while (reader.Read())
            {
                records.Add(new QuarantineRecord
                {
                    Id = reader.IsDBNull(0) ? 0 : (reader.GetFieldType(0) == typeof(long) ? reader.GetInt64(0) : long.Parse(reader.GetString(0))),
                    OriginalPath = reader.GetString(1),
                    QuarantinedAt = DateTime.Parse(reader.GetString(2)),
                    RestoredAt = reader.IsDBNull(3) ? null : DateTime.Parse(reader.GetString(3)),
                    DeletedAt = reader.IsDBNull(4) ? null : DateTime.Parse(reader.GetString(4)),
                    ThreatName = reader.IsDBNull(5) ? null : reader.GetString(5),
                    Hash = reader.IsDBNull(6) ? null : reader.GetString(6)
                });
            }
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Failed to get quarantine history");
        }

        return records;
    }

    #endregion

    #region Scheduled Scans

    /// <summary>
    /// Save or update a scheduled scan
    /// </summary>
    public void SaveScheduledScan(ScanSchedule schedule)
    {
        try
        {
            using var connection = new SqliteConnection(_connectionString);
            connection.Open();

            using var cmd = connection.CreateCommand();
            cmd.CommandText = @"
                INSERT INTO ScheduledScans (Id, Name, ScanType, Schedule, LastRun, NextRun, IsEnabled, Drives, CreatedAt)
                VALUES (@id, @name, @scanType, @schedule, @lastRun, @nextRun, @enabled, @drives, @created)
                ON CONFLICT(Id) DO UPDATE SET
                    Name = @name,
                    ScanType = @scanType,
                    Schedule = @schedule,
                    LastRun = @lastRun,
                    NextRun = @nextRun,
                    IsEnabled = @enabled,
                    Drives = @drives";

            // Serialize schedule details
            var scheduleJson = System.Text.Json.JsonSerializer.Serialize(new
            {
                schedule.Frequency,
                schedule.Hour,
                schedule.Minute,
                schedule.DaysOfWeek,
                schedule.DayOfMonth,
                schedule.ScheduledDate,
                schedule.CustomPaths
            });

            cmd.Parameters.AddWithValue("@id", schedule.Id);
            cmd.Parameters.AddWithValue("@name", schedule.Name);
            cmd.Parameters.AddWithValue("@scanType", schedule.ScanType.ToString());
            cmd.Parameters.AddWithValue("@schedule", scheduleJson);
            cmd.Parameters.AddWithValue("@lastRun", schedule.LastRun == DateTime.MinValue ? DBNull.Value : schedule.LastRun.ToString("O"));
            cmd.Parameters.AddWithValue("@nextRun", DBNull.Value);
            cmd.Parameters.AddWithValue("@enabled", schedule.IsEnabled ? 1 : 0);
            cmd.Parameters.AddWithValue("@drives", string.Join(",", schedule.CustomPaths ?? new List<string>()));
            cmd.Parameters.AddWithValue("@created", DateTime.Now.ToString("O"));

            cmd.ExecuteNonQuery();
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Failed to save scheduled scan: {Name}", schedule.Name);
        }
    }

    /// <summary>
    /// Get all scheduled scans
    /// </summary>
    public List<ScanSchedule> GetScheduledScans()
    {
        var schedules = new List<ScanSchedule>();

        try
        {
            using var connection = new SqliteConnection(_connectionString);
            connection.Open();

            using var cmd = connection.CreateCommand();
            cmd.CommandText = "SELECT Id, Name, ScanType, Schedule, LastRun, IsEnabled FROM ScheduledScans";

            using var reader = cmd.ExecuteReader();
            while (reader.Read())
            {
                var schedule = new ScanSchedule
                {
                    Id = reader.GetString(0),
                    Name = reader.GetString(1),
                    ScanType = Enum.TryParse<ScheduledScanType>(reader.GetString(2), out var st) ? st : ScheduledScanType.Quick,
                    IsEnabled = reader.GetInt32(5) == 1
                };

                // Parse schedule JSON
                if (!reader.IsDBNull(3))
                {
                    try
                    {
                        var scheduleJson = reader.GetString(3);
                        var doc = System.Text.Json.JsonDocument.Parse(scheduleJson);
                        var root = doc.RootElement;

                        if (root.TryGetProperty("Frequency", out var freq))
                            schedule.Frequency = Enum.TryParse<ScanFrequency>(freq.GetString(), out var f) ? f : ScanFrequency.Daily;
                        if (root.TryGetProperty("Hour", out var hour))
                            schedule.Hour = hour.GetInt32();
                        if (root.TryGetProperty("Minute", out var minute))
                            schedule.Minute = minute.GetInt32();
                        if (root.TryGetProperty("DayOfMonth", out var dom))
                            schedule.DayOfMonth = dom.GetInt32();
                        if (root.TryGetProperty("DaysOfWeek", out var dow))
                        {
                            schedule.DaysOfWeek = new List<DayOfWeek>();
                            foreach (var d in dow.EnumerateArray())
                            {
                                if (Enum.TryParse<DayOfWeek>(d.GetString(), out var day))
                                    schedule.DaysOfWeek.Add(day);
                            }
                        }
                    }
                    catch { }
                }

                if (!reader.IsDBNull(4))
                    schedule.LastRun = DateTime.Parse(reader.GetString(4));

                schedules.Add(schedule);
            }
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Failed to get scheduled scans");
        }

        return schedules;
    }

    /// <summary>
    /// Delete a scheduled scan
    /// </summary>
    public void DeleteScheduledScan(string scheduleId)
    {
        try
        {
            using var connection = new SqliteConnection(_connectionString);
            connection.Open();

            using var cmd = connection.CreateCommand();
            cmd.CommandText = "DELETE FROM ScheduledScans WHERE Id = @id";
            cmd.Parameters.AddWithValue("@id", scheduleId);

            cmd.ExecuteNonQuery();
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Failed to delete scheduled scan: {Id}", scheduleId);
        }
    }

    #endregion

    #region Protected Folders

    /// <summary>
    /// Add a protected folder (for ransomware protection)
    /// </summary>
    public void AddProtectedFolder(string folderPath)
    {
        try
        {
            using var connection = new SqliteConnection(_connectionString);
            connection.Open();

            using var cmd = connection.CreateCommand();
            cmd.CommandText = @"
                INSERT OR IGNORE INTO ProtectedFolders (FolderPath, AddedAt, IsEnabled)
                VALUES (@path, @date, 1)";

            cmd.Parameters.AddWithValue("@path", folderPath);
            cmd.Parameters.AddWithValue("@date", DateTime.Now.ToString("O"));

            cmd.ExecuteNonQuery();
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Failed to add protected folder: {Path}", folderPath);
        }
    }

    /// <summary>
    /// Remove a protected folder
    /// </summary>
    public void RemoveProtectedFolder(string folderPath)
    {
        try
        {
            using var connection = new SqliteConnection(_connectionString);
            connection.Open();

            using var cmd = connection.CreateCommand();
            cmd.CommandText = "DELETE FROM ProtectedFolders WHERE FolderPath = @path";
            cmd.Parameters.AddWithValue("@path", folderPath);

            cmd.ExecuteNonQuery();
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Failed to remove protected folder: {Path}", folderPath);
        }
    }

    /// <summary>
    /// Get all protected folders
    /// </summary>
    public List<string> GetProtectedFolders()
    {
        var folders = new List<string>();

        try
        {
            using var connection = new SqliteConnection(_connectionString);
            connection.Open();

            using var cmd = connection.CreateCommand();
            cmd.CommandText = "SELECT FolderPath FROM ProtectedFolders WHERE IsEnabled = 1";

            using var reader = cmd.ExecuteReader();
            while (reader.Read())
            {
                folders.Add(reader.GetString(0));
            }
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Failed to get protected folders");
        }

        return folders;
    }

    #endregion

    #region App Statistics

    /// <summary>
    /// Increment a statistic counter
    /// </summary>
    public void IncrementStat(string key, int amount = 1)
    {
        try
        {
            using var connection = new SqliteConnection(_connectionString);
            connection.Open();

            using var cmd = connection.CreateCommand();
            cmd.CommandText = @"
                INSERT INTO AppStatistics (Key, Value, LastUpdated)
                VALUES (@key, @amount, @time)
                ON CONFLICT(Key) DO UPDATE SET
                    Value = Value + @amount,
                    LastUpdated = @time";

            cmd.Parameters.AddWithValue("@key", key);
            cmd.Parameters.AddWithValue("@amount", amount);
            cmd.Parameters.AddWithValue("@time", DateTime.Now.ToString("O"));

            cmd.ExecuteNonQuery();
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Failed to increment stat {Key}", key);
        }
    }

    /// <summary>
    /// Get a statistic value
    /// </summary>
    public long GetStat(string key)
    {
        try
        {
            using var connection = new SqliteConnection(_connectionString);
            connection.Open();

            using var cmd = connection.CreateCommand();
            cmd.CommandText = "SELECT Value FROM AppStatistics WHERE Key = @key";
            cmd.Parameters.AddWithValue("@key", key);

            var result = cmd.ExecuteScalar();
            return result != null ? Convert.ToInt64(result) : 0;
        }
        catch
        {
            return 0;
        }
    }

    #endregion

    #region Statistics

    /// <summary>
    /// Get database statistics
    /// </summary>
    public DatabaseStatistics GetStatistics()
    {
        var stats = new DatabaseStatistics();

        try
        {
            using var connection = new SqliteConnection(_connectionString);
            connection.Open();

            using var cmd = connection.CreateCommand();

            // Total scans
            cmd.CommandText = "SELECT COUNT(*) FROM ScanHistory";
            stats.TotalScans = Convert.ToInt32(cmd.ExecuteScalar());

            // Total threats
            cmd.CommandText = "SELECT COUNT(*) FROM ThreatLog";
            stats.TotalThreats = Convert.ToInt32(cmd.ExecuteScalar());

            // Last scan
            cmd.CommandText = "SELECT MAX(StartTime) FROM ScanHistory";
            var lastScan = cmd.ExecuteScalar();
            if (lastScan != DBNull.Value && lastScan != null)
            {
                var lastScanStr = lastScan.ToString();
                if (!string.IsNullOrEmpty(lastScanStr))
                    stats.LastScanDate = DateTime.Parse(lastScanStr);
            }

            // Database size
            stats.DatabaseSize = new FileInfo(_databasePath).Length;
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Failed to get database statistics");
        }

        return stats;
    }

    #endregion

    #region Dispose

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        GC.SuppressFinalize(this);
    }

    ~SettingsDatabase()
    {
        Dispose();
    }

    #endregion
}

#region Models

public class ScanHistoryRecord
{
    public long Id { get; set; }
    public string ScanType { get; set; } = string.Empty;
    public DateTime StartTime { get; set; }
    public DateTime? EndTime { get; set; }
    public int ItemsScanned { get; set; }
    public int ThreatsFound { get; set; }
    public int ThreatsRemoved { get; set; }
    public string Status { get; set; } = string.Empty;

    public TimeSpan? Duration => EndTime.HasValue ? EndTime.Value - StartTime : null;
}

public class DatabaseStatistics
{
    public int TotalScans { get; set; }
    public int TotalThreats { get; set; }
    public DateTime? LastScanDate { get; set; }
    public long DatabaseSize { get; set; }

    public string DatabaseSizeText => DatabaseSize switch
    {
        < 1024 => $"{DatabaseSize} B",
        < 1024 * 1024 => $"{DatabaseSize / 1024.0:F1} KB",
        _ => $"{DatabaseSize / (1024.0 * 1024.0):F1} MB"
    };
}

public class WhitelistRecord
{
    public long Id { get; set; }
    public string Path { get; set; } = string.Empty;
    public bool IsPattern { get; set; }
    public string? Reason { get; set; }
    public DateTime AddedAt { get; set; }
}

public class BackupRecord
{
    public long Id { get; set; }
    public string OriginalPath { get; set; } = string.Empty;
    public string BackupPath { get; set; } = string.Empty;
    public DateTime BackupDate { get; set; }
    public long FileSize { get; set; }
    public string? FileHash { get; set; }
    public string? ThreatName { get; set; }
    public bool IsRestored { get; set; }
    public DateTime? RestoredAt { get; set; }
}

public class LicenseRecord
{
    public string? LicenseKey { get; set; }
    public string Tier { get; set; } = "Free";
    public bool IsTrial { get; set; }
    public DateTime? TrialStartDate { get; set; }
    public DateTime? ActivatedAt { get; set; }
    public DateTime? ExpiresAt { get; set; }
    public string? DeviceId { get; set; }
    public DateTime? LastValidated { get; set; }
}

public class QuarantineRecord
{
    public long Id { get; set; }
    public string OriginalPath { get; set; } = string.Empty;
    public DateTime QuarantinedAt { get; set; }
    public DateTime? RestoredAt { get; set; }
    public DateTime? DeletedAt { get; set; }
    public string? ThreatName { get; set; }
    public string? Hash { get; set; }
}

#endregion
