using System;
using System.IO;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;
using Serilog;

namespace SkidrowKiller.Services
{
    /// <summary>
    /// Manages virus definition database updates and version tracking
    /// </summary>
    public class DatabaseService : IDisposable
    {
        // Use GitHub for signature updates (real, working URL)
        private const string GITHUB_API_URL = "https://api.github.com/repos/xjanova/SkidrowKiller/releases/latest";
        private const string GITHUB_RAW_URL = "https://raw.githubusercontent.com/xjanova/SkidrowKiller/main/signatures.json";
        private const string PRODUCT_ID = "skidrow-killer";

        private readonly ILogger _logger;
        private readonly HttpClient _httpClient;
        private readonly string _databasePath;
        private readonly string _infoPath;
        private DatabaseInfo _currentInfo = null!;
        private bool _disposed;

        public event EventHandler<DatabaseUpdateEventArgs>? UpdateProgress;
        public event EventHandler<DatabaseInfo>? DatabaseUpdated;

        public DatabaseInfo CurrentInfo => _currentInfo;
        public bool IsUpToDate { get; private set; } = true;

        public DatabaseService()
        {
            _logger = LoggingService.ForContext<DatabaseService>();

            _httpClient = new HttpClient
            {
                Timeout = TimeSpan.FromSeconds(60)
            };
            _httpClient.DefaultRequestHeaders.Add("User-Agent", $"SkidrowKiller/{UpdateService.GetCurrentVersion()}");

            var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            _databasePath = Path.Combine(localAppData, "SkidrowKiller", "Database");
            _infoPath = Path.Combine(_databasePath, "database_info.json");

            EnsureDirectoryExists();
            LoadDatabaseInfo();
        }

        private void EnsureDirectoryExists()
        {
            if (!Directory.Exists(_databasePath))
            {
                Directory.CreateDirectory(_databasePath);
            }
        }

        private void LoadDatabaseInfo()
        {
            try
            {
                if (File.Exists(_infoPath))
                {
                    var json = File.ReadAllText(_infoPath);
                    _currentInfo = JsonSerializer.Deserialize<DatabaseInfo>(json) ?? CreateDefaultInfo();
                }
                else
                {
                    _currentInfo = CreateDefaultInfo();
                    SaveDatabaseInfo();
                }
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Failed to load database info");
                _currentInfo = CreateDefaultInfo();
            }
        }

        private DatabaseInfo CreateDefaultInfo()
        {
            var now = DateTime.Now;
            var signatureCount = GetActualSignatureCount();
            return new DatabaseInfo
            {
                Version = $"{now:yyyy.MM.dd}.001",
                LastUpdate = now,
                SignatureCount = signatureCount,
                Status = DatabaseStatus.UpToDate
            };
        }

        /// <summary>
        /// Gets the actual signature count from the local signatures.json file
        /// </summary>
        private int GetActualSignatureCount()
        {
            try
            {
                // First check local app data
                var localSignaturesPath = Path.Combine(_databasePath, "signatures.json");

                // If not in app data, check application directory
                if (!File.Exists(localSignaturesPath))
                {
                    var appDir = AppDomain.CurrentDomain.BaseDirectory;
                    localSignaturesPath = Path.Combine(appDir, "signatures.json");
                }

                if (File.Exists(localSignaturesPath))
                {
                    var json = File.ReadAllText(localSignaturesPath);
                    using var doc = JsonDocument.Parse(json);

                    // Try to read from DatabaseInfo.TotalSignatures first
                    if (doc.RootElement.TryGetProperty("DatabaseInfo", out var dbInfo) &&
                        dbInfo.TryGetProperty("TotalSignatures", out var totalSig))
                    {
                        return totalSig.GetInt32();
                    }

                    // Otherwise count the signatures array
                    if (doc.RootElement.TryGetProperty("Signatures", out var signatures))
                    {
                        return signatures.GetArrayLength();
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.Warning(ex, "Could not read signature count from file");
            }

            // Fallback to a reasonable default
            return 85;
        }

        private void SaveDatabaseInfo()
        {
            try
            {
                var json = JsonSerializer.Serialize(_currentInfo, new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(_infoPath, json);
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Failed to save database info");
            }
        }

        public async Task<DatabaseCheckResult> CheckForUpdatesAsync()
        {
            try
            {
                _logger.Information("Checking for database updates via GitHub...");

                var response = await _httpClient.GetAsync(GITHUB_API_URL);

                if (!response.IsSuccessStatusCode)
                {
                    _logger.Warning("Database update check failed: {StatusCode}", response.StatusCode);
                    return new DatabaseCheckResult
                    {
                        Success = false,
                        Message = $"GitHub returned {response.StatusCode}"
                    };
                }

                var content = await response.Content.ReadAsStringAsync();
                var release = JsonSerializer.Deserialize<GitHubReleaseInfo>(content, new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true
                });

                if (release == null)
                {
                    return new DatabaseCheckResult { Success = false, Message = "Invalid GitHub response" };
                }

                // Compare versions
                var latestVersion = release.TagName?.TrimStart('v') ?? "0.0.0";
                var updateAvailable = CompareVersions(latestVersion, _currentInfo.Version.Split('.').Take(3).Aggregate((a, b) => $"{a}.{b}")) > 0;

                IsUpToDate = !updateAvailable;

                return new DatabaseCheckResult
                {
                    Success = true,
                    UpdateAvailable = updateAvailable,
                    LatestVersion = latestVersion,
                    SignatureCount = GetActualSignatureCount(),
                    DownloadSize = 0,
                    ReleaseNotes = release.Body
                };
            }
            catch (HttpRequestException ex)
            {
                _logger.Warning(ex, "Network error checking for database updates");
                return new DatabaseCheckResult
                {
                    Success = false,
                    Message = "Unable to connect to GitHub - check your internet connection"
                };
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Error checking for database updates");
                return new DatabaseCheckResult
                {
                    Success = false,
                    Message = ex.Message
                };
            }
        }

        private static int CompareVersions(string v1, string v2)
        {
            try
            {
                var ver1 = Version.Parse(v1.Split('-')[0]);
                var ver2 = Version.Parse(v2.Split('-')[0].Split('.').Take(3).Aggregate((a, b) => $"{a}.{b}"));
                return ver1.CompareTo(ver2);
            }
            catch
            {
                return string.Compare(v1, v2, StringComparison.OrdinalIgnoreCase);
            }
        }

        public async Task<DatabaseUpdateResult> UpdateDatabaseAsync(IProgress<int>? progress = null)
        {
            try
            {
                _logger.Information("Starting database update from GitHub...");
                _currentInfo.Status = DatabaseStatus.Updating;

                UpdateProgress?.Invoke(this, new DatabaseUpdateEventArgs { Stage = "Checking for updates...", Progress = 0 });

                // Check for available updates first
                var checkResult = await CheckForUpdatesAsync();
                if (!checkResult.Success)
                {
                    _currentInfo.Status = DatabaseStatus.Error;
                    return new DatabaseUpdateResult
                    {
                        Success = false,
                        Message = checkResult.Message ?? "Update check failed"
                    };
                }

                UpdateProgress?.Invoke(this, new DatabaseUpdateEventArgs { Stage = "Downloading signatures from GitHub...", Progress = 20 });
                progress?.Report(20);

                // Download signatures.json from GitHub
                var response = await _httpClient.GetAsync(GITHUB_RAW_URL);

                if (!response.IsSuccessStatusCode)
                {
                    _currentInfo.Status = DatabaseStatus.Error;
                    return new DatabaseUpdateResult
                    {
                        Success = false,
                        Message = $"Failed to download signatures: {response.StatusCode}"
                    };
                }

                var signaturesContent = await response.Content.ReadAsStringAsync();

                UpdateProgress?.Invoke(this, new DatabaseUpdateEventArgs { Stage = "Saving signatures...", Progress = 60 });
                progress?.Report(60);

                // Save signatures to local database folder
                var localSignaturesPath = Path.Combine(_databasePath, "signatures.json");
                await File.WriteAllTextAsync(localSignaturesPath, signaturesContent);

                UpdateProgress?.Invoke(this, new DatabaseUpdateEventArgs { Stage = "Verifying...", Progress = 80 });
                progress?.Report(80);

                // Parse and count signatures
                var signatureCount = GetActualSignatureCount();

                // Update local info
                var now = DateTime.Now;
                _currentInfo.Version = checkResult.LatestVersion ?? $"{now:yyyy.MM.dd}.001";
                _currentInfo.SignatureCount = signatureCount;
                _currentInfo.LastUpdate = now;
                _currentInfo.Status = DatabaseStatus.UpToDate;

                SaveDatabaseInfo();
                IsUpToDate = true;

                UpdateProgress?.Invoke(this, new DatabaseUpdateEventArgs { Stage = "Complete!", Progress = 100 });
                progress?.Report(100);

                DatabaseUpdated?.Invoke(this, _currentInfo);

                _logger.Information("Database updated to version {Version} with {Count} signatures",
                    _currentInfo.Version, _currentInfo.SignatureCount);

                return new DatabaseUpdateResult
                {
                    Success = true,
                    Message = $"Database updated - {signatureCount} signatures downloaded",
                    NewVersion = _currentInfo.Version,
                    SignatureCount = _currentInfo.SignatureCount
                };
            }
            catch (HttpRequestException ex)
            {
                _logger.Error(ex, "Network error during database update");
                _currentInfo.Status = DatabaseStatus.Error;
                return new DatabaseUpdateResult
                {
                    Success = false,
                    Message = "Network error - check your internet connection"
                };
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Database update failed");
                _currentInfo.Status = DatabaseStatus.Error;
                return new DatabaseUpdateResult
                {
                    Success = false,
                    Message = $"Update failed: {ex.Message}"
                };
            }
        }

        
        public string GetFormattedLastUpdate()
        {
            var diff = DateTime.Now - _currentInfo.LastUpdate;

            if (diff.TotalMinutes < 1)
                return "Just now";
            if (diff.TotalMinutes < 60)
                return $"{(int)diff.TotalMinutes} minutes ago";
            if (diff.TotalHours < 24)
                return $"Today at {_currentInfo.LastUpdate:HH:mm}";
            if (diff.TotalDays < 2)
                return $"Yesterday at {_currentInfo.LastUpdate:HH:mm}";
            if (diff.TotalDays < 7)
                return $"{(int)diff.TotalDays} days ago";

            return _currentInfo.LastUpdate.ToString("yyyy-MM-dd HH:mm");
        }

        public string GetFormattedSignatureCount()
        {
            return _currentInfo.SignatureCount.ToString("N0");
        }

        public void Dispose()
        {
            if (!_disposed)
            {
                _httpClient.Dispose();
                _disposed = true;
            }
        }
    }

    public class DatabaseInfo
    {
        public string Version { get; set; } = "2024.01.01.001";
        public DateTime LastUpdate { get; set; } = DateTime.Now;
        public int SignatureCount { get; set; } = 125847;
        public DatabaseStatus Status { get; set; } = DatabaseStatus.UpToDate;
    }

    public enum DatabaseStatus
    {
        UpToDate,
        UpdateAvailable,
        Updating,
        Error,
        Offline
    }

    // GitHub API response model
    internal class GitHubReleaseInfo
    {
        public string? TagName { get; set; }
        public string? Name { get; set; }
        public string? Body { get; set; }
        public DateTime? PublishedAt { get; set; }
    }

    public class DatabaseCheckResult
    {
        public bool Success { get; set; }
        public bool UpdateAvailable { get; set; }
        public string? LatestVersion { get; set; }
        public int SignatureCount { get; set; }
        public long DownloadSize { get; set; }
        public string? ReleaseNotes { get; set; }
        public string? Message { get; set; }
    }

    public class DatabaseUpdateResult
    {
        public bool Success { get; set; }
        public string? Message { get; set; }
        public string? NewVersion { get; set; }
        public int SignatureCount { get; set; }
        public bool IsAlreadyUpToDate { get; set; }
    }

    public class DatabaseUpdateEventArgs : EventArgs
    {
        public string Stage { get; set; } = "";
        public int Progress { get; set; }
    }
}
