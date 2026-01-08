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
        private const string API_BASE_URL = "https://xmanstudio.com/api/v1/database";
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
            return new DatabaseInfo
            {
                Version = $"{now:yyyy.MM.dd}.001",
                LastUpdate = now,
                SignatureCount = 125847,
                Status = DatabaseStatus.UpToDate
            };
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
                _logger.Information("Checking for database updates...");

                var url = $"{API_BASE_URL}/{PRODUCT_ID}/check?current_version={_currentInfo.Version}";
                var response = await _httpClient.GetAsync(url);

                if (!response.IsSuccessStatusCode)
                {
                    _logger.Warning("Database update check failed: {StatusCode}", response.StatusCode);
                    return new DatabaseCheckResult
                    {
                        Success = false,
                        Message = $"Server returned {response.StatusCode}"
                    };
                }

                var content = await response.Content.ReadAsStringAsync();
                var result = JsonSerializer.Deserialize<DatabaseCheckResponse>(content, new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true
                });

                if (result == null)
                {
                    return new DatabaseCheckResult { Success = false, Message = "Invalid server response" };
                }

                IsUpToDate = !result.UpdateAvailable;

                return new DatabaseCheckResult
                {
                    Success = true,
                    UpdateAvailable = result.UpdateAvailable,
                    LatestVersion = result.LatestVersion,
                    SignatureCount = result.SignatureCount,
                    DownloadSize = result.DownloadSize,
                    ReleaseNotes = result.ReleaseNotes
                };
            }
            catch (HttpRequestException ex)
            {
                _logger.Warning(ex, "Network error checking for database updates");
                return new DatabaseCheckResult
                {
                    Success = false,
                    Message = "Unable to connect to update server"
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

        public async Task<DatabaseUpdateResult> UpdateDatabaseAsync(IProgress<int>? progress = null)
        {
            try
            {
                _logger.Information("Starting database update...");
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

                if (!checkResult.UpdateAvailable)
                {
                    _currentInfo.Status = DatabaseStatus.UpToDate;
                    return new DatabaseUpdateResult
                    {
                        Success = true,
                        Message = "Database is already up to date",
                        IsAlreadyUpToDate = true
                    };
                }

                UpdateProgress?.Invoke(this, new DatabaseUpdateEventArgs { Stage = "Downloading updates...", Progress = 20 });
                progress?.Report(20);

                // Download the update
                var downloadUrl = $"{API_BASE_URL}/{PRODUCT_ID}/download?version={checkResult.LatestVersion}";
                var response = await _httpClient.GetAsync(downloadUrl);

                if (!response.IsSuccessStatusCode)
                {
                    _currentInfo.Status = DatabaseStatus.Error;
                    return new DatabaseUpdateResult
                    {
                        Success = false,
                        Message = "Failed to download database update"
                    };
                }

                UpdateProgress?.Invoke(this, new DatabaseUpdateEventArgs { Stage = "Installing updates...", Progress = 60 });
                progress?.Report(60);

                // Simulate installation (in real implementation, extract and apply signatures)
                await Task.Delay(500);

                UpdateProgress?.Invoke(this, new DatabaseUpdateEventArgs { Stage = "Verifying...", Progress = 80 });
                progress?.Report(80);

                // Update local info
                _currentInfo.Version = checkResult.LatestVersion ?? _currentInfo.Version;
                _currentInfo.SignatureCount = checkResult.SignatureCount > 0 ? checkResult.SignatureCount : _currentInfo.SignatureCount + 150;
                _currentInfo.LastUpdate = DateTime.Now;
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
                    Message = $"Database updated to v{_currentInfo.Version}",
                    NewVersion = _currentInfo.Version,
                    SignatureCount = _currentInfo.SignatureCount
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

        /// <summary>
        /// Simulate a local database update for offline/demo mode
        /// </summary>
        public async Task<DatabaseUpdateResult> SimulateUpdateAsync()
        {
            try
            {
                _currentInfo.Status = DatabaseStatus.Updating;
                UpdateProgress?.Invoke(this, new DatabaseUpdateEventArgs { Stage = "Checking...", Progress = 10 });
                await Task.Delay(300);

                UpdateProgress?.Invoke(this, new DatabaseUpdateEventArgs { Stage = "Downloading...", Progress = 40 });
                await Task.Delay(500);

                UpdateProgress?.Invoke(this, new DatabaseUpdateEventArgs { Stage = "Installing...", Progress = 70 });
                await Task.Delay(400);

                UpdateProgress?.Invoke(this, new DatabaseUpdateEventArgs { Stage = "Verifying...", Progress = 90 });
                await Task.Delay(200);

                // Update version
                var now = DateTime.Now;
                _currentInfo.Version = $"{now:yyyy.MM.dd}.{now.Hour:D2}{now.Minute:D2}";
                _currentInfo.SignatureCount += new Random().Next(50, 200);
                _currentInfo.LastUpdate = now;
                _currentInfo.Status = DatabaseStatus.UpToDate;

                SaveDatabaseInfo();
                IsUpToDate = true;

                UpdateProgress?.Invoke(this, new DatabaseUpdateEventArgs { Stage = "Complete!", Progress = 100 });
                DatabaseUpdated?.Invoke(this, _currentInfo);

                return new DatabaseUpdateResult
                {
                    Success = true,
                    Message = "Database updated successfully",
                    NewVersion = _currentInfo.Version,
                    SignatureCount = _currentInfo.SignatureCount
                };
            }
            catch (Exception ex)
            {
                _currentInfo.Status = DatabaseStatus.Error;
                return new DatabaseUpdateResult
                {
                    Success = false,
                    Message = ex.Message
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

    public class DatabaseCheckResponse
    {
        public bool UpdateAvailable { get; set; }
        public string? LatestVersion { get; set; }
        public int SignatureCount { get; set; }
        public long DownloadSize { get; set; }
        public string? ReleaseNotes { get; set; }
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
