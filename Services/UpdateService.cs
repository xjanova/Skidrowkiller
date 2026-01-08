using System.IO;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Reflection;
using Serilog;

namespace SkidrowKiller.Services
{
    /// <summary>
    /// Service for checking and handling application updates via XMAN Studio API
    /// </summary>
    public class UpdateService : IDisposable
    {
        private const string XMAN_API_BASE = "https://xmanstudio.com/api/v1";
        private const string PRODUCT_ID = "skidrow-killer";

        private readonly HttpClient _httpClient;
        private readonly ILogger _logger;
        private LicenseService? _licenseService;
        private bool _disposed;

        public event EventHandler<UpdateInfo>? UpdateAvailable;
        public event EventHandler<string>? UpdateCheckFailed;

        public UpdateService()
        {
            _httpClient = new HttpClient
            {
                Timeout = TimeSpan.FromSeconds(30)
            };
            _httpClient.DefaultRequestHeaders.Add("User-Agent", $"SkidrowKiller/{GetCurrentVersion()}");
            _httpClient.DefaultRequestHeaders.Add("X-Product-ID", PRODUCT_ID);
            _logger = LoggingService.ForContext<UpdateService>();
        }

        /// <summary>
        /// Set license service for license-aware updates
        /// </summary>
        public void SetLicenseService(LicenseService licenseService)
        {
            _licenseService = licenseService;
        }

        /// <summary>
        /// Get the current application version
        /// </summary>
        public static string GetCurrentVersion()
        {
            return Assembly.GetExecutingAssembly()
                .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
                ?? Assembly.GetExecutingAssembly().GetName().Version?.ToString()
                ?? AppConfiguration.Settings.Application.Version;
        }

        /// <summary>
        /// Get detailed version information
        /// </summary>
        public static VersionInfo GetVersionInfo()
        {
            var assembly = Assembly.GetExecutingAssembly();
            var version = assembly.GetName().Version;
            var fileVersion = assembly.GetCustomAttribute<AssemblyFileVersionAttribute>()?.Version;
            var productVersion = assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;

            return new VersionInfo
            {
                Version = version?.ToString() ?? "0.0.0",
                FileVersion = fileVersion ?? version?.ToString() ?? "0.0.0",
                ProductVersion = productVersion ?? version?.ToString() ?? "0.0.0",
                BuildDate = GetBuildDate(assembly),
                Copyright = assembly.GetCustomAttribute<AssemblyCopyrightAttribute>()?.Copyright ?? "",
                Company = assembly.GetCustomAttribute<AssemblyCompanyAttribute>()?.Company ?? ""
            };
        }

        private static DateTime? GetBuildDate(Assembly assembly)
        {
            try
            {
                var location = assembly.Location;
                if (!string.IsNullOrEmpty(location) && File.Exists(location))
                {
                    return File.GetLastWriteTime(location);
                }
            }
            catch { }
            return null;
        }

        /// <summary>
        /// Check for available updates via XMAN Studio API
        /// </summary>
        public async Task<UpdateInfo?> CheckForUpdatesAsync(CancellationToken cancellationToken = default)
        {
            var settings = AppConfiguration.Settings.Updates;
            if (!settings.CheckForUpdatesOnStartup)
            {
                return null;
            }

            try
            {
                // First try XMAN Studio API for licensed users
                if (_licenseService != null && _licenseService.CurrentLicense?.IsValid == true)
                {
                    var xmanUpdate = await CheckXmanStudioUpdatesAsync(cancellationToken);
                    if (xmanUpdate != null) return xmanUpdate;
                }

                // Fallback to GitHub releases for public updates
                if (!string.IsNullOrEmpty(settings.UpdateCheckUrl))
                {
                    return await CheckGitHubUpdatesAsync(settings.UpdateCheckUrl, cancellationToken);
                }

                return null;
            }
            catch (TaskCanceledException)
            {
                _logger.Information("Update check cancelled");
                return null;
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Failed to check for updates");
                UpdateCheckFailed?.Invoke(this, ex.Message);
                return null;
            }
        }

        /// <summary>
        /// Check for updates via XMAN Studio API (licensed users get priority updates)
        /// </summary>
        private async Task<UpdateInfo?> CheckXmanStudioUpdatesAsync(CancellationToken cancellationToken)
        {
            try
            {
                var licenseKey = _licenseService?.CurrentLicense?.LicenseKey;
                if (string.IsNullOrEmpty(licenseKey)) return null;

                _logger.Information("Checking XMAN Studio for updates (licensed user)");

                var request = new HttpRequestMessage(HttpMethod.Get, $"{XMAN_API_BASE}/updates/{PRODUCT_ID}/check");
                request.Headers.Add("X-License-Key", licenseKey);

                var response = await _httpClient.SendAsync(request, cancellationToken);

                if (!response.IsSuccessStatusCode)
                {
                    _logger.Warning("XMAN Studio update check failed: {Status}", response.StatusCode);
                    return null;
                }

                var json = await response.Content.ReadAsStringAsync(cancellationToken);
                var updateResponse = JsonSerializer.Deserialize<XmanUpdateResponse>(json, new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true
                });

                if (updateResponse == null || !updateResponse.UpdateAvailable)
                {
                    _logger.Information("No updates available from XMAN Studio");
                    return null;
                }

                var currentVersion = Version.Parse(GetCurrentVersion().Split('-')[0]);
                var latestVersion = ParseVersion(updateResponse.LatestVersion ?? "");

                if (latestVersion > currentVersion)
                {
                    var updateInfo = new UpdateInfo
                    {
                        CurrentVersion = currentVersion.ToString(),
                        LatestVersion = latestVersion.ToString(),
                        ReleaseNotes = updateResponse.ReleaseNotes ?? "",
                        DownloadUrl = updateResponse.DownloadUrl ?? "",
                        ReleaseUrl = updateResponse.ReleaseUrl ?? $"https://xmanstudio.com/products/{PRODUCT_ID}",
                        PublishedAt = updateResponse.PublishedAt,
                        IsPreRelease = updateResponse.IsPreRelease
                    };

                    _logger.Information("XMAN Studio update available: {CurrentVersion} -> {LatestVersion}",
                        updateInfo.CurrentVersion, updateInfo.LatestVersion);

                    UpdateAvailable?.Invoke(this, updateInfo);
                    return updateInfo;
                }

                return null;
            }
            catch (HttpRequestException ex)
            {
                _logger.Warning(ex, "XMAN Studio update check failed, falling back to GitHub");
                return null;
            }
        }

        /// <summary>
        /// Check for updates via GitHub releases (fallback for free users)
        /// </summary>
        private async Task<UpdateInfo?> CheckGitHubUpdatesAsync(string updateUrl, CancellationToken cancellationToken)
        {
            try
            {
                _logger.Information("Checking for updates at {Url}", updateUrl);

                var response = await _httpClient.GetAsync(updateUrl, cancellationToken);
                response.EnsureSuccessStatusCode();

                var json = await response.Content.ReadAsStringAsync(cancellationToken);
                var release = JsonSerializer.Deserialize<GitHubRelease>(json, new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true
                });

                if (release == null)
                {
                    _logger.Warning("Failed to parse update response");
                    return null;
                }

                var latestVersion = ParseVersion(release.TagName ?? release.Name ?? "");
                var currentVersion = Version.Parse(GetCurrentVersion().Split('-')[0]);

                if (latestVersion > currentVersion)
                {
                    var updateInfo = new UpdateInfo
                    {
                        CurrentVersion = currentVersion.ToString(),
                        LatestVersion = latestVersion.ToString(),
                        ReleaseNotes = release.Body ?? "",
                        DownloadUrl = release.Assets?.FirstOrDefault()?.BrowserDownloadUrl ?? release.HtmlUrl ?? "",
                        ReleaseUrl = release.HtmlUrl ?? "",
                        PublishedAt = release.PublishedAt,
                        IsPreRelease = release.Prerelease
                    };

                    _logger.Information("Update available: {CurrentVersion} -> {LatestVersion}",
                        updateInfo.CurrentVersion, updateInfo.LatestVersion);

                    UpdateAvailable?.Invoke(this, updateInfo);
                    return updateInfo;
                }

                _logger.Information("Application is up to date (v{Version})", currentVersion);
                return null;
            }
            catch (HttpRequestException ex)
            {
                _logger.Warning(ex, "Failed to check for updates: Network error");
                UpdateCheckFailed?.Invoke(this, $"Network error: {ex.Message}");
                return null;
            }
        }

        /// <summary>
        /// Check if user can download updates (licensed or trial)
        /// </summary>
        public bool CanDownloadUpdate()
        {
            if (_licenseService == null) return true; // No license service, allow download
            return _licenseService.CurrentLicense?.IsValid ?? false;
        }

        /// <summary>
        /// Get download URL for update (licensed users get direct download)
        /// </summary>
        public async Task<string?> GetAuthorizedDownloadUrlAsync(string baseDownloadUrl, CancellationToken cancellationToken = default)
        {
            if (_licenseService?.CurrentLicense?.IsValid != true)
            {
                // Free users go to website
                return $"https://xmanstudio.com/products/{PRODUCT_ID}";
            }

            try
            {
                var licenseKey = _licenseService.CurrentLicense.LicenseKey;
                var request = new HttpRequestMessage(HttpMethod.Post, $"{XMAN_API_BASE}/updates/{PRODUCT_ID}/download");
                request.Headers.Add("X-License-Key", licenseKey);

                var response = await _httpClient.SendAsync(request, cancellationToken);

                if (response.IsSuccessStatusCode)
                {
                    var json = await response.Content.ReadAsStringAsync(cancellationToken);
                    var downloadResponse = JsonSerializer.Deserialize<XmanDownloadResponse>(json, new JsonSerializerOptions
                    {
                        PropertyNameCaseInsensitive = true
                    });

                    if (downloadResponse?.Success == true && !string.IsNullOrEmpty(downloadResponse.DownloadUrl))
                    {
                        _logger.Information("Got authorized download URL for licensed user");
                        return downloadResponse.DownloadUrl;
                    }
                }

                _logger.Warning("Could not get authorized download, using base URL");
                return baseDownloadUrl;
            }
            catch (Exception ex)
            {
                _logger.Warning(ex, "Failed to get authorized download URL");
                return baseDownloadUrl;
            }
        }

        private static Version ParseVersion(string versionString)
        {
            // Remove common prefixes like "v" or "version"
            var cleaned = versionString
                .TrimStart('v', 'V')
                .Replace("version", "", StringComparison.OrdinalIgnoreCase)
                .Trim()
                .Split('-')[0]; // Remove pre-release suffix

            if (Version.TryParse(cleaned, out var version))
            {
                return version;
            }

            return new Version(0, 0, 0);
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            _httpClient.Dispose();
        }
    }

    /// <summary>
    /// Version information for the application
    /// </summary>
    public class VersionInfo
    {
        public string Version { get; set; } = "";
        public string FileVersion { get; set; } = "";
        public string ProductVersion { get; set; } = "";
        public DateTime? BuildDate { get; set; }
        public string Copyright { get; set; } = "";
        public string Company { get; set; } = "";

        public override string ToString()
        {
            return $"v{Version}";
        }
    }

    /// <summary>
    /// Information about an available update
    /// </summary>
    public class UpdateInfo
    {
        public string CurrentVersion { get; set; } = "";
        public string LatestVersion { get; set; } = "";
        public string ReleaseNotes { get; set; } = "";
        public string DownloadUrl { get; set; } = "";
        public string ReleaseUrl { get; set; } = "";
        public DateTime? PublishedAt { get; set; }
        public bool IsPreRelease { get; set; }
    }

    // GitHub API response models
    internal class GitHubRelease
    {
        public string? TagName { get; set; }
        public string? Name { get; set; }
        public string? Body { get; set; }
        public string? HtmlUrl { get; set; }
        public bool Prerelease { get; set; }
        public DateTime? PublishedAt { get; set; }
        public List<GitHubAsset>? Assets { get; set; }
    }

    internal class GitHubAsset
    {
        public string? Name { get; set; }
        public string? BrowserDownloadUrl { get; set; }
        public long Size { get; set; }
    }

    // XMAN Studio API response models
    internal class XmanUpdateResponse
    {
        public bool UpdateAvailable { get; set; }
        public string? LatestVersion { get; set; }
        public string? ReleaseNotes { get; set; }
        public string? DownloadUrl { get; set; }
        public string? ReleaseUrl { get; set; }
        public DateTime? PublishedAt { get; set; }
        public bool IsPreRelease { get; set; }
        public bool RequiresLicense { get; set; }
    }

    internal class XmanDownloadResponse
    {
        public bool Success { get; set; }
        public string? DownloadUrl { get; set; }
        public string? Message { get; set; }
        public DateTime? ExpiresAt { get; set; }
    }
}
