using System;
using System.IO;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace SkidrowKiller.Services;

/// <summary>
/// Service for automatically updating malware signatures from a remote repository.
/// Supports GitHub releases and custom update servers.
/// </summary>
public class SignatureUpdateService : IDisposable
{
    private readonly ILogger<SignatureUpdateService>? _logger;
    private readonly HttpClient _httpClient;
    private CancellationTokenSource? _cts;
    private Timer? _updateTimer;
    private bool _disposed;

    // Update URLs
    private string _updateCheckUrl = "https://api.github.com/repos/xjanova/SkidrowKiller/releases/latest";
    private string _signatureDownloadUrl = "https://raw.githubusercontent.com/xjanova/SkidrowKiller/main/signatures.json";

    // Paths
    private readonly string _signaturesPath;
    private readonly string _backupPath;
    private readonly string _versionPath;

    // Settings
    public TimeSpan UpdateInterval { get; set; } = TimeSpan.FromHours(6);
    public bool AutoUpdate { get; set; } = true;

    // Events
    public event EventHandler<UpdateEventArgs>? UpdateAvailable;
    public event EventHandler<UpdateEventArgs>? UpdateCompleted;
    public event EventHandler<UpdateEventArgs>? UpdateFailed;
    public event EventHandler<UpdateProgressEventArgs>? UpdateProgress;

    // Status
    public DateTime LastUpdateCheck { get; private set; }
    public DateTime LastSuccessfulUpdate { get; private set; }
    public string CurrentVersion { get; private set; } = "1.0.0";
    public bool IsUpdating { get; private set; }

    public SignatureUpdateService(ILogger<SignatureUpdateService>? logger = null)
    {
        _logger = logger;

        _httpClient = new HttpClient();
        _httpClient.DefaultRequestHeaders.Add("User-Agent", "SkidrowKiller-Updater/1.0");
        _httpClient.Timeout = TimeSpan.FromSeconds(30);

        // Set up paths
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var dataPath = Path.Combine(appData, "SkidrowKiller");
        Directory.CreateDirectory(dataPath);

        _signaturesPath = Path.Combine(dataPath, "signatures.json");
        _backupPath = Path.Combine(dataPath, "signatures.backup.json");
        _versionPath = Path.Combine(dataPath, "signatures.version");

        // Load current version
        LoadCurrentVersion();
    }

    /// <summary>
    /// Configures the update URLs
    /// </summary>
    public void Configure(string? updateCheckUrl = null, string? signatureDownloadUrl = null)
    {
        if (!string.IsNullOrEmpty(updateCheckUrl))
            _updateCheckUrl = updateCheckUrl;
        if (!string.IsNullOrEmpty(signatureDownloadUrl))
            _signatureDownloadUrl = signatureDownloadUrl;
    }

    /// <summary>
    /// Starts automatic update checking
    /// </summary>
    public void StartAutoUpdate()
    {
        if (!AutoUpdate) return;

        _cts = new CancellationTokenSource();

        // Check immediately, then periodically
        _updateTimer = new Timer(async _ =>
        {
            try
            {
                await CheckAndUpdateAsync();
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Auto-update check failed");
            }
        }, null, TimeSpan.Zero, UpdateInterval);

        _logger?.LogInformation("Auto-update enabled. Interval: {Interval}", UpdateInterval);
    }

    /// <summary>
    /// Stops automatic update checking
    /// </summary>
    public void StopAutoUpdate()
    {
        _cts?.Cancel();
        _updateTimer?.Dispose();
        _updateTimer = null;
        _logger?.LogInformation("Auto-update disabled");
    }

    /// <summary>
    /// Checks for updates and downloads if available
    /// </summary>
    public async Task<UpdateResult> CheckAndUpdateAsync(CancellationToken cancellationToken = default)
    {
        if (IsUpdating)
        {
            return new UpdateResult
            {
                Success = false,
                Message = "Update already in progress"
            };
        }

        IsUpdating = true;
        var result = new UpdateResult();

        try
        {
            _logger?.LogInformation("Checking for signature updates...");
            UpdateProgress?.Invoke(this, new UpdateProgressEventArgs
            {
                Progress = 0,
                Status = "Checking for updates..."
            });

            // Check for new version
            var updateInfo = await CheckForUpdatesAsync(cancellationToken);
            LastUpdateCheck = DateTime.Now;

            if (updateInfo == null)
            {
                result.Success = true;
                result.Message = "Failed to check for updates";
                return result;
            }

            if (!updateInfo.HasUpdate)
            {
                result.Success = true;
                result.Message = "Signatures are up to date";
                result.CurrentVersion = CurrentVersion;
                _logger?.LogInformation("Signatures are up to date (v{Version})", CurrentVersion);
                return result;
            }

            _logger?.LogInformation("Update available: v{Current} -> v{New}",
                CurrentVersion, updateInfo.NewVersion);

            UpdateAvailable?.Invoke(this, new UpdateEventArgs
            {
                CurrentVersion = CurrentVersion,
                NewVersion = updateInfo.NewVersion ?? "",
                Message = "New signature update available"
            });

            // Download update
            UpdateProgress?.Invoke(this, new UpdateProgressEventArgs
            {
                Progress = 25,
                Status = "Downloading signatures..."
            });

            var downloadSuccess = await DownloadSignaturesAsync(
                updateInfo.DownloadUrl ?? _signatureDownloadUrl,
                cancellationToken);

            if (!downloadSuccess)
            {
                result.Success = false;
                result.Message = "Failed to download signatures";
                UpdateFailed?.Invoke(this, new UpdateEventArgs
                {
                    CurrentVersion = CurrentVersion,
                    Message = "Download failed"
                });
                return result;
            }

            UpdateProgress?.Invoke(this, new UpdateProgressEventArgs
            {
                Progress = 75,
                Status = "Verifying signatures..."
            });

            // Verify and apply
            if (await VerifySignaturesAsync())
            {
                CurrentVersion = updateInfo.NewVersion ?? CurrentVersion;
                SaveCurrentVersion();
                LastSuccessfulUpdate = DateTime.Now;

                result.Success = true;
                result.Message = $"Updated to v{CurrentVersion}";
                result.CurrentVersion = CurrentVersion;
                result.PreviousVersion = updateInfo.NewVersion;

                UpdateProgress?.Invoke(this, new UpdateProgressEventArgs
                {
                    Progress = 100,
                    Status = "Update complete"
                });

                UpdateCompleted?.Invoke(this, new UpdateEventArgs
                {
                    CurrentVersion = CurrentVersion,
                    Message = "Signatures updated successfully"
                });

                _logger?.LogInformation("Signatures updated to v{Version}", CurrentVersion);
            }
            else
            {
                // Rollback
                await RollbackAsync();
                result.Success = false;
                result.Message = "Signature verification failed, rolled back";

                UpdateFailed?.Invoke(this, new UpdateEventArgs
                {
                    CurrentVersion = CurrentVersion,
                    Message = "Verification failed"
                });
            }
        }
        catch (OperationCanceledException)
        {
            result.Success = false;
            result.Message = "Update cancelled";
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Update failed");
            result.Success = false;
            result.Message = $"Update failed: {ex.Message}";

            UpdateFailed?.Invoke(this, new UpdateEventArgs
            {
                CurrentVersion = CurrentVersion,
                Message = ex.Message
            });
        }
        finally
        {
            IsUpdating = false;
        }

        return result;
    }

    /// <summary>
    /// Checks for available updates without downloading
    /// </summary>
    public async Task<SignatureUpdateInfo?> CheckForUpdatesAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            var response = await _httpClient.GetAsync(_updateCheckUrl, cancellationToken);

            if (!response.IsSuccessStatusCode)
            {
                _logger?.LogWarning("Update check failed: {StatusCode}", response.StatusCode);
                return null;
            }

            var json = await response.Content.ReadAsStringAsync(cancellationToken);
            var release = JsonSerializer.Deserialize<SignatureGitHubRelease>(json);

            if (release == null)
                return null;

            var newVersion = release.TagName?.TrimStart('v') ?? "0.0.0";

            return new SignatureUpdateInfo
            {
                HasUpdate = CompareVersions(newVersion, CurrentVersion) > 0,
                CurrentVersion = CurrentVersion,
                NewVersion = newVersion,
                DownloadUrl = GetSignatureAssetUrl(release),
                ReleaseNotes = release.Body
            };
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to check for updates");
            return null;
        }
    }

    private async Task<bool> DownloadSignaturesAsync(string url, CancellationToken cancellationToken)
    {
        try
        {
            // Backup current signatures
            if (File.Exists(_signaturesPath))
            {
                File.Copy(_signaturesPath, _backupPath, true);
            }

            // Download new signatures
            var response = await _httpClient.GetAsync(url, cancellationToken);

            if (!response.IsSuccessStatusCode)
            {
                _logger?.LogWarning("Download failed: {StatusCode}", response.StatusCode);
                return false;
            }

            var content = await response.Content.ReadAsStringAsync(cancellationToken);

            // Write to temp file first
            var tempPath = _signaturesPath + ".tmp";
            await File.WriteAllTextAsync(tempPath, content, cancellationToken);

            // Move to final location
            if (File.Exists(_signaturesPath))
                File.Delete(_signaturesPath);
            File.Move(tempPath, _signaturesPath);

            return true;
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to download signatures");
            return false;
        }
    }

    private async Task<bool> VerifySignaturesAsync()
    {
        try
        {
            if (!File.Exists(_signaturesPath))
                return false;

            var content = await File.ReadAllTextAsync(_signaturesPath);

            // Try to parse as JSON
            var doc = JsonDocument.Parse(content);

            // Check for required fields
            if (doc.RootElement.TryGetProperty("version", out _) &&
                doc.RootElement.TryGetProperty("signatures", out var signatures))
            {
                // Verify we have at least some signatures
                if (signatures.GetArrayLength() > 0)
                {
                    return true;
                }
            }

            return false;
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Signature verification failed");
            return false;
        }
    }

    private async Task RollbackAsync()
    {
        try
        {
            if (File.Exists(_backupPath))
            {
                if (File.Exists(_signaturesPath))
                    File.Delete(_signaturesPath);
                File.Copy(_backupPath, _signaturesPath);
                _logger?.LogInformation("Rolled back to previous signatures");
            }
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Rollback failed");
        }

        await Task.CompletedTask;
    }

    private void LoadCurrentVersion()
    {
        try
        {
            if (File.Exists(_versionPath))
            {
                CurrentVersion = File.ReadAllText(_versionPath).Trim();
            }
            else if (File.Exists(_signaturesPath))
            {
                // Try to read version from signatures file
                var content = File.ReadAllText(_signaturesPath);
                var doc = JsonDocument.Parse(content);
                if (doc.RootElement.TryGetProperty("version", out var version))
                {
                    CurrentVersion = version.GetString() ?? "1.0.0";
                }
            }
        }
        catch (Exception ex)
        {
            _logger?.LogWarning(ex, "Failed to load current version");
        }
    }

    private void SaveCurrentVersion()
    {
        try
        {
            File.WriteAllText(_versionPath, CurrentVersion);
        }
        catch (Exception ex)
        {
            _logger?.LogWarning(ex, "Failed to save current version");
        }
    }

    private static int CompareVersions(string v1, string v2)
    {
        try
        {
            var ver1 = Version.Parse(v1);
            var ver2 = Version.Parse(v2);
            return ver1.CompareTo(ver2);
        }
        catch
        {
            return string.Compare(v1, v2, StringComparison.OrdinalIgnoreCase);
        }
    }

    private string? GetSignatureAssetUrl(SignatureGitHubRelease release)
    {
        // Look for signatures.json in release assets
        if (release.Assets != null)
        {
            foreach (var asset in release.Assets)
            {
                if (asset.Name?.Equals("signatures.json", StringComparison.OrdinalIgnoreCase) == true)
                {
                    return asset.BrowserDownloadUrl;
                }
            }
        }

        // Fall back to raw file URL
        return _signatureDownloadUrl;
    }

    /// <summary>
    /// Gets the path to the signatures file
    /// </summary>
    public string GetSignaturesPath() => _signaturesPath;

    /// <summary>
    /// Forces a reload of signatures from disk
    /// </summary>
    public async Task<bool> ReloadSignaturesAsync()
    {
        // This would trigger the MalwareSignatureDatabase to reload
        // For now, just verify the file exists and is valid
        return await VerifySignaturesAsync();
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        StopAutoUpdate();
        _httpClient.Dispose();
        _cts?.Dispose();

        GC.SuppressFinalize(this);
    }
}

#region Models

public class UpdateResult
{
    public bool Success { get; set; }
    public string Message { get; set; } = "";
    public string? CurrentVersion { get; set; }
    public string? PreviousVersion { get; set; }
}

public class SignatureUpdateInfo
{
    public bool HasUpdate { get; set; }
    public string? CurrentVersion { get; set; }
    public string? NewVersion { get; set; }
    public string? DownloadUrl { get; set; }
    public string? ReleaseNotes { get; set; }
}

public class UpdateEventArgs : EventArgs
{
    public string CurrentVersion { get; set; } = "";
    public string NewVersion { get; set; } = "";
    public string Message { get; set; } = "";
}

public class UpdateProgressEventArgs : EventArgs
{
    public int Progress { get; set; }
    public string Status { get; set; } = "";
}

// GitHub API models for signature updates
internal class SignatureGitHubRelease
{
    public string? TagName { get; set; }
    public string? Name { get; set; }
    public string? Body { get; set; }
    public SignatureGitHubAsset[]? Assets { get; set; }
}

internal class SignatureGitHubAsset
{
    public string? Name { get; set; }
    public string? BrowserDownloadUrl { get; set; }
}

#endregion
