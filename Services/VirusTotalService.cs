using System;
using System.Collections.Concurrent;
using System.IO;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace SkidrowKiller.Services;

/// <summary>
/// Integration with VirusTotal API for cloud-based threat intelligence.
/// Provides hash lookup, file scanning, and URL checking capabilities.
/// </summary>
public class VirusTotalService : IDisposable
{
    private readonly ILogger<VirusTotalService>? _logger;
    private readonly HttpClient _httpClient;
    private readonly ConcurrentDictionary<string, VTCacheEntry> _cache;
    private readonly SemaphoreSlim _rateLimiter;

    private string? _apiKey;
    private bool _disposed;

    // API settings
    private const string BaseUrl = "https://www.virustotal.com/api/v3";
    private const int MaxRequestsPerMinute = 4; // Free API limit
    private readonly TimeSpan _cacheExpiration = TimeSpan.FromHours(24);
    private readonly TimeSpan _rateLimitWindow = TimeSpan.FromMinutes(1);

    private DateTime _lastRequestTime = DateTime.MinValue;
    private int _requestsThisMinute;

    // Events
    public event EventHandler<VTScanResultEventArgs>? ScanCompleted;
    public event EventHandler<VTErrorEventArgs>? ErrorOccurred;

    public bool IsConfigured => !string.IsNullOrEmpty(_apiKey);
    public bool IsEnabled { get; set; } = true;

    public VirusTotalService(ILogger<VirusTotalService>? logger = null)
    {
        _logger = logger;
        _cache = new ConcurrentDictionary<string, VTCacheEntry>();
        _rateLimiter = new SemaphoreSlim(1, 1);

        _httpClient = new HttpClient
        {
            BaseAddress = new Uri(BaseUrl),
            Timeout = TimeSpan.FromSeconds(30)
        };
    }

    /// <summary>
    /// Configures the service with an API key
    /// </summary>
    public void Configure(string apiKey)
    {
        _apiKey = apiKey;
        _httpClient.DefaultRequestHeaders.Clear();
        _httpClient.DefaultRequestHeaders.Add("x-apikey", apiKey);
        _httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        _logger?.LogInformation("VirusTotal service configured");
    }

    /// <summary>
    /// Checks a file hash against VirusTotal database
    /// </summary>
    public async Task<VTFileReport?> CheckHashAsync(string hash, CancellationToken cancellationToken = default)
    {
        if (!IsEnabled || !IsConfigured)
            return null;

        // Check cache first
        if (_cache.TryGetValue(hash, out var cached) && !cached.IsExpired)
        {
            _logger?.LogDebug("VT cache hit for {Hash}", hash);
            return cached.Report;
        }

        await WaitForRateLimitAsync(cancellationToken);

        try
        {
            var response = await _httpClient.GetAsync($"/files/{hash}", cancellationToken);

            if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
            {
                _logger?.LogDebug("Hash not found in VT: {Hash}", hash);
                return null;
            }

            if (!response.IsSuccessStatusCode)
            {
                _logger?.LogWarning("VT API error: {StatusCode}", response.StatusCode);
                return null;
            }

            var content = await response.Content.ReadAsStringAsync(cancellationToken);
            var report = ParseFileReport(content);

            if (report != null)
            {
                // Cache the result
                _cache[hash] = new VTCacheEntry(report, _cacheExpiration);
            }

            return report;
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Error checking hash with VirusTotal");
            ErrorOccurred?.Invoke(this, new VTErrorEventArgs { Message = ex.Message });
            return null;
        }
    }

    /// <summary>
    /// Checks a file by computing its hash and looking it up
    /// </summary>
    public async Task<VTFileReport?> CheckFileAsync(string filePath, CancellationToken cancellationToken = default)
    {
        if (!IsEnabled || !IsConfigured)
            return null;

        try
        {
            if (!File.Exists(filePath))
                return null;

            // Compute SHA256 hash
            using var stream = File.OpenRead(filePath);
            using var sha256 = SHA256.Create();
            var hashBytes = await sha256.ComputeHashAsync(stream, cancellationToken);
            var hash = BitConverter.ToString(hashBytes).Replace("-", "").ToLower();

            return await CheckHashAsync(hash, cancellationToken);
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Error checking file with VirusTotal: {Path}", filePath);
            return null;
        }
    }

    /// <summary>
    /// Submits a file for scanning (requires premium API)
    /// </summary>
    public async Task<string?> SubmitFileAsync(string filePath, CancellationToken cancellationToken = default)
    {
        if (!IsEnabled || !IsConfigured)
            return null;

        await WaitForRateLimitAsync(cancellationToken);

        try
        {
            var fileInfo = new FileInfo(filePath);

            // VT free API has 32MB limit
            if (fileInfo.Length > 32 * 1024 * 1024)
            {
                _logger?.LogWarning("File too large for VT submission: {Size} bytes", fileInfo.Length);
                return null;
            }

            using var form = new MultipartFormDataContent();
            using var fileStream = File.OpenRead(filePath);
            using var fileContent = new StreamContent(fileStream);

            fileContent.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
            form.Add(fileContent, "file", Path.GetFileName(filePath));

            var response = await _httpClient.PostAsync("/files", form, cancellationToken);

            if (!response.IsSuccessStatusCode)
            {
                _logger?.LogWarning("VT file submission failed: {StatusCode}", response.StatusCode);
                return null;
            }

            var content = await response.Content.ReadAsStringAsync(cancellationToken);
            var json = JsonDocument.Parse(content);

            if (json.RootElement.TryGetProperty("data", out var data) &&
                data.TryGetProperty("id", out var id))
            {
                return id.GetString();
            }

            return null;
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Error submitting file to VirusTotal");
            return null;
        }
    }

    /// <summary>
    /// Checks a URL against VirusTotal
    /// </summary>
    public async Task<VTUrlReport?> CheckUrlAsync(string url, CancellationToken cancellationToken = default)
    {
        if (!IsEnabled || !IsConfigured)
            return null;

        // URL ID is base64 encoded URL without padding
        var urlId = Convert.ToBase64String(Encoding.UTF8.GetBytes(url))
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');

        // Check cache
        if (_cache.TryGetValue($"url:{urlId}", out var cached) && !cached.IsExpired)
        {
            return cached.UrlReport;
        }

        await WaitForRateLimitAsync(cancellationToken);

        try
        {
            var response = await _httpClient.GetAsync($"/urls/{urlId}", cancellationToken);

            if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
            {
                return null;
            }

            if (!response.IsSuccessStatusCode)
            {
                _logger?.LogWarning("VT URL check failed: {StatusCode}", response.StatusCode);
                return null;
            }

            var content = await response.Content.ReadAsStringAsync(cancellationToken);
            var report = ParseUrlReport(content);

            if (report != null)
            {
                _cache[$"url:{urlId}"] = new VTCacheEntry(report, _cacheExpiration);
            }

            return report;
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Error checking URL with VirusTotal");
            return null;
        }
    }

    /// <summary>
    /// Gets the analysis results for a previously submitted file
    /// </summary>
    public async Task<VTFileReport?> GetAnalysisAsync(string analysisId, CancellationToken cancellationToken = default)
    {
        if (!IsEnabled || !IsConfigured)
            return null;

        await WaitForRateLimitAsync(cancellationToken);

        try
        {
            var response = await _httpClient.GetAsync($"/analyses/{analysisId}", cancellationToken);

            if (!response.IsSuccessStatusCode)
            {
                return null;
            }

            var content = await response.Content.ReadAsStringAsync(cancellationToken);
            return ParseAnalysisReport(content);
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Error getting analysis from VirusTotal");
            return null;
        }
    }

    /// <summary>
    /// Batch check multiple hashes
    /// </summary>
    public async Task<Dictionary<string, VTFileReport?>> CheckHashesAsync(
        IEnumerable<string> hashes,
        CancellationToken cancellationToken = default)
    {
        var results = new Dictionary<string, VTFileReport?>();

        foreach (var hash in hashes)
        {
            if (cancellationToken.IsCancellationRequested)
                break;

            results[hash] = await CheckHashAsync(hash, cancellationToken);
        }

        return results;
    }

    private async Task WaitForRateLimitAsync(CancellationToken cancellationToken)
    {
        await _rateLimiter.WaitAsync(cancellationToken);

        try
        {
            var now = DateTime.Now;

            // Reset counter if minute has passed
            if (now - _lastRequestTime > _rateLimitWindow)
            {
                _requestsThisMinute = 0;
                _lastRequestTime = now;
            }

            // Wait if we've exceeded rate limit
            if (_requestsThisMinute >= MaxRequestsPerMinute)
            {
                var waitTime = _rateLimitWindow - (now - _lastRequestTime);
                if (waitTime > TimeSpan.Zero)
                {
                    _logger?.LogDebug("Rate limit reached, waiting {WaitTime}", waitTime);
                    await Task.Delay(waitTime, cancellationToken);
                    _requestsThisMinute = 0;
                    _lastRequestTime = DateTime.Now;
                }
            }

            _requestsThisMinute++;
        }
        finally
        {
            _rateLimiter.Release();
        }
    }

    private VTFileReport? ParseFileReport(string json)
    {
        try
        {
            var doc = JsonDocument.Parse(json);
            var data = doc.RootElement.GetProperty("data");
            var attributes = data.GetProperty("attributes");

            var stats = attributes.GetProperty("last_analysis_stats");

            return new VTFileReport
            {
                Hash = data.TryGetProperty("id", out var id) ? id.GetString() : null,
                FileName = attributes.TryGetProperty("meaningful_name", out var name) ? name.GetString() : null,
                Malicious = stats.GetProperty("malicious").GetInt32(),
                Suspicious = stats.GetProperty("suspicious").GetInt32(),
                Harmless = stats.GetProperty("harmless").GetInt32(),
                Undetected = stats.GetProperty("undetected").GetInt32(),
                TotalEngines = stats.GetProperty("malicious").GetInt32() +
                              stats.GetProperty("suspicious").GetInt32() +
                              stats.GetProperty("harmless").GetInt32() +
                              stats.GetProperty("undetected").GetInt32(),
                LastAnalysisDate = attributes.TryGetProperty("last_analysis_date", out var date)
                    ? DateTimeOffset.FromUnixTimeSeconds(date.GetInt64()).DateTime
                    : null
            };
        }
        catch (Exception ex)
        {
            _logger?.LogWarning(ex, "Failed to parse VT file report");
            return null;
        }
    }

    private VTUrlReport? ParseUrlReport(string json)
    {
        try
        {
            var doc = JsonDocument.Parse(json);
            var data = doc.RootElement.GetProperty("data");
            var attributes = data.GetProperty("attributes");

            var stats = attributes.GetProperty("last_analysis_stats");

            return new VTUrlReport
            {
                Url = attributes.TryGetProperty("url", out var url) ? url.GetString() : null,
                Malicious = stats.GetProperty("malicious").GetInt32(),
                Suspicious = stats.GetProperty("suspicious").GetInt32(),
                Harmless = stats.GetProperty("harmless").GetInt32(),
                Undetected = stats.GetProperty("undetected").GetInt32()
            };
        }
        catch (Exception ex)
        {
            _logger?.LogWarning(ex, "Failed to parse VT URL report");
            return null;
        }
    }

    private VTFileReport? ParseAnalysisReport(string json)
    {
        try
        {
            var doc = JsonDocument.Parse(json);
            var data = doc.RootElement.GetProperty("data");
            var attributes = data.GetProperty("attributes");

            var status = attributes.GetProperty("status").GetString();

            if (status != "completed")
            {
                return new VTFileReport { Status = status };
            }

            var stats = attributes.GetProperty("stats");

            return new VTFileReport
            {
                Status = status,
                Malicious = stats.GetProperty("malicious").GetInt32(),
                Suspicious = stats.GetProperty("suspicious").GetInt32(),
                Harmless = stats.GetProperty("harmless").GetInt32(),
                Undetected = stats.GetProperty("undetected").GetInt32()
            };
        }
        catch (Exception ex)
        {
            _logger?.LogWarning(ex, "Failed to parse VT analysis report");
            return null;
        }
    }

    /// <summary>
    /// Clears the cache
    /// </summary>
    public void ClearCache()
    {
        _cache.Clear();
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        _httpClient.Dispose();
        _rateLimiter.Dispose();

        GC.SuppressFinalize(this);
    }
}

#region Models

public class VTFileReport
{
    public string? Hash { get; set; }
    public string? FileName { get; set; }
    public string? Status { get; set; }
    public int Malicious { get; set; }
    public int Suspicious { get; set; }
    public int Harmless { get; set; }
    public int Undetected { get; set; }
    public int TotalEngines { get; set; }
    public DateTime? LastAnalysisDate { get; set; }

    public bool IsMalicious => Malicious > 0;
    public bool IsSuspicious => Suspicious > 0 || Malicious > 0;
    public double DetectionRate => TotalEngines > 0 ? (double)Malicious / TotalEngines : 0;

    public string GetVerdict()
    {
        if (Malicious >= 10) return "Malicious";
        if (Malicious >= 5) return "Highly Suspicious";
        if (Malicious >= 1) return "Suspicious";
        if (Suspicious >= 3) return "Potentially Unwanted";
        return "Clean";
    }
}

public class VTUrlReport
{
    public string? Url { get; set; }
    public int Malicious { get; set; }
    public int Suspicious { get; set; }
    public int Harmless { get; set; }
    public int Undetected { get; set; }

    public bool IsMalicious => Malicious > 0;
}

public class VTScanResultEventArgs : EventArgs
{
    public string? FilePath { get; set; }
    public string? Hash { get; set; }
    public VTFileReport? Report { get; set; }
}

public class VTErrorEventArgs : EventArgs
{
    public string Message { get; set; } = "";
}

internal class VTCacheEntry
{
    public VTFileReport? Report { get; }
    public VTUrlReport? UrlReport { get; }
    public DateTime ExpiresAt { get; }

    public bool IsExpired => DateTime.Now > ExpiresAt;

    public VTCacheEntry(VTFileReport report, TimeSpan expiration)
    {
        Report = report;
        ExpiresAt = DateTime.Now + expiration;
    }

    public VTCacheEntry(VTUrlReport report, TimeSpan expiration)
    {
        UrlReport = report;
        ExpiresAt = DateTime.Now + expiration;
    }
}

#endregion
