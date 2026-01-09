using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace SkidrowKiller.Services;

/// <summary>
/// Multi-source Threat Intelligence Service
/// Downloads and aggregates threat data from multiple free/open sources:
/// - abuse.ch (MalwareBazaar, ThreatFox, URLhaus, Feodo Tracker)
/// - ClamAV signatures
/// - YARA rules from community repositories
/// - Hash databases (Team Cymru MHR, VirusShare)
/// </summary>
public class ThreatIntelligenceService : IDisposable
{
    private readonly ILogger<ThreatIntelligenceService>? _logger;
    private readonly HttpClient _httpClient;
    private readonly string _dataPath;
    private readonly string _cachePath;
    private bool _disposed;

    // Feed sources with their update frequencies
    private readonly List<ThreatFeed> _feeds;

    // Events
    public event EventHandler<ThreatIntelProgressEventArgs>? ProgressChanged;
    public event EventHandler<ThreatIntelCompleteEventArgs>? UpdateCompleted;
    public event EventHandler<string>? ErrorOccurred;

    // Status
    public bool IsUpdating { get; private set; }
    public DateTime LastUpdate { get; private set; }
    public ThreatIntelStats Stats { get; private set; } = new();

    public ThreatIntelligenceService(ILogger<ThreatIntelligenceService>? logger = null)
    {
        _logger = logger;

        _httpClient = new HttpClient();
        _httpClient.DefaultRequestHeaders.Add("User-Agent", "SkidrowKiller-ThreatIntel/1.0");
        _httpClient.Timeout = TimeSpan.FromMinutes(5);

        var appData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        _dataPath = Path.Combine(appData, "SkidrowKiller", "ThreatIntel");
        _cachePath = Path.Combine(_dataPath, "cache");
        Directory.CreateDirectory(_dataPath);
        Directory.CreateDirectory(_cachePath);

        // Initialize feeds
        _feeds = InitializeFeeds();

        // Load last update time
        LoadStats();
    }

    private List<ThreatFeed> InitializeFeeds()
    {
        return new List<ThreatFeed>
        {
            // === abuse.ch Feeds (Free, no API key required) ===
            new ThreatFeed
            {
                Id = "malwarebazaar_md5",
                Name = "MalwareBazaar MD5 Hashes",
                Category = FeedCategory.HashDatabase,
                Url = "https://bazaar.abuse.ch/export/txt/md5/recent/",
                UpdateInterval = TimeSpan.FromHours(1),
                RequiredTier = LicenseTier.Free,
                Parser = ParseMalwareBazaarHashes
            },
            new ThreatFeed
            {
                Id = "malwarebazaar_sha256",
                Name = "MalwareBazaar SHA256 Hashes",
                Category = FeedCategory.HashDatabase,
                Url = "https://bazaar.abuse.ch/export/txt/sha256/recent/",
                UpdateInterval = TimeSpan.FromHours(1),
                RequiredTier = LicenseTier.Free,
                Parser = ParseMalwareBazaarHashes
            },
            new ThreatFeed
            {
                Id = "threatfox_iocs",
                Name = "ThreatFox IOCs",
                Category = FeedCategory.IOC,
                Url = "https://threatfox.abuse.ch/export/json/recent/",
                UpdateInterval = TimeSpan.FromHours(1),
                RequiredTier = LicenseTier.Free,
                Parser = ParseThreatFoxIOCs
            },
            new ThreatFeed
            {
                Id = "urlhaus_urls",
                Name = "URLhaus Malicious URLs",
                Category = FeedCategory.MaliciousURL,
                Url = "https://urlhaus.abuse.ch/downloads/csv_recent/",
                UpdateInterval = TimeSpan.FromHours(1),
                RequiredTier = LicenseTier.Free,
                Parser = ParseURLhausURLs
            },
            new ThreatFeed
            {
                Id = "feodo_ips",
                Name = "Feodo Tracker C&C IPs",
                Category = FeedCategory.MaliciousIP,
                Url = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
                UpdateInterval = TimeSpan.FromHours(6),
                RequiredTier = LicenseTier.Free,
                Parser = ParseFeodoIPs
            },
            new ThreatFeed
            {
                Id = "sslbl_fingerprints",
                Name = "SSL Blacklist JA3 Fingerprints",
                Category = FeedCategory.SSLFingerprint,
                Url = "https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv",
                UpdateInterval = TimeSpan.FromHours(12),
                RequiredTier = LicenseTier.Pro,
                Parser = ParseSSLFingerprints
            },

            // === YARA Rules (GitHub repositories) ===
            new ThreatFeed
            {
                Id = "yara_rules_main",
                Name = "Yara-Rules Community",
                Category = FeedCategory.YaraRules,
                Url = "https://github.com/Yara-Rules/rules/archive/refs/heads/master.zip",
                UpdateInterval = TimeSpan.FromDays(1),
                RequiredTier = LicenseTier.Pro,
                Parser = ParseYaraRulesZip
            },
            new ThreatFeed
            {
                Id = "signature_base",
                Name = "Neo23x0 Signature Base",
                Category = FeedCategory.YaraRules,
                Url = "https://github.com/Neo23x0/signature-base/archive/refs/heads/master.zip",
                UpdateInterval = TimeSpan.FromDays(1),
                RequiredTier = LicenseTier.Pro,
                Parser = ParseSignatureBaseZip
            },
            new ThreatFeed
            {
                Id = "reversinglabs_yara",
                Name = "ReversingLabs YARA",
                Category = FeedCategory.YaraRules,
                Url = "https://github.com/reversinglabs/reversinglabs-yara-rules/archive/refs/heads/develop.zip",
                UpdateInterval = TimeSpan.FromDays(1),
                RequiredTier = LicenseTier.Enterprise,
                Parser = ParseReversingLabsYaraZip
            },

            // === ClamAV (Open Source) ===
            new ThreatFeed
            {
                Id = "clamav_daily",
                Name = "ClamAV Daily Signatures",
                Category = FeedCategory.Signatures,
                Url = "https://database.clamav.net/daily.cvd",
                UpdateInterval = TimeSpan.FromDays(1),
                RequiredTier = LicenseTier.Pro,
                Parser = ParseClamAVSignatures
            },

            // === Additional Hash Sources ===
            new ThreatFeed
            {
                Id = "virusshare_hashes",
                Name = "VirusShare Hash List",
                Category = FeedCategory.HashDatabase,
                Url = "https://virusshare.com/hashfiles/VirusShare_00000.md5",
                UpdateInterval = TimeSpan.FromDays(7),
                RequiredTier = LicenseTier.Enterprise,
                Parser = ParseVirusShareHashes
            },

            // === Botnet C&C ===
            new ThreatFeed
            {
                Id = "feodo_recommended",
                Name = "Feodo Recommended Blocklist",
                Category = FeedCategory.MaliciousIP,
                Url = "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt",
                UpdateInterval = TimeSpan.FromHours(6),
                RequiredTier = LicenseTier.Free,
                Parser = ParseFeodoIPs
            },

            // === SSL Certificates ===
            new ThreatFeed
            {
                Id = "sslbl_ips",
                Name = "SSL Blacklist IPs",
                Category = FeedCategory.MaliciousIP,
                Url = "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt",
                UpdateInterval = TimeSpan.FromHours(12),
                RequiredTier = LicenseTier.Pro,
                Parser = ParseSSLIPBlacklist
            }
        };
    }

    /// <summary>
    /// Update all feeds based on license tier
    /// </summary>
    public async Task<ThreatIntelUpdateResult> UpdateAllAsync(
        LicenseTier tier,
        CancellationToken cancellationToken = default)
    {
        if (IsUpdating)
        {
            return new ThreatIntelUpdateResult
            {
                Success = false,
                Message = "Update already in progress"
            };
        }

        IsUpdating = true;
        var result = new ThreatIntelUpdateResult();
        var startTime = DateTime.Now;

        try
        {
            // Filter feeds based on tier
            var availableFeeds = _feeds.Where(f => f.RequiredTier <= tier).ToList();
            var totalFeeds = availableFeeds.Count;
            var completedFeeds = 0;
            var skippedFeeds = 0;

            _logger?.LogInformation("Starting threat intelligence update. {Count} feeds available for {Tier} tier",
                totalFeeds, tier);

            ReportProgress(0, $"Starting update ({totalFeeds} feeds)...", "Initializing", 0, totalFeeds);

            foreach (var feed in availableFeeds)
            {
                cancellationToken.ThrowIfCancellationRequested();

                try
                {
                    // Check if feed needs update
                    if (!NeedsUpdate(feed))
                    {
                        skippedFeeds++;
                        completedFeeds++;
                        var skipProgress = (int)((completedFeeds / (double)totalFeeds) * 100);
                        ReportProgress(skipProgress, $"Skipped {feed.Name} (up to date)", feed.Name, completedFeeds, totalFeeds);
                        continue;
                    }

                    ReportProgress(
                        (int)((completedFeeds / (double)totalFeeds) * 100),
                        $"Downloading {feed.Name}...",
                        feed.Name,
                        completedFeeds,
                        totalFeeds);

                    // Download feed
                    var feedResult = await DownloadAndParseFeedAsync(feed, cancellationToken);

                    if (feedResult.Success)
                    {
                        result.FeedsUpdated++;
                        result.NewHashes += feedResult.NewHashes;
                        result.NewUrls += feedResult.NewUrls;
                        result.NewIPs += feedResult.NewIPs;
                        result.NewYaraRules += feedResult.NewYaraRules;

                        feed.LastUpdate = DateTime.Now;
                        feed.LastItemCount = feedResult.TotalItems;

                        _logger?.LogInformation("Updated {Feed}: {Items} items", feed.Name, feedResult.TotalItems);
                    }
                    else
                    {
                        result.FeedsFailed++;
                        result.Errors.Add($"{feed.Name}: {feedResult.Error}");
                        _logger?.LogWarning("Failed to update {Feed}: {Error}", feed.Name, feedResult.Error);
                    }

                    completedFeeds++;
                }
                catch (Exception ex)
                {
                    result.FeedsFailed++;
                    result.Errors.Add($"{feed.Name}: {ex.Message}");
                    _logger?.LogError(ex, "Error updating feed {Feed}", feed.Name);
                    completedFeeds++;
                }
            }

            // Save updated stats
            Stats.LastUpdate = DateTime.Now;
            Stats.TotalHashes += result.NewHashes;
            Stats.TotalUrls += result.NewUrls;
            Stats.TotalIPs += result.NewIPs;
            Stats.TotalYaraRules += result.NewYaraRules;
            SaveStats();

            result.Success = result.FeedsFailed == 0;
            result.Message = $"Updated {result.FeedsUpdated} feeds, {result.FeedsFailed} failed, {skippedFeeds} skipped";
            result.Duration = DateTime.Now - startTime;

            ReportProgress(100, result.Message, "Complete", totalFeeds, totalFeeds);

            UpdateCompleted?.Invoke(this, new ThreatIntelCompleteEventArgs
            {
                Result = result,
                Stats = Stats
            });
        }
        catch (OperationCanceledException)
        {
            result.Success = false;
            result.Message = "Update cancelled";
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.Message = $"Update failed: {ex.Message}";
            _logger?.LogError(ex, "Threat intelligence update failed");
            ErrorOccurred?.Invoke(this, ex.Message);
        }
        finally
        {
            IsUpdating = false;
            LastUpdate = DateTime.Now;
        }

        return result;
    }

    /// <summary>
    /// Update a specific feed
    /// </summary>
    public async Task<FeedUpdateResult> UpdateFeedAsync(
        string feedId,
        CancellationToken cancellationToken = default)
    {
        var feed = _feeds.FirstOrDefault(f => f.Id == feedId);
        if (feed == null)
        {
            return new FeedUpdateResult { Success = false, Error = "Feed not found" };
        }

        return await DownloadAndParseFeedAsync(feed, cancellationToken);
    }

    private async Task<FeedUpdateResult> DownloadAndParseFeedAsync(
        ThreatFeed feed,
        CancellationToken cancellationToken)
    {
        var result = new FeedUpdateResult();

        try
        {
            // Download content
            var response = await _httpClient.GetAsync(feed.Url, cancellationToken);
            response.EnsureSuccessStatusCode();

            var cachePath = GetCachePath(feed);

            if (feed.Url.EndsWith(".zip"))
            {
                // Handle ZIP files
                var zipBytes = await response.Content.ReadAsByteArrayAsync(cancellationToken);
                var zipPath = cachePath + ".zip";
                await File.WriteAllBytesAsync(zipPath, zipBytes, cancellationToken);

                result = await feed.Parser(zipPath, feed);
            }
            else
            {
                // Handle text/CSV files
                var content = await response.Content.ReadAsStringAsync(cancellationToken);
                await File.WriteAllTextAsync(cachePath, content, cancellationToken);

                result = await feed.Parser(cachePath, feed);
            }

            result.Success = true;
        }
        catch (HttpRequestException ex)
        {
            result.Success = false;
            result.Error = $"Network error: {ex.Message}";
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.Error = ex.Message;
        }

        return result;
    }

    private bool NeedsUpdate(ThreatFeed feed)
    {
        if (feed.LastUpdate == DateTime.MinValue)
            return true;

        return (DateTime.Now - feed.LastUpdate) > feed.UpdateInterval;
    }

    private string GetCachePath(ThreatFeed feed)
    {
        return Path.Combine(_cachePath, $"{feed.Id}.dat");
    }

    private void ReportProgress(int percent, string status, string currentFeed, int completed, int total)
    {
        ProgressChanged?.Invoke(this, new ThreatIntelProgressEventArgs
        {
            PercentComplete = percent,
            Status = status,
            CurrentFeed = currentFeed,
            FeedsCompleted = completed,
            TotalFeeds = total
        });
    }

    #region Feed Parsers

    private async Task<FeedUpdateResult> ParseMalwareBazaarHashes(string path, ThreatFeed feed)
    {
        var result = new FeedUpdateResult();
        var existingHashes = await LoadExistingHashesAsync(feed.Id);
        var newHashes = new HashSet<string>();

        var lines = await File.ReadAllLinesAsync(path);
        foreach (var line in lines)
        {
            if (string.IsNullOrWhiteSpace(line) || line.StartsWith("#"))
                continue;

            var hash = line.Trim().ToLowerInvariant();
            if (hash.Length == 32 || hash.Length == 64) // MD5 or SHA256
            {
                if (!existingHashes.Contains(hash))
                {
                    newHashes.Add(hash);
                }
            }
        }

        // Save new hashes
        await SaveHashesAsync(feed.Id, existingHashes.Union(newHashes));

        result.TotalItems = existingHashes.Count + newHashes.Count;
        result.NewHashes = newHashes.Count;
        return result;
    }

    private async Task<FeedUpdateResult> ParseThreatFoxIOCs(string path, ThreatFeed feed)
    {
        var result = new FeedUpdateResult();

        try
        {
            var json = await File.ReadAllTextAsync(path);
            using var doc = JsonDocument.Parse(json);

            if (doc.RootElement.TryGetProperty("data", out var dataArray))
            {
                var hashes = new List<string>();
                var urls = new List<string>();
                var ips = new List<string>();

                foreach (var ioc in dataArray.EnumerateArray())
                {
                    if (ioc.TryGetProperty("ioc_type", out var typeElement))
                    {
                        var type = typeElement.GetString();
                        var value = ioc.GetProperty("ioc").GetString();

                        if (string.IsNullOrEmpty(value)) continue;

                        switch (type)
                        {
                            case "md5_hash":
                            case "sha256_hash":
                                hashes.Add(value);
                                break;
                            case "url":
                                urls.Add(value);
                                break;
                            case "ip:port":
                                ips.Add(value.Split(':')[0]);
                                break;
                        }
                    }
                }

                await SaveHashesAsync($"{feed.Id}_hashes", hashes);
                await SaveUrlsAsync($"{feed.Id}_urls", urls);
                await SaveIPsAsync($"{feed.Id}_ips", ips);

                result.NewHashes = hashes.Count;
                result.NewUrls = urls.Count;
                result.NewIPs = ips.Count;
                result.TotalItems = hashes.Count + urls.Count + ips.Count;
            }
        }
        catch (Exception ex)
        {
            result.Error = ex.Message;
        }

        return result;
    }

    private async Task<FeedUpdateResult> ParseURLhausURLs(string path, ThreatFeed feed)
    {
        var result = new FeedUpdateResult();
        var urls = new List<string>();

        var lines = await File.ReadAllLinesAsync(path);
        foreach (var line in lines)
        {
            if (string.IsNullOrWhiteSpace(line) || line.StartsWith("#"))
                continue;

            var parts = line.Split(',');
            if (parts.Length >= 3)
            {
                var url = parts[2].Trim('"');
                if (!string.IsNullOrEmpty(url))
                {
                    urls.Add(url);
                }
            }
        }

        await SaveUrlsAsync(feed.Id, urls);
        result.NewUrls = urls.Count;
        result.TotalItems = urls.Count;
        return result;
    }

    private async Task<FeedUpdateResult> ParseFeodoIPs(string path, ThreatFeed feed)
    {
        var result = new FeedUpdateResult();
        var ips = new List<string>();

        var lines = await File.ReadAllLinesAsync(path);
        foreach (var line in lines)
        {
            if (string.IsNullOrWhiteSpace(line) || line.StartsWith("#"))
                continue;

            var ip = line.Trim();
            if (IsValidIP(ip))
            {
                ips.Add(ip);
            }
        }

        await SaveIPsAsync(feed.Id, ips);
        result.NewIPs = ips.Count;
        result.TotalItems = ips.Count;
        return result;
    }

    private async Task<FeedUpdateResult> ParseSSLFingerprints(string path, ThreatFeed feed)
    {
        var result = new FeedUpdateResult();
        var fingerprints = new List<string>();

        var lines = await File.ReadAllLinesAsync(path);
        foreach (var line in lines)
        {
            if (string.IsNullOrWhiteSpace(line) || line.StartsWith("#"))
                continue;

            var parts = line.Split(',');
            if (parts.Length >= 1)
            {
                fingerprints.Add(parts[0].Trim());
            }
        }

        var fingerprintPath = Path.Combine(_dataPath, $"{feed.Id}.txt");
        await File.WriteAllLinesAsync(fingerprintPath, fingerprints);

        result.TotalItems = fingerprints.Count;
        return result;
    }

    private async Task<FeedUpdateResult> ParseSSLIPBlacklist(string path, ThreatFeed feed)
    {
        return await ParseFeodoIPs(path, feed);
    }

    private async Task<FeedUpdateResult> ParseYaraRulesZip(string zipPath, ThreatFeed feed)
    {
        var result = new FeedUpdateResult();
        var yaraPath = Path.Combine(_dataPath, "yara", feed.Id);

        try
        {
            if (Directory.Exists(yaraPath))
                Directory.Delete(yaraPath, true);
            Directory.CreateDirectory(yaraPath);

            using var archive = ZipFile.OpenRead(zipPath);
            var yaraFiles = archive.Entries
                .Where(e => e.Name.EndsWith(".yar") || e.Name.EndsWith(".yara"))
                .ToList();

            foreach (var entry in yaraFiles)
            {
                var destPath = Path.Combine(yaraPath, entry.Name);
                entry.ExtractToFile(destPath, true);
                result.NewYaraRules++;
            }

            result.TotalItems = yaraFiles.Count;
        }
        catch (Exception ex)
        {
            result.Error = ex.Message;
        }

        return result;
    }

    private async Task<FeedUpdateResult> ParseSignatureBaseZip(string zipPath, ThreatFeed feed)
    {
        return await ParseYaraRulesZip(zipPath, feed);
    }

    private async Task<FeedUpdateResult> ParseReversingLabsYaraZip(string zipPath, ThreatFeed feed)
    {
        return await ParseYaraRulesZip(zipPath, feed);
    }

    private async Task<FeedUpdateResult> ParseClamAVSignatures(string path, ThreatFeed feed)
    {
        var result = new FeedUpdateResult();

        // ClamAV CVD files are compressed and need special handling
        // For now, just record that we have the file
        var fileInfo = new FileInfo(path);
        result.TotalItems = 1;
        result.Success = fileInfo.Exists && fileInfo.Length > 0;

        return result;
    }

    private async Task<FeedUpdateResult> ParseVirusShareHashes(string path, ThreatFeed feed)
    {
        return await ParseMalwareBazaarHashes(path, feed);
    }

    #endregion

    #region Storage Helpers

    private async Task<HashSet<string>> LoadExistingHashesAsync(string feedId)
    {
        var hashPath = Path.Combine(_dataPath, $"{feedId}_hashes.txt");
        var hashes = new HashSet<string>();

        if (File.Exists(hashPath))
        {
            var lines = await File.ReadAllLinesAsync(hashPath);
            foreach (var line in lines)
            {
                hashes.Add(line.Trim().ToLowerInvariant());
            }
        }

        return hashes;
    }

    private async Task SaveHashesAsync(string feedId, IEnumerable<string> hashes)
    {
        var hashPath = Path.Combine(_dataPath, $"{feedId}_hashes.txt");
        await File.WriteAllLinesAsync(hashPath, hashes);
    }

    private async Task SaveUrlsAsync(string feedId, IEnumerable<string> urls)
    {
        var urlPath = Path.Combine(_dataPath, $"{feedId}_urls.txt");
        await File.WriteAllLinesAsync(urlPath, urls);
    }

    private async Task SaveIPsAsync(string feedId, IEnumerable<string> ips)
    {
        var ipPath = Path.Combine(_dataPath, $"{feedId}_ips.txt");
        await File.WriteAllLinesAsync(ipPath, ips);
    }

    private bool IsValidIP(string ip)
    {
        return System.Net.IPAddress.TryParse(ip, out _);
    }

    private void LoadStats()
    {
        var statsPath = Path.Combine(_dataPath, "stats.json");
        if (File.Exists(statsPath))
        {
            try
            {
                var json = File.ReadAllText(statsPath);
                Stats = JsonSerializer.Deserialize<ThreatIntelStats>(json) ?? new ThreatIntelStats();

                // Restore per-feed LastUpdate from saved stats
                foreach (var feed in _feeds)
                {
                    if (Stats.FeedLastUpdates.TryGetValue(feed.Id, out var lastUpdate))
                    {
                        feed.LastUpdate = lastUpdate;
                    }
                }
            }
            catch
            {
                Stats = new ThreatIntelStats();
            }
        }
    }

    private void SaveStats()
    {
        // Save per-feed LastUpdate times to stats
        foreach (var feed in _feeds)
        {
            if (feed.LastUpdate != DateTime.MinValue)
            {
                Stats.FeedLastUpdates[feed.Id] = feed.LastUpdate;
            }
        }

        var statsPath = Path.Combine(_dataPath, "stats.json");
        var json = JsonSerializer.Serialize(Stats, new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(statsPath, json);
    }

    #endregion

    #region Query Methods

    /// <summary>
    /// Check if a hash is in the threat database
    /// </summary>
    public async Task<ThreatLookupResult> LookupHashAsync(string hash)
    {
        hash = hash.ToLowerInvariant();
        var result = new ThreatLookupResult { Query = hash };

        foreach (var feed in _feeds.Where(f => f.Category == FeedCategory.HashDatabase))
        {
            var hashes = await LoadExistingHashesAsync(feed.Id);
            if (hashes.Contains(hash))
            {
                result.Found = true;
                result.Source = feed.Name;
                result.ThreatType = "Malware Hash";
                break;
            }
        }

        return result;
    }

    /// <summary>
    /// Check if a URL is in the threat database
    /// </summary>
    public async Task<ThreatLookupResult> LookupUrlAsync(string url)
    {
        var result = new ThreatLookupResult { Query = url };

        foreach (var feed in _feeds.Where(f => f.Category == FeedCategory.MaliciousURL))
        {
            var urlPath = Path.Combine(_dataPath, $"{feed.Id}_urls.txt");
            if (File.Exists(urlPath))
            {
                var urls = await File.ReadAllLinesAsync(urlPath);
                if (urls.Any(u => url.Contains(u, StringComparison.OrdinalIgnoreCase)))
                {
                    result.Found = true;
                    result.Source = feed.Name;
                    result.ThreatType = "Malicious URL";
                    break;
                }
            }
        }

        return result;
    }

    /// <summary>
    /// Check if an IP is in the threat database
    /// </summary>
    public async Task<ThreatLookupResult> LookupIPAsync(string ip)
    {
        var result = new ThreatLookupResult { Query = ip };

        foreach (var feed in _feeds.Where(f => f.Category == FeedCategory.MaliciousIP))
        {
            var ipPath = Path.Combine(_dataPath, $"{feed.Id}_ips.txt");
            if (File.Exists(ipPath))
            {
                var ips = await File.ReadAllLinesAsync(ipPath);
                if (ips.Contains(ip))
                {
                    result.Found = true;
                    result.Source = feed.Name;
                    result.ThreatType = "C&C Server / Malicious IP";
                    break;
                }
            }
        }

        return result;
    }

    /// <summary>
    /// Get all available feeds
    /// </summary>
    public IReadOnlyList<ThreatFeed> GetFeeds() => _feeds.AsReadOnly();

    /// <summary>
    /// Get feeds available for a specific tier
    /// </summary>
    public IReadOnlyList<ThreatFeed> GetFeedsForTier(LicenseTier tier)
    {
        return _feeds.Where(f => f.RequiredTier <= tier).ToList().AsReadOnly();
    }

    #endregion

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _httpClient.Dispose();
        GC.SuppressFinalize(this);
    }
}

#region Models

// Note: LicenseTier enum is defined in LicenseService.cs
// We use it here for feed tier requirements

public enum FeedCategory
{
    HashDatabase,
    IOC,
    MaliciousURL,
    MaliciousIP,
    SSLFingerprint,
    YaraRules,
    Signatures
}

public class ThreatFeed
{
    public string Id { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public FeedCategory Category { get; set; }
    public string Url { get; set; } = string.Empty;
    public TimeSpan UpdateInterval { get; set; }
    public LicenseTier RequiredTier { get; set; }
    public DateTime LastUpdate { get; set; }
    public int LastItemCount { get; set; }
    public Func<string, ThreatFeed, Task<FeedUpdateResult>> Parser { get; set; } = null!;

    public string TierDisplay => RequiredTier switch
    {
        LicenseTier.Free => "Free",
        LicenseTier.Pro => "Pro",
        LicenseTier.Enterprise => "Enterprise",
        _ => "Unknown"
    };

    public string CategoryDisplay => Category switch
    {
        FeedCategory.HashDatabase => "Hash Database",
        FeedCategory.IOC => "IOCs",
        FeedCategory.MaliciousURL => "Malicious URLs",
        FeedCategory.MaliciousIP => "Malicious IPs",
        FeedCategory.SSLFingerprint => "SSL Fingerprints",
        FeedCategory.YaraRules => "YARA Rules",
        FeedCategory.Signatures => "AV Signatures",
        _ => "Other"
    };
}

public class FeedUpdateResult
{
    public bool Success { get; set; }
    public string? Error { get; set; }
    public int TotalItems { get; set; }
    public int NewHashes { get; set; }
    public int NewUrls { get; set; }
    public int NewIPs { get; set; }
    public int NewYaraRules { get; set; }
}

public class ThreatIntelUpdateResult
{
    public bool Success { get; set; }
    public string Message { get; set; } = string.Empty;
    public int FeedsUpdated { get; set; }
    public int FeedsFailed { get; set; }
    public int NewHashes { get; set; }
    public int NewUrls { get; set; }
    public int NewIPs { get; set; }
    public int NewYaraRules { get; set; }
    public TimeSpan Duration { get; set; }
    public List<string> Errors { get; set; } = new();
}

public class ThreatIntelStats
{
    public DateTime LastUpdate { get; set; }
    public int TotalHashes { get; set; }
    public int TotalUrls { get; set; }
    public int TotalIPs { get; set; }
    public int TotalYaraRules { get; set; }

    /// <summary>
    /// Per-feed last update timestamps (feedId -> lastUpdate)
    /// </summary>
    public Dictionary<string, DateTime> FeedLastUpdates { get; set; } = new();

    public string TotalItemsDisplay => $"{TotalHashes + TotalUrls + TotalIPs + TotalYaraRules:N0}";
}

public class ThreatIntelProgressEventArgs : EventArgs
{
    public int PercentComplete { get; set; }
    public string Status { get; set; } = string.Empty;
    public string CurrentFeed { get; set; } = string.Empty;
    public int FeedsCompleted { get; set; }
    public int TotalFeeds { get; set; }
}

public class ThreatIntelCompleteEventArgs : EventArgs
{
    public ThreatIntelUpdateResult Result { get; set; } = null!;
    public ThreatIntelStats Stats { get; set; } = null!;
}

public class ThreatLookupResult
{
    public string Query { get; set; } = string.Empty;
    public bool Found { get; set; }
    public string? Source { get; set; }
    public string? ThreatType { get; set; }
}

#endregion
