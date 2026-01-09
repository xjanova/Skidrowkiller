using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace SkidrowKiller.Services
{
    /// <summary>
    /// Browser Protection Service - Protects browsers from malicious extensions,
    /// hijacked settings, and unwanted modifications.
    /// </summary>
    public class BrowserProtectionService : IDisposable
    {
        private readonly string _configPath;
        private CancellationTokenSource? _cts;
        private bool _isEnabled;
        private bool _isDisposed;
        private readonly List<BrowserInfo> _browsers = new();
        private readonly HashSet<string> _maliciousExtensions = new(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _hijackedSearchEngines = new(StringComparer.OrdinalIgnoreCase);

        // Known malicious browser extension IDs
        private static readonly HashSet<string> KnownMaliciousExtensions = new(StringComparer.OrdinalIgnoreCase)
        {
            // Adware extensions
            "superfish", "wajam", "istartsurf", "ask toolbar", "babylon toolbar",
            "conduit", "searchqu", "sweetim", "mywebsearch", "incredibar",
            // Cryptominers
            "coinhive", "cryptoloot", "jsecoin",
            // Data stealers
            "web companion", "safesear.ch"
        };

        // Known hijacked/unwanted search engines
        private static readonly HashSet<string> KnownHijackedSearchEngines = new(StringComparer.OrdinalIgnoreCase)
        {
            "search.yahoo.com/yhs", "searchnu.com", "search.conduit.com",
            "isearch.babylon.com", "delta-search.com", "do-search.com",
            "websearch.ask.com", "searchgol.com", "istart.webssearches.com",
            "search.myway.com", "search.certified-toolbar.com", "search.imesh.net"
        };

        public event EventHandler<BrowserThreatEventArgs>? ThreatDetected;
        public event EventHandler<string>? LogAdded;

        public bool IsEnabled => _isEnabled;
        public IReadOnlyList<BrowserInfo> DetectedBrowsers => _browsers.AsReadOnly();

        public BrowserProtectionService()
        {
            _configPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "SkidrowKiller", "browser_protection.json");

            _maliciousExtensions = new HashSet<string>(KnownMaliciousExtensions, StringComparer.OrdinalIgnoreCase);
            _hijackedSearchEngines = new HashSet<string>(KnownHijackedSearchEngines, StringComparer.OrdinalIgnoreCase);
        }

        public void Start()
        {
            if (_isEnabled) return;
            _isEnabled = true;
            _cts = new CancellationTokenSource();

            // Detect installed browsers
            DetectBrowsers();

            // Start monitoring
            Task.Run(() => MonitorLoop(_cts.Token));

            RaiseLog("🌐 Browser Protection started");
        }

        public void Stop()
        {
            _cts?.Cancel();
            _isEnabled = false;
            RaiseLog("🌐 Browser Protection stopped");
        }

        private void DetectBrowsers()
        {
            _browsers.Clear();

            // Chrome
            var chromeProfile = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "Google", "Chrome", "User Data");
            if (Directory.Exists(chromeProfile))
            {
                _browsers.Add(new BrowserInfo
                {
                    Name = "Google Chrome",
                    Type = BrowserType.Chrome,
                    ProfilePath = chromeProfile,
                    ExtensionsPath = Path.Combine(chromeProfile, "Default", "Extensions")
                });
            }

            // Edge
            var edgeProfile = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "Microsoft", "Edge", "User Data");
            if (Directory.Exists(edgeProfile))
            {
                _browsers.Add(new BrowserInfo
                {
                    Name = "Microsoft Edge",
                    Type = BrowserType.Edge,
                    ProfilePath = edgeProfile,
                    ExtensionsPath = Path.Combine(edgeProfile, "Default", "Extensions")
                });
            }

            // Firefox
            var firefoxProfile = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "Mozilla", "Firefox", "Profiles");
            if (Directory.Exists(firefoxProfile))
            {
                var profiles = Directory.GetDirectories(firefoxProfile);
                foreach (var profile in profiles)
                {
                    _browsers.Add(new BrowserInfo
                    {
                        Name = "Mozilla Firefox",
                        Type = BrowserType.Firefox,
                        ProfilePath = profile,
                        ExtensionsPath = Path.Combine(profile, "extensions")
                    });
                }
            }

            // Brave
            var braveProfile = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "BraveSoftware", "Brave-Browser", "User Data");
            if (Directory.Exists(braveProfile))
            {
                _browsers.Add(new BrowserInfo
                {
                    Name = "Brave",
                    Type = BrowserType.Brave,
                    ProfilePath = braveProfile,
                    ExtensionsPath = Path.Combine(braveProfile, "Default", "Extensions")
                });
            }

            // Opera
            var operaProfile = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "Opera Software", "Opera Stable");
            if (Directory.Exists(operaProfile))
            {
                _browsers.Add(new BrowserInfo
                {
                    Name = "Opera",
                    Type = BrowserType.Opera,
                    ProfilePath = operaProfile,
                    ExtensionsPath = Path.Combine(operaProfile, "Extensions")
                });
            }

            RaiseLog($"Detected {_browsers.Count} browser(s)");
        }

        private async Task MonitorLoop(CancellationToken token)
        {
            while (!token.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(60000, token); // Check every minute

                    foreach (var browser in _browsers)
                    {
                        await ScanBrowserAsync(browser, token);
                    }
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    RaiseLog($"Browser monitor error: {ex.Message}");
                }
            }
        }

        public async Task<BrowserScanResult> ScanBrowserAsync(BrowserInfo browser, CancellationToken token = default)
        {
            var result = new BrowserScanResult { Browser = browser };

            try
            {
                // Scan extensions
                if (!string.IsNullOrEmpty(browser.ExtensionsPath) && Directory.Exists(browser.ExtensionsPath))
                {
                    await ScanExtensionsAsync(browser, result, token);
                }

                // Check for hijacked settings (Chrome-based)
                if (browser.Type == BrowserType.Chrome || browser.Type == BrowserType.Edge ||
                    browser.Type == BrowserType.Brave)
                {
                    await CheckChromeSettingsAsync(browser, result, token);
                }

                // Check Firefox settings
                if (browser.Type == BrowserType.Firefox)
                {
                    await CheckFirefoxSettingsAsync(browser, result, token);
                }
            }
            catch (Exception ex)
            {
                result.Error = ex.Message;
            }

            return result;
        }

        private async Task ScanExtensionsAsync(BrowserInfo browser, BrowserScanResult result, CancellationToken token)
        {
            try
            {
                var extensionDirs = Directory.GetDirectories(browser.ExtensionsPath);

                foreach (var extDir in extensionDirs)
                {
                    if (token.IsCancellationRequested) break;

                    var extName = Path.GetFileName(extDir);
                    var manifestPath = FindManifest(extDir);

                    if (!string.IsNullOrEmpty(manifestPath))
                    {
                        try
                        {
                            var manifest = await File.ReadAllTextAsync(manifestPath, token);
                            var extInfo = ParseExtensionManifest(manifest, extDir);

                            if (extInfo != null)
                            {
                                // Check if extension is malicious
                                if (IsMaliciousExtension(extInfo))
                                {
                                    result.MaliciousExtensions.Add(extInfo);
                                    ThreatDetected?.Invoke(this, new BrowserThreatEventArgs
                                    {
                                        Browser = browser,
                                        ThreatType = BrowserThreatType.MaliciousExtension,
                                        Description = $"Malicious extension detected: {extInfo.Name}",
                                        Path = extDir
                                    });
                                }
                                else
                                {
                                    result.InstalledExtensions.Add(extInfo);
                                }
                            }
                        }
                        catch { }
                    }

                    result.ExtensionsScanned++;
                }
            }
            catch { }
        }

        private string? FindManifest(string extensionDir)
        {
            // Look in version subdirectories first
            var versionDirs = Directory.GetDirectories(extensionDir);
            foreach (var versionDir in versionDirs)
            {
                var manifest = Path.Combine(versionDir, "manifest.json");
                if (File.Exists(manifest)) return manifest;
            }

            // Check root
            var rootManifest = Path.Combine(extensionDir, "manifest.json");
            return File.Exists(rootManifest) ? rootManifest : null;
        }

        private ExtensionInfo? ParseExtensionManifest(string json, string path)
        {
            try
            {
                using var doc = JsonDocument.Parse(json);
                var root = doc.RootElement;

                return new ExtensionInfo
                {
                    Id = Path.GetFileName(path),
                    Name = root.TryGetProperty("name", out var name) ? name.GetString() ?? "Unknown" : "Unknown",
                    Version = root.TryGetProperty("version", out var ver) ? ver.GetString() ?? "" : "",
                    Description = root.TryGetProperty("description", out var desc) ? desc.GetString() ?? "" : "",
                    Path = path
                };
            }
            catch
            {
                return null;
            }
        }

        private bool IsMaliciousExtension(ExtensionInfo ext)
        {
            var name = ext.Name.ToLower();
            var desc = ext.Description.ToLower();

            // Check against known malicious patterns
            foreach (var pattern in _maliciousExtensions)
            {
                if (name.Contains(pattern.ToLower()) || desc.Contains(pattern.ToLower()))
                {
                    return true;
                }
            }

            // Check for suspicious permissions requests (would need manifest parsing)
            // Check for obfuscated code indicators

            return false;
        }

        private async Task CheckChromeSettingsAsync(BrowserInfo browser, BrowserScanResult result, CancellationToken token)
        {
            try
            {
                var prefsPath = Path.Combine(browser.ProfilePath, "Default", "Preferences");
                if (!File.Exists(prefsPath)) return;

                var prefs = await File.ReadAllTextAsync(prefsPath, token);
                using var doc = JsonDocument.Parse(prefs);
                var root = doc.RootElement;

                // Check search engine
                if (root.TryGetProperty("default_search_provider_data", out var searchData))
                {
                    if (searchData.TryGetProperty("template_url_data", out var urlData))
                    {
                        if (urlData.TryGetProperty("url", out var url))
                        {
                            var searchUrl = url.GetString() ?? "";
                            if (IsHijackedSearchEngine(searchUrl))
                            {
                                result.HijackedSettings.Add(new HijackedSetting
                                {
                                    Type = "Search Engine",
                                    CurrentValue = searchUrl,
                                    Description = "Search engine has been hijacked"
                                });
                                ThreatDetected?.Invoke(this, new BrowserThreatEventArgs
                                {
                                    Browser = browser,
                                    ThreatType = BrowserThreatType.SearchHijack,
                                    Description = $"Hijacked search engine: {searchUrl}"
                                });
                            }
                        }
                    }
                }

                // Check homepage
                if (root.TryGetProperty("homepage", out var homepage))
                {
                    var homeUrl = homepage.GetString() ?? "";
                    if (IsHijackedSearchEngine(homeUrl))
                    {
                        result.HijackedSettings.Add(new HijackedSetting
                        {
                            Type = "Homepage",
                            CurrentValue = homeUrl,
                            Description = "Homepage has been hijacked"
                        });
                    }
                }
            }
            catch { }
        }

        private async Task CheckFirefoxSettingsAsync(BrowserInfo browser, BrowserScanResult result, CancellationToken token)
        {
            try
            {
                var prefsPath = Path.Combine(browser.ProfilePath, "prefs.js");
                if (!File.Exists(prefsPath)) return;

                var prefs = await File.ReadAllTextAsync(prefsPath, token);

                // Check for hijacked search
                if (prefs.Contains("browser.search.defaultenginename"))
                {
                    var match = System.Text.RegularExpressions.Regex.Match(
                        prefs, @"browser\.search\.defaultenginename.*?""([^""]+)""");
                    if (match.Success)
                    {
                        var engine = match.Groups[1].Value;
                        if (IsHijackedSearchEngine(engine))
                        {
                            result.HijackedSettings.Add(new HijackedSetting
                            {
                                Type = "Search Engine",
                                CurrentValue = engine,
                                Description = "Search engine has been hijacked"
                            });
                        }
                    }
                }
            }
            catch { }
        }

        private bool IsHijackedSearchEngine(string url)
        {
            foreach (var hijacked in _hijackedSearchEngines)
            {
                if (url.Contains(hijacked, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
            return false;
        }

        public async Task<bool> RemoveExtensionAsync(BrowserInfo browser, ExtensionInfo extension)
        {
            try
            {
                if (Directory.Exists(extension.Path))
                {
                    Directory.Delete(extension.Path, true);
                    RaiseLog($"Removed malicious extension: {extension.Name}");
                    return true;
                }
            }
            catch (Exception ex)
            {
                RaiseLog($"Failed to remove extension: {ex.Message}");
            }
            return false;
        }

        public async Task<List<BrowserScanResult>> ScanAllBrowsersAsync(CancellationToken token = default)
        {
            var results = new List<BrowserScanResult>();
            foreach (var browser in _browsers)
            {
                var result = await ScanBrowserAsync(browser, token);
                results.Add(result);
            }
            return results;
        }

        private void RaiseLog(string message)
        {
            LogAdded?.Invoke(this, message);
        }

        public void Dispose()
        {
            if (_isDisposed) return;
            _isDisposed = true;
            Stop();
        }
    }

    public class BrowserInfo
    {
        public string Name { get; set; } = string.Empty;
        public BrowserType Type { get; set; }
        public string ProfilePath { get; set; } = string.Empty;
        public string ExtensionsPath { get; set; } = string.Empty;
    }

    public enum BrowserType
    {
        Chrome,
        Firefox,
        Edge,
        Brave,
        Opera,
        Other
    }

    public class ExtensionInfo
    {
        public string Id { get; set; } = string.Empty;
        public string Name { get; set; } = string.Empty;
        public string Version { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public string Path { get; set; } = string.Empty;
    }

    public class HijackedSetting
    {
        public string Type { get; set; } = string.Empty;
        public string CurrentValue { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
    }

    public class BrowserScanResult
    {
        public BrowserInfo Browser { get; set; } = new();
        public int ExtensionsScanned { get; set; }
        public List<ExtensionInfo> InstalledExtensions { get; set; } = new();
        public List<ExtensionInfo> MaliciousExtensions { get; set; } = new();
        public List<HijackedSetting> HijackedSettings { get; set; } = new();
        public string? Error { get; set; }
    }

    public enum BrowserThreatType
    {
        MaliciousExtension,
        SearchHijack,
        HomepageHijack,
        ProxyHijack,
        DnsHijack
    }

    public class BrowserThreatEventArgs : EventArgs
    {
        public BrowserInfo Browser { get; set; } = new();
        public BrowserThreatType ThreatType { get; set; }
        public string Description { get; set; } = string.Empty;
        public string Path { get; set; } = string.Empty;
    }
}
