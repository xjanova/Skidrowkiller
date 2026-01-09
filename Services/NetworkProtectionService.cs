using System.Diagnostics;
using System.IO;
using System.Management;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using SkidrowKiller.Models;

namespace SkidrowKiller.Services
{
    /// <summary>
    /// Advanced network protection service that detects and blocks connections to malicious domains.
    /// Similar to Malwarebytes web protection - blocks warez, crack sites, and malware C2 servers.
    /// </summary>
    public class NetworkProtectionService : IDisposable
    {
        private readonly ThreatAnalyzer _analyzer;
        private CancellationTokenSource? _cts;
        private Task? _monitorTask;
        private Task? _dnsMonitorTask;

        // Blocked domain database
        private readonly HashSet<string> _blockedDomains = new(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _blockedPatterns = new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, BlockedDomainInfo> _domainDatabase = new(StringComparer.OrdinalIgnoreCase);

        // Active blocks and alerts
        private readonly HashSet<string> _activeBlocks = new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, DateTime> _recentAlerts = new();
        private readonly object _alertLock = new();

        // Statistics
        private int _blockedConnections;
        private int _totalChecks;
        private int _domainsBlocked;

        // Native imports for connection monitoring
        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int pdwSize, bool bOrder, int ulAf, TcpTableClass tableClass, uint reserved);

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint GetExtendedUdpTable(IntPtr pUdpTable, ref int pdwSize, bool bOrder, int ulAf, UdpTableClass tableClass, uint reserved);

        private enum TcpTableClass
        {
            TCP_TABLE_OWNER_PID_ALL = 5
        }

        private enum UdpTableClass
        {
            UDP_TABLE_OWNER_PID = 1
        }

        // Events
        public event EventHandler<NetworkBlockedEvent>? ConnectionBlocked;
        public event EventHandler<string>? LogAdded;
        public event EventHandler<ProtectionStatus>? StatusChanged;
        public event EventHandler<SourceAnalysisResult>? SourceAnalysisCompleted;
        public event EventHandler<DeepScanResult>? DeepScanCompleted;

        // Properties
        public bool IsRunning { get; private set; }
        public bool HostsFileProtection { get; set; } = true;
        public bool AutoBlockNewThreats { get; set; } = true;
        public bool KillMaliciousProcesses { get; set; } = false;
        public int BlockedConnections => _blockedConnections;
        public int TotalChecks => _totalChecks;
        public int DomainsInDatabase => _blockedDomains.Count;

        public NetworkProtectionService(ThreatAnalyzer analyzer)
        {
            _analyzer = analyzer;
            LoadMaliciousDomainDatabase();
        }

        #region Domain Database

        private void LoadMaliciousDomainDatabase()
        {
            // === WAREZ / CRACK SITES ===
            AddBlockedDomain("skidrow-games.com", "Warez/Crack Site", "SKIDROW crack distribution site", 9);
            AddBlockedDomain("skidrowreloaded.com", "Warez/Crack Site", "SKIDROW crack distribution site", 9);
            AddBlockedDomain("skidrowcodex.net", "Warez/Crack Site", "SKIDROW/CODEX crack site", 9);
            AddBlockedDomain("skidrowrepacks.com", "Warez/Crack Site", "SKIDROW repacks site", 9);
            AddBlockedDomain("skidrow-games.io", "Warez/Crack Site", "SKIDROW crack site", 9);
            AddBlockedDomain("skidrowkey.com", "Warez/Crack Site", "SKIDROW keygen site", 9);

            AddBlockedDomain("codexpcgames.com", "Warez/Crack Site", "CODEX crack distribution", 9);
            AddBlockedDomain("codex-games.com", "Warez/Crack Site", "CODEX crack site", 9);

            AddBlockedDomain("fitgirl-repacks.site", "Warez/Crack Site", "FitGirl repacks site", 8);
            AddBlockedDomain("fitgirl-repack.com", "Warez/Crack Site", "FitGirl repacks (fake)", 9);
            AddBlockedDomain("fitgirlrepacks.co", "Warez/Crack Site", "FitGirl repacks site", 8);

            AddBlockedDomain("steamunlocked.net", "Warez/Crack Site", "Pirated Steam games", 9);
            AddBlockedDomain("steamunlocked.one", "Warez/Crack Site", "Pirated Steam games", 9);
            AddBlockedDomain("steam-unlocked.com", "Warez/Crack Site", "Pirated Steam games", 9);

            AddBlockedDomain("igg-games.com", "Warez/Crack Site", "Pirated games with bundled malware", 10);
            AddBlockedDomain("igggames.com", "Warez/Crack Site", "Pirated games with bundled malware", 10);

            AddBlockedDomain("oceanofgames.com", "Warez/Crack Site", "Pirated games - known malware", 10);
            AddBlockedDomain("ocean-of-games.com", "Warez/Crack Site", "Pirated games - known malware", 10);

            AddBlockedDomain("nosteam.ro", "Warez/Crack Site", "NoSteam crack site", 8);
            AddBlockedDomain("nosteamgames.com", "Warez/Crack Site", "NoSteam crack site", 8);

            AddBlockedDomain("crackwatch.com", "Warez/Crack Site", "Crack release tracker", 7);
            AddBlockedDomain("crack-watch.com", "Warez/Crack Site", "Crack release tracker", 7);

            AddBlockedDomain("pcgamestorrents.com", "Warez/Crack Site", "Pirated games torrents", 9);
            AddBlockedDomain("gload.to", "Warez/Crack Site", "German warez site", 8);
            AddBlockedDomain("ovagames.com", "Warez/Crack Site", "Pirated games", 8);

            AddBlockedDomain("1337x.to", "Torrent Site", "Torrent site with cracks", 7);
            AddBlockedDomain("rarbg.to", "Torrent Site", "Torrent site", 7);
            AddBlockedDomain("thepiratebay.org", "Torrent Site", "Torrent site", 7);
            AddBlockedDomain("piratebay.live", "Torrent Site", "Pirate Bay mirror", 7);

            // === KEYGEN / SERIAL SITES ===
            AddBlockedDomain("serialkey.net", "Keygen Site", "Serial key distribution", 9);
            AddBlockedDomain("keygeninja.com", "Keygen Site", "Keygen distribution", 9);
            AddBlockedDomain("serialfree.com", "Keygen Site", "Free serials - malware risk", 9);
            AddBlockedDomain("crackedpcs.com", "Keygen Site", "Cracked software", 9);

            // === KMS / ACTIVATION TOOLS ===
            AddBlockedDomain("kmspico.io", "Activation Tool", "KMSpico - often bundled with malware", 10);
            AddBlockedDomain("kmsauto.net", "Activation Tool", "KMSAuto - malware risk", 10);
            AddBlockedDomain("kmspico.com", "Activation Tool", "KMSpico - malware risk", 10);

            // === KNOWN C2 / MALWARE DOMAINS ===
            AddBlockedDomain("malware-traffic-analysis.net", "Security Research", "Malware analysis site", 3);

            // Dynamic C2 patterns (will be matched with wildcards)
            _blockedPatterns.Add("*skidrow*");
            _blockedPatterns.Add("*codex-game*");
            _blockedPatterns.Add("*cracked-games*");
            _blockedPatterns.Add("*free-steam-keys*");
            _blockedPatterns.Add("*keygen*download*");
            _blockedPatterns.Add("*crack*download*");
            _blockedPatterns.Add("*warez*");
            _blockedPatterns.Add("*nulled*");
            _blockedPatterns.Add("*pirate*game*");
            _blockedPatterns.Add("*torrent*game*");

            RaiseLog($"📚 [DATABASE] Loaded {_blockedDomains.Count} blocked domains, {_blockedPatterns.Count} patterns");
        }

        public void AddBlockedDomain(string domain, string category, string description, int threatLevel)
        {
            domain = domain.ToLower().Trim();
            if (domain.StartsWith("www."))
                domain = domain.Substring(4);

            _blockedDomains.Add(domain);
            _blockedDomains.Add("www." + domain);

            _domainDatabase[domain] = new BlockedDomainInfo
            {
                Domain = domain,
                Category = category,
                Description = description,
                ThreatLevel = threatLevel,
                AddedDate = DateTime.Now
            };
        }

        public bool IsDomainBlocked(string domain)
        {
            if (string.IsNullOrEmpty(domain)) return false;

            domain = domain.ToLower().Trim();
            if (domain.StartsWith("www."))
                domain = domain.Substring(4);

            Interlocked.Increment(ref _totalChecks);

            // Direct match
            if (_blockedDomains.Contains(domain))
                return true;

            // Pattern matching
            foreach (var pattern in _blockedPatterns)
            {
                if (MatchesPattern(domain, pattern))
                    return true;
            }

            // Subdomain check
            var parts = domain.Split('.');
            for (var i = 1; i < parts.Length - 1; i++)
            {
                var parentDomain = string.Join(".", parts.Skip(i));
                if (_blockedDomains.Contains(parentDomain))
                    return true;
            }

            return false;
        }

        private bool MatchesPattern(string domain, string pattern)
        {
            // Convert wildcard pattern to regex
            var regex = "^" + Regex.Escape(pattern)
                .Replace("\\*", ".*")
                .Replace("\\?", ".") + "$";

            return Regex.IsMatch(domain, regex, RegexOptions.IgnoreCase);
        }

        public BlockedDomainInfo? GetDomainInfo(string domain)
        {
            domain = domain.ToLower().Trim();
            if (domain.StartsWith("www."))
                domain = domain.Substring(4);

            return _domainDatabase.GetValueOrDefault(domain);
        }

        #endregion

        #region Network Monitoring

        public void Start()
        {
            if (IsRunning) return;

            _cts = new CancellationTokenSource();
            IsRunning = true;
            _blockedConnections = 0;
            _totalChecks = 0;

            // Apply hosts file blocks
            if (HostsFileProtection)
            {
                ApplyHostsFileBlocks();
            }

            // Start monitoring
            _monitorTask = Task.Run(() => MonitorConnectionsLoop(_cts.Token));
            _dnsMonitorTask = Task.Run(() => MonitorDnsLoop(_cts.Token));

            RaiseLog("🌐 [NETWORK] Web protection started");
            RaiseLog($"   ├─ Domain database: {_blockedDomains.Count} domains");
            RaiseLog($"   ├─ Pattern rules: {_blockedPatterns.Count} patterns");
            RaiseLog($"   ├─ Hosts file protection: {(HostsFileProtection ? "Enabled" : "Disabled")}");
            RaiseLog($"   └─ Auto-kill malicious: {(KillMaliciousProcesses ? "Enabled" : "Disabled")}");

            StatusChanged?.Invoke(this, ProtectionStatus.Safe);
        }

        public void Stop()
        {
            if (!IsRunning) return;

            _cts?.Cancel();
            IsRunning = false;

            RaiseLog("🌐 [NETWORK] Web protection stopped");
            RaiseLog($"   📊 Blocked {_blockedConnections} connections, checked {_totalChecks} requests");
        }

        private async Task MonitorConnectionsLoop(CancellationToken token)
        {
            while (!token.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(1000, token);
                    await CheckActiveConnections(token);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    RaiseLog($"⚠️ [NETWORK] Monitor error: {ex.Message}");
                }
            }
        }

        private async Task CheckActiveConnections(CancellationToken token)
        {
            try
            {
                var connections = await GetTcpConnectionsWithProcessAsync();

                foreach (var conn in connections)
                {
                    if (token.IsCancellationRequested) break;

                    // Try to resolve IP to hostname
                    var hostname = await ResolveHostnameAsync(conn.RemoteAddress);

                    if (!string.IsNullOrEmpty(hostname) && IsDomainBlocked(hostname))
                    {
                        await HandleBlockedConnection(conn, hostname);
                    }
                }
            }
            catch { }
        }

        private async Task<string?> ResolveHostnameAsync(string ipAddress)
        {
            try
            {
                if (!IPAddress.TryParse(ipAddress, out var ip))
                    return null;

                // Skip local/private IPs
                if (IsPrivateIp(ip))
                    return null;

                var entry = await Dns.GetHostEntryAsync(ip);
                return entry?.HostName;
            }
            catch
            {
                return null;
            }
        }

        private bool IsPrivateIp(IPAddress ip)
        {
            var bytes = ip.GetAddressBytes();
            if (bytes.Length != 4) return false;

            // 10.x.x.x
            if (bytes[0] == 10) return true;
            // 172.16.x.x - 172.31.x.x
            if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) return true;
            // 192.168.x.x
            if (bytes[0] == 192 && bytes[1] == 168) return true;
            // 127.x.x.x
            if (bytes[0] == 127) return true;

            return false;
        }

        private async Task HandleBlockedConnection(TcpConnectionInfo conn, string hostname)
        {
            var alertKey = $"{hostname}:{conn.ProcessId}";

            lock (_alertLock)
            {
                // Rate limit alerts (once per minute per domain/process)
                if (_recentAlerts.TryGetValue(alertKey, out var lastAlert))
                {
                    if ((DateTime.Now - lastAlert).TotalMinutes < 1)
                        return;
                }
                _recentAlerts[alertKey] = DateTime.Now;
            }

            Interlocked.Increment(ref _blockedConnections);

            var domainInfo = GetDomainInfo(hostname);
            var processName = GetProcessName(conn.ProcessId);

            var blockedEvent = new NetworkBlockedEvent
            {
                Timestamp = DateTime.Now,
                Domain = hostname,
                IpAddress = conn.RemoteAddress,
                Port = conn.RemotePort,
                ProcessId = conn.ProcessId,
                ProcessName = processName,
                Category = domainInfo?.Category ?? "Unknown",
                Description = domainInfo?.Description ?? "Blocked by pattern rule",
                ThreatLevel = domainInfo?.ThreatLevel ?? 7,
                Action = "Blocked"
            };

            // Log the block
            RaiseLog($"🚫 [BLOCKED] Connection to potentially risky site");
            RaiseLog($"   Domain: {hostname}");
            RaiseLog($"   App: {processName} (PID: {conn.ProcessId})");
            RaiseLog($"   Category: {blockedEvent.Category}");
            RaiseLog($"   Reason: {blockedEvent.Description}");

            // Raise event
            ConnectionBlocked?.Invoke(this, blockedEvent);
            StatusChanged?.Invoke(this, ProtectionStatus.Warning);

            // Kill process if enabled
            if (KillMaliciousProcesses && domainInfo?.ThreatLevel >= 9)
            {
                await KillProcessAsync(conn.ProcessId, processName);
            }

            // Add to hosts file if not already blocked
            if (HostsFileProtection && !_activeBlocks.Contains(hostname))
            {
                AddToHostsFile(hostname);
                _activeBlocks.Add(hostname);
            }
        }

        private string GetProcessName(int processId)
        {
            try
            {
                using var process = Process.GetProcessById(processId);
                return process.ProcessName;
            }
            catch
            {
                return $"Unknown (PID: {processId})";
            }
        }

        private async Task KillProcessAsync(int processId, string processName)
        {
            try
            {
                using var process = Process.GetProcessById(processId);
                process.Kill(true);
                RaiseLog($"💀 [KILLED] Terminated malicious process: {processName}");
            }
            catch (Exception ex)
            {
                RaiseLog($"⚠️ [KILL] Failed to terminate {processName}: {ex.Message}");
            }

            await Task.CompletedTask;
        }

        #endregion

        #region DNS Monitoring

        private async Task MonitorDnsLoop(CancellationToken token)
        {
            // Monitor DNS cache and queries using netsh
            while (!token.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(5000, token);
                    await CheckDnsCache(token);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch { }
            }
        }

        private async Task CheckDnsCache(CancellationToken token)
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "ipconfig",
                    Arguments = "/displaydns",
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using var process = Process.Start(psi);
                if (process == null) return;

                var output = await process.StandardOutput.ReadToEndAsync(token);
                await process.WaitForExitAsync(token);

                // Parse DNS entries
                var matches = Regex.Matches(output, @"Record Name[\s.]+:\s+(.+)", RegexOptions.IgnoreCase);

                foreach (Match match in matches)
                {
                    var domain = match.Groups[1].Value.Trim();

                    if (IsDomainBlocked(domain) && !_activeBlocks.Contains(domain))
                    {
                        RaiseLog($"🔍 [DNS] Detected query to blocked domain: {domain}");

                        if (HostsFileProtection)
                        {
                            AddToHostsFile(domain);
                            _activeBlocks.Add(domain);
                            Interlocked.Increment(ref _domainsBlocked);
                        }
                    }
                }
            }
            catch { }
        }

        #endregion

        #region Hosts File Management

        private readonly string _hostsFilePath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.System),
            "drivers", "etc", "hosts");

        private const string HOSTS_MARKER_START = "# === SKIDROW KILLER PROTECTION START ===";
        private const string HOSTS_MARKER_END = "# === SKIDROW KILLER PROTECTION END ===";

        public void ApplyHostsFileBlocks()
        {
            try
            {
                // Read current hosts file
                var hostsContent = File.Exists(_hostsFilePath)
                    ? File.ReadAllText(_hostsFilePath)
                    : "";

                // Remove old entries
                hostsContent = RemoveOurHostsEntries(hostsContent);

                // Add new block entries
                var newEntries = new StringBuilder();
                newEntries.AppendLine();
                newEntries.AppendLine(HOSTS_MARKER_START);
                newEntries.AppendLine("# Blocked domains to protect against malware and piracy sites");
                newEntries.AppendLine($"# Generated: {DateTime.Now}");
                newEntries.AppendLine();

                foreach (var domain in _blockedDomains.Take(500)) // Limit to prevent huge files
                {
                    newEntries.AppendLine($"0.0.0.0 {domain}");
                    _activeBlocks.Add(domain);
                }

                newEntries.AppendLine();
                newEntries.AppendLine(HOSTS_MARKER_END);

                // Write back
                File.WriteAllText(_hostsFilePath, hostsContent + newEntries.ToString());

                _domainsBlocked = _activeBlocks.Count;
                RaiseLog($"✅ [HOSTS] Applied {_activeBlocks.Count} domain blocks to hosts file");

                // Flush DNS cache
                FlushDnsCache();
            }
            catch (UnauthorizedAccessException)
            {
                RaiseLog("⚠️ [HOSTS] Need administrator rights to modify hosts file");
            }
            catch (Exception ex)
            {
                RaiseLog($"⚠️ [HOSTS] Failed to update hosts file: {ex.Message}");
            }
        }

        public void RemoveHostsFileBlocks()
        {
            try
            {
                if (!File.Exists(_hostsFilePath)) return;

                var hostsContent = File.ReadAllText(_hostsFilePath);
                hostsContent = RemoveOurHostsEntries(hostsContent);
                File.WriteAllText(_hostsFilePath, hostsContent);

                _activeBlocks.Clear();
                RaiseLog("✅ [HOSTS] Removed all protection entries from hosts file");

                FlushDnsCache();
            }
            catch (Exception ex)
            {
                RaiseLog($"⚠️ [HOSTS] Failed to clean hosts file: {ex.Message}");
            }
        }

        private string RemoveOurHostsEntries(string content)
        {
            // Remove everything between our markers
            var pattern = $@"{Regex.Escape(HOSTS_MARKER_START)}[\s\S]*?{Regex.Escape(HOSTS_MARKER_END)}";
            return Regex.Replace(content, pattern, "", RegexOptions.Multiline).Trim();
        }

        private void AddToHostsFile(string domain)
        {
            try
            {
                var hostsContent = File.ReadAllText(_hostsFilePath);

                if (!hostsContent.Contains(domain))
                {
                    // Find our section and add to it
                    var insertPos = hostsContent.IndexOf(HOSTS_MARKER_END);
                    if (insertPos > 0)
                    {
                        var newEntry = $"0.0.0.0 {domain}\n0.0.0.0 www.{domain}\n";
                        hostsContent = hostsContent.Insert(insertPos, newEntry);
                        File.WriteAllText(_hostsFilePath, hostsContent);

                        RaiseLog($"✅ [HOSTS] Blocked: {domain}");
                        FlushDnsCache();
                    }
                }
            }
            catch { }
        }

        private void FlushDnsCache()
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "ipconfig",
                    Arguments = "/flushdns",
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                Process.Start(psi)?.WaitForExit(5000);
            }
            catch { }
        }

        #endregion

        #region TCP Connection Enumeration

        private async Task<List<TcpConnectionInfo>> GetTcpConnectionsWithProcessAsync()
        {
            var connections = new List<TcpConnectionInfo>();

            try
            {
                // Use netstat for reliable results
                var psi = new ProcessStartInfo
                {
                    FileName = "netstat",
                    Arguments = "-ano",
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using var process = Process.Start(psi);
                if (process == null) return connections;

                var output = await process.StandardOutput.ReadToEndAsync();
                await process.WaitForExitAsync();

                // Parse netstat output
                var lines = output.Split('\n');
                foreach (var line in lines)
                {
                    if (!line.Contains("ESTABLISHED") && !line.Contains("SYN_SENT"))
                        continue;

                    var parts = line.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length >= 5)
                    {
                        try
                        {
                            var foreignParts = parts[2].Split(':');
                            if (foreignParts.Length >= 2)
                            {
                                connections.Add(new TcpConnectionInfo
                                {
                                    LocalAddress = parts[1],
                                    RemoteAddress = foreignParts[0],
                                    RemotePort = int.Parse(foreignParts.Last()),
                                    State = parts[3],
                                    ProcessId = int.Parse(parts[4])
                                });
                            }
                        }
                        catch { }
                    }
                }
            }
            catch { }

            return connections;
        }

        #endregion

        #region Source Analysis & Deep Scan

        /// <summary>
        /// วิเคราะห์หาต้นเหตุของ malicious connection - หา parent process, command line, related files
        /// </summary>
        public async Task<SourceAnalysisResult> AnalyzeSourceAsync(int processId, string domain)
        {
            var result = new SourceAnalysisResult
            {
                ProcessId = processId,
                Domain = domain,
                AnalysisTime = DateTime.Now
            };

            RaiseLog($"🔬 [ANALYSIS] Starting source analysis for PID {processId}...");

            try
            {
                // 1. Get process details
                using var process = Process.GetProcessById(processId);
                result.ProcessName = process.ProcessName;
                result.ProcessPath = GetProcessPath(processId);
                result.ProcessStartTime = process.StartTime;

                RaiseLog($"   ├─ Process: {result.ProcessName}");
                RaiseLog($"   ├─ Path: {result.ProcessPath}");

                // 2. Get command line
                result.CommandLine = GetProcessCommandLine(processId);
                if (!string.IsNullOrEmpty(result.CommandLine))
                {
                    RaiseLog($"   ├─ Command: {result.CommandLine}");
                }

                // 3. Find parent process chain
                result.ParentChain = await GetParentProcessChainAsync(processId);
                if (result.ParentChain.Count > 0)
                {
                    RaiseLog($"   ├─ Parent chain ({result.ParentChain.Count} levels):");
                    foreach (var parent in result.ParentChain)
                    {
                        RaiseLog($"   │  └─ {parent.ProcessName} (PID: {parent.ProcessId}) - {parent.ProcessPath}");
                    }
                }

                // 4. Get loaded modules (DLLs)
                result.LoadedModules = GetProcessModules(processId);
                var suspiciousModules = result.LoadedModules.Where(m => IsSuspiciousModule(m)).ToList();
                if (suspiciousModules.Count > 0)
                {
                    RaiseLog($"   ├─ Suspicious modules ({suspiciousModules.Count}):");
                    foreach (var module in suspiciousModules.Take(5))
                    {
                        RaiseLog($"   │  └─ {Path.GetFileName(module)}");
                    }
                }

                // 5. Find related files in same directory
                if (!string.IsNullOrEmpty(result.ProcessPath) && File.Exists(result.ProcessPath))
                {
                    var dir = Path.GetDirectoryName(result.ProcessPath);
                    if (dir != null)
                    {
                        result.RelatedFiles = GetRelatedFiles(dir);
                        RaiseLog($"   ├─ Related files in directory: {result.RelatedFiles.Count}");
                    }
                }

                // 6. Calculate file hash
                if (!string.IsNullOrEmpty(result.ProcessPath) && File.Exists(result.ProcessPath))
                {
                    result.FileHash = await CalculateFileHashAsync(result.ProcessPath);
                    RaiseLog($"   ├─ SHA256: {result.FileHash}");
                }

                // 7. Check registry persistence
                result.RegistryPersistence = await CheckRegistryPersistenceAsync(result.ProcessName, result.ProcessPath);
                if (result.RegistryPersistence.Count > 0)
                {
                    RaiseLog($"   ├─ Registry persistence found ({result.RegistryPersistence.Count} entries):");
                    foreach (var reg in result.RegistryPersistence.Take(3))
                    {
                        RaiseLog($"   │  └─ {reg}");
                    }
                }

                // 8. Determine threat level and root cause
                result.ThreatLevel = CalculateThreatLevel(result);
                result.RootCause = DetermineRootCause(result);
                result.Recommendation = GetRecommendation(result);

                RaiseLog($"   ├─ Threat Level: {result.ThreatLevel}/10");
                RaiseLog($"   ├─ Root Cause: {result.RootCause}");
                RaiseLog($"   └─ Recommendation: {result.Recommendation}");

                result.Success = true;
            }
            catch (Exception ex)
            {
                result.Error = ex.Message;
                RaiseLog($"   └─ Error: {ex.Message}");
            }

            SourceAnalysisCompleted?.Invoke(this, result);
            return result;
        }

        /// <summary>
        /// Deep Scan - สแกนเฉพาะจุดที่เกี่ยวข้องกับ malicious connection
        /// </summary>
        public async Task<DeepScanResult> DeepScanAsync(SourceAnalysisResult sourceAnalysis)
        {
            var result = new DeepScanResult
            {
                SourceAnalysis = sourceAnalysis,
                ScanTime = DateTime.Now
            };

            RaiseLog($"🎯 [DEEP SCAN] Starting targeted scan based on source analysis...");

            try
            {
                // 1. Scan the malicious process executable
                if (!string.IsNullOrEmpty(sourceAnalysis.ProcessPath) && File.Exists(sourceAnalysis.ProcessPath))
                {
                    RaiseLog($"   ├─ Scanning main executable: {Path.GetFileName(sourceAnalysis.ProcessPath)}");
                    var mainFileScan = await ScanFileDeepAsync(sourceAnalysis.ProcessPath);
                    if (mainFileScan.IsMalicious)
                    {
                        result.MaliciousFiles.Add(mainFileScan);
                        RaiseLog($"   │  └─ MALICIOUS: {mainFileScan.ThreatName} (Score: {mainFileScan.Score})");
                    }
                }

                // 2. Scan parent process executables
                foreach (var parent in sourceAnalysis.ParentChain)
                {
                    if (!string.IsNullOrEmpty(parent.ProcessPath) && File.Exists(parent.ProcessPath))
                    {
                        RaiseLog($"   ├─ Scanning parent: {Path.GetFileName(parent.ProcessPath)}");
                        var parentScan = await ScanFileDeepAsync(parent.ProcessPath);
                        if (parentScan.IsMalicious)
                        {
                            result.MaliciousFiles.Add(parentScan);
                            RaiseLog($"   │  └─ MALICIOUS: {parentScan.ThreatName}");
                        }
                    }
                }

                // 3. Scan related files in same directory
                foreach (var relatedFile in sourceAnalysis.RelatedFiles.Take(50))
                {
                    var ext = Path.GetExtension(relatedFile).ToLower();
                    if (ext == ".exe" || ext == ".dll" || ext == ".bat" || ext == ".cmd" || ext == ".ps1" || ext == ".vbs")
                    {
                        var scan = await ScanFileDeepAsync(relatedFile);
                        if (scan.IsMalicious)
                        {
                            result.MaliciousFiles.Add(scan);
                            RaiseLog($"   ├─ MALICIOUS: {Path.GetFileName(relatedFile)} - {scan.ThreatName}");
                        }
                    }
                }

                // 4. Scan suspicious modules
                var suspiciousModules = sourceAnalysis.LoadedModules.Where(m => IsSuspiciousModule(m)).ToList();
                foreach (var module in suspiciousModules.Take(20))
                {
                    if (File.Exists(module))
                    {
                        var scan = await ScanFileDeepAsync(module);
                        if (scan.IsMalicious)
                        {
                            result.MaliciousFiles.Add(scan);
                            RaiseLog($"   ├─ MALICIOUS MODULE: {Path.GetFileName(module)} - {scan.ThreatName}");
                        }
                    }
                }

                // 5. Check temp directories for related malware
                var tempDirs = new[]
                {
                    Path.GetTempPath(),
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData) + "\\Temp",
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData)
                };

                foreach (var tempDir in tempDirs)
                {
                    if (Directory.Exists(tempDir))
                    {
                        var recentFiles = GetRecentFilesInDirectory(tempDir, TimeSpan.FromHours(24));
                        foreach (var file in recentFiles.Take(20))
                        {
                            var ext = Path.GetExtension(file).ToLower();
                            if (ext == ".exe" || ext == ".dll" || ext == ".bat")
                            {
                                var scan = await ScanFileDeepAsync(file);
                                if (scan.IsMalicious)
                                {
                                    result.MaliciousFiles.Add(scan);
                                    RaiseLog($"   ├─ MALICIOUS (TEMP): {Path.GetFileName(file)} - {scan.ThreatName}");
                                }
                            }
                        }
                    }
                }

                // 6. Summarize results
                result.TotalFilesScanned = result.MaliciousFiles.Count +
                    sourceAnalysis.RelatedFiles.Count +
                    suspiciousModules.Count;

                result.Success = true;

                RaiseLog($"   └─ Deep scan complete: {result.MaliciousFiles.Count} malicious files found");

                if (result.MaliciousFiles.Count > 0)
                {
                    RaiseLog($"⚠️ [ACTION REQUIRED] Found {result.MaliciousFiles.Count} malicious files!");
                    foreach (var malFile in result.MaliciousFiles)
                    {
                        RaiseLog($"   • {malFile.FilePath}");
                        RaiseLog($"     Threat: {malFile.ThreatName}");
                        RaiseLog($"     Action: {malFile.RecommendedAction}");
                    }
                }
            }
            catch (Exception ex)
            {
                result.Error = ex.Message;
                RaiseLog($"   └─ Error: {ex.Message}");
            }

            DeepScanCompleted?.Invoke(this, result);
            return result;
        }

        /// <summary>
        /// Combined: Analyze source and perform deep scan
        /// </summary>
        public async Task<DeepScanResult> AnalyzeAndScanAsync(int processId, string domain)
        {
            var sourceAnalysis = await AnalyzeSourceAsync(processId, domain);
            return await DeepScanAsync(sourceAnalysis);
        }

        #region Helper Methods for Analysis

        private string GetProcessPath(int processId)
        {
            try
            {
                using var process = Process.GetProcessById(processId);
                return process.MainModule?.FileName ?? "";
            }
            catch
            {
                // Try WMI if direct access fails
                try
                {
                    using var searcher = new ManagementObjectSearcher(
                        $"SELECT ExecutablePath FROM Win32_Process WHERE ProcessId = {processId}");
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        return obj["ExecutablePath"]?.ToString() ?? "";
                    }
                }
                catch { }
            }
            return "";
        }

        private string GetProcessCommandLine(int processId)
        {
            try
            {
                using var searcher = new ManagementObjectSearcher(
                    $"SELECT CommandLine FROM Win32_Process WHERE ProcessId = {processId}");
                foreach (ManagementObject obj in searcher.Get())
                {
                    return obj["CommandLine"]?.ToString() ?? "";
                }
            }
            catch { }
            return "";
        }

        private async Task<List<ParentProcessInfo>> GetParentProcessChainAsync(int processId)
        {
            var chain = new List<ParentProcessInfo>();
            var currentPid = processId;
            var visited = new HashSet<int>();

            while (currentPid > 0 && chain.Count < 10 && !visited.Contains(currentPid))
            {
                visited.Add(currentPid);

                try
                {
                    using var searcher = new ManagementObjectSearcher(
                        $"SELECT ParentProcessId, Name, ExecutablePath FROM Win32_Process WHERE ProcessId = {currentPid}");

                    foreach (ManagementObject obj in searcher.Get())
                    {
                        var parentPid = Convert.ToInt32(obj["ParentProcessId"]);
                        if (parentPid <= 0 || parentPid == currentPid) break;

                        // Get parent info
                        using var parentSearcher = new ManagementObjectSearcher(
                            $"SELECT Name, ExecutablePath, CommandLine FROM Win32_Process WHERE ProcessId = {parentPid}");

                        foreach (ManagementObject parentObj in parentSearcher.Get())
                        {
                            chain.Add(new ParentProcessInfo
                            {
                                ProcessId = parentPid,
                                ProcessName = parentObj["Name"]?.ToString() ?? "Unknown",
                                ProcessPath = parentObj["ExecutablePath"]?.ToString() ?? "",
                                CommandLine = parentObj["CommandLine"]?.ToString() ?? ""
                            });
                        }

                        currentPid = parentPid;
                        break;
                    }
                }
                catch
                {
                    break;
                }
            }

            await Task.CompletedTask;
            return chain;
        }

        private List<string> GetProcessModules(int processId)
        {
            var modules = new List<string>();
            try
            {
                using var process = Process.GetProcessById(processId);
                foreach (ProcessModule module in process.Modules)
                {
                    modules.Add(module.FileName);
                }
            }
            catch { }
            return modules;
        }

        private bool IsSuspiciousModule(string modulePath)
        {
            var fileName = Path.GetFileName(modulePath).ToLower();
            var directory = Path.GetDirectoryName(modulePath)?.ToLower() ?? "";

            // Suspicious if in temp or appdata
            if (directory.Contains("temp") || directory.Contains("appdata\\local\\temp"))
                return true;

            // Suspicious patterns
            var suspiciousPatterns = new[]
            {
                "inject", "hook", "patch", "crack", "keygen", "loader",
                "bypass", "cheat", "hack", "trainer", "activat"
            };

            return suspiciousPatterns.Any(p => fileName.Contains(p));
        }

        private List<string> GetRelatedFiles(string directory)
        {
            var files = new List<string>();
            try
            {
                files.AddRange(Directory.GetFiles(directory, "*.exe"));
                files.AddRange(Directory.GetFiles(directory, "*.dll"));
                files.AddRange(Directory.GetFiles(directory, "*.bat"));
                files.AddRange(Directory.GetFiles(directory, "*.cmd"));
                files.AddRange(Directory.GetFiles(directory, "*.ps1"));
                files.AddRange(Directory.GetFiles(directory, "*.vbs"));
            }
            catch { }
            return files;
        }

        private List<string> GetRecentFilesInDirectory(string directory, TimeSpan maxAge)
        {
            var files = new List<string>();
            try
            {
                var cutoff = DateTime.Now - maxAge;
                var allFiles = Directory.GetFiles(directory, "*.*", SearchOption.TopDirectoryOnly);
                files.AddRange(allFiles.Where(f =>
                {
                    try { return File.GetLastWriteTime(f) > cutoff; }
                    catch { return false; }
                }));
            }
            catch { }
            return files;
        }

        private async Task<string> CalculateFileHashAsync(string filePath)
        {
            try
            {
                using var sha256 = SHA256.Create();
                using var stream = File.OpenRead(filePath);
                var hash = await Task.Run(() => sha256.ComputeHash(stream));
                return BitConverter.ToString(hash).Replace("-", "").ToLower();
            }
            catch
            {
                return "";
            }
        }

        private async Task<List<string>> CheckRegistryPersistenceAsync(string processName, string processPath)
        {
            var persistence = new List<string>();

            var registryPaths = new[]
            {
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
                @"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
            };

            await Task.Run(() =>
            {
                foreach (var path in registryPaths)
                {
                    try
                    {
                        using var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(path);
                        if (key != null)
                        {
                            foreach (var valueName in key.GetValueNames())
                            {
                                var value = key.GetValue(valueName)?.ToString() ?? "";
                                if (value.Contains(processName, StringComparison.OrdinalIgnoreCase) ||
                                    (!string.IsNullOrEmpty(processPath) && value.Contains(processPath, StringComparison.OrdinalIgnoreCase)))
                                {
                                    persistence.Add($"HKCU\\{path}\\{valueName}");
                                }
                            }
                        }
                    }
                    catch { }

                    try
                    {
                        using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(path);
                        if (key != null)
                        {
                            foreach (var valueName in key.GetValueNames())
                            {
                                var value = key.GetValue(valueName)?.ToString() ?? "";
                                if (value.Contains(processName, StringComparison.OrdinalIgnoreCase) ||
                                    (!string.IsNullOrEmpty(processPath) && value.Contains(processPath, StringComparison.OrdinalIgnoreCase)))
                                {
                                    persistence.Add($"HKLM\\{path}\\{valueName}");
                                }
                            }
                        }
                    }
                    catch { }
                }
            });

            return persistence;
        }

        private int CalculateThreatLevel(SourceAnalysisResult result)
        {
            int score = 5; // Base score

            // High threat if in temp directory
            if (result.ProcessPath?.ToLower().Contains("temp") == true)
                score += 2;

            // High threat if has registry persistence
            if (result.RegistryPersistence.Count > 0)
                score += 2;

            // High threat if has suspicious modules
            if (result.LoadedModules.Any(m => IsSuspiciousModule(m)))
                score += 1;

            // Check domain info
            var domainInfo = GetDomainInfo(result.Domain);
            if (domainInfo != null)
                score = Math.Max(score, domainInfo.ThreatLevel);

            return Math.Min(10, score);
        }

        private string DetermineRootCause(SourceAnalysisResult result)
        {
            // Check if it's a browser
            var browsers = new[] { "chrome", "firefox", "edge", "opera", "brave", "msedge" };
            if (browsers.Any(b => result.ProcessName.ToLower().Contains(b)))
            {
                return "Browser visiting malicious website - may be redirected by malware or intentional visit";
            }

            // Check if launched from temp
            if (result.ProcessPath?.ToLower().Contains("temp") == true)
            {
                return "Executable running from TEMP directory - likely downloaded malware or crack";
            }

            // Check parent chain
            if (result.ParentChain.Any(p => p.ProcessPath?.ToLower().Contains("temp") == true))
            {
                return "Launched by process in TEMP directory - infection chain detected";
            }

            // Check for crack/piracy indicators
            var crackIndicators = new[] { "crack", "keygen", "patch", "activat", "loader", "kmspico", "kmsauto" };
            if (crackIndicators.Any(i =>
                result.ProcessName.ToLower().Contains(i) ||
                (result.ProcessPath?.ToLower().Contains(i) == true) ||
                (result.CommandLine?.ToLower().Contains(i) == true)))
            {
                return "Piracy/crack tool detected - known source of malware distribution";
            }

            // Check registry persistence
            if (result.RegistryPersistence.Count > 0)
            {
                return "Process has established registry persistence - malware characteristic";
            }

            return "Process making suspicious network connection - investigate further";
        }

        private string GetRecommendation(SourceAnalysisResult result)
        {
            if (result.ThreatLevel >= 8)
            {
                return "CRITICAL: Terminate process and quarantine related files immediately";
            }
            else if (result.ThreatLevel >= 6)
            {
                return "HIGH: Run deep scan and consider removing the application";
            }
            else if (result.ThreatLevel >= 4)
            {
                return "MEDIUM: Monitor activity and scan related files";
            }
            return "LOW: Continue monitoring";
        }

        private async Task<DeepScanFileResult> ScanFileDeepAsync(string filePath)
        {
            var result = new DeepScanFileResult
            {
                FilePath = filePath,
                FileName = Path.GetFileName(filePath)
            };

            try
            {
                // Calculate hash
                result.FileHash = await CalculateFileHashAsync(filePath);

                // Check against threat analyzer
                var analysisResult = await _analyzer.AnalyzePathDeepAsync(filePath);
                if (analysisResult != null)
                {
                    result.Score = analysisResult.Score;
                    result.IsMalicious = analysisResult.Score >= 60;

                    if (result.IsMalicious)
                    {
                        result.ThreatName = analysisResult.MatchedPatterns.FirstOrDefault() ?? "Suspicious.Gen";
                        result.Category = analysisResult.SeverityDisplay;
                        result.RecommendedAction = result.Score >= 80 ? "Quarantine" : "Review";
                    }
                }

                // Additional pattern checks
                var fileName = Path.GetFileName(filePath).ToLower();
                var malwarePatterns = new Dictionary<string, string>
                {
                    { "crack", "HackTool.Crack" },
                    { "keygen", "HackTool.Keygen" },
                    { "patch", "HackTool.Patcher" },
                    { "loader", "Trojan.Loader" },
                    { "inject", "Trojan.Injector" },
                    { "bypass", "HackTool.Bypass" },
                    { "activat", "HackTool.Activator" },
                    { "kmspico", "Riskware.KMSpico" },
                    { "kmsauto", "Riskware.KMSAuto" }
                };

                foreach (var pattern in malwarePatterns)
                {
                    if (fileName.Contains(pattern.Key))
                    {
                        result.IsMalicious = true;
                        result.ThreatName = pattern.Value;
                        result.Score = Math.Max(result.Score, 70);
                        result.RecommendedAction = "Quarantine";
                        break;
                    }
                }
            }
            catch (Exception ex)
            {
                result.Error = ex.Message;
            }

            return result;
        }

        #endregion

        #endregion

        #region Cleanup

        public void Dispose()
        {
            Stop();
            _cts?.Dispose();
        }

        private void RaiseLog(string message)
        {
            LogAdded?.Invoke(this, message);
        }

        #endregion
    }

    #region Data Classes

    public class TcpConnectionInfo
    {
        public string LocalAddress { get; set; } = string.Empty;
        public string RemoteAddress { get; set; } = string.Empty;
        public int RemotePort { get; set; }
        public string State { get; set; } = string.Empty;
        public int ProcessId { get; set; }
    }

    public class BlockedDomainInfo
    {
        public string Domain { get; set; } = string.Empty;
        public string Category { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public int ThreatLevel { get; set; }
        public DateTime AddedDate { get; set; }
    }

    public class NetworkBlockedEvent
    {
        public DateTime Timestamp { get; set; }
        public string Domain { get; set; } = string.Empty;
        public string IpAddress { get; set; } = string.Empty;
        public int Port { get; set; }
        public int ProcessId { get; set; }
        public string ProcessName { get; set; } = string.Empty;
        public string Category { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public int ThreatLevel { get; set; }
        public string Action { get; set; } = string.Empty;
    }

    /// <summary>
    /// Result of source analysis - หาต้นเหตุของ malicious connection
    /// </summary>
    public class SourceAnalysisResult
    {
        public int ProcessId { get; set; }
        public string ProcessName { get; set; } = string.Empty;
        public string ProcessPath { get; set; } = string.Empty;
        public DateTime ProcessStartTime { get; set; }
        public string CommandLine { get; set; } = string.Empty;
        public string Domain { get; set; } = string.Empty;
        public string FileHash { get; set; } = string.Empty;
        public List<ParentProcessInfo> ParentChain { get; set; } = new();
        public List<string> LoadedModules { get; set; } = new();
        public List<string> RelatedFiles { get; set; } = new();
        public List<string> RegistryPersistence { get; set; } = new();
        public int ThreatLevel { get; set; }
        public string RootCause { get; set; } = string.Empty;
        public string Recommendation { get; set; } = string.Empty;
        public bool Success { get; set; }
        public string Error { get; set; } = string.Empty;
        public DateTime AnalysisTime { get; set; }
    }

    public class ParentProcessInfo
    {
        public int ProcessId { get; set; }
        public string ProcessName { get; set; } = string.Empty;
        public string ProcessPath { get; set; } = string.Empty;
        public string CommandLine { get; set; } = string.Empty;
    }

    /// <summary>
    /// Result of deep scan - สแกนเฉพาะจุดที่เกี่ยวข้องกับ malicious connection
    /// </summary>
    public class DeepScanResult
    {
        public SourceAnalysisResult SourceAnalysis { get; set; } = new();
        public List<DeepScanFileResult> MaliciousFiles { get; set; } = new();
        public int TotalFilesScanned { get; set; }
        public bool Success { get; set; }
        public string Error { get; set; } = string.Empty;
        public DateTime ScanTime { get; set; }
    }

    public class DeepScanFileResult
    {
        public string FilePath { get; set; } = string.Empty;
        public string FileName { get; set; } = string.Empty;
        public string FileHash { get; set; } = string.Empty;
        public bool IsMalicious { get; set; }
        public string ThreatName { get; set; } = string.Empty;
        public string Category { get; set; } = string.Empty;
        public int Score { get; set; }
        public string RecommendedAction { get; set; } = string.Empty;
        public string Error { get; set; } = string.Empty;
    }

    #endregion
}
