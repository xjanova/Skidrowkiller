using System.IO;
using Microsoft.Extensions.Logging;
using SkidrowKiller.Models;

namespace SkidrowKiller.Services
{
    /// <summary>
    /// Advanced threat analysis engine that integrates multiple detection methods:
    /// - Signature-based detection (patterns, hashes)
    /// - Heuristic analysis (behavior, characteristics)
    /// - PE file analysis (entropy, packing, imports)
    /// - YARA-style rules
    /// - Behavioral API pattern analysis
    /// - Entropy-based packing detection
    /// - VirusTotal cloud lookup
    /// </summary>
    public class ThreatAnalyzer
    {
        private readonly WhitelistManager _whitelistManager;
        private readonly MalwareSignatureDatabase _signatureDb;
        private readonly PEAnalyzer _peAnalyzer;
        private readonly HeuristicEngine _heuristicEngine;
        private readonly BehavioralAnalyzer? _behavioralAnalyzer;
        private readonly EntropyAnalyzer? _entropyAnalyzer;
        private readonly VirusTotalService? _virusTotalService;
        private readonly ILogger<ThreatAnalyzer>? _logger;

        // Legacy pattern dictionaries for backwards compatibility
        private readonly Dictionary<string, int> _highConfidencePatterns = new(StringComparer.OrdinalIgnoreCase)
        {
            // Scene groups - high score when found with context
            { "skidrow", 45 },
            { "skid-row", 45 },
            { "skid_row", 45 },
            { "reloaded", 35 },
            { "codex", 35 },
            { "plaza", 30 },
            { "cpy", 35 },
            { "steampunks", 40 },
            { "hoodlum", 35 },
            { "prophet", 30 },
            { "flt", 25 },
            { "razor1911", 40 },
            { "empress", 40 },
            { "fitgirl", 35 },
            { "dodi", 30 },
            { "elamigos", 30 },
            // Chinese crack groups (higher risk of bundled malware)
            { "3dm", 50 },
            { "3dmgame", 50 },
            { "ali213", 50 },
        };

        private readonly Dictionary<string, int> _mediumConfidencePatterns = new(StringComparer.OrdinalIgnoreCase)
        {
            { "crack", 20 },
            { "keygen", 35 },
            { "patch", 15 },
            { "loader", 15 },
            { "trainer", 20 },
            { "nocd", 35 },
            { "nodvd", 35 },
            { "activator", 40 },
            { "kmspico", 50 },
            { "kmsauto", 50 },
            { "hwidgen", 45 },
        };

        private readonly Dictionary<string, int> _suspiciousDlls = new(StringComparer.OrdinalIgnoreCase)
        {
            { "steam_api.dll", 30 },
            { "steam_api64.dll", 30 },
            { "steamclient.dll", 35 },
            { "steamclient64.dll", 35 },
            { "steam_emu.dll", 55 },
            { "cream_api.dll", 55 },
            { "uwpsteamapi.dll", 45 },
            { "goldberg_steam_api.dll", 55 },
            { "sse.dll", 45 },
            { "SmartSteamEmu.dll", 55 },
            { "origin_emu.dll", 50 },
        };

        private readonly Dictionary<string, int> _malwarePatterns = new(StringComparer.OrdinalIgnoreCase)
        {
            // RATs
            { "njrat", 90 },
            { "darkcomet", 90 },
            { "asyncrat", 90 },
            { "quasarrat", 90 },
            { "orcusrat", 90 },
            { "nanocore", 90 },
            { "remcos", 85 },
            { "warzone", 85 },
            // Stealers
            { "redline", 90 },
            { "vidar", 90 },
            { "raccoon", 90 },
            { "azorult", 90 },
            // Ransomware
            { "wannacry", 95 },
            { "ryuk", 95 },
            { "lockbit", 95 },
            { "conti", 95 },
            { "revil", 95 },
            // Cryptominers
            { "xmrig", 80 },
            { "cpuminer", 80 },
            { "cgminer", 80 },
            { "ethminer", 80 },
            // Botnet
            { "emotet", 95 },
            { "trickbot", 95 },
            { "qakbot", 95 },
            { "dridex", 95 },
            // Generic
            { "trojan", 85 },
            { "backdoor", 85 },
            { "rootkit", 90 },
            { "keylogger", 85 },
            { "spyware", 80 },
        };

        private readonly Dictionary<string, int> _suspiciousExtensions = new(StringComparer.OrdinalIgnoreCase)
        {
            { ".crack", 60 },
            { ".keygen", 60 },
            { ".exe.bak", 35 },
            { ".dll.bak", 35 },
            { ".pdf.exe", 80 },
            { ".doc.exe", 80 },
            { ".jpg.exe", 80 },
            { ".txt.exe", 80 },
            { ".mp3.exe", 80 },
        };

        private readonly string[] _boosterPatterns = {
            "game", "steam", "origin", "ubisoft", "epic", "gog",
            "fix", "update", "release", "v1.", "v2.", "-", "_"
        };

        private readonly string[] _safeContextPatterns = {
            "microsoft", "windows", "system32", "syswow64",
            "nvidia", "amd", "intel", "realtek",
            "visual studio", "dotnet", ".net",
            "github", "gitlab", "bitbucket",
            "node_modules", "packages", "nuget",
            "documentation", "docs", "readme",
            "backup", "archive", "old",
            "jetbrains", "vscode", "sublime",
        };

        // Configurable thresholds
        public int MinimumScoreToReport { get; set; } = 20;
        public int CriticalScoreThreshold { get; set; } = 80;
        public int HighScoreThreshold { get; set; } = 60;
        public int MediumScoreThreshold { get; set; } = 40;
        public int LowScoreThreshold { get; set; } = 20;
        public bool EnableDeepAnalysis { get; set; } = true;
        public bool EnablePEAnalysis { get; set; } = true;
        public bool EnableHeuristicAnalysis { get; set; } = true;
        public bool EnableBehavioralAnalysis { get; set; } = true;
        public bool EnableEntropyAnalysis { get; set; } = true;
        public bool EnableVirusTotalLookup { get; set; } = false; // Disabled by default (needs API key)

        public ThreatAnalyzer(WhitelistManager whitelistManager, ILogger<ThreatAnalyzer>? logger = null)
        {
            _whitelistManager = whitelistManager;
            _logger = logger;
            _signatureDb = new MalwareSignatureDatabase();
            _peAnalyzer = new PEAnalyzer(_signatureDb);
            _heuristicEngine = new HeuristicEngine(_signatureDb, _peAnalyzer);
            _behavioralAnalyzer = new BehavioralAnalyzer(null);
            _entropyAnalyzer = new EntropyAnalyzer(null);
        }

        /// <summary>
        /// Constructor with full dependency injection
        /// </summary>
        public ThreatAnalyzer(
            WhitelistManager whitelistManager,
            BehavioralAnalyzer? behavioralAnalyzer,
            EntropyAnalyzer? entropyAnalyzer,
            VirusTotalService? virusTotalService,
            ILogger<ThreatAnalyzer>? logger = null)
        {
            _whitelistManager = whitelistManager;
            _behavioralAnalyzer = behavioralAnalyzer;
            _entropyAnalyzer = entropyAnalyzer;
            _virusTotalService = virusTotalService;
            _logger = logger;
            _signatureDb = new MalwareSignatureDatabase();
            _peAnalyzer = new PEAnalyzer(_signatureDb);
            _heuristicEngine = new HeuristicEngine(_signatureDb, _peAnalyzer);
        }

        /// <summary>
        /// Configures VirusTotal integration
        /// </summary>
        public void ConfigureVirusTotal(string apiKey)
        {
            if (_virusTotalService != null && !string.IsNullOrEmpty(apiKey))
            {
                _virusTotalService.Configure(apiKey);
                EnableVirusTotalLookup = true;
            }
        }

        /// <summary>
        /// Analyzes a file path for potential threats using multiple detection methods
        /// </summary>
        public ThreatInfo? AnalyzePath(string path)
        {
            if (string.IsNullOrEmpty(path)) return null;

            // Check whitelist first
            if (_whitelistManager.IsWhitelisted(path))
            {
                return null;
            }

            var score = 0;
            var matchedPatterns = new List<string>();
            var isFile = File.Exists(path);
            var isDir = Directory.Exists(path);

            if (!isFile && !isDir) return null;

            var name = Path.GetFileName(path);
            var lowerPath = path.ToLower();
            var lowerName = name.ToLower();

            // 1. Check signature database first
            var sigMatch = _signatureDb.CheckPath(path);
            if (sigMatch != null)
            {
                score += sigMatch.MatchScore;
                foreach (var reason in sigMatch.MatchReasons)
                {
                    matchedPatterns.Add($"[SIG] {reason}");
                }
            }

            // 2. Check for safe context (reduces false positives)
            var safeContextScore = 0;
            foreach (var safePattern in _safeContextPatterns)
            {
                if (lowerPath.Contains(safePattern))
                {
                    safeContextScore += 15;
                }
            }

            // 3. Check malware patterns first (highest priority)
            foreach (var (pattern, patternScore) in _malwarePatterns)
            {
                if (lowerName.Contains(pattern) || lowerPath.Contains($"\\{pattern}\\"))
                {
                    score += patternScore;
                    matchedPatterns.Add($"[MALWARE] {pattern}");
                }
            }

            // 4. Check high confidence patterns (scene groups)
            foreach (var (pattern, patternScore) in _highConfidencePatterns)
            {
                if (lowerName.Contains(pattern) || lowerPath.Contains($"\\{pattern}\\"))
                {
                    score += patternScore;
                    matchedPatterns.Add($"[HIGH] {pattern}");
                }
            }

            // 5. Check medium confidence patterns
            foreach (var (pattern, patternScore) in _mediumConfidencePatterns)
            {
                if (lowerName.Contains(pattern))
                {
                    score += patternScore;
                    matchedPatterns.Add($"[MED] {pattern}");
                }
            }

            // 6. Check suspicious DLLs
            if (isFile)
            {
                foreach (var (dll, dllScore) in _suspiciousDlls)
                {
                    if (string.Equals(lowerName, dll, StringComparison.OrdinalIgnoreCase))
                    {
                        // Check if it's in a legitimate Steam folder
                        if (lowerPath.Contains("steamapps") || lowerPath.Contains("steam\\bin"))
                        {
                            // Reduce score for legitimate Steam installations
                            score += dllScore / 2;
                            matchedPatterns.Add($"[DLL-LEGIT?] {dll}");
                        }
                        else
                        {
                            score += dllScore;
                            matchedPatterns.Add($"[DLL] {dll}");
                        }
                    }
                }

                // 7. Check suspicious extensions
                foreach (var (ext, extScore) in _suspiciousExtensions)
                {
                    if (lowerName.EndsWith(ext))
                    {
                        score += extScore;
                        matchedPatterns.Add($"[EXT] {ext}");
                    }
                }
            }

            // 8. Apply booster (multiple patterns together = more suspicious)
            var boosterCount = _boosterPatterns.Count(p => lowerPath.Contains(p));
            if (boosterCount >= 2 && score > 0)
            {
                var boostAmount = boosterCount * 5;
                score += boostAmount;
                matchedPatterns.Add($"[BOOST] +{boostAmount} (context)");
            }

            // 9. Apply safe context reduction
            if (safeContextScore > 0)
            {
                var reduction = Math.Min(safeContextScore, score / 2);
                score = Math.Max(0, score - reduction);
                if (reduction > 0)
                {
                    matchedPatterns.Add($"[SAFE] -{reduction} (trusted context)");
                }
            }

            // 10. Apply caution directory penalty
            if (_whitelistManager.IsInCautionDirectory(path) && score < 50)
            {
                var originalScore = score;
                score = (int)(score * 0.7);
                if (originalScore != score)
                {
                    matchedPatterns.Add($"[CAUTION] -30% (protected directory)");
                }
            }

            // No patterns matched = safe
            if (matchedPatterns.Count == 0 || score < MinimumScoreToReport)
            {
                return null;
            }

            // Determine severity based on score
            var severity = DetermineServerity(score);

            // Very low score = don't report
            if (severity == ThreatSeverity.Safe)
            {
                return null;
            }

            var category = ClassifyThreatCategory(matchedPatterns, lowerName, lowerPath);
            var malwareName = GenerateMalwareName(category, matchedPatterns, name);
            var (recommendation, canIgnore) = GenerateRecommendation(category, severity, matchedPatterns);
            var detectionReason = GenerateDetectionReason(matchedPatterns);

            return new ThreatInfo
            {
                Type = isFile ? ThreatType.File : ThreatType.Directory,
                Severity = severity,
                Category = category,
                Path = path,
                Name = name,
                MalwareName = malwareName,
                MalwareFamily = ExtractMalwareFamily(matchedPatterns),
                Description = GenerateDescription(matchedPatterns, severity),
                DetectionReason = detectionReason,
                Recommendation = recommendation,
                CanIgnore = canIgnore,
                Score = Math.Min(score, 100),
                MatchedPatterns = matchedPatterns
            };
        }

        /// <summary>
        /// Deep analysis of a file including PE analysis, heuristics, and YARA rules
        /// </summary>
        public async Task<ThreatInfo?> AnalyzePathDeepAsync(string path)
        {
            // Start with basic analysis
            var threat = AnalyzePath(path);

            if (!EnableDeepAnalysis) return threat;

            // If it's a file, perform deeper analysis
            if (!File.Exists(path)) return threat;

            var extension = Path.GetExtension(path).ToLower();
            var isExecutable = extension == ".exe" || extension == ".dll" || extension == ".scr" || extension == ".sys";

            // Initialize threat if needed
            threat ??= new ThreatInfo
            {
                Type = ThreatType.File,
                Path = path,
                Name = Path.GetFileName(path),
                Score = 0,
                MatchedPatterns = new List<string>()
            };

            try
            {
                // 1. Hash-based detection
                var sha256 = await _signatureDb.ComputeSHA256Async(path);
                if (!string.IsNullOrEmpty(sha256))
                {
                    var hashMatch = _signatureDb.CheckHash(sha256, HashType.SHA256);
                    if (hashMatch != null)
                    {
                        threat.Score += hashMatch.ThreatLevel * 10;
                        threat.MatchedPatterns.Add($"[HASH] {hashMatch.MalwareName} ({hashMatch.MalwareFamily})");
                    }
                }

                // 2. PE Analysis for executables
                if (isExecutable && EnablePEAnalysis)
                {
                    var peResult = await _peAnalyzer.AnalyzeAsync(path);
                    if (peResult.IsValid)
                    {
                        threat.Score += peResult.ThreatScore / 2;

                        if (peResult.IsPacked)
                        {
                            threat.MatchedPatterns.Add($"[PE] Packed ({peResult.PackerName})");
                        }

                        if (peResult.HasEmbeddedExecutable)
                        {
                            threat.MatchedPatterns.Add($"[PE] Embedded executable");
                        }

                        foreach (var technique in peResult.DetectedTechniques.Take(3))
                        {
                            threat.MatchedPatterns.Add($"[PE] {technique}");
                        }

                        if (peResult.SuspiciousImports.Count > 5)
                        {
                            threat.MatchedPatterns.Add($"[PE] {peResult.SuspiciousImports.Count} suspicious imports");
                        }
                    }
                }

                // 3. YARA rule scanning
                var yaraMatches = await _signatureDb.ScanWithYaraAsync(path);
                foreach (var match in yaraMatches)
                {
                    threat.Score += match.Rule.ThreatLevel * 5;
                    threat.MatchedPatterns.Add($"[YARA] {match.Rule.Name}");
                }

                // 4. Content signature analysis
                var contentMatch = await _signatureDb.CheckFileContentAsync(path);
                if (contentMatch != null && contentMatch.MatchScore > 0)
                {
                    threat.Score += contentMatch.MatchScore / 2;
                    foreach (var reason in contentMatch.MatchReasons.Where(r => r.Contains("Content")))
                    {
                        threat.MatchedPatterns.Add($"[CONTENT] {reason}");
                    }
                }

                // 5. Heuristic analysis
                if (EnableHeuristicAnalysis)
                {
                    var heuristicResult = await _heuristicEngine.AnalyzeFileAsync(path);
                    if (heuristicResult.Score > 20)
                    {
                        threat.Score += heuristicResult.Score / 3;

                        foreach (var indicator in heuristicResult.SuspiciousIndicators.Take(3))
                        {
                            threat.MatchedPatterns.Add($"[HEUR] {indicator}");
                        }

                        foreach (var technique in heuristicResult.DetectedTechniques)
                        {
                            threat.MatchedPatterns.Add($"[TECH] {technique}");
                        }
                    }
                }

                // 6. Behavioral API analysis
                if (EnableBehavioralAnalysis && _behavioralAnalyzer != null && isExecutable)
                {
                    try
                    {
                        var behaviorResult = _behavioralAnalyzer.AnalyzeFile(path);
                        if (behaviorResult.IsSuspicious)
                        {
                            threat.Score += behaviorResult.TotalScore / 3;

                            foreach (var api in behaviorResult.SuspiciousApis.Take(3))
                            {
                                threat.MatchedPatterns.Add($"[API] {api.Name} ({api.Category})");
                            }

                            foreach (var pattern in behaviorResult.DetectedPatterns.Take(2))
                            {
                                threat.MatchedPatterns.Add($"[BEHAVIOR] {pattern.Name}");
                            }

                            if (behaviorResult.SuspiciousStrings.Count > 0)
                            {
                                threat.MatchedPatterns.Add($"[STRINGS] {behaviorResult.SuspiciousStrings.Count} suspicious strings");
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger?.LogDebug(ex, "Behavioral analysis failed for {Path}", path);
                    }
                }

                // 7. Entropy analysis (packing detection)
                if (EnableEntropyAnalysis && _entropyAnalyzer != null && isExecutable)
                {
                    try
                    {
                        var entropyResult = await _entropyAnalyzer.AnalyzeFileAsync(path);
                        if (entropyResult.IsSuspicious)
                        {
                            threat.Score += entropyResult.ThreatScore / 4;

                            if (entropyResult.IsPacked)
                            {
                                threat.MatchedPatterns.Add($"[ENTROPY] Packed ({entropyResult.PackerName ?? "Unknown"})");
                            }

                            if (entropyResult.OverallEntropy >= 7.5)
                            {
                                threat.MatchedPatterns.Add($"[ENTROPY] Very high entropy ({entropyResult.OverallEntropy:F2})");
                            }
                            else if (entropyResult.OverallEntropy >= 7.0)
                            {
                                threat.MatchedPatterns.Add($"[ENTROPY] High entropy ({entropyResult.OverallEntropy:F2})");
                            }

                            foreach (var indicator in entropyResult.Indicators.Take(2))
                            {
                                threat.MatchedPatterns.Add($"[ENTROPY] {indicator}");
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger?.LogDebug(ex, "Entropy analysis failed for {Path}", path);
                    }
                }

                // 8. VirusTotal cloud lookup
                if (EnableVirusTotalLookup && _virusTotalService != null && _virusTotalService.IsConfigured)
                {
                    try
                    {
                        var vtResult = await _virusTotalService.CheckFileAsync(path);
                        if (vtResult != null)
                        {
                            if (vtResult.Malicious > 0)
                            {
                                // Weight based on detection rate
                                int vtScore = vtResult.Malicious switch
                                {
                                    >= 20 => 50,
                                    >= 10 => 40,
                                    >= 5 => 30,
                                    >= 2 => 20,
                                    _ => 10
                                };
                                threat.Score += vtScore;
                                threat.MatchedPatterns.Add($"[VT] {vtResult.Malicious}/{vtResult.TotalEngines} engines detected");
                            }
                            else if (vtResult.Suspicious > 0)
                            {
                                threat.Score += vtResult.Suspicious * 2;
                                threat.MatchedPatterns.Add($"[VT] {vtResult.Suspicious} engines flagged as suspicious");
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger?.LogDebug(ex, "VirusTotal lookup failed for {Path}", path);
                    }
                }
            }
            catch
            {
                // Continue with what we have
            }

            // Recalculate severity
            threat.Score = Math.Min(threat.Score, 100);
            threat.Severity = DetermineServerity(threat.Score);

            if (threat.Severity == ThreatSeverity.Safe || threat.Score < MinimumScoreToReport)
            {
                return null;
            }

            threat.Description = GenerateDescription(threat.MatchedPatterns, threat.Severity);
            return threat;
        }

        /// <summary>
        /// Analyzes a running process for threats
        /// </summary>
        public ThreatInfo? AnalyzeProcess(int processId, string processName, string? executablePath, List<string>? loadedDlls)
        {
            var score = 0;
            var matchedPatterns = new List<string>();

            var lowerName = processName.ToLower();
            var lowerPath = executablePath?.ToLower() ?? "";

            // Check whitelist
            if (!string.IsNullOrEmpty(executablePath) && _whitelistManager.IsWhitelisted(executablePath))
            {
                return null;
            }

            // 1. Check malware patterns first
            foreach (var (pattern, patternScore) in _malwarePatterns)
            {
                if (lowerName.Contains(pattern))
                {
                    score += patternScore;
                    matchedPatterns.Add($"[PROC-MAL] {pattern}");
                }
            }

            // 2. Check process name against scene group patterns
            foreach (var (pattern, patternScore) in _highConfidencePatterns)
            {
                if (lowerName.Contains(pattern))
                {
                    score += patternScore;
                    matchedPatterns.Add($"[PROC] {pattern}");
                }
            }

            // 3. Check executable path
            foreach (var (pattern, patternScore) in _highConfidencePatterns)
            {
                if (lowerPath.Contains(pattern))
                {
                    score += patternScore;
                    matchedPatterns.Add($"[PATH] {pattern}");
                }
            }

            // 4. Check loaded DLLs for suspicious modules
            if (loadedDlls != null)
            {
                foreach (var dll in loadedDlls)
                {
                    var dllName = Path.GetFileName(dll).ToLower();
                    foreach (var (suspiciousDll, dllScore) in _suspiciousDlls)
                    {
                        if (string.Equals(dllName, suspiciousDll, StringComparison.OrdinalIgnoreCase))
                        {
                            // Don't flag if running from legitimate Steam
                            if (!dll.ToLower().Contains("steamapps"))
                            {
                                score += dllScore;
                                matchedPatterns.Add($"[INJECTED] {suspiciousDll}");
                            }
                        }
                    }

                    // Check for DLLs loaded from suspicious locations
                    var lowerDllPath = dll.ToLower();
                    if (lowerDllPath.Contains(@"\temp\") || lowerDllPath.Contains(@"\appdata\local\temp\"))
                    {
                        score += 25;
                        matchedPatterns.Add($"[DLL-TEMP] {Path.GetFileName(dll)}");
                    }
                }
            }

            // 5. Check for suspicious process locations
            if (!string.IsNullOrEmpty(executablePath))
            {
                if (lowerPath.Contains(@"\temp\") || lowerPath.Contains(@"\appdata\local\temp\"))
                {
                    score += 20;
                    matchedPatterns.Add("[LOC] Running from temp directory");
                }

                if (lowerPath.Contains(@"\users\public\"))
                {
                    score += 15;
                    matchedPatterns.Add("[LOC] Running from public directory");
                }
            }

            if (score < MinimumScoreToReport || matchedPatterns.Count == 0)
            {
                return null;
            }

            var severity = DetermineServerity(score);

            if (severity == ThreatSeverity.Safe)
            {
                return null;
            }

            return new ThreatInfo
            {
                Type = ThreatType.Process,
                Severity = severity,
                Path = executablePath ?? processName,
                Name = processName,
                Description = $"Suspicious process detected: {processName}",
                Score = Math.Min(score, 100),
                MatchedPatterns = matchedPatterns,
                ProcessId = processId,
                LoadedDlls = loadedDlls
            };
        }

        /// <summary>
        /// Deep process analysis including heuristics
        /// </summary>
        public async Task<ThreatInfo?> AnalyzeProcessDeepAsync(System.Diagnostics.Process process)
        {
            // Start with basic analysis
            string? execPath = null;
            List<string>? loadedDlls = null;

            try { execPath = process.MainModule?.FileName; } catch { }
            try
            {
                loadedDlls = process.Modules.Cast<System.Diagnostics.ProcessModule>()
                    .Select(m => m.FileName)
                    .Where(f => !string.IsNullOrEmpty(f))
                    .ToList();
            }
            catch { }

            var threat = AnalyzeProcess(process.Id, process.ProcessName, execPath, loadedDlls);

            if (!EnableHeuristicAnalysis) return threat;

            // Perform deep heuristic analysis
            try
            {
                var heuristicResult = await _heuristicEngine.AnalyzeProcessAsync(process);

                if (heuristicResult.Score > 20)
                {
                    threat ??= new ThreatInfo
                    {
                        Type = ThreatType.Process,
                        Path = execPath ?? process.ProcessName,
                        Name = process.ProcessName,
                        ProcessId = process.Id,
                        Score = 0,
                        MatchedPatterns = new List<string>()
                    };

                    threat.Score += heuristicResult.Score / 2;

                    foreach (var indicator in heuristicResult.SuspiciousIndicators.Take(5))
                    {
                        threat.MatchedPatterns.Add($"[HEUR] {indicator}");
                    }

                    foreach (var technique in heuristicResult.DetectedTechniques)
                    {
                        threat.MatchedPatterns.Add($"[TECH] {technique}");
                    }

                    threat.Score = Math.Min(threat.Score, 100);
                    threat.Severity = DetermineServerity(threat.Score);
                    threat.Description = GenerateDescription(threat.MatchedPatterns, threat.Severity);
                }
            }
            catch { }

            if (threat != null && threat.Severity == ThreatSeverity.Safe)
            {
                return null;
            }

            return threat;
        }

        /// <summary>
        /// Scans registry for persistence threats
        /// </summary>
        public async Task<List<ThreatInfo>> ScanRegistryAsync()
        {
            var threats = new List<ThreatInfo>();

            var registryThreats = await _heuristicEngine.ScanRegistryPersistenceAsync();

            foreach (var regThreat in registryThreats)
            {
                if (regThreat.ThreatLevel >= ThreatSeverity.Low)
                {
                    threats.Add(new ThreatInfo
                    {
                        Type = ThreatType.Registry,
                        Severity = regThreat.ThreatLevel,
                        Path = regThreat.RegistryPath,
                        Name = Path.GetFileName(regThreat.FilePath),
                        Description = $"Suspicious persistence: {regThreat.Description}",
                        Score = regThreat.Score,
                        MatchedPatterns = regThreat.SuspiciousIndicators
                    });
                }
            }

            return threats;
        }

        private ThreatSeverity DetermineServerity(int score)
        {
            return score switch
            {
                >= 80 => ThreatSeverity.Critical,
                >= 60 => ThreatSeverity.High,
                >= 40 => ThreatSeverity.Medium,
                >= 20 => ThreatSeverity.Low,
                _ => ThreatSeverity.Safe
            };
        }

        private string GenerateDescription(List<string> patterns, ThreatSeverity severity)
        {
            var patternList = string.Join(", ", patterns
                .Select(p => ExtractPatternName(p))
                .Where(p => !string.IsNullOrEmpty(p))
                .Distinct()
                .Take(5));

            return severity switch
            {
                ThreatSeverity.Critical => $"CRITICAL THREAT! Matches: {patternList}",
                ThreatSeverity.High => $"High risk detected. Patterns: {patternList}",
                ThreatSeverity.Medium => $"Suspicious item found. Contains: {patternList}",
                ThreatSeverity.Low => $"Potentially unwanted. Contains: {patternList}",
                _ => $"Safe. Contains: {patternList}"
            };
        }

        private string ExtractPatternName(string pattern)
        {
            // Remove tags like [HIGH], [MED], etc.
            var cleaned = System.Text.RegularExpressions.Regex.Replace(pattern, @"\[(.*?)\]\s*", "");
            return cleaned.Trim();
        }

        /// <summary>
        /// Gets the signature database for direct access
        /// </summary>
        public MalwareSignatureDatabase SignatureDatabase => _signatureDb;

        /// <summary>
        /// Gets the PE analyzer for direct access
        /// </summary>
        public PEAnalyzer PEAnalyzer => _peAnalyzer;

        /// <summary>
        /// Gets the heuristic engine for direct access
        /// </summary>
        public HeuristicEngine HeuristicEngine => _heuristicEngine;

        #region Threat Classification

        /// <summary>
        /// Classifies the threat into a category based on matched patterns
        /// </summary>
        private ThreatCategory ClassifyThreatCategory(List<string> patterns, string lowerName, string lowerPath)
        {
            var patternsLower = string.Join(" ", patterns).ToLower();

            // Check for dangerous malware first (highest priority)
            if (patternsLower.Contains("ransomware") || patternsLower.Contains("wannacry") ||
                patternsLower.Contains("ryuk") || patternsLower.Contains("lockbit"))
                return ThreatCategory.Ransomware;

            if (patternsLower.Contains("njrat") || patternsLower.Contains("darkcomet") ||
                patternsLower.Contains("asyncrat") || patternsLower.Contains("quasarrat") ||
                patternsLower.Contains("nanocore") || patternsLower.Contains("remcos"))
                return ThreatCategory.RAT;

            if (patternsLower.Contains("redline") || patternsLower.Contains("vidar") ||
                patternsLower.Contains("raccoon") || patternsLower.Contains("azorult") ||
                patternsLower.Contains("stealer"))
                return ThreatCategory.Stealer;

            if (patternsLower.Contains("emotet") || patternsLower.Contains("trickbot") ||
                patternsLower.Contains("qakbot") || patternsLower.Contains("dridex") ||
                patternsLower.Contains("botnet"))
                return ThreatCategory.Botnet;

            if (patternsLower.Contains("rootkit"))
                return ThreatCategory.Rootkit;

            if (patternsLower.Contains("trojan") || patternsLower.Contains("backdoor"))
                return ThreatCategory.Trojan;

            if (patternsLower.Contains("xmrig") || patternsLower.Contains("cpuminer") ||
                patternsLower.Contains("cgminer") || patternsLower.Contains("cryptominer") ||
                patternsLower.Contains("ethminer"))
                return ThreatCategory.Cryptominer;

            if (patternsLower.Contains("keylogger") || patternsLower.Contains("spyware"))
                return ThreatCategory.Spyware;

            // Check for crack-related tools
            if (patternsLower.Contains("keygen") || lowerName.Contains("keygen"))
                return ThreatCategory.Keygen;

            if (patternsLower.Contains("trainer") || lowerName.Contains("trainer"))
                return ThreatCategory.Trainer;

            if (patternsLower.Contains("kmspico") || patternsLower.Contains("kmsauto") ||
                patternsLower.Contains("hwidgen") || patternsLower.Contains("activator"))
                return ThreatCategory.Activator;

            if (patternsLower.Contains("steam_api") || patternsLower.Contains("steam_emu") ||
                patternsLower.Contains("cream_api") || patternsLower.Contains("goldberg") ||
                patternsLower.Contains("smartsteamemu"))
                return ThreatCategory.SteamEmulator;

            if (patternsLower.Contains("loader") || lowerName.Contains("loader"))
                return ThreatCategory.Loader;

            if (patternsLower.Contains("patch") || lowerName.Contains("patcher"))
                return ThreatCategory.Patcher;

            // Scene group cracks
            if (patternsLower.Contains("skidrow") || patternsLower.Contains("codex") ||
                patternsLower.Contains("plaza") || patternsLower.Contains("reloaded") ||
                patternsLower.Contains("cpy") || patternsLower.Contains("fitgirl") ||
                patternsLower.Contains("empress") || patternsLower.Contains("dodi") ||
                patternsLower.Contains("3dm") || patternsLower.Contains("crack"))
                return ThreatCategory.Crack;

            if (patternsLower.Contains("adware") || patternsLower.Contains("pup"))
                return ThreatCategory.Adware;

            return ThreatCategory.Suspicious;
        }

        /// <summary>
        /// Generates a malware name like "Crack.Skidrow" or "Trojan.Redline"
        /// </summary>
        private string GenerateMalwareName(ThreatCategory category, List<string> patterns, string fileName)
        {
            var family = ExtractMalwareFamily(patterns);
            var prefix = category switch
            {
                ThreatCategory.Crack => "Crack",
                ThreatCategory.Keygen => "HackTool.Keygen",
                ThreatCategory.Trainer => "HackTool.Trainer",
                ThreatCategory.Patcher => "HackTool.Patcher",
                ThreatCategory.Loader => "HackTool.Loader",
                ThreatCategory.Activator => "HackTool.Activator",
                ThreatCategory.SteamEmulator => "HackTool.SteamEmu",
                ThreatCategory.Trojan => "Trojan",
                ThreatCategory.Ransomware => "Ransom",
                ThreatCategory.Cryptominer => "CoinMiner",
                ThreatCategory.Stealer => "Stealer",
                ThreatCategory.RAT => "RAT",
                ThreatCategory.Spyware => "Spyware",
                ThreatCategory.Adware => "Adware",
                ThreatCategory.Rootkit => "Rootkit",
                ThreatCategory.Botnet => "Botnet",
                _ => "Suspicious"
            };

            if (!string.IsNullOrEmpty(family))
            {
                return $"{prefix}.{family}";
            }

            // Use filename as identifier if no family found
            var cleanName = System.IO.Path.GetFileNameWithoutExtension(fileName)
                .Replace(" ", "")
                .Replace("-", "")
                .Replace("_", "");
            if (cleanName.Length > 15) cleanName = cleanName.Substring(0, 15);

            return $"{prefix}.{cleanName}";
        }

        /// <summary>
        /// Extracts the malware family name from patterns
        /// </summary>
        private string ExtractMalwareFamily(List<string> patterns)
        {
            // Scene groups
            string[] sceneGroups = { "skidrow", "codex", "plaza", "reloaded", "cpy", "fitgirl",
                                     "empress", "dodi", "3dm", "ali213", "hoodlum", "razor1911" };
            // Malware families
            string[] malwareFamilies = { "redline", "vidar", "raccoon", "azorult", "njrat",
                                          "darkcomet", "asyncrat", "quasarrat", "nanocore",
                                          "emotet", "trickbot", "wannacry", "ryuk", "lockbit",
                                          "xmrig", "kmspico", "kmsauto" };

            var patternsLower = string.Join(" ", patterns).ToLower();

            foreach (var group in sceneGroups)
            {
                if (patternsLower.Contains(group))
                    return char.ToUpper(group[0]) + group.Substring(1);
            }

            foreach (var family in malwareFamilies)
            {
                if (patternsLower.Contains(family))
                    return char.ToUpper(family[0]) + family.Substring(1);
            }

            return string.Empty;
        }

        /// <summary>
        /// Generates recommendation and determines if threat can be ignored
        /// </summary>
        private (string Recommendation, bool CanIgnore) GenerateRecommendation(
            ThreatCategory category, ThreatSeverity severity, List<string> patterns)
        {
            return category switch
            {
                // Dangerous - NEVER ignore
                ThreatCategory.Ransomware => (
                    "DELETE IMMEDIATELY! Ransomware can encrypt all your files and demand payment. " +
                    "Disconnect from network and run full scan.",
                    false),

                ThreatCategory.RAT => (
                    "DELETE IMMEDIATELY! Remote Access Trojans allow hackers to control your computer. " +
                    "Change all passwords after removal.",
                    false),

                ThreatCategory.Stealer => (
                    "DELETE IMMEDIATELY! This malware steals passwords, credit cards, and personal data. " +
                    "Change all passwords after removal.",
                    false),

                ThreatCategory.Botnet => (
                    "DELETE IMMEDIATELY! Your computer may be part of a criminal network. " +
                    "Full system scan recommended.",
                    false),

                ThreatCategory.Rootkit => (
                    "DELETE IMMEDIATELY! Rootkits hide deep in your system. " +
                    "Consider reinstalling Windows if problems persist.",
                    false),

                ThreatCategory.Trojan => (
                    "Delete recommended. Trojans can steal data and install other malware. " +
                    "Run full system scan after removal.",
                    false),

                ThreatCategory.Cryptominer => (
                    "Delete recommended. Crypto miners slow your computer and increase electricity costs. " +
                    "Check CPU usage to verify.",
                    false),

                ThreatCategory.Spyware => (
                    "Delete recommended. Spyware monitors your activity and steals information. " +
                    "Check for other infections.",
                    false),

                // Cracks - User decision
                ThreatCategory.Crack => severity >= ThreatSeverity.High
                    ? ("This crack may contain hidden malware. Many cracks bundle trojans or miners. " +
                       "Delete unless you fully trust the source.", false)
                    : ("Game crack detected from scene group. While not always malicious, " +
                       "cracks can contain hidden malware. Delete if you didn't intentionally download this.", true),

                ThreatCategory.Keygen => (
                    "Key generators often contain hidden malware. They are also illegal in most countries. " +
                    "Delete recommended - use legitimate software instead.",
                    severity < ThreatSeverity.High),

                ThreatCategory.Trainer => (
                    "Game trainer/cheat detected. While often harmless, some contain malware. " +
                    "Keep only if downloaded from a trusted source.",
                    severity < ThreatSeverity.Medium),

                ThreatCategory.Activator => (
                    "Windows/Office activator detected (e.g., KMSpico). These are illegal and often " +
                    "bundled with malware. Delete and use legitimate licenses.",
                    false),

                ThreatCategory.SteamEmulator => severity >= ThreatSeverity.High
                    ? ("Steam emulator detected outside of normal game folder. May indicate piracy or malware.", false)
                    : ("Steam API emulator detected. Common in cracked games. " +
                       "Safe if you intentionally installed the game.", true),

                ThreatCategory.Loader or ThreatCategory.Patcher => (
                    "Crack loader/patcher detected. Can modify game files. " +
                    "Delete if not intentionally used for a specific game.",
                    severity < ThreatSeverity.High),

                ThreatCategory.Adware => (
                    "Adware/PUP detected. Displays unwanted ads and may track your activity. " +
                    "Removal recommended for privacy and performance.",
                    true),

                _ => severity >= ThreatSeverity.High
                    ? ("Suspicious file detected. Delete recommended due to high threat score.", false)
                    : ("Suspicious file detected. Review manually if you recognize this file.", true)
            };
        }

        /// <summary>
        /// Generates a human-readable detection reason
        /// </summary>
        private string GenerateDetectionReason(List<string> patterns)
        {
            var reasons = new List<string>();

            foreach (var pattern in patterns.Take(5))
            {
                if (pattern.Contains("[MALWARE]"))
                    reasons.Add("Known malware pattern detected");
                else if (pattern.Contains("[HIGH]"))
                    reasons.Add("Scene group crack signature");
                else if (pattern.Contains("[DLL]"))
                    reasons.Add("Suspicious DLL file");
                else if (pattern.Contains("[INJECTED]"))
                    reasons.Add("DLL injection detected");
                else if (pattern.Contains("[HASH]"))
                    reasons.Add("Known malware hash match");
                else if (pattern.Contains("[PE]"))
                    reasons.Add("Suspicious executable structure");
                else if (pattern.Contains("[YARA]"))
                    reasons.Add("YARA rule match");
                else if (pattern.Contains("[HEUR]"))
                    reasons.Add("Heuristic analysis flag");
                else if (pattern.Contains("[VT]"))
                    reasons.Add("VirusTotal detection");
                else if (pattern.Contains("[ENTROPY]"))
                    reasons.Add("Packed/encrypted file");
                else if (pattern.Contains("[MED]"))
                    reasons.Add("Suspicious pattern in filename");
            }

            return reasons.Count > 0
                ? string.Join("; ", reasons.Distinct())
                : "Pattern matching detected suspicious content";
        }

        #endregion
    }
}
