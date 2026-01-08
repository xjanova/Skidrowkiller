using System.IO;
using SkidrowKiller.Models;

namespace SkidrowKiller.Services
{
    /// <summary>
    /// Intelligent threat analysis with scoring system to reduce false positives.
    /// Uses multiple factors to determine threat severity.
    /// </summary>
    public class ThreatAnalyzer
    {
        // High confidence patterns (exact match malware groups)
        private readonly Dictionary<string, int> _highConfidencePatterns = new(StringComparer.OrdinalIgnoreCase)
        {
            // Scene groups - high score when found with context
            { "skidrow", 40 },
            { "skid-row", 40 },
            { "skid_row", 40 },
            { "reloaded", 30 },
            { "codex", 30 },
            { "plaza", 25 },
            { "cpy", 30 },
            { "steampunks", 35 },
            { "hoodlum", 30 },
            { "prophet", 25 },
            { "flt", 20 },
            { "razor1911", 35 },
            { "empress", 35 },
        };

        // Medium confidence patterns (could be false positive)
        private readonly Dictionary<string, int> _mediumConfidencePatterns = new(StringComparer.OrdinalIgnoreCase)
        {
            { "crack", 15 },   // Reduced - could be legitimate
            { "keygen", 25 },
            { "patch", 10 },   // Very low - many legitimate patches
            { "loader", 10 },  // Very low - legitimate game loaders exist
            { "trainer", 15 },
            { "nocd", 30 },
            { "nodvd", 30 },
        };

        // Suspicious DLLs (fake Steam DLLs)
        private readonly Dictionary<string, int> _suspiciousDlls = new(StringComparer.OrdinalIgnoreCase)
        {
            { "steam_api.dll", 25 },      // Could be legitimate
            { "steam_api64.dll", 25 },
            { "steamclient.dll", 30 },
            { "steamclient64.dll", 30 },
            { "steam_emu.dll", 50 },      // Emulator = high score
            { "cream_api.dll", 50 },      // DLC unlocker
            { "uwpsteamapi.dll", 40 },
            { "goldberg_steam_api.dll", 50 },
            { "sse.dll", 40 },
            { "SmartSteamEmu.dll", 50 },
        };

        // File extensions that are highly suspicious
        private readonly Dictionary<string, int> _suspiciousExtensions = new(StringComparer.OrdinalIgnoreCase)
        {
            { ".crack", 60 },
            { ".keygen", 60 },
            { ".exe.bak", 30 },
            { ".dll.bak", 30 },
        };

        // Booster patterns - increase score when found together
        private readonly string[] _boosterPatterns = new[]
        {
            "game", "steam", "origin", "ubisoft", "epic", "gog",
            "fix", "update", "release", "v1.", "v2.", "-"
        };

        // Reducer patterns - decrease score (legitimate contexts)
        private readonly string[] _safeContextPatterns = new[]
        {
            "microsoft", "windows", "system32", "syswow64",
            "nvidia", "amd", "intel", "realtek",
            "visual studio", "dotnet", ".net",
            "github", "gitlab", "bitbucket",
            "node_modules", "packages", "nuget",
            "documentation", "docs", "readme",
            "backup", "archive", "old",
        };

        private readonly WhitelistManager _whitelistManager;

        public ThreatAnalyzer(WhitelistManager whitelistManager)
        {
            _whitelistManager = whitelistManager;
        }

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

            // Check for safe context (reduces false positives)
            var safeContextScore = 0;
            foreach (var safePattern in _safeContextPatterns)
            {
                if (lowerPath.Contains(safePattern))
                {
                    safeContextScore += 15;
                }
            }

            // Check high confidence patterns
            foreach (var (pattern, patternScore) in _highConfidencePatterns)
            {
                if (lowerName.Contains(pattern) || lowerPath.Contains($"\\{pattern}\\"))
                {
                    score += patternScore;
                    matchedPatterns.Add($"[HIGH] {pattern}");
                }
            }

            // Check medium confidence patterns
            foreach (var (pattern, patternScore) in _mediumConfidencePatterns)
            {
                if (lowerName.Contains(pattern))
                {
                    score += patternScore;
                    matchedPatterns.Add($"[MED] {pattern}");
                }
            }

            // Check suspicious DLLs
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

                // Check suspicious extensions
                foreach (var (ext, extScore) in _suspiciousExtensions)
                {
                    if (lowerName.EndsWith(ext))
                    {
                        score += extScore;
                        matchedPatterns.Add($"[EXT] {ext}");
                    }
                }
            }

            // Apply booster (multiple patterns together = more suspicious)
            var boosterCount = _boosterPatterns.Count(p => lowerPath.Contains(p));
            if (boosterCount >= 2 && score > 0)
            {
                score += boosterCount * 5;
            }

            // Apply safe context reduction
            score = Math.Max(0, score - safeContextScore);

            // Apply caution directory penalty (ask more questions)
            if (_whitelistManager.IsInCautionDirectory(path) && score < 50)
            {
                // Lower the score for items in caution directories unless very suspicious
                score = (int)(score * 0.7);
            }

            // No patterns matched = safe
            if (matchedPatterns.Count == 0 || score == 0)
            {
                return null;
            }

            // Determine severity based on score
            var severity = score switch
            {
                >= 80 => ThreatSeverity.Critical,
                >= 60 => ThreatSeverity.High,
                >= 40 => ThreatSeverity.Medium,
                >= 20 => ThreatSeverity.Low,
                _ => ThreatSeverity.Safe
            };

            // Very low score = don't report
            if (severity == ThreatSeverity.Safe)
            {
                return null;
            }

            return new ThreatInfo
            {
                Type = isFile ? ThreatType.File : ThreatType.Directory,
                Severity = severity,
                Path = path,
                Name = name,
                Description = GenerateDescription(matchedPatterns, severity),
                Score = Math.Min(score, 100),
                MatchedPatterns = matchedPatterns
            };
        }

        public ThreatInfo? AnalyzeProcess(int processId, string processName, string? executablePath, List<string>? loadedDlls)
        {
            var score = 0;
            var matchedPatterns = new List<string>();

            var lowerName = processName.ToLower();
            var lowerPath = executablePath?.ToLower() ?? "";

            // Check process name against patterns
            foreach (var (pattern, patternScore) in _highConfidencePatterns)
            {
                if (lowerName.Contains(pattern))
                {
                    score += patternScore;
                    matchedPatterns.Add($"[PROC] {pattern}");
                }
            }

            // Check executable path
            foreach (var (pattern, patternScore) in _highConfidencePatterns)
            {
                if (lowerPath.Contains(pattern))
                {
                    score += patternScore;
                    matchedPatterns.Add($"[PATH] {pattern}");
                }
            }

            // Check loaded DLLs
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
                }
            }

            if (score == 0 || matchedPatterns.Count == 0)
            {
                return null;
            }

            var severity = score switch
            {
                >= 80 => ThreatSeverity.Critical,
                >= 60 => ThreatSeverity.High,
                >= 40 => ThreatSeverity.Medium,
                >= 20 => ThreatSeverity.Low,
                _ => ThreatSeverity.Safe
            };

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

        private string GenerateDescription(List<string> patterns, ThreatSeverity severity)
        {
            var patternList = string.Join(", ", patterns.Select(p =>
                p.Replace("[HIGH] ", "")
                 .Replace("[MED] ", "")
                 .Replace("[DLL] ", "")
                 .Replace("[EXT] ", "")
                 .Replace("[DLL-LEGIT?] ", "")
            ).Distinct());

            return severity switch
            {
                ThreatSeverity.Critical => $"Critical threat detected! Matches: {patternList}",
                ThreatSeverity.High => $"High risk item detected. Patterns: {patternList}",
                ThreatSeverity.Medium => $"Suspicious item found. Contains: {patternList}",
                ThreatSeverity.Low => $"Potentially unwanted. Contains: {patternList}",
                _ => $"Safe. Contains: {patternList}"
            };
        }
    }
}
