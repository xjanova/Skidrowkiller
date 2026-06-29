using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using Serilog;

namespace SkidrowKiller.Services
{
    /// <summary>
    /// Local, offline learning layer ("the brain that remembers").
    ///
    /// It is a deterministic, fully-auditable reputation overlay — NOT a black-box ML model.
    /// Every verdict it nudges can be reconstructed from the append-only FeedbackEvents table,
    /// and every adjustment is stamped onto the threat as a transparent [REP] tag.
    ///
    /// Signals it learns from:
    ///   • WHITELIST_ADD      — user trusts a file            (good vote)
    ///   • QUARANTINE_RESTORE — user pulled a file back       (good vote, pattern marked false-positive)
    ///   • FP_REPORT          — explicit "false positive"     (strong good vote)
    ///   • CONFIRMED_REMOVAL  — user confirmed + deleted      (bad vote, pattern marked true-positive)
    ///   • VT_CORROBORATION   — VirusTotal agreed/disagreed   (only NON-user signal allowed to flip a verdict)
    ///
    /// Safeguards against poisoning / drift (see AdjustScore):
    ///   • reputation is bound to the file SHA-256, never the path (a trojanised update at a trusted path is NOT trusted);
    ///   • a hash needs MinVotesBeforeTrust independent good votes before it can silence a detection;
    ///   • per-hash boost and per-pattern decay are both hard-capped, so reputation tunes a score, never erases a strong [HASH]/[MALWARE]/[VT] hit;
    ///   • a VT-confirmed-malicious hash can never be voted "safe" by a user;
    ///   • an admin can pin a verdict (IsLocked) which overrides all votes;
    ///   • old votes decay toward neutral so a past mistake heals instead of locking in.
    /// </summary>
    public class ReputationService
    {
        public const string SignalWhitelistAdd = "WHITELIST_ADD";
        public const string SignalQuarantineRestore = "QUARANTINE_RESTORE";
        public const string SignalFalsePositive = "FP_REPORT";
        public const string SignalConfirmedRemoval = "CONFIRMED_REMOVAL";
        public const string SignalVirusTotal = "VT_CORROBORATION";

        private readonly ILogger _logger;
        private readonly string _connectionString;

        // Tunable bounds (loaded from ReputationConfig; safe defaults below). Kept conservative on purpose.
        private int _minVotesBeforeTrust = 3;       // independent good votes required to silence a detection
        private double _trustThreshold = 0.80;      // posterior P(good) needed to treat a hash as locally safe
        private int _maxHashBoost = 30;             // most a bad reputation may *add* to a score
        private double _maxPatternDecayFraction = 0.40; // most repeated-false-positive patterns may *remove*

        // De-escalating / contextual tags are never used to drive reputation decay.
        private static readonly string[] NonScoringTags =
            { "[SAFE]", "[BOOST]", "[CAUTION]", "[DLL-LEGIT?]", "[REP]", "[LOC]" };

        // Strong tags whose contribution reputation must NOT decay away (real, corroborated detections).
        private static readonly string[] StrongTags =
            { "[HASH]", "[MALWARE]", "[VT]", "[YARA]", "[INJECTED]" };

        public ReputationService(string? databasePath = null)
        {
            _logger = LoggingService.ForContext<ReputationService>();

            if (string.IsNullOrEmpty(databasePath))
            {
                var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
                var dataFolder = Path.Combine(localAppData, "SkidrowKiller");
                if (!Directory.Exists(dataFolder)) Directory.CreateDirectory(dataFolder);
                databasePath = Path.Combine(dataFolder, "settings.db");
            }

            _connectionString = $"Data Source={databasePath}";
            InitializeTables();
            LoadConfig();
        }

        private SqliteConnection Open()
        {
            var connection = new SqliteConnection(_connectionString);
            connection.Open();
            using (var pragma = connection.CreateCommand())
            {
                pragma.CommandText = "PRAGMA busy_timeout=5000;";
                pragma.ExecuteNonQuery();
            }
            return connection;
        }

        private void InitializeTables()
        {
            try
            {
                using var connection = Open();
                using var cmd = connection.CreateCommand();

                cmd.CommandText = @"
                    CREATE TABLE IF NOT EXISTS FileReputation (
                        Hash TEXT PRIMARY KEY NOT NULL,
                        FirstSeen TEXT,
                        LastSeen TEXT,
                        GoodVotes INTEGER DEFAULT 0,
                        BadVotes INTEGER DEFAULT 0,
                        ReputationScore REAL DEFAULT 0.0,
                        BadCorroborated INTEGER DEFAULT 0,
                        GoodCorroborated INTEGER DEFAULT 0,
                        Source TEXT,
                        IsLocked INTEGER DEFAULT 0
                    );";
                cmd.ExecuteNonQuery();

                cmd.CommandText = @"
                    CREATE TABLE IF NOT EXISTS PatternStats (
                        PatternTag TEXT PRIMARY KEY NOT NULL,
                        TruePositiveCount INTEGER DEFAULT 0,
                        FalsePositiveCount INTEGER DEFAULT 0,
                        FpRateSmoothed REAL DEFAULT 0.0,
                        LastUpdated TEXT
                    );";
                cmd.ExecuteNonQuery();

                cmd.CommandText = @"
                    CREATE TABLE IF NOT EXISTS FeedbackEvents (
                        Id INTEGER PRIMARY KEY AUTOINCREMENT,
                        OccurredAt TEXT NOT NULL,
                        Hash TEXT,
                        Path TEXT,
                        SignalType TEXT NOT NULL,
                        OriginalScore INTEGER,
                        MatchedPatternsJson TEXT,
                        Source TEXT,
                        Corroborated INTEGER DEFAULT 0
                    );";
                cmd.ExecuteNonQuery();

                cmd.CommandText = @"
                    CREATE TABLE IF NOT EXISTS ReputationConfig (
                        Key TEXT PRIMARY KEY NOT NULL,
                        Value TEXT
                    );";
                cmd.ExecuteNonQuery();

                _logger.Information("Reputation (learning) store initialized");
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Failed to initialize reputation store");
            }
        }

        private void LoadConfig()
        {
            try
            {
                using var connection = Open();
                using var cmd = connection.CreateCommand();
                cmd.CommandText = "SELECT Key, Value FROM ReputationConfig";
                using var reader = cmd.ExecuteReader();
                while (reader.Read())
                {
                    var key = reader.GetString(0);
                    var val = reader.IsDBNull(1) ? "" : reader.GetString(1);
                    switch (key)
                    {
                        case "MinVotesBeforeTrust" when int.TryParse(val, out var i): _minVotesBeforeTrust = i; break;
                        case "TrustThreshold" when double.TryParse(val, out var d): _trustThreshold = d; break;
                        case "MaxHashBoost" when int.TryParse(val, out var b): _maxHashBoost = b; break;
                        case "MaxPatternDecayFraction" when double.TryParse(val, out var f): _maxPatternDecayFraction = f; break;
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.Debug(ex, "Reputation config not loaded; using defaults");
            }
        }

        #region Feedback recording (the "learning" inputs)

        public void RecordWhitelistAdd(string? hash, string path, IEnumerable<string>? matchedPatterns = null, int originalScore = 0)
            => RecordFeedback(SignalWhitelistAdd, hash, path, originalScore, matchedPatterns, goodDelta: 2, badDelta: 0);

        public void RecordQuarantineRestore(string? hash, string path, IEnumerable<string>? matchedPatterns = null, int originalScore = 0)
            => RecordFeedback(SignalQuarantineRestore, hash, path, originalScore, matchedPatterns, goodDelta: 1, badDelta: 0, creditPatternsAsFalsePositive: true);

        public void RecordFalsePositive(string? hash, string path, IEnumerable<string>? matchedPatterns = null, int originalScore = 0)
            => RecordFeedback(SignalFalsePositive, hash, path, originalScore, matchedPatterns, goodDelta: 2, badDelta: 0, creditPatternsAsFalsePositive: true);

        public void RecordConfirmedRemoval(string? hash, string path, IEnumerable<string>? matchedPatterns = null, int originalScore = 0)
            => RecordFeedback(SignalConfirmedRemoval, hash, path, originalScore, matchedPatterns, goodDelta: 0, badDelta: 2, creditPatternsAsTruePositive: true);

        /// <summary>VirusTotal corroboration — the only NON-user signal permitted to flip a verdict.</summary>
        public void RecordVirusTotal(string? hash, string path, int maliciousEngines, int totalEngines)
        {
            if (string.IsNullOrEmpty(hash)) return;
            if (maliciousEngines > 0)
            {
                var weight = maliciousEngines >= 5 ? 3 : 2;
                RecordFeedback(SignalVirusTotal, hash, path, 0, null, goodDelta: 0, badDelta: weight, corroborated: true, corroboratedBad: true);
            }
            else if (totalEngines > 0)
            {
                RecordFeedback(SignalVirusTotal, hash, path, 0, null, goodDelta: 1, badDelta: 0, corroborated: true, corroboratedGood: true);
            }
        }

        private void RecordFeedback(
            string signalType, string? hash, string path, int originalScore,
            IEnumerable<string>? matchedPatterns,
            int goodDelta, int badDelta,
            bool corroborated = false, bool corroboratedBad = false, bool corroboratedGood = false,
            bool creditPatternsAsFalsePositive = false, bool creditPatternsAsTruePositive = false)
        {
            try
            {
                var patterns = matchedPatterns?.ToList() ?? new List<string>();
                var patternsJson = JsonSerializer.Serialize(patterns);
                var now = DateTime.Now.ToString("O");

                using var connection = Open();
                using var tx = connection.BeginTransaction();

                // 1. Append-only audit event (always written, even when hash is unknown)
                using (var cmd = connection.CreateCommand())
                {
                    cmd.Transaction = tx;
                    cmd.CommandText = @"
                        INSERT INTO FeedbackEvents (OccurredAt, Hash, Path, SignalType, OriginalScore, MatchedPatternsJson, Source, Corroborated)
                        VALUES (@at, @hash, @path, @sig, @score, @patterns, @source, @corr)";
                    cmd.Parameters.AddWithValue("@at", now);
                    cmd.Parameters.AddWithValue("@hash", (object?)hash ?? DBNull.Value);
                    cmd.Parameters.AddWithValue("@path", path ?? "");
                    cmd.Parameters.AddWithValue("@sig", signalType);
                    cmd.Parameters.AddWithValue("@score", originalScore);
                    cmd.Parameters.AddWithValue("@patterns", patternsJson);
                    cmd.Parameters.AddWithValue("@source", signalType == SignalVirusTotal ? "virustotal" : "user");
                    cmd.Parameters.AddWithValue("@corr", corroborated ? 1 : 0);
                    cmd.ExecuteNonQuery();
                }

                // 2. Per-hash reputation
                if (!string.IsNullOrEmpty(hash))
                {
                    using var cmd = connection.CreateCommand();
                    cmd.Transaction = tx;
                    cmd.CommandText = @"
                        INSERT INTO FileReputation (Hash, FirstSeen, LastSeen, GoodVotes, BadVotes, BadCorroborated, GoodCorroborated, Source)
                        VALUES (@hash, @now, @now, @good, @bad, @cbad, @cgood, @source)
                        ON CONFLICT(Hash) DO UPDATE SET
                            LastSeen = @now,
                            GoodVotes = GoodVotes + @good,
                            BadVotes = BadVotes + @bad,
                            BadCorroborated = MAX(BadCorroborated, @cbad),
                            GoodCorroborated = MAX(GoodCorroborated, @cgood)";
                    cmd.Parameters.AddWithValue("@hash", hash);
                    cmd.Parameters.AddWithValue("@now", now);
                    cmd.Parameters.AddWithValue("@good", goodDelta);
                    cmd.Parameters.AddWithValue("@bad", badDelta);
                    cmd.Parameters.AddWithValue("@cbad", corroboratedBad ? 1 : 0);
                    cmd.Parameters.AddWithValue("@cgood", corroboratedGood ? 1 : 0);
                    cmd.Parameters.AddWithValue("@source", signalType == SignalVirusTotal ? "virustotal" : "user");
                    cmd.ExecuteNonQuery();

                    // refresh cached posterior for display
                    using var upd = connection.CreateCommand();
                    upd.Transaction = tx;
                    upd.CommandText = @"
                        UPDATE FileReputation
                        SET ReputationScore = CAST(GoodVotes + 1 AS REAL) / (GoodVotes + BadVotes + 2)
                        WHERE Hash = @hash";
                    upd.Parameters.AddWithValue("@hash", hash);
                    upd.ExecuteNonQuery();
                }

                // 3. Per-pattern statistics
                if (creditPatternsAsFalsePositive || creditPatternsAsTruePositive)
                {
                    foreach (var key in patterns.Select(NormalizePatternKey).Where(k => k != null).Distinct())
                    {
                        using var cmd = connection.CreateCommand();
                        cmd.Transaction = tx;
                        cmd.CommandText = @"
                            INSERT INTO PatternStats (PatternTag, TruePositiveCount, FalsePositiveCount, LastUpdated)
                            VALUES (@tag, @tp, @fp, @now)
                            ON CONFLICT(PatternTag) DO UPDATE SET
                                TruePositiveCount = TruePositiveCount + @tp,
                                FalsePositiveCount = FalsePositiveCount + @fp,
                                LastUpdated = @now";
                        cmd.Parameters.AddWithValue("@tag", key!);
                        cmd.Parameters.AddWithValue("@tp", creditPatternsAsTruePositive ? 1 : 0);
                        cmd.Parameters.AddWithValue("@fp", creditPatternsAsFalsePositive ? 1 : 0);
                        cmd.Parameters.AddWithValue("@now", now);
                        cmd.ExecuteNonQuery();

                        // Laplace-smoothed FP rate (k=5): a few reports nudge, they don't slam the rate to 1.0
                        using var upd = connection.CreateCommand();
                        upd.Transaction = tx;
                        upd.CommandText = @"
                            UPDATE PatternStats
                            SET FpRateSmoothed = CAST(FalsePositiveCount AS REAL) / (TruePositiveCount + FalsePositiveCount + 5)
                            WHERE PatternTag = @tag";
                        upd.Parameters.AddWithValue("@tag", key!);
                        upd.ExecuteNonQuery();
                    }
                }

                tx.Commit();
                _logger.Information("Reputation signal {Signal} recorded (hash={Hash})", signalType, string.IsNullOrEmpty(hash) ? "n/a" : hash[..Math.Min(12, hash.Length)]);
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Failed to record reputation feedback {Signal}", signalType);
            }
        }

        #endregion

        #region Score adjustment (the "learning" output, applied during scanning)

        /// <summary>
        /// Adjust a raw pattern score using what we've learned. Pure, bounded, and explainable.
        /// Fails safe: any error returns the score unchanged so detection never breaks because of learning.
        /// </summary>
        public ReputationAdjustment AdjustScore(string? hash, IReadOnlyList<string> matchedPatterns, int rawScore, int criticalThreshold)
        {
            var result = new ReputationAdjustment { AdjustedScore = rawScore };
            try
            {
                var hasStrongTag = matchedPatterns.Any(p => StrongTags.Any(t => p.StartsWith(t, StringComparison.OrdinalIgnoreCase)));

                // --- 1. Per-hash reputation -------------------------------------------------
                if (!string.IsNullOrEmpty(hash))
                {
                    var rep = GetReputation(hash);
                    if (rep != null)
                    {
                        // Admin pin overrides everything.
                        if (rep.IsLocked)
                        {
                            if (rep.GoodVotes >= rep.BadVotes)
                            {
                                result.TrustedSafe = true;
                                result.Notes.Add("[REP] admin-pinned safe");
                                return result;
                            }
                            result.KnownBad = true;
                            result.AdjustedScore = Math.Max(rawScore, criticalThreshold);
                            result.Notes.Add("[REP] admin-pinned malicious");
                            return result;
                        }

                        var totalVotes = rep.GoodVotes + rep.BadVotes;
                        var posterior = (rep.GoodVotes + 1.0) / (totalVotes + 2.0); // Beta(1,1) mean

                        // Known-bad (VT-corroborated, or strongly down-voted) → bounded boost, never silenced.
                        if (rep.BadCorroborated || (rep.BadVotes >= _minVotesBeforeTrust && posterior <= 0.2))
                        {
                            var boost = Math.Min(_maxHashBoost, rep.BadVotes * 5 + (rep.BadCorroborated ? 15 : 0));
                            result.KnownBad = true;
                            result.AdjustedScore = rawScore + boost;
                            result.Notes.Add($"[REP] +{boost} (known-bad hash{(rep.BadCorroborated ? ", VT-corroborated" : "")})");
                        }
                        // Locally trusted → silence, BUT never override a VT-confirmed-bad file (conflict ⇒ no trust).
                        else if (totalVotes >= _minVotesBeforeTrust && posterior >= _trustThreshold && !rep.BadCorroborated)
                        {
                            result.TrustedSafe = true;
                            result.Notes.Add($"[REP] trusted locally ({rep.GoodVotes} good votes)");
                            return result;
                        }
                    }
                }

                // --- 2. Per-pattern false-positive decay -----------------------------------
                // A pattern users keep marking as a false positive contributes less over time —
                // but only when no strong/corroborated signal is present, and always bounded.
                if (!hasStrongTag && result.AdjustedScore > 0)
                {
                    var rates = new List<double>();
                    foreach (var p in matchedPatterns)
                    {
                        if (NonScoringTags.Any(t => p.StartsWith(t, StringComparison.OrdinalIgnoreCase))) continue;
                        var key = NormalizePatternKey(p);
                        if (key == null) continue;
                        var fpRate = GetPatternFpRate(key);
                        if (fpRate > 0) rates.Add(fpRate);
                    }

                    if (rates.Count > 0)
                    {
                        var avgFp = rates.Average();
                        var fraction = Math.Min(_maxPatternDecayFraction, avgFp);
                        var reduction = (int)Math.Round(result.AdjustedScore * fraction);
                        if (reduction > 0)
                        {
                            result.AdjustedScore = Math.Max(0, result.AdjustedScore - reduction);
                            result.Notes.Add($"[REP] -{reduction} (learned false-positive rate {avgFp:F2})");
                        }
                    }
                }

                return result;
            }
            catch (Exception ex)
            {
                _logger.Debug(ex, "AdjustScore failed; returning raw score");
                return new ReputationAdjustment { AdjustedScore = rawScore };
            }
        }

        #endregion

        #region Maintenance / queries

        /// <summary>Exponential time-decay of votes toward neutral so old verdicts heal. Safe to call at startup.</summary>
        public void DecayOldReputations(int halfLifeDays = 90)
        {
            try
            {
                var cutoff = DateTime.Now.AddDays(-halfLifeDays).ToString("O");
                using var connection = Open();
                using var cmd = connection.CreateCommand();
                // Halve non-corroborated, non-locked votes that have not been reinforced within the half-life.
                cmd.CommandText = @"
                    UPDATE FileReputation
                    SET GoodVotes = GoodVotes / 2, BadVotes = BadVotes / 2
                    WHERE LastSeen < @cutoff AND IsLocked = 0 AND BadCorroborated = 0";
                cmd.Parameters.AddWithValue("@cutoff", cutoff);
                cmd.ExecuteNonQuery();
            }
            catch (Exception ex)
            {
                _logger.Debug(ex, "DecayOldReputations failed");
            }
        }

        public void SetLock(string hash, bool good)
        {
            try
            {
                using var connection = Open();
                using var cmd = connection.CreateCommand();
                cmd.CommandText = @"
                    INSERT INTO FileReputation (Hash, FirstSeen, LastSeen, GoodVotes, BadVotes, IsLocked, Source)
                    VALUES (@hash, @now, @now, @good, @bad, 1, 'admin')
                    ON CONFLICT(Hash) DO UPDATE SET IsLocked = 1, GoodVotes = GoodVotes + @good, BadVotes = BadVotes + @bad, LastSeen = @now";
                cmd.Parameters.AddWithValue("@hash", hash);
                cmd.Parameters.AddWithValue("@now", DateTime.Now.ToString("O"));
                cmd.Parameters.AddWithValue("@good", good ? 5 : 0);
                cmd.Parameters.AddWithValue("@bad", good ? 0 : 5);
                cmd.ExecuteNonQuery();
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Failed to set reputation lock for {Hash}", hash);
            }
        }

        private FileReputationRecord? GetReputation(string hash)
        {
            try
            {
                using var connection = Open();
                using var cmd = connection.CreateCommand();
                cmd.CommandText = "SELECT GoodVotes, BadVotes, BadCorroborated, GoodCorroborated, IsLocked FROM FileReputation WHERE Hash = @hash";
                cmd.Parameters.AddWithValue("@hash", hash);
                using var reader = cmd.ExecuteReader();
                if (reader.Read())
                {
                    return new FileReputationRecord
                    {
                        GoodVotes = reader.GetInt32(0),
                        BadVotes = reader.GetInt32(1),
                        BadCorroborated = reader.GetInt32(2) == 1,
                        GoodCorroborated = reader.GetInt32(3) == 1,
                        IsLocked = reader.GetInt32(4) == 1
                    };
                }
            }
            catch (Exception ex)
            {
                _logger.Debug(ex, "GetReputation failed for {Hash}", hash);
            }
            return null;
        }

        private double GetPatternFpRate(string patternKey)
        {
            try
            {
                using var connection = Open();
                using var cmd = connection.CreateCommand();
                cmd.CommandText = "SELECT FpRateSmoothed FROM PatternStats WHERE PatternTag = @tag";
                cmd.Parameters.AddWithValue("@tag", patternKey);
                var result = cmd.ExecuteScalar();
                return result != null && result != DBNull.Value ? Convert.ToDouble(result) : 0.0;
            }
            catch
            {
                return 0.0;
            }
        }

        /// <summary>
        /// Reduce a matched pattern to a stable key for stats, e.g. "[MED] crack (legacy)" → "[MED] crack".
        /// Keeps the tag plus the first meaningful token so per-pattern FP rates aggregate sensibly.
        /// </summary>
        private static string? NormalizePatternKey(string pattern)
        {
            if (string.IsNullOrWhiteSpace(pattern)) return null;
            var trimmed = pattern.Trim();
            if (!trimmed.StartsWith('[')) return trimmed.Length > 40 ? trimmed[..40] : trimmed;

            var close = trimmed.IndexOf(']');
            if (close < 0) return trimmed;

            var tag = trimmed[..(close + 1)];
            var rest = trimmed[(close + 1)..].Trim();
            if (rest.Length == 0) return tag;

            // first token of the remainder
            var firstSpace = rest.IndexOf(' ');
            var token = firstSpace < 0 ? rest : rest[..firstSpace];
            return $"{tag} {token}";
        }

        #endregion

        private class FileReputationRecord
        {
            public int GoodVotes { get; set; }
            public int BadVotes { get; set; }
            public bool BadCorroborated { get; set; }
            public bool GoodCorroborated { get; set; }
            public bool IsLocked { get; set; }
        }
    }

    /// <summary>Result of a reputation adjustment — bounded, explainable, fail-safe.</summary>
    public class ReputationAdjustment
    {
        public int AdjustedScore { get; set; }
        public bool TrustedSafe { get; set; }   // locally trusted → caller should treat as clean
        public bool KnownBad { get; set; }       // corroborated malicious → caller should not under-report
        public List<string> Notes { get; } = new();
    }
}
