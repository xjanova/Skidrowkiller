using System;
using System.Text;

namespace SkidrowKiller.Services
{
    /// <summary>
    /// ssdeep-compatible Context-Triggered Piecewise Hashing (CTPH / "spamsum").
    ///
    /// A fuzzy hash changes only a little when the file changes only a little, so two builds of the same
    /// malware family — even with a different SHA-256 — produce similar fuzzy hashes. Compare() returns a
    /// 0–100 similarity, letting the scanner catch VARIANTS that exact-hash and imphash miss.
    /// Pure managed implementation (no native ssdeep dependency).
    /// </summary>
    public static class FuzzyHash
    {
        private const int SpamsumLength = 64;
        private const int MinBlocksize = 3;
        private const int RollingWindow = 7;
        private const uint HashPrime = 0x01000193;
        private const uint HashInit = 0x28021967;
        private const string B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

        private struct Roll
        {
            public uint H1, H2, H3;
            public uint[] Window;
            public uint N;
        }

        private static uint RollHash(ref Roll r, byte b)
        {
            r.H2 -= r.H1;
            r.H2 += (uint)(RollingWindow * b);
            r.H1 += b;
            r.H1 -= r.Window[r.N % RollingWindow];
            r.Window[r.N % RollingWindow] = b;
            r.N++;
            r.H3 <<= 5;
            r.H3 ^= b;
            return r.H1 + r.H2 + r.H3;
        }

        private static uint SumHash(byte b, uint h) => (h * HashPrime) ^ b;

        /// <summary>Compute the ssdeep signature "blocksize:sig1:sig2" for a byte buffer.</summary>
        public static string Compute(byte[] data)
        {
            if (data == null || data.Length == 0) return "3::";

            uint blocksize = MinBlocksize;
            while (blocksize * SpamsumLength < data.Length)
                blocksize *= 2;

            string sig1, sig2;
            while (true)
            {
                var sb1 = new StringBuilder();
                var sb2 = new StringBuilder();
                var roll = new Roll { H1 = 0, H2 = 0, H3 = 0, Window = new uint[RollingWindow], N = 0 };
                uint h1 = HashInit, h2 = HashInit;

                foreach (var b in data)
                {
                    var rh = RollHash(ref roll, b);
                    h1 = SumHash(b, h1);
                    h2 = SumHash(b, h2);

                    if (rh % blocksize == blocksize - 1 && sb1.Length < SpamsumLength - 1)
                    {
                        sb1.Append(B64[(int)(h1 % 64)]);
                        h1 = HashInit;
                    }
                    if (rh % (blocksize * 2) == (blocksize * 2) - 1 && sb2.Length < (SpamsumLength / 2) - 1)
                    {
                        sb2.Append(B64[(int)(h2 % 64)]);
                        h2 = HashInit;
                    }
                }

                sb1.Append(B64[(int)(h1 % 64)]);
                sb2.Append(B64[(int)(h2 % 64)]);
                sig1 = sb1.ToString();
                sig2 = sb2.ToString();

                // If the chosen blocksize produced too short a signature, halve it and retry.
                if (blocksize > MinBlocksize && sig1.Length < SpamsumLength / 2)
                {
                    blocksize /= 2;
                    continue;
                }
                break;
            }

            return $"{blocksize}:{sig1}:{sig2}";
        }

        /// <summary>Similarity 0–100 between two ssdeep signatures (0 = unrelated, 100 = identical).</summary>
        public static int Compare(string? a, string? b)
        {
            if (string.IsNullOrEmpty(a) || string.IsNullOrEmpty(b)) return 0;

            var pa = a.Split(':');
            var pb = b.Split(':');
            if (pa.Length != 3 || pb.Length != 3) return 0;
            if (!long.TryParse(pa[0], out var bsA) || !long.TryParse(pb[0], out var bsB)) return 0;

            // Signatures are only comparable when blocksizes are equal or adjacent (2x).
            int score = 0;
            if (bsA == bsB)
            {
                score = Math.Max(ScoreStrings(pa[1], pb[1], bsA), ScoreStrings(pa[2], pb[2], bsA * 2));
            }
            else if (bsA == bsB * 2)
            {
                score = ScoreStrings(pa[1], pb[2], bsA);
            }
            else if (bsB == bsA * 2)
            {
                score = ScoreStrings(pa[2], pb[1], bsB);
            }
            return score;
        }

        private static int ScoreStrings(string s1, string s2, long blocksize)
        {
            s1 = EliminateLongRuns(s1);
            s2 = EliminateLongRuns(s2);
            if (s1.Length == 0 || s2.Length == 0) return 0;

            // Require a common substring of length >= ROLLING_WINDOW, else they are unrelated.
            if (!HasCommonSubstring(s1, s2, RollingWindow)) return 0;

            var dist = Levenshtein(s1, s2);
            var score = (dist * SpamsumLength) / (s1.Length + s2.Length);
            score = (100 * score) / SpamsumLength;
            score = 100 - score;

            // Cap the score for small blocksizes (short signatures can't be highly confident).
            var cap = (int)(blocksize / MinBlocksize * Math.Min(s1.Length, s2.Length));
            if (score > cap) score = cap;
            if (score > 100) score = 100;
            if (score < 0) score = 0;
            return score;
        }

        private static string EliminateLongRuns(string s)
        {
            if (s.Length < 4) return s;
            var sb = new StringBuilder(s.Length);
            foreach (var c in s)
            {
                // collapse runs of 4+ identical chars to 3 (matches ssdeep behavior)
                int n = sb.Length;
                if (n >= 3 && sb[n - 1] == c && sb[n - 2] == c && sb[n - 3] == c) continue;
                sb.Append(c);
            }
            return sb.ToString();
        }

        private static bool HasCommonSubstring(string s1, string s2, int len)
        {
            if (s1.Length < len || s2.Length < len) return false;
            for (var i = 0; i + len <= s1.Length; i++)
            {
                var sub = s1.Substring(i, len);
                if (s2.Contains(sub)) return true;
            }
            return false;
        }

        private static int Levenshtein(string s, string t)
        {
            var n = s.Length;
            var m = t.Length;
            var prev = new int[m + 1];
            var cur = new int[m + 1];
            for (var j = 0; j <= m; j++) prev[j] = j;

            for (var i = 1; i <= n; i++)
            {
                cur[0] = i;
                for (var j = 1; j <= m; j++)
                {
                    var cost = s[i - 1] == t[j - 1] ? 0 : 1;
                    cur[j] = Math.Min(Math.Min(cur[j - 1] + 1, prev[j] + 1), prev[j - 1] + cost);
                }
                (prev, cur) = (cur, prev);
            }
            return prev[m];
        }
    }
}
