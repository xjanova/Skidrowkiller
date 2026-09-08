using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using Microsoft.Win32;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using SkidrowKiller.Models;
using Serilog;

namespace SkidrowKiller.Services
{
    /// <summary>
    /// In-app diagnostics that PROVE the product actually scans, removes, quarantines and updates.
    /// Every check runs against the real services on small, benign, synthetic inputs in a neutral
    /// temp sandbox (NOT real malware — so it won't fight Windows Defender). This is how you answer
    /// "does it really work?" without needing live samples.
    /// </summary>
    public class SelfTestService
    {
        private readonly ThreatAnalyzer _analyzer;
        private readonly QuarantineService? _quarantine;
        private readonly BackupManager? _backup;
        private readonly ThreatIntelligenceService? _intel;
        private readonly ILogger _logger;

        /// <summary>
        /// Private scanner instance. The self-test must NOT drive the app's shared SafeScanner: its
        /// ScanCompleted event would pop the "Scan completed!" dialog on the Scan screen, and its
        /// re-entrancy gate would reject the run outright while a real scan is in progress.
        /// </summary>
        private readonly SafeScanner? _scanner;

        public SelfTestService(ThreatAnalyzer analyzer,
            QuarantineService? quarantine = null,
            WhitelistManager? whitelist = null,
            BackupManager? backup = null,
            ThreatIntelligenceService? intel = null)
        {
            _analyzer = analyzer;
            _quarantine = quarantine;
            _backup = backup;
            _intel = intel;
            _logger = LoggingService.ForContext<SelfTestService>();

            if (whitelist != null && backup != null)
                _scanner = new SafeScanner(analyzer, whitelist, backup, quarantine);
        }

        public async Task<List<SelfTestResult>> RunAsync()
        {
            var results = new List<SelfTestResult>();
            // Neutral sandbox (must NOT contain "skidrowkiller" or the analyzer self-excludes it).
            var dir = Path.Combine(Path.GetTempPath(), "skk_selftest_" + Guid.NewGuid().ToString("N"));

            try
            {
                Directory.CreateDirectory(dir);

                await RunDetectionChecksAsync(results, dir);
                await RunRemovalChecksAsync(results, dir);
                await RunEradicationChecksAsync(results, dir);
                await RunQuarantineChecksAsync(results, dir);
                RunLearningChecksAsync(results, dir);
                RunLibraryChecks(results);
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Self-test run failed");
            }
            finally
            {
                try { if (Directory.Exists(dir)) Directory.Delete(dir, true); } catch { }
            }

            return results;
        }

        #region Detection

        private async Task RunDetectionChecksAsync(List<SelfTestResult> results, string dir)
        {
            // 1) Suspicious extension (.crack)
            await SafeCheck(results, "Detect by filename (.crack)", () =>
            {
                var f = Path.Combine(dir, "sample_release.crack");
                File.WriteAllText(f, "benign self-test content");
                return Task.FromResult(_analyzer.AnalyzePath(f) != null);
            });

            // 2) Scene-group filename pattern (razor1911 + keygen)
            await SafeCheck(results, "Detect by scene-group name pattern", () =>
            {
                var f = Path.Combine(dir, "razor1911_keygen_readme.txt");
                File.WriteAllText(f, "benign self-test content");
                return Task.FromResult(_analyzer.AnalyzePath(f) != null);
            });

            // 3) THE important one: a known-bad HASH on a file with a completely innocent name.
            //    This is what real malware looks like on disk. It proves the scanner consults the
            //    hash library and not just the filename — the exact gap that made the downloaded
            //    virus database useless during a scan.
            await SafeCheck(results, "Detect by content hash (innocent filename)", async () =>
            {
                var f = Path.Combine(dir, "holiday_photo_2024.dat");
                File.WriteAllBytes(f, System.Text.Encoding.ASCII.GetBytes("skk-selftest-body-0001"));

                var sha256 = await _analyzer.SignatureDatabase.ComputeSHA256Async(f);
                if (string.IsNullOrEmpty(sha256)) return false;

                _analyzer.SignatureDatabase.AddHash(sha256, HashType.SHA256,
                    "SelfTest.SyntheticSample", "SelfTest", 9);

                // Exactly the call SafeScanner makes for every file it scans.
                var verdict = await _analyzer.AnalyzeFileAsync(f, DetectionDepth.Signature);
                return verdict != null && verdict.MatchedPatterns.Any(p => p.StartsWith("[HASH]"));
            });

            // 4) NTFS Alternate Data Stream hiding an executable
            await SafeCheck(results, "Detect hidden ADS executable stream", () =>
            {
                var f = Path.Combine(dir, "invoice.txt");
                File.WriteAllText(f, "ordinary document body");
                try
                {
                    // MZ header so it is recognised as executable-like; benign 4-byte stub.
                    File.WriteAllBytes(f + ":payload.exe", new byte[] { 0x4D, 0x5A, 0x90, 0x00 });
                }
                catch { }
                var ads = AdsScanner.ScanFile(f);
                return Task.FromResult(ads.HasHiddenExecutableStream);
            });

            // 5) Ransomware anti-recovery content signature
            await SafeCheck(results, "Detect anti-recovery command in file content", async () =>
            {
                var f = Path.Combine(dir, "maintenance_note.txt");
                File.WriteAllText(f, "step1 echo cleaning\r\nstep2 vssadmin delete shadows /all /quiet\r\n");
                var match = await _analyzer.SignatureDatabase.CheckFileContentAsync(f);
                return match != null && match.MatchScore > 0;
            });

            // 6) FALSE-POSITIVE negative — a perfectly benign file must NOT be flagged
            await SafeCheck(results, "No false positive on a benign file", async () =>
            {
                var f = Path.Combine(dir, "vacation_notes.txt");
                File.WriteAllText(f, "Remember to water the plants and call mom on Sunday.");
                return await _analyzer.AnalyzeFileAsync(f, DetectionDepth.Full) == null;
            });

            // 7) End-to-end: a real SafeScanner run must surface the hash-matched file.
            if (_scanner != null)
            {
                await SafeCheck(results, "Full scan finds the hash-matched file", async () =>
                {
                    var scanDir = Path.Combine(dir, "scan_target");
                    Directory.CreateDirectory(scanDir);

                    var f = Path.Combine(scanDir, "family_album.dat");
                    File.WriteAllBytes(f, System.Text.Encoding.ASCII.GetBytes("skk-selftest-body-0002"));

                    var sha256 = await _analyzer.SignatureDatabase.ComputeSHA256Async(f);
                    if (string.IsNullOrEmpty(sha256)) return false;
                    _analyzer.SignatureDatabase.AddHash(sha256, HashType.SHA256,
                        "SelfTest.SyntheticSample", "SelfTest", 9);

                    var hits = new List<ThreatInfo>();
                    void OnFound(object? s, ThreatInfo t) => hits.Add(t);

                    _scanner.ThreatFound += OnFound;
                    try
                    {
                        await _scanner.ScanAsync(scanFiles: true, scanRegistry: false, scanProcesses: false,
                            Views.ScanMode.Custom, null, new List<string> { scanDir });
                    }
                    finally { _scanner.ThreatFound -= OnFound; }

                    return hits.Any(t => string.Equals(t.Path, f, StringComparison.OrdinalIgnoreCase));
                });
            }
        }

        #endregion

        #region Removal

        private async Task RunRemovalChecksAsync(List<SelfTestResult> results, string dir)
        {
            if (_scanner == null) return;

            await SafeCheck(results, "Remove wipes the file from disk", async () =>
            {
                var f = Path.Combine(dir, "doomed_payload.bin");
                File.WriteAllBytes(f, RandomNumberGenerator.GetBytes(2048));

                var threat = new ThreatInfo
                {
                    Type = ThreatType.File,
                    Path = f,
                    Name = Path.GetFileName(f),
                    Score = 95
                };

                var ok = await _scanner.RemoveThreatAsync(threat, backup: _backup != null);
                return ok && !File.Exists(f);
            });

            if (_backup != null)
            {
                await SafeCheck(results, "Removal takes a restorable backup first", async () =>
                {
                    var f = Path.Combine(dir, "recoverable_payload.bin");
                    var bytes = RandomNumberGenerator.GetBytes(1024);
                    File.WriteAllBytes(f, bytes);

                    var threat = new ThreatInfo
                    {
                        Type = ThreatType.File,
                        Path = f,
                        Name = Path.GetFileName(f),
                        Score = 95
                    };

                    if (!await _scanner.RemoveThreatAsync(threat, backup: true)) return false;
                    if (File.Exists(f)) return false;
                    if (!threat.IsBackedUp || string.IsNullOrEmpty(threat.BackupPath)) return false;

                    var restored = _backup.Restore(threat.BackupPath) && File.Exists(f)
                                   && File.ReadAllBytes(f).SequenceEqual(bytes);

                    _backup.DeleteBackup(threat.BackupPath);
                    return restored;
                });
            }
        }

        #endregion

        #region Eradication (kill + persistence + wipe)

        private const string SelfTestRunValue = "SkidrowKillerSelfTest";
        private const string RunKeyPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";

        /// <summary>A harmless, signed Microsoft executable we can copy and run as a stand-in sample.</summary>
        private static string StandInExecutable => Path.Combine(Environment.SystemDirectory, "ping.exe");

        private async Task RunEradicationChecksAsync(List<SelfTestResult> results, string dir)
        {
            if (_scanner == null) return;

            // K1: a RUNNING sample. Killing the PID alone used to leave the image on disk and the
            //     old code reported "securely wiped" for a file that was still there.
            await SafeCheck(results, "Kill a running sample and wipe its image", async () =>
            {
                var image = Path.Combine(dir, "live_sample.exe");
                File.Copy(StandInExecutable, image);

                using var proc = Process.Start(new ProcessStartInfo(image, "-n 60 127.0.0.1")
                {
                    UseShellExecute = false, CreateNoWindow = true
                });
                if (proc == null) throw new InvalidOperationException("could not start the stand-in process");

                try
                {
                    var threat = new ThreatInfo
                    {
                        Type = ThreatType.Process, Path = image, Name = "live_sample.exe",
                        ProcessId = proc.Id, Score = 95, Severity = ThreatSeverity.Critical
                    };

                    var outcome = await _scanner.EradicateAsync(threat, backup: false, EradicationMode.Delete);
                    proc.WaitForExit(3000);

                    return outcome.ProcessesKilled >= 1 && proc.HasExited
                           && (!File.Exists(image) || outcome.DeferredToReboot);
                }
                finally
                {
                    try { if (!proc.HasExited) proc.Kill(true); } catch { }
                }
            });

            // K2: persistence. A file removal that leaves the Run key behind is a removal that fails
            //     at the next logon.
            await SafeCheck(results, "Autorun entry pointing at the sample is removed", async () =>
            {
                var image = Path.Combine(dir, "persist_sample.exe");
                File.Copy(StandInExecutable, image);

                using (var run = Registry.CurrentUser.OpenSubKey(RunKeyPath, writable: true))
                    run?.SetValue(SelfTestRunValue, $"\"{image}\" -n 1 127.0.0.1");

                try
                {
                    var threat = new ThreatInfo
                    {
                        Type = ThreatType.File, Path = image, Name = "persist_sample.exe",
                        Score = 95, Severity = ThreatSeverity.Critical
                    };

                    var outcome = await _scanner.EradicateAsync(threat, backup: false, EradicationMode.Delete);

                    bool stillThere;
                    using (var check = Registry.CurrentUser.OpenSubKey(RunKeyPath))
                        stillThere = check?.GetValue(SelfTestRunValue) != null;

                    return outcome.RunEntriesRemoved >= 1 && !stillThere && !File.Exists(image);
                }
                finally
                {
                    try
                    {
                        using var run = Registry.CurrentUser.OpenSubKey(RunKeyPath, writable: true);
                        run?.DeleteValue(SelfTestRunValue, throwOnMissingValue: false);
                    }
                    catch { }
                }
            });

            // K3: honesty. Removal must NOT claim success for a file it could not remove.
            await SafeCheck(results, "Removal reports failure honestly", async () =>
            {
                var locked = Path.Combine(dir, "locked_sample.bin");
                File.WriteAllBytes(locked, new byte[4096]);

                // Hold the file open with no sharing so both the wipe and the delete must fail.
                using var hold = new FileStream(locked, FileMode.Open, FileAccess.ReadWrite, FileShare.None);

                var threat = new ThreatInfo { Type = ThreatType.File, Path = locked, Name = "locked_sample.bin", Score = 95 };
                var removed = await _scanner.RemoveThreatAsync(threat, backup: false);

                // Either it was honestly reported as not removed, or it was honestly deferred to
                // reboot - what it must never do is return true while the file is still here.
                return !removed && File.Exists(locked) && !string.IsNullOrEmpty(threat.RemovalNote);
            });
        }

        #endregion

        #region Learning

        private void RunLearningChecksAsync(List<SelfTestResult> results, string dir)
        {
            var rep = _analyzer.Reputation;
            if (rep == null)
            {
                results.Add(new SelfTestResult
                {
                    Name = "Learning memory is attached",
                    Passed = false,
                    Detail = "ReputationService is not wired into the analyzer"
                });
                return;
            }

            // L1: three confirmed removals of the same bytes must make the engine score them higher
            //     next time (a single removal deliberately does not - MinVotesBeforeTrust guards
            //     against one click poisoning the memory).
            try
            {
                var f = Path.Combine(dir, "learn_bad.bin");
                File.WriteAllBytes(f, System.Security.Cryptography.RandomNumberGenerator.GetBytes(512));
                var hash = MalwareSignatureDatabase.ComputeSHA256(File.ReadAllBytes(f));
                var patterns = new List<string> { "[SIG] selftest-pattern" };

                var before = rep.AdjustScore(hash, patterns, 30, 80);
                for (var i = 0; i < 3; i++) rep.RecordConfirmedRemoval(hash, f, patterns, 30);
                var after = rep.AdjustScore(hash, patterns, 30, 80);

                results.Add(new SelfTestResult
                {
                    Name = "Learns from confirmed removals",
                    Passed = !before.KnownBad && after.KnownBad && after.AdjustedScore > before.AdjustedScore,
                    Detail = $"score {before.AdjustedScore} → {after.AdjustedScore} after 3 confirmed removals"
                });
            }
            catch (Exception ex)
            {
                results.Add(new SelfTestResult { Name = "Learns from confirmed removals", Passed = false, Detail = ex.Message });
            }

            // L2: repeated "this is safe" feedback must silence the detection for those bytes.
            try
            {
                var f = Path.Combine(dir, "learn_good.bin");
                File.WriteAllBytes(f, System.Security.Cryptography.RandomNumberGenerator.GetBytes(512));
                var hash = MalwareSignatureDatabase.ComputeSHA256(File.ReadAllBytes(f));
                var patterns = new List<string> { "[SIG] selftest-pattern" };

                var before = rep.AdjustScore(hash, patterns, 30, 80);
                rep.RecordWhitelistAdd(hash, f, patterns, 30);
                rep.RecordWhitelistAdd(hash, f, patterns, 30);
                var after = rep.AdjustScore(hash, patterns, 30, 80);

                results.Add(new SelfTestResult
                {
                    Name = "Learns from 'this is safe' feedback",
                    Passed = !before.TrustedSafe && after.TrustedSafe,
                    Detail = after.TrustedSafe ? "hash is now locally trusted" : "hash was not trusted after feedback"
                });
            }
            catch (Exception ex)
            {
                results.Add(new SelfTestResult { Name = "Learns from 'this is safe' feedback", Passed = false, Detail = ex.Message });
            }
        }

        #endregion

        #region Quarantine

        private async Task RunQuarantineChecksAsync(List<SelfTestResult> results, string dir)
        {
            if (_quarantine == null) return;

            await SafeCheck(results, "Quarantine isolates, encrypts and restores", () =>
            {
                var f = Path.Combine(dir, "quarantine_me.bin");
                var bytes = RandomNumberGenerator.GetBytes(4096);
                File.WriteAllBytes(f, bytes);

                var result = _quarantine.QuarantineFile(f, new ThreatInfo
                {
                    Type = ThreatType.File,
                    Path = f,
                    Name = Path.GetFileName(f),
                    Score = 90
                });

                if (!result.Success || result.Entry == null) return Task.FromResult(false);

                // Original removed, encrypted blob present, and the blob is NOT the raw payload.
                if (File.Exists(f)) return Task.FromResult(false);
                if (!File.Exists(result.Entry.QuarantineFilePath)) return Task.FromResult(false);

                var blob = File.ReadAllBytes(result.Entry.QuarantineFilePath);
                if (blob.SequenceEqual(bytes)) return Task.FromResult(false); // stored in the clear

                // Round-trip: restore must give back byte-identical content.
                var restored = _quarantine.RestoreItem(result.Entry.Id);
                var ok = restored.Success && File.Exists(f) && File.ReadAllBytes(f).SequenceEqual(bytes);

                try { _quarantine.DeletePermanently(result.Entry.Id); } catch { }
                return Task.FromResult(ok);
            });
        }

        #endregion

        #region Virus library

        private void RunLibraryChecks(List<SelfTestResult> results)
        {
            var db = _analyzer.SignatureDatabase;

            results.Add(new SelfTestResult
            {
                Name = "Signature database loaded",
                Passed = db.TotalSignatures > 0,
                Detail = $"{db.TotalSignatures:N0} signatures, {db.TotalYaraRules:N0} YARA rules"
            });

            // The virus library only counts if hashes actually reached the engine.
            results.Add(new SelfTestResult
            {
                Name = "Virus hash library reached the engine",
                Passed = db.TotalHashes > 0,
                Detail = db.TotalHashes > 0
                    ? $"{db.TotalHashes:N0} known-bad hashes in memory"
                    : "0 hashes — run Update All on the Threat Intelligence screen"
            });

            if (_intel != null)
            {
                var stats = _intel.Stats;
                var total = stats.TotalHashes + stats.TotalUrls + stats.TotalIPs + stats.TotalYaraRules;
                results.Add(new SelfTestResult
                {
                    Name = "Threat-intel feeds have been downloaded",
                    Passed = total > 0,
                    Detail = total > 0
                        ? $"{total:N0} indicators cached, last update {_intel.LastUpdate:g}"
                        : "no feed data cached yet"
                });
            }
        }

        #endregion

        private async Task SafeCheck(List<SelfTestResult> results, string name, Func<Task<bool>> check)
        {
            try
            {
                var passed = await check();
                results.Add(new SelfTestResult { Name = name, Passed = passed });
            }
            catch (Exception ex)
            {
                results.Add(new SelfTestResult { Name = name, Passed = false, Detail = ex.Message });
            }
        }
    }

    public class SelfTestResult
    {
        public string Name { get; set; } = "";
        public bool Passed { get; set; }
        public string Detail { get; set; } = "";
        public string StatusText => Passed ? "PASS" : (string.IsNullOrEmpty(Detail) ? "FAIL" : "ERROR");

        /// <summary>Hide the second line entirely when a check has nothing extra to say.</summary>
        public System.Windows.Visibility DetailVisibility => string.IsNullOrWhiteSpace(Detail)
            ? System.Windows.Visibility.Collapsed
            : System.Windows.Visibility.Visible;

        public System.Windows.Media.Brush StatusBrush => Passed
            ? (System.Windows.Media.Brush)System.Windows.Application.Current.FindResource("SuccessBrush")
            : (System.Windows.Media.Brush)System.Windows.Application.Current.FindResource("DangerBrush");
    }
}
