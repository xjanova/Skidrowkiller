using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using Serilog;

namespace SkidrowKiller.Services
{
    /// <summary>
    /// In-app diagnostics that PROVE the detection engine actually fires. It builds small, benign,
    /// synthetic inputs in a neutral temp sandbox (NOT real malware — so it won't fight Windows Defender)
    /// and asserts each detection layer reaches the expected verdict, including a false-positive negative
    /// check. This is how you answer "does it really detect?" without needing live malware samples.
    /// </summary>
    public class SelfTestService
    {
        private readonly ThreatAnalyzer _analyzer;
        private readonly ILogger _logger;

        public SelfTestService(ThreatAnalyzer analyzer)
        {
            _analyzer = analyzer;
            _logger = LoggingService.ForContext<SelfTestService>();
        }

        public async Task<List<SelfTestResult>> RunAsync()
        {
            var results = new List<SelfTestResult>();
            // Neutral sandbox (must NOT contain "skidrowkiller" or the analyzer self-excludes it).
            var dir = Path.Combine(Path.GetTempPath(), "skk_selftest_" + Guid.NewGuid().ToString("N"));

            try
            {
                Directory.CreateDirectory(dir);

                // 1) Suspicious extension (.crack)
                await SafeCheck(results, "Suspicious extension (.crack)", () =>
                {
                    var f = Path.Combine(dir, "sample_release.crack");
                    File.WriteAllText(f, "benign self-test content");
                    return Task.FromResult(_analyzer.AnalyzePath(f) != null);
                });

                // 2) Scene-group filename pattern (razor1911 + keygen)
                await SafeCheck(results, "Scene-group filename pattern", () =>
                {
                    var f = Path.Combine(dir, "razor1911_keygen_readme.txt");
                    File.WriteAllText(f, "benign self-test content");
                    return Task.FromResult(_analyzer.AnalyzePath(f) != null);
                });

                // 3) NTFS Alternate Data Stream hiding an executable
                await SafeCheck(results, "Hidden ADS executable stream", () =>
                {
                    var f = Path.Combine(dir, "invoice.txt");
                    File.WriteAllText(f, "ordinary document body");
                    try
                    {
                        // MZ header so it is recognised as executable-like; benign 2-byte stub.
                        File.WriteAllBytes(f + ":payload.exe", new byte[] { 0x4D, 0x5A, 0x90, 0x00 });
                    }
                    catch { }
                    var ads = AdsScanner.ScanFile(f);
                    return Task.FromResult(ads.HasHiddenExecutableStream);
                });

                // 4) Ransomware anti-recovery content signature
                await SafeCheck(results, "Ransomware anti-recovery content", async () =>
                {
                    var f = Path.Combine(dir, "maintenance_note.txt");
                    File.WriteAllText(f, "step1 echo cleaning\r\nstep2 vssadmin delete shadows /all /quiet\r\n");
                    var match = await _analyzer.SignatureDatabase.CheckFileContentAsync(f);
                    return match != null && match.MatchScore > 0;
                });

                // 5) FALSE-POSITIVE negative — a perfectly benign file must NOT be flagged
                await SafeCheck(results, "No false positive on benign file", () =>
                {
                    var f = Path.Combine(dir, "vacation_notes.txt");
                    File.WriteAllText(f, "Remember to water the plants and call mom on Sunday.");
                    return Task.FromResult(_analyzer.AnalyzePath(f) == null);
                });
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

        public System.Windows.Media.Brush StatusBrush => Passed
            ? (System.Windows.Media.Brush)System.Windows.Application.Current.FindResource("SuccessBrush")
            : (System.Windows.Media.Brush)System.Windows.Application.Current.FindResource("DangerBrush");
    }
}
