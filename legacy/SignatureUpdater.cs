using System;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;

namespace SkidrowKiller
{
    public class SignatureUpdate
    {
        public string Version { get; set; } = "1.0";
        public DateTime UpdatedDate { get; set; }
        public int SignatureCount { get; set; }
        public string Source { get; set; } = string.Empty;
    }

    public class SignatureUpdater
    {
        private readonly string updateInfoPath;
        private readonly string signaturesPath;
        private static readonly HttpClient httpClient = new HttpClient
        {
            Timeout = TimeSpan.FromMinutes(5)
        };

        // Free malware signature sources
        private const string YARA_RULES_URL = "https://raw.githubusercontent.com/Yara-Rules/rules/master/malware/MALW_Warez.yar";
        private const string COMMUNITY_SIGNATURES_URL = "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/gen_cn_hacktools.yar";

        public event EventHandler<string>? UpdateProgress;
        public event EventHandler<string>? UpdateCompleted;
        public event EventHandler<string>? UpdateFailed;

        public SignatureUpdater()
        {
            string exeDir = AppDomain.CurrentDomain.BaseDirectory;
            updateInfoPath = Path.Combine(exeDir, "update_info.json");
            signaturesPath = Path.Combine(exeDir, "signatures.json");

            httpClient.DefaultRequestHeaders.Add("User-Agent", "SkidrowKiller/3.0");
        }

        public async Task<bool> CheckForUpdatesAsync()
        {
            try
            {
                var currentInfo = GetCurrentUpdateInfo();

                // Check if update is needed (once per day)
                if (currentInfo != null &&
                    (DateTime.Now - currentInfo.UpdatedDate).TotalDays < 1)
                {
                    RaiseUpdateProgress("Signatures are up to date");
                    return false;
                }

                return true;
            }
            catch
            {
                return true; // If can't check, assume update needed
            }
        }

        public async Task<bool> DownloadAndUpdateSignaturesAsync()
        {
            try
            {
                RaiseUpdateProgress("Starting signature update...");

                // Download YARA rules for warez/cracks
                RaiseUpdateProgress("Downloading YARA malware rules...");
                string yaraContent = await DownloadWithRetryAsync(YARA_RULES_URL);

                if (string.IsNullOrEmpty(yaraContent))
                {
                    RaiseUpdateProgress("Failed to download YARA rules, using fallback...");
                    yaraContent = await DownloadWithRetryAsync(COMMUNITY_SIGNATURES_URL);
                }

                // Parse YARA rules and convert to our signature format
                RaiseUpdateProgress("Processing signatures...");
                var newSignatures = ParseYaraRules(yaraContent);

                if (newSignatures.Count == 0)
                {
                    RaiseUpdateFailed("No valid signatures found in update");
                    return false;
                }

                // Load existing signatures
                var existingDb = new SignatureDatabase();
                var existingSignatures = existingDb.GetAllSignatures();

                // Merge with existing (keep custom ones)
                RaiseUpdateProgress("Merging with existing signatures...");
                var mergedSignatures = MergeSignatures(existingSignatures, newSignatures);

                // Save updated signatures
                var options = new JsonSerializerOptions { WriteIndented = true };
                string json = JsonSerializer.Serialize(mergedSignatures, options);
                File.WriteAllText(signaturesPath, json);

                // Update info file
                var updateInfo = new SignatureUpdate
                {
                    Version = "3.0",
                    UpdatedDate = DateTime.Now,
                    SignatureCount = mergedSignatures.Count,
                    Source = "YARA-Rules + Community"
                };

                string infoJson = JsonSerializer.Serialize(updateInfo, options);
                File.WriteAllText(updateInfoPath, infoJson);

                RaiseUpdateCompleted($"Updated successfully! {mergedSignatures.Count} signatures loaded.");
                return true;
            }
            catch (Exception ex)
            {
                RaiseUpdateFailed($"Update failed: {ex.Message}");
                return false;
            }
        }

        private async Task<string> DownloadWithRetryAsync(string url, int maxRetries = 3)
        {
            for (int i = 0; i < maxRetries; i++)
            {
                try
                {
                    var response = await httpClient.GetAsync(url);
                    if (response.IsSuccessStatusCode)
                    {
                        return await response.Content.ReadAsStringAsync();
                    }
                }
                catch
                {
                    if (i == maxRetries - 1) throw;
                    await Task.Delay(2000 * (i + 1)); // Exponential backoff
                }
            }
            return string.Empty;
        }

        private System.Collections.Generic.List<MalwareSignature> ParseYaraRules(string yaraContent)
        {
            var signatures = new System.Collections.Generic.List<MalwareSignature>();

            if (string.IsNullOrEmpty(yaraContent))
                return signatures;

            try
            {
                // Simple YARA parser - extract rule names and strings
                var lines = yaraContent.Split('\n');
                MalwareSignature? currentSig = null;
                bool inStringsSection = false;

                foreach (var line in lines)
                {
                    var trimmed = line.Trim();

                    // New rule
                    if (trimmed.StartsWith("rule "))
                    {
                        if (currentSig != null)
                        {
                            signatures.Add(currentSig);
                        }

                        var ruleName = trimmed.Replace("rule ", "").Split(new[] { '{', ':' })[0].Trim();
                        currentSig = new MalwareSignature
                        {
                            Name = ruleName,
                            Category = "YARA-Downloaded",
                            ThreatLevel = 8,
                            Description = $"Downloaded from YARA rules: {ruleName}",
                            FileNamePatterns = new System.Collections.Generic.List<string>(),
                            ProcessNamePatterns = new System.Collections.Generic.List<string>(),
                            RegistryKeyPatterns = new System.Collections.Generic.List<string>(),
                            SuspiciousDLLs = new System.Collections.Generic.List<string>()
                        };
                    }

                    // Strings section
                    if (trimmed == "strings:")
                    {
                        inStringsSection = true;
                        continue;
                    }

                    if (trimmed == "condition:")
                    {
                        inStringsSection = false;
                    }

                    // Extract patterns from strings
                    if (inStringsSection && currentSig != null && trimmed.Contains("="))
                    {
                        var pattern = ExtractPatternFromYaraString(trimmed);
                        if (!string.IsNullOrEmpty(pattern))
                        {
                            currentSig.FileNamePatterns.Add(pattern.ToLower());
                            currentSig.ProcessNamePatterns.Add(pattern.ToLower());
                        }
                    }
                }

                if (currentSig != null)
                {
                    signatures.Add(currentSig);
                }
            }
            catch
            {
                // If parsing fails, return what we have
            }

            return signatures;
        }

        private string ExtractPatternFromYaraString(string yaraString)
        {
            try
            {
                // Extract string value from YARA format: $a = "pattern" or $a = { hex }
                var parts = yaraString.Split('=');
                if (parts.Length < 2) return string.Empty;

                var value = parts[1].Trim();

                // String pattern
                if (value.StartsWith("\"") && value.Contains("\""))
                {
                    var start = value.IndexOf('"') + 1;
                    var end = value.IndexOf('"', start);
                    if (end > start)
                    {
                        var pattern = value.Substring(start, end - start);
                        // Clean up pattern
                        pattern = pattern.Replace("\\x", "")
                                       .Replace("\\", "")
                                       .Replace("*", "")
                                       .Trim();

                        if (pattern.Length >= 3) // Only meaningful patterns
                        {
                            return pattern;
                        }
                    }
                }
            }
            catch { }

            return string.Empty;
        }

        private System.Collections.Generic.List<MalwareSignature> MergeSignatures(
            System.Collections.Generic.List<MalwareSignature> existing,
            System.Collections.Generic.List<MalwareSignature> downloaded)
        {
            var merged = new System.Collections.Generic.List<MalwareSignature>();

            // Keep all custom (non-downloaded) signatures
            merged.AddRange(existing.Where(s => s.Category != "YARA-Downloaded"));

            // Add new downloaded signatures
            merged.AddRange(downloaded);

            return merged;
        }

        private SignatureUpdate? GetCurrentUpdateInfo()
        {
            try
            {
                if (File.Exists(updateInfoPath))
                {
                    string json = File.ReadAllText(updateInfoPath);
                    return JsonSerializer.Deserialize<SignatureUpdate>(json);
                }
            }
            catch { }

            return null;
        }

        public SignatureUpdate? GetUpdateInfo()
        {
            return GetCurrentUpdateInfo();
        }

        private void RaiseUpdateProgress(string message)
        {
            UpdateProgress?.Invoke(this, message);
        }

        private void RaiseUpdateCompleted(string message)
        {
            UpdateCompleted?.Invoke(this, message);
        }

        private void RaiseUpdateFailed(string message)
        {
            UpdateFailed?.Invoke(this, message);
        }
    }
}
