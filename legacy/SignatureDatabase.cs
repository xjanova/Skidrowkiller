using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;

namespace SkidrowKiller
{
    public class MalwareSignature
    {
        public string Name { get; set; } = string.Empty;
        public string Category { get; set; } = string.Empty;
        public List<string> FileNamePatterns { get; set; } = new List<string>();
        public List<string> ProcessNamePatterns { get; set; } = new List<string>();
        public List<string> RegistryKeyPatterns { get; set; } = new List<string>();
        public List<string> SuspiciousDLLs { get; set; } = new List<string>();
        public string Description { get; set; } = string.Empty;
        public int ThreatLevel { get; set; } // 1-10
    }

    public class SignatureDatabase
    {
        private List<MalwareSignature> signatures = new List<MalwareSignature>();
        private readonly string databasePath;

        public SignatureDatabase()
        {
            // Use portable path - same directory as executable
            string exeDir = AppDomain.CurrentDomain.BaseDirectory;
            databasePath = Path.Combine(exeDir, "signatures.json");

            LoadSignatures();
        }

        private void LoadSignatures()
        {
            try
            {
                if (File.Exists(databasePath))
                {
                    string json = File.ReadAllText(databasePath);
                    signatures = JsonSerializer.Deserialize<List<MalwareSignature>>(json) ?? new List<MalwareSignature>();
                }
                else
                {
                    // Create default signatures
                    CreateDefaultSignatures();
                    SaveSignatures();
                }
            }
            catch
            {
                CreateDefaultSignatures();
            }
        }

        private void CreateDefaultSignatures()
        {
            signatures = new List<MalwareSignature>
            {
                new MalwareSignature
                {
                    Name = "Skidrow Crack Tools",
                    Category = "Crack/Keygen",
                    FileNamePatterns = new List<string>
                    {
                        "skidrow", "skid-row", "skid_row", "skdr",
                        "crack", "keygen", "patch", "loader"
                    },
                    ProcessNamePatterns = new List<string>
                    {
                        "skidrow", "crack", "keygen"
                    },
                    RegistryKeyPatterns = new List<string>
                    {
                        "skidrow", "crack"
                    },
                    Description = "Skidrow crack tools and keygens",
                    ThreatLevel = 8
                },
                new MalwareSignature
                {
                    Name = "Warez Groups",
                    Category = "Crack Groups",
                    FileNamePatterns = new List<string>
                    {
                        "reloaded", "codex", "plaza", "cpy", "3dm",
                        "ali213", "flt", "hoodlum", "prophet", "steampunks"
                    },
                    ProcessNamePatterns = new List<string>
                    {
                        "reloaded", "codex", "plaza"
                    },
                    Description = "Known warez/crack group tools",
                    ThreatLevel = 7
                },
                new MalwareSignature
                {
                    Name = "Steam Emulators",
                    Category = "Game Cracks",
                    FileNamePatterns = new List<string>
                    {
                        "smartsteam", "nosteam", "greensteam"
                    },
                    SuspiciousDLLs = new List<string>
                    {
                        "steam_api.dll", "steam_api64.dll",
                        "steamclient.dll", "steamclient64.dll",
                        "steam_emu.dll", "cream_api.dll", "uwpsteamapi.dll"
                    },
                    Description = "Steam emulators and cracked API",
                    ThreatLevel = 6
                },
                new MalwareSignature
                {
                    Name = "Trojan Backdoors",
                    Category = "Trojan",
                    ProcessNamePatterns = new List<string>
                    {
                        "backdoor", "trojan", "rat", "netbus"
                    },
                    Description = "Known trojan and backdoor patterns",
                    ThreatLevel = 10
                },
                new MalwareSignature
                {
                    Name = "Cryptominers",
                    Category = "Miner",
                    ProcessNamePatterns = new List<string>
                    {
                        "xmrig", "cgminer", "bfgminer", "cryptonight"
                    },
                    FileNamePatterns = new List<string>
                    {
                        "miner", "xmrig", "cgminer"
                    },
                    Description = "Cryptocurrency miners",
                    ThreatLevel = 9
                }
            };
        }

        public void SaveSignatures()
        {
            try
            {
                var options = new JsonSerializerOptions { WriteIndented = true };
                string json = JsonSerializer.Serialize(signatures, options);
                File.WriteAllText(databasePath, json);
            }
            catch
            {
                // Silently fail
            }
        }

        public List<MalwareSignature> GetAllSignatures()
        {
            return new List<MalwareSignature>(signatures);
        }

        public List<string> GetAllFilePatterns()
        {
            return signatures
                .SelectMany(s => s.FileNamePatterns)
                .Distinct()
                .ToList();
        }

        public List<string> GetAllProcessPatterns()
        {
            return signatures
                .SelectMany(s => s.ProcessNamePatterns)
                .Distinct()
                .ToList();
        }

        public List<string> GetAllRegistryPatterns()
        {
            return signatures
                .SelectMany(s => s.RegistryKeyPatterns)
                .Distinct()
                .ToList();
        }

        public List<string> GetAllSuspiciousDLLs()
        {
            return signatures
                .SelectMany(s => s.SuspiciousDLLs)
                .Distinct()
                .ToList();
        }

        public MalwareSignature? FindMatchingSignature(string text, string type)
        {
            if (string.IsNullOrEmpty(text)) return null;

            var lowerText = text.ToLower();

            foreach (var signature in signatures.OrderByDescending(s => s.ThreatLevel))
            {
                var patterns = type.ToLower() switch
                {
                    "file" => signature.FileNamePatterns,
                    "process" => signature.ProcessNamePatterns,
                    "registry" => signature.RegistryKeyPatterns,
                    "dll" => signature.SuspiciousDLLs,
                    _ => new List<string>()
                };

                if (patterns.Any(p => lowerText.Contains(p.ToLower())))
                {
                    return signature;
                }
            }

            return null;
        }

        public void AddCustomSignature(MalwareSignature signature)
        {
            signatures.Add(signature);
            SaveSignatures();
        }

        public string GetDatabasePath() => databasePath;

        public int GetSignatureCount() => signatures.Count;

        public DateTime GetLastModified()
        {
            try
            {
                if (File.Exists(databasePath))
                {
                    return File.GetLastWriteTime(databasePath);
                }
            }
            catch { }

            return DateTime.MinValue;
        }
    }
}
