namespace SkidrowKiller.Models
{
    public enum ThreatSeverity
    {
        Safe = 0,
        Low = 1,
        Medium = 2,
        High = 3,
        Critical = 4
    }

    public enum ThreatType
    {
        File,
        Directory,
        Registry,
        Process,
        DllInjection,
        NetworkConnection
    }

    /// <summary>
    /// Category of threat - helps users understand what type of threat it is
    /// </summary>
    public enum ThreatCategory
    {
        Unknown,
        Crack,           // Scene group cracks (Skidrow, Codex, etc.)
        Keygen,          // Key generators
        Trainer,         // Game trainers/cheats
        Patcher,         // Crack patchers
        Loader,          // Crack loaders
        Activator,       // Windows/Office activators (KMSpico, etc.)
        SteamEmulator,   // Steam API emulators
        Trojan,          // Trojans and backdoors
        Ransomware,      // Ransomware
        Cryptominer,     // Cryptocurrency miners
        Stealer,         // Password/data stealers
        RAT,             // Remote Access Trojans
        Spyware,         // Spyware and keyloggers
        Adware,          // Adware and PUPs
        Rootkit,         // Rootkits
        Botnet,          // Botnet malware
        Suspicious       // Generic suspicious file
    }

    public class ThreatInfo
    {
        public string Id { get; set; } = Guid.NewGuid().ToString();
        public ThreatType Type { get; set; }
        public ThreatSeverity Severity { get; set; }
        public ThreatCategory Category { get; set; } = ThreatCategory.Unknown;
        public string Path { get; set; } = string.Empty;
        public string Name { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public int Score { get; set; } // 0-100, higher = more dangerous
        public List<string> MatchedPatterns { get; set; } = new();
        public DateTime DetectedAt { get; set; } = DateTime.Now;
        public bool IsWhitelisted { get; set; }
        public bool IsBackedUp { get; set; }
        public string? BackupPath { get; set; }
        public bool RequiresConfirmation => Score < 80 && !IsHighConfidence;
        public bool IsHighConfidence => Score >= 80 || MatchedPatterns.Count >= 3;

        // Enhanced threat info
        public string MalwareName { get; set; } = string.Empty;  // e.g., "Crack.Skidrow", "Trojan.Redline"
        public string MalwareFamily { get; set; } = string.Empty; // e.g., "Skidrow", "Redline"
        public string DetectionReason { get; set; } = string.Empty; // Why it was detected
        public string Recommendation { get; set; } = string.Empty;  // What user should do
        public bool CanIgnore { get; set; } = false; // Can user safely ignore this?

        // For processes
        public int? ProcessId { get; set; }
        public List<string>? LoadedDlls { get; set; }

        public string SeverityDisplay => Severity switch
        {
            ThreatSeverity.Critical => "CRITICAL",
            ThreatSeverity.High => "HIGH",
            ThreatSeverity.Medium => "MEDIUM",
            ThreatSeverity.Low => "LOW",
            _ => "SAFE"
        };

        public string CategoryDisplay => Category switch
        {
            ThreatCategory.Crack => "Game Crack",
            ThreatCategory.Keygen => "Key Generator",
            ThreatCategory.Trainer => "Game Trainer",
            ThreatCategory.Patcher => "Crack Patcher",
            ThreatCategory.Loader => "Crack Loader",
            ThreatCategory.Activator => "Activator Tool",
            ThreatCategory.SteamEmulator => "Steam Emulator",
            ThreatCategory.Trojan => "Trojan",
            ThreatCategory.Ransomware => "Ransomware",
            ThreatCategory.Cryptominer => "Crypto Miner",
            ThreatCategory.Stealer => "Info Stealer",
            ThreatCategory.RAT => "Remote Access Trojan",
            ThreatCategory.Spyware => "Spyware",
            ThreatCategory.Adware => "Adware/PUP",
            ThreatCategory.Rootkit => "Rootkit",
            ThreatCategory.Botnet => "Botnet",
            ThreatCategory.Suspicious => "Suspicious File",
            _ => "Unknown"
        };

        public string CanIgnoreDisplay => CanIgnore
            ? "May be safe to ignore if you trust the source"
            : "Should be removed - potential security risk";
    }

    public class ScanResult
    {
        public long TotalScanned { get; set; }
        public int ThreatsFound { get; set; }
        public int ThreatsRemoved { get; set; }
        public int ThreatsBackedUp { get; set; }
        public int ThreatsSkipped { get; set; }
        public int FailedToRemove { get; set; }
        public TimeSpan Duration { get; set; }
        public List<ThreatInfo> Threats { get; set; } = new();
    }

    public class WhitelistEntry
    {
        public string Id { get; set; } = Guid.NewGuid().ToString();
        public string Path { get; set; } = string.Empty;
        public string Name { get; set; } = string.Empty;
        public string Reason { get; set; } = string.Empty;
        public DateTime AddedAt { get; set; } = DateTime.Now;
        public bool IsPattern { get; set; } // true = wildcard pattern, false = exact path
    }
}
