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

    public class ThreatInfo
    {
        public string Id { get; set; } = Guid.NewGuid().ToString();
        public ThreatType Type { get; set; }
        public ThreatSeverity Severity { get; set; }
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
