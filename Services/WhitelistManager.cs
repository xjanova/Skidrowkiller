using System.IO;
using SkidrowKiller.Models;

namespace SkidrowKiller.Services
{
    public class WhitelistManager
    {
        private readonly SettingsDatabase? _db;
        private readonly object _lock = new();

        // System paths that should NEVER be deleted
        private readonly HashSet<string> _protectedPaths = new(StringComparer.OrdinalIgnoreCase)
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            Environment.GetFolderPath(Environment.SpecialFolder.System),
            Environment.GetFolderPath(Environment.SpecialFolder.SystemX86),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "SysWOW64"),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
        };

        // Known safe Steam files (legitimate game files)
        private readonly HashSet<string> _knownSafeFiles = new(StringComparer.OrdinalIgnoreCase)
        {
            "steam.exe",
            "steamwebhelper.exe",
            "steamerrorreporter.exe",
        };

        // Directories that commonly have false positives
        private readonly string[] _cautionDirectories = new[]
        {
            "steamapps", "steam", "program files", "program files (x86)",
            ".git", "node_modules", "packages", "bin", "obj"
        };

        // Self-protection: whitelist our own executable and directory
        private readonly string _selfPath;
        private readonly string _selfDirectory;

        public WhitelistManager(SettingsDatabase? db = null)
        {
            _db = db;

            // Self-protection: get our own path to avoid flagging ourselves
            _selfPath = Environment.ProcessPath ?? "";
            _selfDirectory = AppDomain.CurrentDomain.BaseDirectory;
        }

        public bool IsWhitelisted(string path)
        {
            if (string.IsNullOrEmpty(path)) return false;

            // Self-protection: never flag ourselves!
            if (!string.IsNullOrEmpty(_selfPath) && path.Equals(_selfPath, StringComparison.OrdinalIgnoreCase))
                return true;

            if (!string.IsNullOrEmpty(_selfDirectory) && path.StartsWith(_selfDirectory, StringComparison.OrdinalIgnoreCase))
                return true;

            lock (_lock)
            {
                // Check system protected paths
                foreach (var protectedPath in _protectedPaths)
                {
                    if (path.StartsWith(protectedPath, StringComparison.OrdinalIgnoreCase))
                    {
                        // Allow scanning but be extra careful
                        var relativePath = path.Substring(protectedPath.Length).TrimStart(Path.DirectorySeparatorChar);
                        if (string.IsNullOrEmpty(relativePath))
                            return true; // Don't delete root system folders
                    }
                }

                // Check known safe files
                var fileName = Path.GetFileName(path);
                if (_knownSafeFiles.Contains(fileName))
                    return true;

                // Check database whitelist
                if (_db != null)
                {
                    return _db.IsWhitelisted(path);
                }
            }

            return false;
        }

        public bool IsInCautionDirectory(string path)
        {
            var lowerPath = path.ToLower();
            return _cautionDirectories.Any(dir => lowerPath.Contains(dir));
        }

        public bool IsSystemProtected(string path)
        {
            foreach (var protectedPath in _protectedPaths)
            {
                if (path.Equals(protectedPath, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
            return false;
        }

        public void AddToWhitelist(string path, string reason, bool isPattern = false)
        {
            lock (_lock)
            {
                _db?.AddToWhitelist(path, reason, isPattern);
            }
        }

        public void RemoveFromWhitelist(string path)
        {
            lock (_lock)
            {
                _db?.RemoveFromWhitelist(path);
            }
        }

        public void RemoveFromWhitelistById(long id)
        {
            lock (_lock)
            {
                _db?.RemoveFromWhitelistById(id);
            }
        }

        public List<WhitelistEntry> GetWhitelist()
        {
            lock (_lock)
            {
                if (_db == null) return new List<WhitelistEntry>();

                var records = _db.GetWhitelist();
                return records.Select(r => new WhitelistEntry
                {
                    Id = r.Id.ToString(),
                    Path = r.Path,
                    Name = Path.GetFileName(r.Path),
                    Reason = r.Reason ?? "",
                    IsPattern = r.IsPattern,
                    AddedAt = r.AddedAt
                }).ToList();
            }
        }
    }
}
