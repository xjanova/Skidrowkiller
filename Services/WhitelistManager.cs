using System.IO;
using System.Text.Json;
using SkidrowKiller.Models;

namespace SkidrowKiller.Services
{
    public class WhitelistManager
    {
        private readonly string _whitelistPath;
        private List<WhitelistEntry> _whitelist = new();
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

        public WhitelistManager()
        {
            _whitelistPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "whitelist.json");

            // Self-protection: get our own path to avoid flagging ourselves
            _selfPath = Environment.ProcessPath ?? "";
            _selfDirectory = AppDomain.CurrentDomain.BaseDirectory;

            LoadWhitelist();
        }

        public void LoadWhitelist()
        {
            lock (_lock)
            {
                try
                {
                    if (File.Exists(_whitelistPath))
                    {
                        var json = File.ReadAllText(_whitelistPath);
                        _whitelist = JsonSerializer.Deserialize<List<WhitelistEntry>>(json) ?? new();
                    }
                }
                catch
                {
                    _whitelist = new();
                }
            }
        }

        public void SaveWhitelist()
        {
            lock (_lock)
            {
                try
                {
                    var json = JsonSerializer.Serialize(_whitelist, new JsonSerializerOptions { WriteIndented = true });
                    File.WriteAllText(_whitelistPath, json);
                }
                catch { }
            }
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

                // Check user whitelist
                foreach (var entry in _whitelist)
                {
                    if (entry.IsPattern)
                    {
                        if (MatchesPattern(path, entry.Path))
                            return true;
                    }
                    else
                    {
                        if (path.Equals(entry.Path, StringComparison.OrdinalIgnoreCase))
                            return true;
                    }
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
                if (_whitelist.Any(w => w.Path.Equals(path, StringComparison.OrdinalIgnoreCase)))
                    return;

                _whitelist.Add(new WhitelistEntry
                {
                    Path = path,
                    Name = Path.GetFileName(path),
                    Reason = reason,
                    IsPattern = isPattern
                });

                SaveWhitelist();
            }
        }

        public void RemoveFromWhitelist(string id)
        {
            lock (_lock)
            {
                _whitelist.RemoveAll(w => w.Id == id);
                SaveWhitelist();
            }
        }

        public List<WhitelistEntry> GetWhitelist()
        {
            lock (_lock)
            {
                return _whitelist.ToList();
            }
        }

        private bool MatchesPattern(string path, string pattern)
        {
            // Simple wildcard matching
            if (pattern.EndsWith("*"))
            {
                var prefix = pattern.TrimEnd('*');
                return path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase);
            }
            if (pattern.StartsWith("*"))
            {
                var suffix = pattern.TrimStart('*');
                return path.EndsWith(suffix, StringComparison.OrdinalIgnoreCase);
            }
            if (pattern.Contains("*"))
            {
                var parts = pattern.Split('*');
                var index = 0;
                foreach (var part in parts)
                {
                    var found = path.IndexOf(part, index, StringComparison.OrdinalIgnoreCase);
                    if (found < 0) return false;
                    index = found + part.Length;
                }
                return true;
            }
            return path.Equals(pattern, StringComparison.OrdinalIgnoreCase);
        }
    }
}
