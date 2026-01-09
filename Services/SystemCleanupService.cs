using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace SkidrowKiller.Services
{
    /// <summary>
    /// System Cleanup Service - Removes junk files, temporary files, and other system clutter
    /// to improve performance and free up disk space.
    /// </summary>
    public class SystemCleanupService : IDisposable
    {
        private bool _isDisposed;

        // Categories of files to clean
        public static readonly CleanupCategory[] CleanupCategories = new[]
        {
            new CleanupCategory
            {
                Id = "temp_files",
                Name = "Temporary Files",
                Description = "Windows and application temporary files",
                Paths = new[]
                {
                    Path.GetTempPath(),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp")
                },
                Patterns = new[] { "*.*" },
                IsSelected = true
            },
            new CleanupCategory
            {
                Id = "recycle_bin",
                Name = "Recycle Bin",
                Description = "Deleted files in Recycle Bin",
                IsRecycleBin = true,
                IsSelected = true
            },
            new CleanupCategory
            {
                Id = "browser_cache",
                Name = "Browser Cache",
                Description = "Cached files from web browsers",
                Paths = GetBrowserCachePaths(),
                Patterns = new[] { "*.*" },
                IsSelected = true
            },
            new CleanupCategory
            {
                Id = "browser_cookies",
                Name = "Browser Cookies",
                Description = "Cookies from web browsers (may log you out of websites)",
                Paths = GetBrowserCookiePaths(),
                Patterns = new[] { "*.*" },
                IsSelected = false
            },
            new CleanupCategory
            {
                Id = "browser_history",
                Name = "Browser History",
                Description = "Browsing history from web browsers",
                Paths = GetBrowserHistoryPaths(),
                Patterns = new[] { "*.*" },
                IsSelected = false
            },
            new CleanupCategory
            {
                Id = "windows_logs",
                Name = "Windows Logs",
                Description = "Windows log files",
                Paths = new[]
                {
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Logs"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "CrashDumps")
                },
                Patterns = new[] { "*.log", "*.dmp", "*.mdmp" },
                IsSelected = true
            },
            new CleanupCategory
            {
                Id = "windows_update",
                Name = "Windows Update Cleanup",
                Description = "Old Windows Update files",
                Paths = new[]
                {
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "SoftwareDistribution", "Download")
                },
                Patterns = new[] { "*.*" },
                IsSelected = false
            },
            new CleanupCategory
            {
                Id = "thumbnails",
                Name = "Thumbnail Cache",
                Description = "Cached thumbnails for images and videos",
                Paths = new[]
                {
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                        "Microsoft", "Windows", "Explorer")
                },
                Patterns = new[] { "thumbcache_*.db", "iconcache_*.db" },
                IsSelected = true
            },
            new CleanupCategory
            {
                Id = "prefetch",
                Name = "Prefetch Files",
                Description = "Windows prefetch cache (may slow down first app launch)",
                Paths = new[]
                {
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Prefetch")
                },
                Patterns = new[] { "*.pf" },
                IsSelected = false
            },
            new CleanupCategory
            {
                Id = "recent_docs",
                Name = "Recent Documents",
                Description = "List of recently accessed documents",
                Paths = new[]
                {
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                        "Microsoft", "Windows", "Recent")
                },
                Patterns = new[] { "*.lnk" },
                IsSelected = false
            },
            new CleanupCategory
            {
                Id = "installer_cache",
                Name = "Installer Cache",
                Description = "Cached installer files",
                Paths = new[]
                {
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                        "Package Cache")
                },
                Patterns = new[] { "*.*" },
                IsSelected = false
            }
        };

        public event EventHandler<CleanupProgressEventArgs>? ProgressChanged;
        public event EventHandler<string>? LogAdded;

        public SystemCleanupService()
        {
        }

        private static string[] GetBrowserCachePaths()
        {
            var paths = new List<string>();
            var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

            // Chrome
            paths.Add(Path.Combine(localAppData, "Google", "Chrome", "User Data", "Default", "Cache"));
            paths.Add(Path.Combine(localAppData, "Google", "Chrome", "User Data", "Default", "Code Cache"));

            // Edge
            paths.Add(Path.Combine(localAppData, "Microsoft", "Edge", "User Data", "Default", "Cache"));
            paths.Add(Path.Combine(localAppData, "Microsoft", "Edge", "User Data", "Default", "Code Cache"));

            // Firefox
            var firefoxProfiles = Path.Combine(appData, "Mozilla", "Firefox", "Profiles");
            if (Directory.Exists(firefoxProfiles))
            {
                foreach (var profile in Directory.GetDirectories(firefoxProfiles))
                {
                    paths.Add(Path.Combine(profile, "cache2"));
                }
            }

            // Brave
            paths.Add(Path.Combine(localAppData, "BraveSoftware", "Brave-Browser", "User Data", "Default", "Cache"));

            // Opera
            paths.Add(Path.Combine(appData, "Opera Software", "Opera Stable", "Cache"));

            return paths.ToArray();
        }

        private static string[] GetBrowserCookiePaths()
        {
            var paths = new List<string>();
            var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

            // Chrome
            paths.Add(Path.Combine(localAppData, "Google", "Chrome", "User Data", "Default", "Cookies"));

            // Edge
            paths.Add(Path.Combine(localAppData, "Microsoft", "Edge", "User Data", "Default", "Cookies"));

            // Brave
            paths.Add(Path.Combine(localAppData, "BraveSoftware", "Brave-Browser", "User Data", "Default", "Cookies"));

            return paths.ToArray();
        }

        private static string[] GetBrowserHistoryPaths()
        {
            var paths = new List<string>();
            var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

            // Chrome
            paths.Add(Path.Combine(localAppData, "Google", "Chrome", "User Data", "Default", "History"));

            // Edge
            paths.Add(Path.Combine(localAppData, "Microsoft", "Edge", "User Data", "Default", "History"));

            // Brave
            paths.Add(Path.Combine(localAppData, "BraveSoftware", "Brave-Browser", "User Data", "Default", "History"));

            return paths.ToArray();
        }

        public async Task<CleanupAnalysisResult> AnalyzeAsync(
            IEnumerable<string> selectedCategories,
            CancellationToken token = default)
        {
            var result = new CleanupAnalysisResult();
            var categories = CleanupCategories.Where(c => selectedCategories.Contains(c.Id)).ToList();

            RaiseLog("Starting cleanup analysis...");

            foreach (var category in categories)
            {
                if (token.IsCancellationRequested) break;

                var categoryResult = new CategoryAnalysisResult { Category = category };

                if (category.IsRecycleBin)
                {
                    // Estimate recycle bin size
                    try
                    {
                        var drives = DriveInfo.GetDrives().Where(d => d.IsReady && d.DriveType == DriveType.Fixed);
                        foreach (var drive in drives)
                        {
                            var recyclePath = Path.Combine(drive.RootDirectory.FullName, "$Recycle.Bin");
                            if (Directory.Exists(recyclePath))
                            {
                                await AnalyzeDirectoryAsync(recyclePath, categoryResult, token);
                            }
                        }
                    }
                    catch { }
                }
                else if (category.Paths != null)
                {
                    foreach (var path in category.Paths)
                    {
                        if (token.IsCancellationRequested) break;

                        if (Directory.Exists(path))
                        {
                            await AnalyzeDirectoryAsync(path, categoryResult, token, category.Patterns);
                        }
                        else if (File.Exists(path))
                        {
                            try
                            {
                                var info = new FileInfo(path);
                                categoryResult.TotalSize += info.Length;
                                categoryResult.FileCount++;
                            }
                            catch { }
                        }
                    }
                }

                result.Categories.Add(categoryResult);
                result.TotalSize += categoryResult.TotalSize;
                result.TotalFiles += categoryResult.FileCount;

                RaiseProgress(category.Name, (categories.IndexOf(category) + 1) * 100 / categories.Count);
            }

            RaiseLog($"Analysis complete: {FormatSize(result.TotalSize)} in {result.TotalFiles:N0} files");
            return result;
        }

        private async Task AnalyzeDirectoryAsync(
            string path,
            CategoryAnalysisResult result,
            CancellationToken token,
            string[]? patterns = null)
        {
            await Task.Run(() =>
            {
                try
                {
                    patterns ??= new[] { "*.*" };

                    foreach (var pattern in patterns)
                    {
                        if (token.IsCancellationRequested) return;

                        try
                        {
                            var files = Directory.GetFiles(path, pattern, SearchOption.AllDirectories);
                            foreach (var file in files)
                            {
                                if (token.IsCancellationRequested) return;

                                try
                                {
                                    var info = new FileInfo(file);
                                    result.TotalSize += info.Length;
                                    result.FileCount++;
                                }
                                catch { }
                            }
                        }
                        catch { }
                    }
                }
                catch { }
            }, token);
        }

        public async Task<CleanupResult> CleanAsync(
            IEnumerable<string> selectedCategories,
            CancellationToken token = default)
        {
            var result = new CleanupResult();
            var categories = CleanupCategories.Where(c => selectedCategories.Contains(c.Id)).ToList();

            RaiseLog("Starting cleanup...");

            foreach (var category in categories)
            {
                if (token.IsCancellationRequested) break;

                RaiseProgress($"Cleaning {category.Name}...", (categories.IndexOf(category)) * 100 / categories.Count);

                if (category.IsRecycleBin)
                {
                    await EmptyRecycleBinAsync(result, token);
                }
                else if (category.Paths != null)
                {
                    foreach (var path in category.Paths)
                    {
                        if (token.IsCancellationRequested) break;

                        if (Directory.Exists(path))
                        {
                            await CleanDirectoryAsync(path, result, token, category.Patterns);
                        }
                        else if (File.Exists(path))
                        {
                            await DeleteFileAsync(path, result);
                        }
                    }
                }
            }

            RaiseProgress("Cleanup complete", 100);
            RaiseLog($"Cleanup complete: {FormatSize(result.SpaceFreed)} freed, {result.FilesDeleted:N0} files removed");

            return result;
        }

        private async Task EmptyRecycleBinAsync(CleanupResult result, CancellationToken token)
        {
            await Task.Run(() =>
            {
                try
                {
                    // Use Shell32 to empty recycle bin
                    SHEmptyRecycleBin(IntPtr.Zero, null, SHERB_NOCONFIRMATION | SHERB_NOPROGRESSUI | SHERB_NOSOUND);
                    RaiseLog("Recycle Bin emptied");
                }
                catch (Exception ex)
                {
                    RaiseLog($"Failed to empty Recycle Bin: {ex.Message}");
                }
            }, token);
        }

        private async Task CleanDirectoryAsync(
            string path,
            CleanupResult result,
            CancellationToken token,
            string[]? patterns = null)
        {
            await Task.Run(() =>
            {
                try
                {
                    patterns ??= new[] { "*.*" };

                    foreach (var pattern in patterns)
                    {
                        if (token.IsCancellationRequested) return;

                        try
                        {
                            var files = Directory.GetFiles(path, pattern, SearchOption.AllDirectories);
                            foreach (var file in files)
                            {
                                if (token.IsCancellationRequested) return;
                                DeleteFileAsync(file, result).Wait();
                            }
                        }
                        catch { }
                    }

                    // Try to delete empty directories
                    try
                    {
                        DeleteEmptyDirectories(path);
                    }
                    catch { }
                }
                catch { }
            }, token);
        }

        private async Task DeleteFileAsync(string path, CleanupResult result)
        {
            await Task.Run(() =>
            {
                try
                {
                    var info = new FileInfo(path);
                    var size = info.Length;

                    // Remove read-only attribute if set
                    if ((info.Attributes & FileAttributes.ReadOnly) == FileAttributes.ReadOnly)
                    {
                        info.Attributes &= ~FileAttributes.ReadOnly;
                    }

                    File.Delete(path);
                    result.FilesDeleted++;
                    result.SpaceFreed += size;
                }
                catch
                {
                    result.FilesFailed++;
                }
            });
        }

        private void DeleteEmptyDirectories(string path)
        {
            try
            {
                foreach (var dir in Directory.GetDirectories(path))
                {
                    DeleteEmptyDirectories(dir);

                    if (!Directory.EnumerateFileSystemEntries(dir).Any())
                    {
                        try
                        {
                            Directory.Delete(dir);
                        }
                        catch { }
                    }
                }
            }
            catch { }
        }

        public static string FormatSize(long bytes)
        {
            string[] sizes = { "B", "KB", "MB", "GB", "TB" };
            int order = 0;
            double size = bytes;

            while (size >= 1024 && order < sizes.Length - 1)
            {
                order++;
                size /= 1024;
            }

            return $"{size:0.##} {sizes[order]}";
        }

        private void RaiseProgress(string status, int percent)
        {
            ProgressChanged?.Invoke(this, new CleanupProgressEventArgs
            {
                Status = status,
                PercentComplete = percent
            });
        }

        private void RaiseLog(string message)
        {
            LogAdded?.Invoke(this, message);
        }

        // P/Invoke for emptying recycle bin
        [System.Runtime.InteropServices.DllImport("shell32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
        private static extern int SHEmptyRecycleBin(IntPtr hwnd, string? pszRootPath, uint dwFlags);

        private const uint SHERB_NOCONFIRMATION = 0x00000001;
        private const uint SHERB_NOPROGRESSUI = 0x00000002;
        private const uint SHERB_NOSOUND = 0x00000004;

        public void Dispose()
        {
            if (_isDisposed) return;
            _isDisposed = true;
        }
    }

    public class CleanupCategory
    {
        public string Id { get; set; } = string.Empty;
        public string Name { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public string[]? Paths { get; set; }
        public string[]? Patterns { get; set; }
        public bool IsRecycleBin { get; set; }
        public bool IsSelected { get; set; }
    }

    public class CleanupAnalysisResult
    {
        public List<CategoryAnalysisResult> Categories { get; set; } = new();
        public long TotalSize { get; set; }
        public int TotalFiles { get; set; }
    }

    public class CategoryAnalysisResult
    {
        public CleanupCategory Category { get; set; } = new();
        public long TotalSize { get; set; }
        public int FileCount { get; set; }
    }

    public class CleanupResult
    {
        public int FilesDeleted { get; set; }
        public int FilesFailed { get; set; }
        public long SpaceFreed { get; set; }
    }

    public class CleanupProgressEventArgs : EventArgs
    {
        public string Status { get; set; } = string.Empty;
        public int PercentComplete { get; set; }
    }
}
