using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32;

namespace SkidrowKiller
{
    public class ProgressEventArgs : EventArgs
    {
        public int Percentage { get; set; }
        public string CurrentItem { get; set; } = string.Empty;
        public long ScannedCount { get; set; }
        public int FoundCount { get; set; }
    }

    public class ScanResult
    {
        public long TotalScanned { get; set; }
        public int ThreatsFound { get; set; }
        public int ThreatsRemoved { get; set; }
        public int FailedToRemove { get; set; }
    }

    public class Scanner
    {
        private readonly bool scanFiles;
        private readonly bool scanRegistry;
        private readonly bool scanProcesses;
        private readonly bool autoDelete;
        private CancellationTokenSource? cancellationTokenSource;
        private bool isPaused;
        private readonly ManualResetEventSlim pauseEvent = new ManualResetEventSlim(true);
        private LogWriter? logWriter;

        public event EventHandler<ProgressEventArgs>? ProgressChanged;
        public event EventHandler<string>? LogAdded;
        public event EventHandler<string>? StatusChanged;
        public event EventHandler<ScanResult>? ScanCompleted;

        public bool IsPaused => isPaused;
        public string? LogFilePath => logWriter?.LogFilePath;

        private readonly string[] skidrowPatterns = new[]
        {
            "skidrow",
            "skid-row",
            "skid_row",
            "skdr",
            "crack",
            "keygen",
            "reloaded",
            "codex",
            "plaza",
            "cpy",
            "3dm",
            "ali213",
            "flt",
            "hoodlum",
            "prophet",
            "steampunks",
            "darksiders",
            "smartsteam",
            "nosteam",
            "steam_api.dll",
            "steam_api64.dll",
            "steamclient.dll",
            "steamclient64.dll"
        };

        private readonly string[] suspiciousExtensions = new[]
        {
            ".crack",
            ".keygen",
            ".patch",
            ".loader"
        };

        private readonly string[] criticalFolders = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp"),
            Path.GetTempPath()
        };

        public Scanner(bool scanFiles, bool scanRegistry, bool scanProcesses, bool autoDelete)
        {
            this.scanFiles = scanFiles;
            this.scanRegistry = scanRegistry;
            this.scanProcesses = scanProcesses;
            this.autoDelete = autoDelete;
        }

        public async Task StartScanAsync()
        {
            cancellationTokenSource = new CancellationTokenSource();
            var token = cancellationTokenSource.Token;

            long totalScanned = 0;
            int threatsFound = 0;
            int threatsRemoved = 0;
            int failedToRemove = 0;

            logWriter = new LogWriter();

            try
            {
                RaiseStatusChanged("เริ่มการสแกน...");
                RaiseLogAdded("=" + new string('=', 60));
                RaiseLogAdded("เริ่มสแกนระบบเพื่อค้นหา Skidrow Malware");
                RaiseLogAdded($"Log file: {logWriter.LogFilePath}");
                RaiseLogAdded("=" + new string('=', 60));

                if (scanFiles)
                {
                    RaiseStatusChanged("กำลังสแกนไฟล์...");
                    RaiseLogAdded("\n[FILE SCAN] เริ่มสแกนไฟล์");

                    var fileResults = await ScanFilesAsync(token);
                    totalScanned += fileResults.Scanned;
                    threatsFound += fileResults.Found;
                    threatsRemoved += fileResults.Removed;
                    failedToRemove += fileResults.Failed;
                }

                if (scanRegistry && !token.IsCancellationRequested)
                {
                    RaiseStatusChanged("กำลังสแกน Registry...");
                    RaiseLogAdded("\n[REGISTRY SCAN] เริ่มสแกน Registry");

                    var registryResults = await ScanRegistryAsync(token);
                    totalScanned += registryResults.Scanned;
                    threatsFound += registryResults.Found;
                    threatsRemoved += registryResults.Removed;
                    failedToRemove += registryResults.Failed;
                }

                if (scanProcesses && !token.IsCancellationRequested)
                {
                    RaiseStatusChanged("กำลังสแกน Processes/Memory...");
                    RaiseLogAdded("\n[PROCESS/MEMORY SCAN] เริ่มสแกน RAM และ Processes");

                    var processResults = await ScanProcessesAsync(token);
                    totalScanned += processResults.Scanned;
                    threatsFound += processResults.Found;
                    threatsRemoved += processResults.Removed;
                    failedToRemove += processResults.Failed;
                }

                RaiseLogAdded("\n" + new string('=', 60));
                RaiseLogAdded("สรุปผลการสแกน:");
                RaiseLogAdded($"  - ตรวจสอบแล้ว: {totalScanned:N0}");
                RaiseLogAdded($"  - พบภัยคุกคาม: {threatsFound}");
                RaiseLogAdded($"  - ลบสำเร็จ: {threatsRemoved}");
                RaiseLogAdded($"  - ลบไม่สำเร็จ: {failedToRemove}");
                RaiseLogAdded(new string('=', 60));

                logWriter?.WriteSummary(totalScanned, threatsFound, threatsRemoved, failedToRemove);

                ScanCompleted?.Invoke(this, new ScanResult
                {
                    TotalScanned = totalScanned,
                    ThreatsFound = threatsFound,
                    ThreatsRemoved = threatsRemoved,
                    FailedToRemove = failedToRemove
                });
            }
            catch (OperationCanceledException)
            {
                RaiseLogAdded("\n[หยุดการสแกน] ผู้ใช้หยุดการทำงาน");
                RaiseStatusChanged("หยุดการสแกนแล้ว");

                logWriter?.WriteLine("\n[SCAN CANCELLED] User stopped the scan");
                logWriter?.Dispose();
            }
            catch (Exception ex)
            {
                RaiseLogAdded($"\n[ERROR] เกิดข้อผิดพลาด: {ex.Message}");
                RaiseStatusChanged("เกิดข้อผิดพลาด");

                logWriter?.WriteLine($"\n[ERROR] Exception occurred: {ex.Message}");
                logWriter?.Dispose();
            }
            finally
            {
                logWriter?.Dispose();
            }
        }

        private async Task<(long Scanned, int Found, int Removed, int Failed)> ScanFilesAsync(CancellationToken token)
        {
            long scanned = 0;
            int found = 0;
            int removed = 0;
            int failed = 0;

            List<string> drives = new List<string>();
            try
            {
                drives.AddRange(DriveInfo.GetDrives()
                    .Where(d => d.IsReady && (d.DriveType == DriveType.Fixed || d.DriveType == DriveType.Removable))
                    .Select(d => d.RootDirectory.FullName));
            }
            catch (Exception ex)
            {
                RaiseLogAdded($"[WARNING] ไม่สามารถดึงรายการไดรฟ์: {ex.Message}");
            }

            foreach (var folder in criticalFolders)
            {
                if (!drives.Any(d => folder.StartsWith(d, StringComparison.OrdinalIgnoreCase)))
                {
                    if (Directory.Exists(folder) && !drives.Contains(folder))
                    {
                        drives.Add(folder);
                    }
                }
            }

            foreach (var path in drives)
            {
                if (token.IsCancellationRequested) break;

                try
                {
                    await Task.Run(() => ScanDirectory(path, ref scanned, ref found, ref removed, ref failed, token), token);
                }
                catch (Exception ex)
                {
                    RaiseLogAdded($"[ERROR] ไม่สามารถสแกน {path}: {ex.Message}");
                }
            }

            return (scanned, found, removed, failed);
        }

        private void ScanDirectory(string directory, ref long scanned, ref int found, ref int removed, ref int failed, CancellationToken token)
        {
            try
            {
                pauseEvent.Wait(token);

                if (token.IsCancellationRequested) return;

                var files = Directory.GetFiles(directory);

                foreach (var file in files)
                {
                    if (token.IsCancellationRequested) return;
                    pauseEvent.Wait(token);

                    scanned++;

                    if (scanned % 100 == 0)
                    {
                        RaiseProgressChanged(0, file, scanned, found);
                    }

                    if (IsSkidrowRelated(file))
                    {
                        found++;
                        RaiseLogAdded($"[THREAT] พบไฟล์: {file}");

                        if (autoDelete || ConfirmDelete(file))
                        {
                            if (TryDeleteFile(file))
                            {
                                removed++;
                                RaiseLogAdded($"  -> ลบสำเร็จ");
                            }
                            else
                            {
                                failed++;
                                RaiseLogAdded($"  -> ลบไม่สำเร็จ");
                            }
                        }
                    }
                }

                var directories = Directory.GetDirectories(directory);
                foreach (var dir in directories)
                {
                    if (token.IsCancellationRequested) return;

                    var dirName = Path.GetFileName(dir).ToLower();
                    if (skidrowPatterns.Any(p => dirName.Contains(p)))
                    {
                        found++;
                        RaiseLogAdded($"[THREAT] พบโฟลเดอร์: {dir}");

                        if (autoDelete || ConfirmDelete(dir))
                        {
                            if (TryDeleteDirectory(dir))
                            {
                                removed++;
                                RaiseLogAdded($"  -> ลบสำเร็จ");
                                continue;
                            }
                            else
                            {
                                failed++;
                                RaiseLogAdded($"  -> ลบไม่สำเร็จ");
                            }
                        }
                    }

                    ScanDirectory(dir, ref scanned, ref found, ref removed, ref failed, token);
                }
            }
            catch (UnauthorizedAccessException)
            {
            }
            catch (Exception ex)
            {
                RaiseLogAdded($"[ERROR] {directory}: {ex.Message}");
            }
        }

        private async Task<(long Scanned, int Found, int Removed, int Failed)> ScanRegistryAsync(CancellationToken token)
        {
            long scanned = 0;
            int found = 0;
            int removed = 0;
            int failed = 0;

            var rootKeys = new[]
            {
                Registry.CurrentUser,
                Registry.LocalMachine,
                Registry.Users
            };

            var scanPaths = new[]
            {
                @"Software",
                @"Software\Microsoft\Windows\CurrentVersion\Run",
                @"Software\Microsoft\Windows\CurrentVersion\RunOnce",
                @"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
                @"Software\Classes"
            };

            foreach (var rootKey in rootKeys)
            {
                if (token.IsCancellationRequested) break;

                foreach (var path in scanPaths)
                {
                    if (token.IsCancellationRequested) break;

                    try
                    {
                        await Task.Run(() => ScanRegistryKey(rootKey, path, ref scanned, ref found, ref removed, ref failed, token), token);
                    }
                    catch (Exception ex)
                    {
                        RaiseLogAdded($"[ERROR] Registry {rootKey.Name}\\{path}: {ex.Message}");
                    }
                }
            }

            return (scanned, found, removed, failed);
        }

        private void ScanRegistryKey(RegistryKey rootKey, string path, ref long scanned, ref int found, ref int removed, ref int failed, CancellationToken token)
        {
            try
            {
                pauseEvent.Wait(token);
                if (token.IsCancellationRequested) return;

                using var key = rootKey.OpenSubKey(path, writable: false);
                if (key == null) return;

                scanned++;
                RaiseProgressChanged(0, $"{rootKey.Name}\\{path}", scanned, found);

                var valueNames = key.GetValueNames();
                foreach (var valueName in valueNames)
                {
                    if (token.IsCancellationRequested) return;
                    pauseEvent.Wait(token);

                    scanned++;

                    var value = key.GetValue(valueName)?.ToString() ?? "";
                    if (IsSkidrowRelated(valueName) || IsSkidrowRelated(value))
                    {
                        found++;
                        RaiseLogAdded($"[THREAT] Registry: {rootKey.Name}\\{path}\\{valueName}");
                        RaiseLogAdded($"  Value: {value}");

                        if (autoDelete || ConfirmDelete($"{rootKey.Name}\\{path}\\{valueName}"))
                        {
                            if (TryDeleteRegistryValue(rootKey, path, valueName))
                            {
                                removed++;
                                RaiseLogAdded($"  -> ลบสำเร็จ");
                            }
                            else
                            {
                                failed++;
                                RaiseLogAdded($"  -> ลบไม่สำเร็จ");
                            }
                        }
                    }
                }

                var subKeyNames = key.GetSubKeyNames();
                foreach (var subKeyName in subKeyNames)
                {
                    if (token.IsCancellationRequested) return;

                    if (IsSkidrowRelated(subKeyName))
                    {
                        found++;
                        RaiseLogAdded($"[THREAT] Registry Key: {rootKey.Name}\\{path}\\{subKeyName}");

                        if (autoDelete || ConfirmDelete($"{rootKey.Name}\\{path}\\{subKeyName}"))
                        {
                            if (TryDeleteRegistryKey(rootKey, $"{path}\\{subKeyName}"))
                            {
                                removed++;
                                RaiseLogAdded($"  -> ลบสำเร็จ");
                                continue;
                            }
                            else
                            {
                                failed++;
                                RaiseLogAdded($"  -> ลบไม่สำเร็จ");
                            }
                        }
                    }

                    ScanRegistryKey(rootKey, $"{path}\\{subKeyName}", ref scanned, ref found, ref removed, ref failed, token);
                }
            }
            catch (UnauthorizedAccessException)
            {
            }
            catch (Exception ex)
            {
                RaiseLogAdded($"[ERROR] Registry scan error: {ex.Message}");
            }
        }

        private async Task<(long Scanned, int Found, int Removed, int Failed)> ScanProcessesAsync(CancellationToken token)
        {
            long scanned = 0;
            int found = 0;
            int removed = 0;
            int failed = 0;

            try
            {
                var processScanner = new ProcessScanner();
                processScanner.LogAdded += (s, msg) => RaiseLogAdded(msg);

                pauseEvent.Wait(token);

                var threats = await processScanner.ScanProcessesAsync(token);

                scanned = threats.Count;
                found = threats.Count;

                RaiseProgressChanged(0, "Analyzing process threats...", scanned, found);

                if (threats.Any())
                {
                    if (autoDelete)
                    {
                        var (terminated, failedKill) = await processScanner.TerminateThreatsAsync(
                            threats,
                            autoDelete,
                            token
                        );
                        removed = terminated;
                        failed = failedKill;
                    }
                    else
                    {
                        RaiseLogAdded("\n[INFO] Auto-kill disabled. Processes not terminated.");
                        RaiseLogAdded("       Enable 'ลบ/Kill ทันทีเมื่อพบ' to terminate malicious processes.");
                    }
                }
                else
                {
                    RaiseLogAdded("\n[OK] No malicious processes found in memory!");
                }
            }
            catch (Exception ex)
            {
                RaiseLogAdded($"[ERROR] Process scan error: {ex.Message}");
            }

            return (scanned, found, removed, failed);
        }

        private bool IsSkidrowRelated(string text)
        {
            if (string.IsNullOrEmpty(text)) return false;

            var lowerText = text.ToLower();

            if (skidrowPatterns.Any(p => lowerText.Contains(p)))
                return true;

            if (suspiciousExtensions.Any(ext => lowerText.EndsWith(ext)))
                return true;

            return false;
        }

        private bool ConfirmDelete(string item)
        {
            return true;
        }

        private bool TryDeleteFile(string filePath)
        {
            try
            {
                File.SetAttributes(filePath, FileAttributes.Normal);
                File.Delete(filePath);
                return true;
            }
            catch
            {
                return false;
            }
        }

        private bool TryDeleteDirectory(string directoryPath)
        {
            try
            {
                Directory.Delete(directoryPath, recursive: true);
                return true;
            }
            catch
            {
                return false;
            }
        }

        private bool TryDeleteRegistryValue(RegistryKey rootKey, string path, string valueName)
        {
            try
            {
                using var key = rootKey.OpenSubKey(path, writable: true);
                if (key == null) return false;

                key.DeleteValue(valueName);
                return true;
            }
            catch
            {
                return false;
            }
        }

        private bool TryDeleteRegistryKey(RegistryKey rootKey, string path)
        {
            try
            {
                rootKey.DeleteSubKeyTree(path);
                return true;
            }
            catch
            {
                return false;
            }
        }

        public void Pause()
        {
            isPaused = true;
            pauseEvent.Reset();
            RaiseLogAdded("\n[PAUSE] หยุดชั่วคราว");
        }

        public void Resume()
        {
            isPaused = false;
            pauseEvent.Set();
            RaiseLogAdded("[RESUME] ดำเนินการต่อ\n");
        }

        public void Stop()
        {
            cancellationTokenSource?.Cancel();
        }

        private void RaiseProgressChanged(int percentage, string currentItem, long scannedCount, int foundCount)
        {
            ProgressChanged?.Invoke(this, new ProgressEventArgs
            {
                Percentage = percentage,
                CurrentItem = currentItem,
                ScannedCount = scannedCount,
                FoundCount = foundCount
            });
        }

        private void RaiseLogAdded(string message)
        {
            LogAdded?.Invoke(this, message);
            logWriter?.WriteLine(message);
        }

        private void RaiseStatusChanged(string status)
        {
            StatusChanged?.Invoke(this, status);
        }
    }
}
