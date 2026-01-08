using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace SkidrowKiller
{
    public class ProcessThreat
    {
        public int ProcessId { get; set; }
        public string ProcessName { get; set; } = string.Empty;
        public string ExecutablePath { get; set; } = string.Empty;
        public string CommandLine { get; set; } = string.Empty;
        public List<string> SuspiciousModules { get; set; } = new List<string>();
        public string Reason { get; set; } = string.Empty;
    }

    public class ProcessScanner
    {
        private readonly string[] skidrowPatterns = new[]
        {
            "skidrow",
            "skid-row",
            "skid_row",
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
            "smartsteam",
            "nosteam",
            "steam_api",
            "steamclient"
        };

        private readonly string[] suspiciousDlls = new[]
        {
            "steam_api.dll",
            "steam_api64.dll",
            "steamclient.dll",
            "steamclient64.dll",
            "steam_emu.dll",
            "cream_api.dll",
            "uwpsteamapi.dll"
        };

        [DllImport("kernel32.dll")]
        private static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("psapi.dll", SetLastError = true)]
        private static extern bool EnumProcessModules(IntPtr hProcess, [Out] IntPtr[] lphModule,
            uint cb, out uint lpcbNeeded);

        [DllImport("psapi.dll", CharSet = CharSet.Unicode)]
        private static extern uint GetModuleFileNameEx(IntPtr hProcess, IntPtr hModule,
            [Out] StringBuilder lpBaseName, uint nSize);

        private const uint PROCESS_QUERY_INFORMATION = 0x0400;
        private const uint PROCESS_VM_READ = 0x0010;

        public event EventHandler<string>? LogAdded;

        public async Task<List<ProcessThreat>> ScanProcessesAsync(CancellationToken token)
        {
            List<ProcessThreat> threats = new List<ProcessThreat>();

            RaiseLogAdded("\n[PROCESS SCAN] เริ่มสแกน Processes ใน Memory");
            RaiseLogAdded(new string('-', 60));

            try
            {
                var processes = Process.GetProcesses();
                RaiseLogAdded($"พบ {processes.Length} processes ที่กำลังทำงาน");

                foreach (var process in processes)
                {
                    if (token.IsCancellationRequested) break;

                    try
                    {
                        var threat = await Task.Run(() => ScanProcess(process), token);
                        if (threat != null)
                        {
                            threats.Add(threat);
                            RaiseLogAdded($"\n[THREAT] Process: {threat.ProcessName} (PID: {threat.ProcessId})");
                            RaiseLogAdded($"  Path: {threat.ExecutablePath}");
                            RaiseLogAdded($"  Reason: {threat.Reason}");

                            if (threat.SuspiciousModules.Any())
                            {
                                RaiseLogAdded($"  Suspicious DLLs:");
                                foreach (var module in threat.SuspiciousModules)
                                {
                                    RaiseLogAdded($"    - {module}");
                                }
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        // Skip processes we can't access
                        if (ex is UnauthorizedAccessException || ex is InvalidOperationException)
                            continue;
                    }
                    finally
                    {
                        try { process.Dispose(); } catch { }
                    }
                }

                RaiseLogAdded(new string('-', 60));
                RaiseLogAdded($"Process scan complete: พบ {threats.Count} ภัยคุกคาม");
            }
            catch (Exception ex)
            {
                RaiseLogAdded($"[ERROR] Process scan error: {ex.Message}");
            }

            return threats;
        }

        private ProcessThreat? ScanProcess(Process process)
        {
            try
            {
                string processName = process.ProcessName.ToLower();
                string executablePath = string.Empty;
                string commandLine = string.Empty;
                List<string> suspiciousModules = new List<string>();

                // Get executable path
                try
                {
                    executablePath = process.MainModule?.FileName ?? string.Empty;
                }
                catch { }

                // Check process name
                if (skidrowPatterns.Any(p => processName.Contains(p)))
                {
                    return new ProcessThreat
                    {
                        ProcessId = process.Id,
                        ProcessName = process.ProcessName,
                        ExecutablePath = executablePath,
                        CommandLine = commandLine,
                        Reason = $"Process name contains suspicious pattern: {processName}"
                    };
                }

                // Check executable path
                if (!string.IsNullOrEmpty(executablePath) &&
                    skidrowPatterns.Any(p => executablePath.ToLower().Contains(p)))
                {
                    return new ProcessThreat
                    {
                        ProcessId = process.Id,
                        ProcessName = process.ProcessName,
                        ExecutablePath = executablePath,
                        CommandLine = commandLine,
                        Reason = $"Executable path contains suspicious pattern"
                    };
                }

                // Check loaded modules (DLLs)
                suspiciousModules = GetSuspiciousModules(process);
                if (suspiciousModules.Any())
                {
                    return new ProcessThreat
                    {
                        ProcessId = process.Id,
                        ProcessName = process.ProcessName,
                        ExecutablePath = executablePath,
                        CommandLine = commandLine,
                        SuspiciousModules = suspiciousModules,
                        Reason = $"Process loaded {suspiciousModules.Count} suspicious DLL(s)"
                    };
                }

                // Check command line using WMI
                commandLine = GetProcessCommandLine(process.Id);
                if (!string.IsNullOrEmpty(commandLine) &&
                    skidrowPatterns.Any(p => commandLine.ToLower().Contains(p)))
                {
                    return new ProcessThreat
                    {
                        ProcessId = process.Id,
                        ProcessName = process.ProcessName,
                        ExecutablePath = executablePath,
                        CommandLine = commandLine,
                        Reason = $"Command line contains suspicious pattern"
                    };
                }
            }
            catch
            {
                // Skip processes we can't access
            }

            return null;
        }

        private List<string> GetSuspiciousModules(Process process)
        {
            List<string> suspicious = new List<string>();

            try
            {
                ProcessModuleCollection modules;
                try
                {
                    modules = process.Modules;
                }
                catch
                {
                    // If 32-bit process can't access 64-bit modules, try native method
                    return GetSuspiciousModulesNative(process);
                }

                foreach (ProcessModule module in modules)
                {
                    try
                    {
                        string moduleName = Path.GetFileName(module.FileName).ToLower();
                        string modulePath = module.FileName.ToLower();

                        // Check against suspicious DLL list
                        if (suspiciousDlls.Any(dll => moduleName.Equals(dll, StringComparison.OrdinalIgnoreCase)))
                        {
                            suspicious.Add(module.FileName);
                            continue;
                        }

                        // Check against patterns
                        if (skidrowPatterns.Any(p => moduleName.Contains(p) || modulePath.Contains(p)))
                        {
                            suspicious.Add(module.FileName);
                        }
                    }
                    catch { }
                }
            }
            catch { }

            return suspicious;
        }

        private List<string> GetSuspiciousModulesNative(Process process)
        {
            List<string> suspicious = new List<string>();

            try
            {
                IntPtr hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, process.Id);
                if (hProcess == IntPtr.Zero)
                    return suspicious;

                try
                {
                    IntPtr[] hModules = new IntPtr[1024];
                    uint cbNeeded;

                    if (EnumProcessModules(hProcess, hModules, (uint)(hModules.Length * IntPtr.Size), out cbNeeded))
                    {
                        int moduleCount = (int)(cbNeeded / IntPtr.Size);

                        for (int i = 0; i < moduleCount; i++)
                        {
                            StringBuilder sb = new StringBuilder(260);
                            if (GetModuleFileNameEx(hProcess, hModules[i], sb, (uint)sb.Capacity) > 0)
                            {
                                string modulePath = sb.ToString();
                                string moduleName = Path.GetFileName(modulePath).ToLower();

                                if (suspiciousDlls.Any(dll => moduleName.Equals(dll, StringComparison.OrdinalIgnoreCase)) ||
                                    skidrowPatterns.Any(p => moduleName.Contains(p) || modulePath.ToLower().Contains(p)))
                                {
                                    suspicious.Add(modulePath);
                                }
                            }
                        }
                    }
                }
                finally
                {
                    CloseHandle(hProcess);
                }
            }
            catch { }

            return suspicious;
        }

        private string GetProcessCommandLine(int processId)
        {
            try
            {
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(
                    $"SELECT CommandLine FROM Win32_Process WHERE ProcessId = {processId}"))
                {
                    using (ManagementObjectCollection objects = searcher.Get())
                    {
                        var obj = objects.Cast<ManagementObject>().FirstOrDefault();
                        return obj?["CommandLine"]?.ToString() ?? string.Empty;
                    }
                }
            }
            catch
            {
                return string.Empty;
            }
        }

        public bool TryKillProcess(int processId, out string error)
        {
            error = string.Empty;

            try
            {
                var process = Process.GetProcessById(processId);
                string processName = process.ProcessName;

                // Try graceful close first
                try
                {
                    if (!process.CloseMainWindow())
                    {
                        // If graceful close fails, force kill
                        process.Kill(entireProcessTree: true);
                    }

                    process.WaitForExit(5000); // Wait up to 5 seconds

                    if (!process.HasExited)
                    {
                        process.Kill(entireProcessTree: true);
                        process.WaitForExit(2000);
                    }

                    return process.HasExited;
                }
                catch (Exception ex)
                {
                    error = ex.Message;
                    return false;
                }
            }
            catch (ArgumentException)
            {
                // Process already exited
                return true;
            }
            catch (Exception ex)
            {
                error = ex.Message;
                return false;
            }
        }

        public async Task<(int Terminated, int Failed)> TerminateThreatsAsync(
            List<ProcessThreat> threats,
            bool autoKill,
            CancellationToken token)
        {
            int terminated = 0;
            int failed = 0;

            RaiseLogAdded("\n[TERMINATE] เริ่มการ terminate processes ที่เป็นภัยคุกคาม");

            foreach (var threat in threats)
            {
                if (token.IsCancellationRequested) break;

                RaiseLogAdded($"\nProcessing PID {threat.ProcessId} ({threat.ProcessName})...");

                if (autoKill || ConfirmKill(threat))
                {
                    if (TryKillProcess(threat.ProcessId, out string error))
                    {
                        terminated++;
                        RaiseLogAdded($"  -> Terminated successfully");
                    }
                    else
                    {
                        failed++;
                        RaiseLogAdded($"  -> Failed to terminate: {error}");
                    }
                }
                else
                {
                    RaiseLogAdded($"  -> Skipped by user");
                }

                await Task.Delay(100, token); // Small delay between kills
            }

            RaiseLogAdded($"\nTermination complete: {terminated} terminated, {failed} failed");

            return (terminated, failed);
        }

        private bool ConfirmKill(ProcessThreat threat)
        {
            // In auto mode this won't be called, but keep for manual mode
            return true;
        }

        private void RaiseLogAdded(string message)
        {
            LogAdded?.Invoke(this, message);
        }
    }
}
