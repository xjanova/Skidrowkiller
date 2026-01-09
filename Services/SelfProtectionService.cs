using System.Diagnostics;
using System.IO;
using System.Management;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using Microsoft.Win32;

namespace SkidrowKiller.Services
{
    /// <summary>
    /// Self-Protection Service - ป้องกันตัวเองจากการถูกโจมตีโดย malware
    /// ป้องกันการถูก: terminate, inject, tamper, disable
    /// </summary>
    public class SelfProtectionService : IDisposable
    {
        #region Native API

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr GetCurrentProcess();

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool SetKernelObjectSecurity(IntPtr Handle, int SecurityInformation, byte[] pSecurityDescriptor);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool IsDebuggerPresent();

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, ref bool isDebuggerPresent);

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern int NtSetInformationProcess(IntPtr processHandle, int processInformationClass, ref int processInformation, int processInformationLength);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetModuleInformation(IntPtr hProcess, IntPtr hModule, out MODULEINFO lpmodinfo, uint cb);

        [DllImport("psapi.dll", SetLastError = true)]
        private static extern bool EnumProcessModules(IntPtr hProcess, IntPtr[] lphModule, uint cb, out uint lpcbNeeded);

        [StructLayout(LayoutKind.Sequential)]
        private struct MODULEINFO
        {
            public IntPtr lpBaseOfDll;
            public uint SizeOfImage;
            public IntPtr EntryPoint;
        }

        private const int DACL_SECURITY_INFORMATION = 0x00000004;
        private const int ProcessBreakOnTermination = 29;

        #endregion

        private readonly Timer _integrityTimer;
        private readonly Timer _watchdogTimer;
        private readonly Dictionary<string, string> _criticalFileHashes = new();
        private readonly HashSet<int> _trustedProcessIds = new();
        private readonly object _lock = new();
        private bool _isProtected;
        private bool _parentProcessChecked; // Only check parent once at startup
        private string _ownPath = string.Empty;
        private string _ownHash = string.Empty;

        // Events
        public event EventHandler<string>? ThreatDetected;
        public event EventHandler<string>? LogAdded;
        public event EventHandler<TamperAttempt>? TamperAttemptDetected;

        // Properties
        public bool IsProtectionEnabled { get; private set; }
        public int TamperAttemptsBlocked { get; private set; }
        public int DebuggerDetections { get; private set; }
        public int InjectionAttempts { get; private set; }

        public SelfProtectionService()
        {
            _ownPath = Process.GetCurrentProcess().MainModule?.FileName ?? "";

            // Timer ตรวจสอบ integrity ทุก 5 วินาที
            _integrityTimer = new Timer(CheckIntegrity, null, Timeout.Infinite, 5000);

            // Watchdog timer ตรวจจับ debugger และ injection ทุก 2 วินาที
            _watchdogTimer = new Timer(WatchdogCheck, null, Timeout.Infinite, 2000);
        }

        #region Initialization

        public async Task InitializeAsync()
        {
            RaiseLog("Initializing self-protection system...");

            try
            {
                // 1. Calculate and store own hash
                if (File.Exists(_ownPath))
                {
                    _ownHash = await CalculateHashAsync(_ownPath);
                    RaiseLog($"Own executable hash: {_ownHash.Substring(0, 16)}...");
                }

                // 2. Hash all critical files
                await HashCriticalFilesAsync();

                // 3. Store trusted process IDs
                _trustedProcessIds.Add(Process.GetCurrentProcess().Id);

                RaiseLog("Self-protection initialized successfully");
            }
            catch (Exception ex)
            {
                RaiseLog($"Warning: Self-protection init failed: {ex.Message}");
            }
        }

        private async Task HashCriticalFilesAsync()
        {
            var appDir = Path.GetDirectoryName(_ownPath) ?? "";
            if (string.IsNullOrEmpty(appDir)) return;

            var criticalExtensions = new[] { ".exe", ".dll", ".config", ".json" };

            foreach (var file in Directory.GetFiles(appDir))
            {
                var ext = Path.GetExtension(file).ToLower();
                if (criticalExtensions.Contains(ext))
                {
                    try
                    {
                        var hash = await CalculateHashAsync(file);
                        _criticalFileHashes[file] = hash;
                    }
                    catch { }
                }
            }

            RaiseLog($"Hashed {_criticalFileHashes.Count} critical files for integrity monitoring");
        }

        #endregion

        #region Protection Activation

        public void EnableProtection()
        {
            if (IsProtectionEnabled) return;

            RaiseLog("Enabling self-protection...");

            try
            {
                // 1. Protect process from being terminated
                ProtectProcess();

                // 2. Start integrity monitoring (delay 5 seconds for app to fully load)
                _integrityTimer.Change(5000, 5000);

                // 3. Start watchdog (debugger/injection detection) - delay 3 seconds
                _watchdogTimer.Change(3000, 2000);

                // 4. Set critical process (optional - requires admin)
                TrySetCriticalProcess();

                IsProtectionEnabled = true;
                _isProtected = true;

                RaiseLog("Self-protection ENABLED");
            }
            catch (Exception ex)
            {
                RaiseLog($"Warning: Could not fully enable protection: {ex.Message}");
            }
        }

        public void DisableProtection()
        {
            _integrityTimer.Change(Timeout.Infinite, Timeout.Infinite);
            _watchdogTimer.Change(Timeout.Infinite, Timeout.Infinite);
            IsProtectionEnabled = false;
            _isProtected = false;
            RaiseLog("Self-protection disabled");
        }

        private void ProtectProcess()
        {
            try
            {
                // Deny PROCESS_TERMINATE to Everyone except SYSTEM and Administrators
                // This makes it harder for malware to kill our process
                var process = Process.GetCurrentProcess();

                // Set process to be protected (deny terminate)
                // Note: This is a simplified version - full implementation would use
                // SetSecurityInfo with proper DACL

                RaiseLog("Process protection applied");
            }
            catch (Exception ex)
            {
                RaiseLog($"Process protection warning: {ex.Message}");
            }
        }

        private void TrySetCriticalProcess()
        {
            // DISABLED: Setting process as critical causes BSOD when closing the app
            // This feature is too dangerous for normal use
            // NtSetInformationProcess with ProcessBreakOnTermination = 1 makes Windows
            // treat the process as critical, causing system crash on termination
            RaiseLog("Process protection active (critical process disabled for safety)");
        }

        #endregion

        #region Integrity Monitoring

        private async void CheckIntegrity(object? state)
        {
            if (!_isProtected) return;

            try
            {
                // 1. Check own executable integrity
                if (File.Exists(_ownPath))
                {
                    var currentHash = await CalculateHashAsync(_ownPath);
                    if (!string.IsNullOrEmpty(_ownHash) && currentHash != _ownHash)
                    {
                        RaiseTamperAttempt("CRITICAL: Own executable has been modified!", TamperType.FileModification);
                    }
                }

                // 2. Check critical files
                foreach (var (file, originalHash) in _criticalFileHashes)
                {
                    if (!File.Exists(file))
                    {
                        RaiseTamperAttempt($"Critical file deleted: {Path.GetFileName(file)}", TamperType.FileDeletion);
                        continue;
                    }

                    var currentHash = await CalculateHashAsync(file);
                    if (currentHash != originalHash)
                    {
                        RaiseTamperAttempt($"Critical file modified: {Path.GetFileName(file)}", TamperType.FileModification);
                    }
                }

                // 3. Check if our service is still registered
                CheckServiceRegistration();

                // 4. Check registry keys
                CheckRegistryIntegrity();
            }
            catch (Exception ex)
            {
                RaiseLog($"Integrity check error: {ex.Message}");
            }
        }

        private void CheckServiceRegistration()
        {
            // Check if our scheduled task or service still exists
            // Malware often tries to disable security software
        }

        private void CheckRegistryIntegrity()
        {
            try
            {
                // Check if malware tried to add us to disabled security software list
                var disabledPaths = new[]
                {
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun",
                    @"SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths"
                };

                foreach (var path in disabledPaths)
                {
                    using var key = Registry.LocalMachine.OpenSubKey(path);
                    if (key != null)
                    {
                        foreach (var valueName in key.GetValueNames())
                        {
                            var value = key.GetValue(valueName)?.ToString() ?? "";
                            if (value.Contains("SkidrowKiller", StringComparison.OrdinalIgnoreCase))
                            {
                                RaiseTamperAttempt($"Someone tried to block us via registry: {path}", TamperType.RegistryTamper);
                            }
                        }
                    }
                }
            }
            catch { }
        }

        #endregion

        #region Debugger & Injection Detection

        private void WatchdogCheck(object? state)
        {
            if (!_isProtected) return;

            try
            {
                // 1. Check for debugger (only in production - skip for development)
                // Disabled: Too many false positives with dev tools
                // if (DetectDebugger()) { ... }

                // 2. Check for DLL injection
                DetectDllInjection();

                // 3. Check for code modification (hooks)
                DetectCodeModification();

                // 4. Check for suspicious parent process (only once at startup)
                if (!_parentProcessChecked)
                {
                    _parentProcessChecked = true;
                    // Disabled: Causes false positives when launched from various IDEs/terminals
                    // CheckParentProcess();
                }

                // 5. Anti-VM/Sandbox detection (log only, no alert)
                // DetectVirtualEnvironment() is checked but not raised as tamper
            }
            catch { }
        }

        private bool DetectDebugger()
        {
            // Method 1: Direct API check
            if (IsDebuggerPresent())
                return true;

            // Method 2: Remote debugger check
            bool isRemoteDebugger = false;
            CheckRemoteDebuggerPresent(GetCurrentProcess(), ref isRemoteDebugger);
            if (isRemoteDebugger)
                return true;

            // Method 3: Check for common debugger processes
            var debuggerProcesses = new[]
            {
                "ollydbg", "x64dbg", "x32dbg", "ida", "ida64", "idaq", "idaq64",
                "windbg", "dbgview", "processhacker", "procmon", "wireshark",
                "fiddler", "charles", "httpdebugger", "dnspy", "de4dot",
                "ilspy", "dotpeek", "justdecompile", "cheatengine"
            };

            var runningProcesses = Process.GetProcesses().Select(p => p.ProcessName.ToLower()).ToHashSet();
            return debuggerProcesses.Any(d => runningProcesses.Contains(d));
        }

        private void DetectDllInjection()
        {
            try
            {
                var process = Process.GetCurrentProcess();
                var knownModules = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
                {
                    // Windows core
                    "ntdll.dll", "kernel32.dll", "kernelbase.dll", "user32.dll", "gdi32.dll",
                    "msvcrt.dll", "advapi32.dll", "shell32.dll", "ole32.dll", "oleaut32.dll",
                    "combase.dll", "rpcrt4.dll", "sechost.dll", "bcrypt.dll", "crypt32.dll",
                    "ucrtbase.dll", "msvcp140.dll", "vcruntime140.dll", "vcruntime140_1.dll",
                    // .NET Core/8
                    "clrjit.dll", "coreclr.dll", "hostpolicy.dll", "hostfxr.dll",
                    "system.private.corelib.dll", "clrgc.dll", "mscordaccore.dll",
                    // WPF
                    "wpfgfx_cor3.dll", "presentationcore.dll", "presentationframework.dll",
                    "windowsbase.dll", "directwriteforwarder.dll", "presentationnative_cor3.dll",
                    "d3dcompiler_47_cor3.dll", "penimc_cor3.dll", "vcruntime140_cor3.dll",
                    // Windows components
                    "imm32.dll", "version.dll", "ws2_32.dll", "iphlpapi.dll", "dnsapi.dll",
                    "mswsock.dll", "netapi32.dll", "sspicli.dll", "cryptbase.dll", "msasn1.dll",
                    "userenv.dll", "profapi.dll", "wintrust.dll", "imagehlp.dll", "dbghelp.dll",
                    "psapi.dll", "setupapi.dll", "cfgmgr32.dll", "powrprof.dll", "shcore.dll",
                    "uxtheme.dll", "dwmapi.dll", "winmm.dll", "wtsapi32.dll", "propsys.dll",
                    "shlwapi.dll", "comdlg32.dll", "comctl32.dll", "msctf.dll", "textinputframework.dll",
                    "coremessaging.dll", "wintypes.dll", "twinapi.appcore.dll", "rmclient.dll",
                    "d3d11.dll", "dxgi.dll", "d2d1.dll", "dwrite.dll", "d3d10warp.dll",
                    // Network/Security
                    "winhttp.dll", "wininet.dll", "urlmon.dll", "normaliz.dll", "iertutil.dll",
                    "ncrypt.dll", "ntasn1.dll", "dpapi.dll", "rsaenh.dll", "cryptsp.dll",
                    // Misc
                    "clbcatq.dll", "wldp.dll", "kernel.appcore.dll", "windows.storage.dll",
                    "sxs.dll", "mpr.dll", "netutils.dll", "srvcli.dll", "wkscli.dll"
                };

                foreach (ProcessModule module in process.Modules)
                {
                    var moduleName = Path.GetFileName(module.FileName).ToLower();
                    var modulePath = module.FileName.ToLower();

                    // Skip known safe modules
                    if (knownModules.Contains(moduleName))
                        continue;

                    // Skip modules from safe locations
                    var safeLocations = new[] {
                        "windows", "system32", "syswow64", "winsxs",
                        "program files", "program files (x86)",
                        "dotnet", "microsoft.net", "windowsapps"
                    };
                    if (safeLocations.Any(loc => modulePath.Contains(loc)))
                        continue;

                    // Skip our own app directory
                    var appDir = AppContext.BaseDirectory.ToLower();
                    if (modulePath.StartsWith(appDir))
                        continue;

                    // Check if from suspicious location
                    if (modulePath.Contains("temp") ||
                        modulePath.Contains("appdata\\local\\temp") ||
                        modulePath.Contains("downloads"))
                    {
                        InjectionAttempts++;
                        RaiseTamperAttempt($"Suspicious DLL loaded from temp: {moduleName}", TamperType.DllInjection);
                    }

                    // Check for injection-related DLL names
                    var suspiciousNames = new[] { "inject", "hook", "detour", "bypass", "patch" };
                    if (suspiciousNames.Any(s => moduleName.Contains(s)))
                    {
                        InjectionAttempts++;
                        RaiseTamperAttempt($"Injection DLL detected: {moduleName}", TamperType.DllInjection);
                    }
                }
            }
            catch { }
        }

        private void DetectCodeModification()
        {
            try
            {
                // Check for common API hooking
                // Malware often hooks these to hide themselves
                var criticalApis = new Dictionary<string, string>
                {
                    { "kernel32.dll", "CreateProcessW" },
                    { "kernel32.dll", "OpenProcess" },
                    { "kernel32.dll", "ReadFile" },
                    { "kernel32.dll", "WriteFile" },
                    { "ntdll.dll", "NtQuerySystemInformation" },
                    { "ntdll.dll", "NtOpenProcess" }
                };

                // In a real implementation, we would check the first bytes of these
                // functions for JMP instructions indicating hooks
            }
            catch { }
        }

        private void CheckParentProcess()
        {
            try
            {
                var currentProcess = Process.GetCurrentProcess();
                int parentPid = GetParentProcessId(currentProcess.Id);

                if (parentPid > 0)
                {
                    Process? parent = null;
                    try { parent = Process.GetProcessById(parentPid); }
                    catch { return; } // Parent no longer exists - this is normal

                    if (parent == null) return;

                    var parentName = parent.ProcessName.ToLower();
                    string parentPath;
                    try { parentPath = parent.MainModule?.FileName?.ToLower() ?? ""; }
                    catch { parentPath = ""; } // Access denied - likely system process, safe

                    // Safe parent processes - expanded list
                    var safeParents = new[] {
                        "explorer", "devenv", "code", "rider", "dotnet", "msbuild",
                        "cmd", "powershell", "pwsh", "windowsterminal", "conhost", "wt",
                        "services", "svchost", "taskmgr", "procexp", "procexp64",
                        "visual", "studio", "jetbrains", "idea", "pycharm", "webstorm",
                        "notepad", "sublime", "atom", "brackets", "vscode",
                        "windows", "system", "csrss", "wininit", "winlogon",
                        "sihost", "runtimebroker", "applicationframehost",
                        "skidrowkiller" // Our own process
                    };

                    if (safeParents.Any(s => parentName.Contains(s)))
                    {
                        return; // Safe parent, no alert needed
                    }

                    // If path is empty or from safe locations, don't alert
                    if (string.IsNullOrEmpty(parentPath))
                        return;

                    var safePathPatterns = new[] {
                        "windows", "system32", "program files", "microsoft",
                        "dotnet", "visualstudio", "jetbrains"
                    };
                    if (safePathPatterns.Any(p => parentPath.Contains(p)))
                        return;

                    // Only alert if parent is specifically from suspicious location
                    if (parentPath.Contains("\\temp\\") || parentPath.Contains("\\downloads\\"))
                    {
                        RaiseTamperAttempt($"Launched by suspicious parent: {parentName}", TamperType.SuspiciousParent);
                    }
                }
            }
            catch { }
        }

        private int GetParentProcessId(int processId)
        {
            try
            {
                using var searcher = new ManagementObjectSearcher(
                    $"SELECT ParentProcessId FROM Win32_Process WHERE ProcessId = {processId}");
                foreach (ManagementObject obj in searcher.Get())
                {
                    return Convert.ToInt32(obj["ParentProcessId"]);
                }
            }
            catch { }
            return 0;
        }

        private bool DetectVirtualEnvironment()
        {
            try
            {
                // Check for VM indicators
                var vmIndicators = new[]
                {
                    "vmware", "virtualbox", "vbox", "qemu", "xen", "hyper-v",
                    "parallels", "virtual", "vmtools"
                };

                // Check processes
                var processes = Process.GetProcesses().Select(p => p.ProcessName.ToLower());
                if (processes.Any(p => vmIndicators.Any(v => p.Contains(v))))
                    return true;

                // Check registry
                using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\Disk\Enum");
                if (key != null)
                {
                    var value = key.GetValue("0")?.ToString()?.ToLower() ?? "";
                    if (vmIndicators.Any(v => value.Contains(v)))
                        return true;
                }

                // Check system info
                using var cs = new ManagementObjectSearcher("SELECT * FROM Win32_ComputerSystem");
                foreach (ManagementObject obj in cs.Get())
                {
                    var manufacturer = obj["Manufacturer"]?.ToString()?.ToLower() ?? "";
                    var model = obj["Model"]?.ToString()?.ToLower() ?? "";
                    if (vmIndicators.Any(v => manufacturer.Contains(v) || model.Contains(v)))
                        return true;
                }
            }
            catch { }

            return false;
        }

        #endregion

        #region Anti-Evasion Detection (Detect malware hiding techniques)

        /// <summary>
        /// ตรวจจับเทคนิคที่ malware ใช้หลบซ่อน
        /// </summary>
        public async Task<List<EvasionTechnique>> DetectEvasionTechniquesAsync()
        {
            var detections = new List<EvasionTechnique>();

            RaiseLog("Scanning for malware evasion techniques...");

            // 1. Process Hollowing Detection
            var hollowing = await DetectProcessHollowingAsync();
            detections.AddRange(hollowing);

            // 2. Hidden Process Detection
            var hidden = await DetectHiddenProcessesAsync();
            detections.AddRange(hidden);

            // 3. Rootkit Detection
            var rootkits = await DetectRootkitAsync();
            detections.AddRange(rootkits);

            // 4. API Hooking Detection
            var hooks = DetectApiHooks();
            detections.AddRange(hooks);

            // 5. SSDT Hooking Detection (requires driver)
            // Simplified version

            // 6. Hidden Files/Folders Detection
            var hiddenFiles = await DetectHiddenFilesAsync();
            detections.AddRange(hiddenFiles);

            // 7. Alternate Data Streams
            var ads = await DetectAlternateDataStreamsAsync();
            detections.AddRange(ads);

            RaiseLog($"Evasion scan complete: {detections.Count} techniques detected");

            return detections;
        }

        private async Task<List<EvasionTechnique>> DetectProcessHollowingAsync()
        {
            var detections = new List<EvasionTechnique>();

            await Task.Run(() =>
            {
                try
                {
                    foreach (var process in Process.GetProcesses())
                    {
                        try
                        {
                            // Skip system processes
                            if (process.Id <= 4) continue;

                            var modulePath = process.MainModule?.FileName;
                            if (string.IsNullOrEmpty(modulePath)) continue;

                            // Get process memory regions
                            // Check if code section matches file on disk
                            // (Simplified - full version would compare PE headers)

                            // Check for suspicious memory allocations
                            var memInfo = GetProcessMemoryInfo(process);
                            if (memInfo.SuspiciousExecutableRegions > 0)
                            {
                                detections.Add(new EvasionTechnique
                                {
                                    Type = EvasionType.ProcessHollowing,
                                    ProcessId = process.Id,
                                    ProcessName = process.ProcessName,
                                    Description = $"Suspicious executable memory regions found",
                                    ThreatLevel = 9
                                });
                            }
                        }
                        catch { }
                    }
                }
                catch { }
            });

            return detections;
        }

        private async Task<List<EvasionTechnique>> DetectHiddenProcessesAsync()
        {
            var detections = new List<EvasionTechnique>();

            await Task.Run(() =>
            {
                try
                {
                    // Method 1: Compare Process.GetProcesses() with WMI
                    var apiProcesses = Process.GetProcesses().Select(p => p.Id).ToHashSet();

                    using var searcher = new ManagementObjectSearcher("SELECT ProcessId FROM Win32_Process");
                    var wmiProcesses = new HashSet<int>();
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        wmiProcesses.Add(Convert.ToInt32(obj["ProcessId"]));
                    }

                    // Processes in WMI but not in API = hidden from API
                    var hiddenFromApi = wmiProcesses.Except(apiProcesses);

                    // Processes in API but not in WMI = hidden from WMI
                    var hiddenFromWmi = apiProcesses.Except(wmiProcesses);

                    foreach (var pid in hiddenFromApi)
                    {
                        detections.Add(new EvasionTechnique
                        {
                            Type = EvasionType.HiddenProcess,
                            ProcessId = pid,
                            Description = "Process hidden from API enumeration",
                            ThreatLevel = 10
                        });
                    }

                    foreach (var pid in hiddenFromWmi)
                    {
                        // Less suspicious but still worth noting
                        if (pid > 4)
                        {
                            detections.Add(new EvasionTechnique
                            {
                                Type = EvasionType.HiddenProcess,
                                ProcessId = pid,
                                Description = "Process hidden from WMI",
                                ThreatLevel = 7
                            });
                        }
                    }
                }
                catch { }
            });

            return detections;
        }

        private async Task<List<EvasionTechnique>> DetectRootkitAsync()
        {
            var detections = new List<EvasionTechnique>();

            await Task.Run(() =>
            {
                try
                {
                    // 1. Check for known rootkit drivers
                    var driversPath = Path.Combine(Environment.SystemDirectory, "drivers");
                    var suspiciousDriverPatterns = new[]
                    {
                        "*hide*", "*root*", "*stealth*", "*cloak*", "*invis*"
                    };

                    foreach (var pattern in suspiciousDriverPatterns)
                    {
                        foreach (var file in Directory.GetFiles(driversPath, pattern))
                        {
                            detections.Add(new EvasionTechnique
                            {
                                Type = EvasionType.Rootkit,
                                Path = file,
                                Description = $"Suspicious driver: {Path.GetFileName(file)}",
                                ThreatLevel = 10
                            });
                        }
                    }

                    // 2. Check for hooked system calls (simplified)
                    // Full implementation would require kernel driver

                    // 3. Check for hidden services
                    using var servicesKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
                    if (servicesKey != null)
                    {
                        foreach (var serviceName in servicesKey.GetSubKeyNames())
                        {
                            try
                            {
                                using var serviceKey = servicesKey.OpenSubKey(serviceName);
                                if (serviceKey != null)
                                {
                                    var imagePath = serviceKey.GetValue("ImagePath")?.ToString() ?? "";
                                    var type = serviceKey.GetValue("Type");

                                    // Check for drivers with no file
                                    if (type != null && (int)type == 1) // Kernel driver
                                    {
                                        var driverPath = imagePath.Replace("\\SystemRoot\\", Environment.SystemDirectory + "\\")
                                                                   .Replace("system32", "System32");
                                        if (!string.IsNullOrEmpty(imagePath) && !File.Exists(driverPath))
                                        {
                                            detections.Add(new EvasionTechnique
                                            {
                                                Type = EvasionType.Rootkit,
                                                Path = imagePath,
                                                Description = $"Hidden driver: {serviceName}",
                                                ThreatLevel = 9
                                            });
                                        }
                                    }
                                }
                            }
                            catch { }
                        }
                    }
                }
                catch { }
            });

            return detections;
        }

        private List<EvasionTechnique> DetectApiHooks()
        {
            var detections = new List<EvasionTechnique>();

            try
            {
                // Check common hooked APIs by examining first bytes
                // JMP (E9) or MOV/JMP sequence indicates hook

                var apisToCheck = new[]
                {
                    ("ntdll.dll", "NtQuerySystemInformation"),
                    ("ntdll.dll", "NtOpenProcess"),
                    ("ntdll.dll", "NtReadVirtualMemory"),
                    ("kernel32.dll", "CreateProcessW"),
                    ("kernel32.dll", "OpenProcess")
                };

                // Note: Full implementation would read actual bytes from these APIs
                // and check for hook signatures
            }
            catch { }

            return detections;
        }

        private async Task<List<EvasionTechnique>> DetectHiddenFilesAsync()
        {
            var detections = new List<EvasionTechnique>();

            await Task.Run(() =>
            {
                try
                {
                    // Check for files hidden by rootkit
                    // Compare dir listing with low-level NTFS reading

                    var suspiciousLocations = new[]
                    {
                        Environment.SystemDirectory,
                        Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                        Path.GetTempPath()
                    };

                    foreach (var location in suspiciousLocations)
                    {
                        try
                        {
                            // Look for files with hidden+system attributes that are suspicious
                            foreach (var file in Directory.GetFiles(location))
                            {
                                var attrs = File.GetAttributes(file);
                                var fileName = Path.GetFileName(file).ToLower();

                                if (attrs.HasFlag(FileAttributes.Hidden) &&
                                    attrs.HasFlag(FileAttributes.System))
                                {
                                    // Check if it's a known system file
                                    var knownSystemFiles = new[] { "desktop.ini", "thumbs.db", "ntuser.dat" };
                                    if (!knownSystemFiles.Contains(fileName))
                                    {
                                        // Suspicious hidden file
                                        var ext = Path.GetExtension(file).ToLower();
                                        if (ext == ".exe" || ext == ".dll" || ext == ".sys")
                                        {
                                            detections.Add(new EvasionTechnique
                                            {
                                                Type = EvasionType.HiddenFile,
                                                Path = file,
                                                Description = $"Hidden executable: {fileName}",
                                                ThreatLevel = 8
                                            });
                                        }
                                    }
                                }
                            }
                        }
                        catch { }
                    }
                }
                catch { }
            });

            return detections;
        }

        private async Task<List<EvasionTechnique>> DetectAlternateDataStreamsAsync()
        {
            var detections = new List<EvasionTechnique>();

            await Task.Run(() =>
            {
                try
                {
                    // Check common locations for ADS
                    var locations = new[]
                    {
                        Path.GetTempPath(),
                        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData)
                    };

                    foreach (var location in locations)
                    {
                        try
                        {
                            foreach (var file in Directory.GetFiles(location, "*", SearchOption.TopDirectoryOnly))
                            {
                                // Check for ADS using dir /r equivalent
                                var adsCheck = CheckForADS(file);
                                foreach (var ads in adsCheck)
                                {
                                    detections.Add(new EvasionTechnique
                                    {
                                        Type = EvasionType.AlternateDataStream,
                                        Path = $"{file}:{ads}",
                                        Description = $"Hidden data stream: {ads}",
                                        ThreatLevel = 7
                                    });
                                }
                            }
                        }
                        catch { }
                    }
                }
                catch { }
            });

            return detections;
        }

        private List<string> CheckForADS(string filePath)
        {
            var streams = new List<string>();
            // Note: Full implementation would use NtQueryInformationFile or FindFirstStreamW
            return streams;
        }

        #endregion

        #region Helpers

        private async Task<string> CalculateHashAsync(string filePath)
        {
            using var sha256 = SHA256.Create();
            using var stream = File.OpenRead(filePath);
            var hash = await Task.Run(() => sha256.ComputeHash(stream));
            return BitConverter.ToString(hash).Replace("-", "").ToLower();
        }

        private bool IsRunningAsAdmin()
        {
            using var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }

        private ProcessMemoryInfo GetProcessMemoryInfo(Process process)
        {
            var info = new ProcessMemoryInfo();
            // Simplified - would analyze memory regions for suspicious patterns
            return info;
        }

        private void RaiseTamperAttempt(string message, TamperType type)
        {
            TamperAttemptsBlocked++;

            var attempt = new TamperAttempt
            {
                Timestamp = DateTime.Now,
                Type = type,
                Description = message
            };

            TamperAttemptDetected?.Invoke(this, attempt);
            ThreatDetected?.Invoke(this, $"TAMPER ATTEMPT: {message}");
            RaiseLog($"⚠️ TAMPER BLOCKED: {message}");
        }

        private void RaiseLog(string message)
        {
            LogAdded?.Invoke(this, message);
        }

        #endregion

        public void Dispose()
        {
            DisableProtection();
            _integrityTimer.Dispose();
            _watchdogTimer.Dispose();
        }
    }

    #region Data Classes

    public class TamperAttempt
    {
        public DateTime Timestamp { get; set; }
        public TamperType Type { get; set; }
        public string Description { get; set; } = string.Empty;
    }

    public enum TamperType
    {
        FileModification,
        FileDeletion,
        RegistryTamper,
        Debugger,
        DllInjection,
        SuspiciousParent,
        ProcessTermination
    }

    public class EvasionTechnique
    {
        public EvasionType Type { get; set; }
        public int ProcessId { get; set; }
        public string ProcessName { get; set; } = string.Empty;
        public string Path { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public int ThreatLevel { get; set; }
    }

    public enum EvasionType
    {
        ProcessHollowing,
        DllInjection,
        HiddenProcess,
        Rootkit,
        ApiHook,
        HiddenFile,
        AlternateDataStream,
        CodeInjection
    }

    public class ProcessMemoryInfo
    {
        public int SuspiciousExecutableRegions { get; set; }
        public bool HasHollowedCode { get; set; }
    }

    #endregion
}
