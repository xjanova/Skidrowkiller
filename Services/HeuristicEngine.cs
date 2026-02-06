using System.Diagnostics;
using System.IO;
using System.Management;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using Microsoft.Win32;
using SkidrowKiller.Models;

namespace SkidrowKiller.Services
{
    /// <summary>
    /// Advanced heuristic analysis engine for detecting malware based on behavior patterns,
    /// process characteristics, and system modifications without relying solely on signatures.
    /// </summary>
    public class HeuristicEngine
    {
        private readonly MalwareSignatureDatabase _signatureDb;
        private readonly PEAnalyzer _peAnalyzer;

        // Process monitoring state
        private readonly Dictionary<int, ProcessBehavior> _processMonitor = new();
        private readonly HashSet<string> _knownSafeProcesses = new(StringComparer.OrdinalIgnoreCase);

        // Suspicious behavior thresholds
        private const int FILE_OPERATIONS_THRESHOLD = 100;
        private const int REGISTRY_OPERATIONS_THRESHOLD = 50;
        private const int NETWORK_CONNECTIONS_THRESHOLD = 20;
        private const int CHILD_PROCESSES_THRESHOLD = 10;

        // Suspicious ports for C2 communication
        private readonly int[] _c2Ports = {
            4444, 5555, 6666, 7777, 8888, 9999, // Common RAT ports
            1337, 31337, 12345, 54321, 65535,   // Hacker culture ports
            8080, 8443, 3389, 5900, 5901,       // Remote access
            6667, 6668, 6669,                    // IRC (botnet C2)
            1080, 9050, 9150,                    // SOCKS/Tor
        };

        public HeuristicEngine(MalwareSignatureDatabase signatureDb, PEAnalyzer peAnalyzer)
        {
            _signatureDb = signatureDb;
            _peAnalyzer = peAnalyzer;
            LoadKnownSafeProcesses();
        }

        private void LoadKnownSafeProcesses()
        {
            // System processes
            _knownSafeProcesses.UnionWith(new[]
            {
                "system", "smss.exe", "csrss.exe", "wininit.exe", "services.exe",
                "lsass.exe", "winlogon.exe", "svchost.exe", "dwm.exe", "explorer.exe",
                "taskhostw.exe", "sihost.exe", "fontdrvhost.exe", "RuntimeBroker.exe",
                "SearchIndexer.exe", "SearchHost.exe", "ShellExperienceHost.exe",
                "StartMenuExperienceHost.exe", "TextInputHost.exe", "ctfmon.exe",
                "conhost.exe", "dllhost.exe", "spoolsv.exe", "WmiPrvSE.exe",
                "MsMpEng.exe", "NisSrv.exe", "SecurityHealthService.exe",
                "audiodg.exe", "mstsc.exe", "notepad.exe", "calc.exe",
            });
        }

        #region File Heuristics

        /// <summary>
        /// Performs comprehensive heuristic analysis on a file
        /// </summary>
        public async Task<HeuristicResult> AnalyzeFileAsync(string filePath)
        {
            var result = new HeuristicResult { FilePath = filePath };

            if (!File.Exists(filePath))
            {
                result.ErrorMessage = "File not found";
                return result;
            }

            try
            {
                var fileInfo = new FileInfo(filePath);
                result.FileName = fileInfo.Name;
                result.FileSize = fileInfo.Length;

                // Check file attributes
                AnalyzeFileAttributes(fileInfo, result);

                // Check file location
                AnalyzeFileLocation(filePath, result);

                // Check file name patterns
                AnalyzeFileName(fileInfo.Name, result);

                // For executables, perform PE analysis
                var extension = fileInfo.Extension.ToLower();
                if (extension == ".exe" || extension == ".dll" || extension == ".scr" || extension == ".sys")
                {
                    await AnalyzeExecutableAsync(filePath, result);
                }
                else if (extension == ".ps1" || extension == ".bat" || extension == ".cmd" || extension == ".vbs" || extension == ".js")
                {
                    await AnalyzeScriptAsync(filePath, result);
                }

                // Check digital signature
                await CheckDigitalSignatureAsync(filePath, result);

                // Calculate final threat score
                CalculateThreatScore(result);
            }
            catch (Exception ex)
            {
                result.ErrorMessage = ex.Message;
            }

            return result;
        }

        private void AnalyzeFileAttributes(FileInfo fileInfo, HeuristicResult result)
        {
            var attrs = fileInfo.Attributes;

            if (attrs.HasFlag(FileAttributes.Hidden))
            {
                result.SuspiciousIndicators.Add("File is hidden");
                result.Score += 10;
            }

            if (attrs.HasFlag(FileAttributes.System))
            {
                result.SuspiciousIndicators.Add("File has system attribute");
                result.Score += 5;
            }

            // Check for recently created files with old timestamps
            if (fileInfo.LastWriteTime < fileInfo.CreationTime)
            {
                result.SuspiciousIndicators.Add("Timestomping detected (modified date before creation date)");
                result.Score += 20;
            }

            // Check for very recent creation in system directories
            var isSystemDir = fileInfo.DirectoryName?.Contains("Windows", StringComparison.OrdinalIgnoreCase) ?? false;
            if (isSystemDir && fileInfo.CreationTime > DateTime.Now.AddHours(-24))
            {
                result.SuspiciousIndicators.Add("Recently created file in system directory");
                result.Score += 15;
            }
        }

        private void AnalyzeFileLocation(string filePath, HeuristicResult result)
        {
            var lowerPath = filePath.ToLower();

            // Suspicious locations
            var suspiciousLocations = new Dictionary<string, (string Description, int Score)>
            {
                { @"\temp\", ("Located in temp directory", 10) },
                { @"\appdata\local\temp\", ("Located in user temp directory", 10) },
                { @"\appdata\roaming\", ("Located in roaming AppData", 5) },
                { @"\programdata\", ("Located in ProgramData", 5) },
                { @"\users\public\", ("Located in Public folder", 8) },
                { @"\recycle", ("Located in Recycle Bin", 15) },
                { @"\$recycle.bin\", ("Located in Recycle Bin", 15) },
                { @"\system volume information\", ("Located in System Volume Information", 20) },
            };

            foreach (var (location, (description, score)) in suspiciousLocations)
            {
                if (lowerPath.Contains(location))
                {
                    result.SuspiciousIndicators.Add(description);
                    result.Score += score;
                    break;
                }
            }

            // Check for executable in non-standard locations
            var ext = Path.GetExtension(filePath).ToLower();
            if ((ext == ".exe" || ext == ".dll") &&
                !lowerPath.Contains(@"\program files") &&
                !lowerPath.Contains(@"\windows\system32") &&
                !lowerPath.Contains(@"\windows\syswow64"))
            {
                result.SuspiciousIndicators.Add("Executable in non-standard location");
                result.Score += 10;
            }
        }

        private void AnalyzeFileName(string fileName, HeuristicResult result)
        {
            var lowerName = fileName.ToLower();

            // Double extension check
            var doubleExtensions = new[] { ".pdf.exe", ".doc.exe", ".jpg.exe", ".txt.exe", ".mp3.exe", ".docx.scr", ".xlsx.exe" };
            foreach (var ext in doubleExtensions)
            {
                if (lowerName.EndsWith(ext))
                {
                    result.SuspiciousIndicators.Add($"Double extension detected: {ext}");
                    result.Score += 30;
                    result.DetectedTechniques.Add("Social Engineering - Double Extension");
                }
            }

            // Right-to-left override character (Unicode trick)
            if (fileName.Contains('\u202E'))
            {
                result.SuspiciousIndicators.Add("Right-to-left override character detected (Unicode filename spoofing)");
                result.Score += 40;
                result.DetectedTechniques.Add("Social Engineering - Unicode Spoof");
            }

            // Impersonating system files
            var systemFileNames = new[] { "svchost", "csrss", "lsass", "services", "winlogon", "explorer", "cmd" };
            foreach (var sysFile in systemFileNames)
            {
                if (lowerName.Contains(sysFile) && !lowerName.Equals($"{sysFile}.exe"))
                {
                    // Could be typosquatting (svch0st, scvhost, etc.)
                    if (LevenshteinDistance(lowerName.Replace(".exe", ""), sysFile) <= 2)
                    {
                        result.SuspiciousIndicators.Add($"Possible system file impersonation: {fileName}");
                        result.Score += 25;
                        result.DetectedTechniques.Add("Defense Evasion - Masquerading");
                    }
                }
            }

            // Random/obfuscated file names
            if (Regex.IsMatch(fileName, @"^[a-z0-9]{8,16}\.(exe|dll|scr)$", RegexOptions.IgnoreCase))
            {
                result.SuspiciousIndicators.Add("Random-looking filename pattern");
                result.Score += 10;
            }

            // GUID-like filenames
            if (Regex.IsMatch(fileName, @"^[{]?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}[}]?\.(exe|dll)", RegexOptions.IgnoreCase))
            {
                result.SuspiciousIndicators.Add("GUID-based filename (common for malware)");
                result.Score += 15;
            }
        }

        private async Task AnalyzeExecutableAsync(string filePath, HeuristicResult result)
        {
            var peResult = await _peAnalyzer.AnalyzeAsync(filePath);

            if (!peResult.IsValid) return;

            result.IsPE = true;
            result.PEAnalysis = peResult;

            // Add PE analysis indicators
            if (peResult.IsPacked)
            {
                result.SuspiciousIndicators.Add($"File is packed with {peResult.PackerName ?? "unknown packer"}");
                result.Score += 15;
            }

            if (peResult.IsObfuscated)
            {
                result.SuspiciousIndicators.Add($"File is obfuscated with {peResult.ObfuscatorName ?? "unknown obfuscator"}");
                result.Score += 10;
            }

            if (peResult.OverallEntropy > 7.2)
            {
                result.SuspiciousIndicators.Add($"Very high entropy ({peResult.OverallEntropy:F2}) - likely encrypted/compressed");
                result.Score += 20;
            }

            if (peResult.HasEmbeddedExecutable)
            {
                result.SuspiciousIndicators.Add("Contains embedded executable");
                result.Score += 25;
            }

            foreach (var technique in peResult.DetectedTechniques)
            {
                result.DetectedTechniques.Add(technique);
            }

            result.Score += peResult.ThreatScore / 2; // Weight PE analysis
        }

        private async Task AnalyzeScriptAsync(string filePath, HeuristicResult result)
        {
            try
            {
                var content = await File.ReadAllTextAsync(filePath);
                var lowerContent = content.ToLower();

                // PowerShell suspicious patterns
                var psPatterns = new Dictionary<string, (string Description, int Score)>
                {
                    { "-enc ", ("Encoded command execution", 30) },
                    { "encodedcommand", ("Encoded command parameter", 30) },
                    { "invoke-expression", ("Dynamic code execution (IEX)", 25) },
                    { "iex ", ("Dynamic code execution (IEX)", 25) },
                    { "downloadstring", ("Remote code download", 30) },
                    { "downloadfile", ("File download capability", 20) },
                    { "webclient", ("Web communication", 15) },
                    { "invoke-webrequest", ("Web request capability", 15) },
                    { "start-process -windowstyle hidden", ("Hidden process execution", 35) },
                    { "-windowstyle hidden", ("Hidden window", 25) },
                    { "bypass", ("Execution policy bypass", 20) },
                    { "set-executionpolicy", ("Execution policy modification", 20) },
                    { "add-type", ("Dynamic type loading", 15) },
                    { "[system.reflection.assembly]", ("Reflection/dynamic loading", 20) },
                    { "mimikatz", ("Credential theft tool", 40) },
                    { "invoke-mimikatz", ("Credential theft", 40) },
                    { "get-credential", ("Credential harvesting", 15) },
                    { "convertto-securestring", ("Secure string manipulation", 10) },
                    { "amsi", ("AMSI bypass attempt", 30) },
                    { "virtualallocex", ("Process injection API", 35) },
                    { "writeprocessmemory", ("Process injection API", 35) },
                    { "createremotethread", ("Remote thread creation", 35) },
                };

                // Batch/CMD suspicious patterns
                var cmdPatterns = new Dictionary<string, (string Description, int Score)>
                {
                    { "reg add", ("Registry modification", 15) },
                    { "reg delete", ("Registry deletion", 15) },
                    { "schtasks /create", ("Scheduled task creation", 25) },
                    { "bitsadmin /transfer", ("Background download", 25) },
                    { "certutil -urlcache", ("Download via certutil", 30) },
                    { "powershell -e", ("Encoded PowerShell execution", 30) },
                    { "attrib +h +s", ("Hide file", 20) },
                    { "net user /add", ("User creation", 25) },
                    { "net localgroup administrators", ("Admin group modification", 30) },
                    { "sc create", ("Service creation", 25) },
                    { "wmic process call create", ("Process creation via WMI", 25) },
                };

                // VBScript suspicious patterns
                var vbsPatterns = new Dictionary<string, (string Description, int Score)>
                {
                    { "wscript.shell", ("Shell execution", 20) },
                    { "scripting.filesystemobject", ("File system access", 15) },
                    { "msxml2.xmlhttp", ("HTTP communication", 20) },
                    { "adodb.stream", ("Binary stream handling", 20) },
                    { "createobject", ("COM object creation", 10) },
                };

                var extension = Path.GetExtension(filePath).ToLower();

                Dictionary<string, (string, int)> patterns = extension switch
                {
                    ".ps1" => psPatterns,
                    ".bat" or ".cmd" => cmdPatterns,
                    ".vbs" or ".vbe" or ".wsf" => vbsPatterns,
                    ".js" or ".jse" => vbsPatterns, // Similar patterns
                    _ => new Dictionary<string, (string, int)>()
                };

                foreach (var (pattern, (description, score)) in patterns)
                {
                    if (lowerContent.Contains(pattern))
                    {
                        result.SuspiciousIndicators.Add($"Script pattern: {description}");
                        result.Score += score;
                    }
                }

                // Base64 detection
                var base64Regex = new Regex(@"[A-Za-z0-9+/=]{50,}", RegexOptions.Compiled);
                if (base64Regex.IsMatch(content))
                {
                    result.SuspiciousIndicators.Add("Contains large Base64 encoded data");
                    result.Score += 20;
                }

                // IP address patterns (potential C2)
                var ipRegex = new Regex(@"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b");
                var ipMatches = ipRegex.Matches(content);
                if (ipMatches.Count > 0)
                {
                    result.SuspiciousIndicators.Add($"Contains {ipMatches.Count} IP address(es)");
                    result.Score += 10;
                }
            }
            catch { }
        }

        private async Task CheckDigitalSignatureAsync(string filePath, HeuristicResult result)
        {
            try
            {
                // Using Windows API to check Authenticode signature
                var extension = Path.GetExtension(filePath).ToLower();
                if (extension != ".exe" && extension != ".dll" && extension != ".sys") return;

                var fileInfo = new FileInfo(filePath);
                if (fileInfo.Length < 1024) return;

                // Check for valid signature using sigcheck-like approach
                // This is a simplified check - production would use WinVerifyTrust
                var content = await File.ReadAllBytesAsync(filePath);
                var hasSignature = ContainsSignature(content);

                if (!hasSignature)
                {
                    result.SuspiciousIndicators.Add("Executable is not digitally signed");
                    result.Score += 10;
                    result.IsUnsigned = true;
                }
            }
            catch { }
        }

        private bool ContainsSignature(byte[] content)
        {
            // Look for certificate table in PE
            // This is a simplified check
            try
            {
                if (content.Length < 512) return false;

                var peOffset = BitConverter.ToInt32(content, 0x3C);
                if (peOffset < 0 || peOffset + 200 > content.Length) return false;

                // Check PE signature
                if (BitConverter.ToUInt32(content, peOffset) != 0x00004550) return false;

                // Certificate table directory entry
                var optionalHeaderOffset = peOffset + 24;
                var magic = BitConverter.ToUInt16(content, optionalHeaderOffset);
                var certTableOffset = magic == 0x20B ? optionalHeaderOffset + 144 : optionalHeaderOffset + 128;

                if (certTableOffset + 8 > content.Length) return false;

                var certRva = BitConverter.ToUInt32(content, certTableOffset);
                var certSize = BitConverter.ToUInt32(content, certTableOffset + 4);

                return certRva > 0 && certSize > 0;
            }
            catch
            {
                return false;
            }
        }

        #endregion

        #region Process Heuristics

        /// <summary>
        /// Analyzes a running process for suspicious behavior
        /// </summary>
        public async Task<ProcessHeuristicResult> AnalyzeProcessAsync(Process process)
        {
            var result = new ProcessHeuristicResult
            {
                ProcessId = process.Id,
                ProcessName = process.ProcessName
            };

            try
            {
                // Get executable path
                try
                {
                    result.ExecutablePath = process.MainModule?.FileName;
                }
                catch
                {
                    result.SuspiciousIndicators.Add("Unable to access process executable path");
                    result.Score += 10;
                }

                // Check if it's a known safe process
                if (_knownSafeProcesses.Contains(process.ProcessName.ToLower()) ||
                    _knownSafeProcesses.Contains(process.ProcessName.ToLower() + ".exe"))
                {
                    result.IsKnownSafe = true;
                }

                // Check parent process
                await AnalyzeParentProcessAsync(process, result);

                // Check command line
                AnalyzeCommandLine(process, result);

                // Check loaded modules
                AnalyzeLoadedModules(process, result);

                // Check network connections
                await AnalyzeNetworkActivityAsync(process, result);

                // Check for suspicious process characteristics
                AnalyzeProcessCharacteristics(process, result);

                // Calculate threat score
                CalculateProcessThreatScore(result);
            }
            catch (Exception ex)
            {
                result.ErrorMessage = ex.Message;
            }

            return result;
        }

        private async Task AnalyzeParentProcessAsync(Process process, ProcessHeuristicResult result)
        {
            try
            {
                var parentId = await GetParentProcessIdAsync(process.Id);
                if (parentId > 0)
                {
                    result.ParentProcessId = parentId;
                    try
                    {
                        using var parent = Process.GetProcessById(parentId);
                        result.ParentProcessName = parent.ProcessName;

                        // Suspicious parent-child relationships
                        var suspicious = new Dictionary<string, string[]>
                        {
                            { "winword", new[] { "cmd", "powershell", "wscript", "cscript", "mshta" } },
                            { "excel", new[] { "cmd", "powershell", "wscript", "cscript", "mshta" } },
                            { "outlook", new[] { "cmd", "powershell", "wscript", "cscript", "mshta" } },
                            { "powerpnt", new[] { "cmd", "powershell", "wscript", "cscript" } },
                            { "svchost", new[] { "cmd", "powershell" } }, // Can be suspicious
                        };

                        var parentName = parent.ProcessName.ToLower();
                        var childName = process.ProcessName.ToLower();

                        if (suspicious.TryGetValue(parentName, out var suspiciousChildren))
                        {
                            if (suspiciousChildren.Contains(childName))
                            {
                                result.SuspiciousIndicators.Add($"Suspicious parent-child: {parentName} -> {childName}");
                                result.Score += 30;
                                result.DetectedTechniques.Add("Execution - Suspicious Spawning");
                            }
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }

        private async Task<int> GetParentProcessIdAsync(int processId)
        {
            try
            {
                using var searcher = new ManagementObjectSearcher(
                    $"SELECT ParentProcessId FROM Win32_Process WHERE ProcessId = {processId}");
                using var results = searcher.Get();

                foreach (var item in results)
                {
                    return Convert.ToInt32(item["ParentProcessId"]);
                }
            }
            catch { }

            return 0;
        }

        private void AnalyzeCommandLine(Process process, ProcessHeuristicResult result)
        {
            try
            {
                using var searcher = new ManagementObjectSearcher(
                    $"SELECT CommandLine FROM Win32_Process WHERE ProcessId = {process.Id}");
                using var results = searcher.Get();

                foreach (var item in results)
                {
                    var cmdLine = item["CommandLine"]?.ToString();
                    if (string.IsNullOrEmpty(cmdLine)) continue;

                    result.CommandLine = cmdLine;

                    // Suspicious command line patterns
                    var patterns = new Dictionary<string, (string Description, int Score)>
                    {
                        { "-enc ", ("Encoded PowerShell", 30) },
                        { "-encodedcommand", ("Encoded PowerShell", 30) },
                        { "-nop ", ("No profile (stealth)", 15) },
                        { "-noprofile", ("No profile (stealth)", 15) },
                        { "-w hidden", ("Hidden window", 25) },
                        { "-windowstyle hidden", ("Hidden window", 25) },
                        { "bypass", ("Execution policy bypass", 20) },
                        { "downloadstring", ("Remote download", 30) },
                        { "invoke-expression", ("Dynamic execution", 25) },
                        { "iex(", ("Dynamic execution", 25) },
                        { "frombase64", ("Base64 decoding", 20) },
                        { "certutil", ("CertUtil abuse", 25) },
                        { "bitsadmin", ("BitsAdmin abuse", 20) },
                        { "regsvr32 /s /n /u", ("Regsvr32 abuse", 30) },
                        { "mshta vbscript:", ("MSHTA abuse", 35) },
                        { "rundll32.exe javascript:", ("Rundll32 abuse", 35) },
                    };

                    var lowerCmd = cmdLine.ToLower();
                    foreach (var (pattern, (description, score)) in patterns)
                    {
                        if (lowerCmd.Contains(pattern))
                        {
                            result.SuspiciousIndicators.Add($"Command line: {description}");
                            result.Score += score;
                        }
                    }
                }
            }
            catch { }
        }

        private void AnalyzeLoadedModules(Process process, ProcessHeuristicResult result)
        {
            try
            {
                var modules = process.Modules;
                var loadedDlls = new List<string>();

                foreach (ProcessModule module in modules)
                {
                    loadedDlls.Add(module.FileName);

                    // Check for suspicious DLLs
                    var dllName = Path.GetFileName(module.FileName).ToLower();

                    // DLL loaded from temp
                    if (module.FileName.ToLower().Contains(@"\temp\"))
                    {
                        result.SuspiciousIndicators.Add($"DLL loaded from temp: {dllName}");
                        result.Score += 15;
                    }

                    // DLL loaded from AppData
                    if (module.FileName.ToLower().Contains(@"\appdata\"))
                    {
                        result.SuspiciousIndicators.Add($"DLL loaded from AppData: {dllName}");
                        result.Score += 10;
                    }

                    // Known malicious DLL patterns
                    var maliciousDlls = new[] { "steam_api.dll", "steam_api64.dll", "cream_api.dll", "goldberg" };
                    if (maliciousDlls.Any(m => dllName.Contains(m)) &&
                        !module.FileName.ToLower().Contains("steamapps"))
                    {
                        result.SuspiciousIndicators.Add($"Suspicious DLL: {dllName}");
                        result.Score += 20;
                    }
                }

                result.LoadedModules = loadedDlls;
            }
            catch { }
        }

        private async Task AnalyzeNetworkActivityAsync(Process process, ProcessHeuristicResult result)
        {
            try
            {
                var connections = IPGlobalProperties.GetIPGlobalProperties()
                    .GetActiveTcpConnections()
                    .ToList();

                // Note: Getting the owning process for connections requires admin rights
                // This is a simplified check

                foreach (var conn in connections)
                {
                    if (_c2Ports.Contains(conn.RemoteEndPoint.Port))
                    {
                        result.SuspiciousIndicators.Add($"Connection to suspicious port: {conn.RemoteEndPoint.Port}");
                        result.Score += 20;
                    }
                }
            }
            catch { }

            await Task.CompletedTask;
        }

        private void AnalyzeProcessCharacteristics(Process process, ProcessHeuristicResult result)
        {
            try
            {
                // High memory usage for small executable
                if (process.WorkingSet64 > 500 * 1024 * 1024) // >500MB
                {
                    result.SuspiciousIndicators.Add("Unusually high memory usage");
                    result.Score += 10;
                }

                // Check CPU usage
                try
                {
                    var cpuCounter = new PerformanceCounter("Process", "% Processor Time", process.ProcessName, true);
                    var cpuUsage = cpuCounter.NextValue();
                    Thread.Sleep(100);
                    cpuUsage = cpuCounter.NextValue();

                    if (cpuUsage > 80)
                    {
                        result.SuspiciousIndicators.Add($"High CPU usage: {cpuUsage:F1}%");
                        result.Score += 15;
                    }
                }
                catch { }
            }
            catch { }
        }

        private void CalculateProcessThreatScore(ProcessHeuristicResult result)
        {
            // Apply caps and adjustments
            if (result.IsKnownSafe && result.Score < 50)
            {
                result.Score = (int)(result.Score * 0.5); // Reduce score for known safe processes
            }

            result.Score = Math.Min(result.Score, 100);

            result.ThreatLevel = result.Score switch
            {
                >= 80 => ThreatSeverity.Critical,
                >= 60 => ThreatSeverity.High,
                >= 40 => ThreatSeverity.Medium,
                >= 20 => ThreatSeverity.Low,
                _ => ThreatSeverity.Safe
            };
        }

        #endregion

        #region Registry Heuristics

        /// <summary>
        /// Comprehensive registry persistence check
        /// </summary>
        public async Task<List<RegistryThreat>> ScanRegistryPersistenceAsync()
        {
            var threats = new List<RegistryThreat>();

            // All known persistence locations
            var persistenceLocations = new[]
            {
                // Run keys
                (@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "Run Key"),
                (@"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "RunOnce Key"),
                (@"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices", "RunServices Key"),
                (@"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce", "RunServicesOnce Key"),
                (@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "Winlogon"),

                // Explorer
                (@"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders", "Shell Folders"),
                (@"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders", "User Shell Folders"),

                // Services
                (@"SYSTEM\CurrentControlSet\Services", "Services"),

                // Browser helpers
                (@"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects", "BHO"),
                (@"SOFTWARE\Microsoft\Internet Explorer\Extensions", "IE Extensions"),

                // Shell extensions
                (@"SOFTWARE\Classes\*\shellex\ContextMenuHandlers", "Context Menu Handlers"),
                (@"SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers", "Directory Context Menu"),
                (@"SOFTWARE\Classes\Folder\shellex\ContextMenuHandlers", "Folder Context Menu"),

                // AppInit
                (@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows", "AppInit_DLLs"),

                // Image File Execution Options (IFEO)
                (@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options", "IFEO"),

                // Scheduled Tasks (registry remnants)
                (@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks", "Task Cache"),

                // COM Objects
                (@"SOFTWARE\Classes\CLSID", "COM Objects"),

                // Print Monitors
                (@"SYSTEM\CurrentControlSet\Control\Print\Monitors", "Print Monitors"),

                // Security Providers
                (@"SYSTEM\CurrentControlSet\Control\SecurityProviders", "Security Providers"),

                // LSA
                (@"SYSTEM\CurrentControlSet\Control\Lsa", "LSA"),

                // WMI
                (@"SOFTWARE\Microsoft\WBEM\ESS\//./root/subscription", "WMI Subscription"),

                // Active Setup
                (@"SOFTWARE\Microsoft\Active Setup\Installed Components", "Active Setup"),

                // Boot Execute
                (@"SYSTEM\CurrentControlSet\Control\Session Manager", "Boot Execute"),

                // Known DLLs
                (@"SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs", "Known DLLs"),
            };

            foreach (var (path, description) in persistenceLocations)
            {
                // Check both HKCU and HKLM
                await CheckRegistryLocation(Registry.CurrentUser, path, description, threats);
                await CheckRegistryLocation(Registry.LocalMachine, path, description, threats);
            }

            // Check HKU for all users
            try
            {
                using var hkuKey = Registry.Users;
                foreach (var sid in hkuKey.GetSubKeyNames())
                {
                    if (sid.StartsWith("S-1-5-21")) // User SIDs
                    {
                        var userRunPath = $@"{sid}\SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
                        await CheckRegistryLocation(Registry.Users, userRunPath, "User Run Key", threats);
                    }
                }
            }
            catch { }

            return threats;
        }

        private async Task CheckRegistryLocation(RegistryKey root, string path, string description, List<RegistryThreat> threats)
        {
            try
            {
                using var key = root.OpenSubKey(path, false);
                if (key == null) return;

                foreach (var valueName in key.GetValueNames())
                {
                    try
                    {
                        var value = key.GetValue(valueName)?.ToString();
                        if (string.IsNullOrEmpty(value)) continue;

                        var filePath = ExtractFilePath(value);
                        if (string.IsNullOrEmpty(filePath)) continue;

                        var threat = await AnalyzeRegistryEntry(root.Name, path, valueName, value, filePath, description);
                        if (threat != null)
                        {
                            threats.Add(threat);
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }

        private string? ExtractFilePath(string value)
        {
            // Remove quotes
            value = value.Trim('"', ' ');

            // Try to extract path from command line
            var match = Regex.Match(value, @"([A-Za-z]:\\[^\s""]+\.(exe|dll|bat|cmd|vbs|ps1|js))", RegexOptions.IgnoreCase);
            if (match.Success)
            {
                return match.Groups[1].Value;
            }

            // Try rundll32 pattern
            match = Regex.Match(value, @"rundll32\.exe\s+([^,\s]+)", RegexOptions.IgnoreCase);
            if (match.Success)
            {
                return match.Groups[1].Value;
            }

            return null;
        }

        private async Task<RegistryThreat?> AnalyzeRegistryEntry(string rootKey, string path, string valueName, string value, string filePath, string description)
        {
            // Self-exclusion: Skip if this is SkidrowKiller's own registry entries
            var lowerFilePath = filePath.ToLower();
            var lowerValue = value.ToLower();
            if (lowerFilePath.Contains("skidrowkiller") || lowerFilePath.Contains("skidrow killer") ||
                lowerFilePath.Contains("skidrow-killer") || lowerFilePath.Contains("skidrow_killer") ||
                lowerValue.Contains("skidrowkiller") || valueName.ToLower().Contains("skidrowkiller"))
            {
                return null;
            }

            var threat = new RegistryThreat
            {
                RegistryPath = $@"{rootKey}\{path}\{valueName}",
                Value = value,
                FilePath = filePath,
                Description = description
            };

            // Check if file exists
            if (!File.Exists(filePath))
            {
                threat.SuspiciousIndicators.Add("Referenced file does not exist");
                threat.Score += 10;
            }
            else
            {
                // Analyze the file
                var fileResult = await AnalyzeFileAsync(filePath);
                threat.Score += fileResult.Score / 2;

                foreach (var indicator in fileResult.SuspiciousIndicators.Take(5))
                {
                    threat.SuspiciousIndicators.Add(indicator);
                }
            }

            // Check for suspicious patterns in the value
            if (lowerValue.Contains("-enc ") || lowerValue.Contains("encodedcommand"))
            {
                threat.SuspiciousIndicators.Add("Encoded PowerShell in registry");
                threat.Score += 35;
            }

            if (lowerValue.Contains(@"\temp\") || lowerValue.Contains(@"\appdata\local\temp\"))
            {
                threat.SuspiciousIndicators.Add("Persistence points to temp folder");
                threat.Score += 25;
            }

            if (lowerValue.Contains("powershell") && lowerValue.Contains("hidden"))
            {
                threat.SuspiciousIndicators.Add("Hidden PowerShell execution");
                threat.Score += 30;
            }

            // Determine threat level
            threat.ThreatLevel = threat.Score switch
            {
                >= 60 => ThreatSeverity.High,
                >= 40 => ThreatSeverity.Medium,
                >= 20 => ThreatSeverity.Low,
                _ => ThreatSeverity.Safe
            };

            return threat.Score >= 15 ? threat : null;
        }

        #endregion

        #region Helpers

        private void CalculateThreatScore(HeuristicResult result)
        {
            // Apply any final adjustments
            result.Score = Math.Min(result.Score, 100);

            result.ThreatLevel = result.Score switch
            {
                >= 80 => ThreatSeverity.Critical,
                >= 60 => ThreatSeverity.High,
                >= 40 => ThreatSeverity.Medium,
                >= 20 => ThreatSeverity.Low,
                _ => ThreatSeverity.Safe
            };
        }

        private int LevenshteinDistance(string s1, string s2)
        {
            var n = s1.Length;
            var m = s2.Length;
            var d = new int[n + 1, m + 1];

            for (var i = 0; i <= n; i++) d[i, 0] = i;
            for (var j = 0; j <= m; j++) d[0, j] = j;

            for (var i = 1; i <= n; i++)
            {
                for (var j = 1; j <= m; j++)
                {
                    var cost = s1[i - 1] == s2[j - 1] ? 0 : 1;
                    d[i, j] = Math.Min(
                        Math.Min(d[i - 1, j] + 1, d[i, j - 1] + 1),
                        d[i - 1, j - 1] + cost);
                }
            }

            return d[n, m];
        }

        #endregion
    }

    #region Result Classes

    public class HeuristicResult
    {
        public string FilePath { get; set; } = string.Empty;
        public string FileName { get; set; } = string.Empty;
        public long FileSize { get; set; }
        public bool IsPE { get; set; }
        public bool IsUnsigned { get; set; }
        public PEAnalysisResult? PEAnalysis { get; set; }
        public int Score { get; set; }
        public ThreatSeverity ThreatLevel { get; set; }
        public List<string> SuspiciousIndicators { get; set; } = new();
        public List<string> DetectedTechniques { get; set; } = new();
        public string? ErrorMessage { get; set; }
    }

    public class ProcessHeuristicResult
    {
        public int ProcessId { get; set; }
        public string ProcessName { get; set; } = string.Empty;
        public string? ExecutablePath { get; set; }
        public string? CommandLine { get; set; }
        public int? ParentProcessId { get; set; }
        public string? ParentProcessName { get; set; }
        public bool IsKnownSafe { get; set; }
        public List<string> LoadedModules { get; set; } = new();
        public int Score { get; set; }
        public ThreatSeverity ThreatLevel { get; set; }
        public List<string> SuspiciousIndicators { get; set; } = new();
        public List<string> DetectedTechniques { get; set; } = new();
        public string? ErrorMessage { get; set; }
    }

    public class ProcessBehavior
    {
        public int ProcessId { get; set; }
        public int FileOperations { get; set; }
        public int RegistryOperations { get; set; }
        public int NetworkConnections { get; set; }
        public int ChildProcesses { get; set; }
        public DateTime StartTime { get; set; }
    }

    public class RegistryThreat
    {
        public string RegistryPath { get; set; } = string.Empty;
        public string Value { get; set; } = string.Empty;
        public string FilePath { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public int Score { get; set; }
        public ThreatSeverity ThreatLevel { get; set; }
        public List<string> SuspiciousIndicators { get; set; } = new();
    }

    #endregion
}
