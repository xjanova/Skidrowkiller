using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Extensions.Logging;

namespace SkidrowKiller.Services;

/// <summary>
/// Behavioral analyzer for detecting suspicious API patterns and runtime behavior
/// that indicate malware activity
/// </summary>
public class BehavioralAnalyzer
{
    private readonly ILogger<BehavioralAnalyzer>? _logger;

    // Suspicious Windows API imports that malware commonly uses
    private static readonly Dictionary<string, SuspiciousApiInfo> SuspiciousApis = new(StringComparer.OrdinalIgnoreCase)
    {
        // Process Injection APIs
        ["VirtualAllocEx"] = new("Process Injection", "Allocates memory in another process", 8),
        ["WriteProcessMemory"] = new("Process Injection", "Writes to another process memory", 9),
        ["CreateRemoteThread"] = new("Process Injection", "Creates thread in another process", 10),
        ["NtCreateThreadEx"] = new("Process Injection", "Native API for remote thread creation", 10),
        ["RtlCreateUserThread"] = new("Process Injection", "Creates user thread in another process", 10),
        ["QueueUserAPC"] = new("Process Injection", "Queues APC for code execution", 8),
        ["NtQueueApcThread"] = new("Process Injection", "Native APC queueing", 9),
        ["SetThreadContext"] = new("Process Injection", "Modifies thread context for injection", 9),
        ["NtUnmapViewOfSection"] = new("Process Hollowing", "Unmaps sections for process hollowing", 10),

        // Credential Theft APIs
        ["CredEnumerateW"] = new("Credential Theft", "Enumerates stored credentials", 8),
        ["CredReadW"] = new("Credential Theft", "Reads stored credentials", 8),
        ["LsaRetrievePrivateData"] = new("Credential Theft", "Retrieves LSA private data", 9),
        ["SamIConnect"] = new("Credential Theft", "Connects to SAM database", 10),
        ["SamrQueryInformationUser"] = new("Credential Theft", "Queries SAM user information", 10),

        // Keylogging APIs
        ["SetWindowsHookExA"] = new("Keylogging", "Sets Windows hook (keyboard)", 7),
        ["SetWindowsHookExW"] = new("Keylogging", "Sets Windows hook (keyboard)", 7),
        ["GetAsyncKeyState"] = new("Keylogging", "Gets async keyboard state", 6),
        ["GetKeyState"] = new("Keylogging", "Gets keyboard state", 5),
        ["GetKeyboardState"] = new("Keylogging", "Gets full keyboard state", 6),
        ["RegisterRawInputDevices"] = new("Keylogging", "Registers for raw input", 5),

        // Screen Capture APIs
        ["BitBlt"] = new("Screen Capture", "Bit block transfer for screenshots", 4),
        ["GetDC"] = new("Screen Capture", "Gets device context for capture", 3),
        ["CreateCompatibleDC"] = new("Screen Capture", "Creates compatible DC", 3),
        ["PrintWindow"] = new("Screen Capture", "Captures window content", 5),

        // Privilege Escalation APIs
        ["AdjustTokenPrivileges"] = new("Privilege Escalation", "Adjusts process privileges", 6),
        ["ImpersonateLoggedOnUser"] = new("Privilege Escalation", "Impersonates user token", 8),
        ["SetTokenInformation"] = new("Privilege Escalation", "Modifies token information", 7),
        ["DuplicateTokenEx"] = new("Privilege Escalation", "Duplicates access token", 7),

        // Anti-Analysis APIs
        ["IsDebuggerPresent"] = new("Anti-Analysis", "Checks for debugger", 6),
        ["CheckRemoteDebuggerPresent"] = new("Anti-Analysis", "Checks for remote debugger", 7),
        ["NtQueryInformationProcess"] = new("Anti-Analysis", "Queries process info (anti-debug)", 5),
        ["OutputDebugStringA"] = new("Anti-Analysis", "Anti-debug timing attack", 4),
        ["GetTickCount"] = new("Anti-Analysis", "Timing-based anti-analysis", 3),
        ["QueryPerformanceCounter"] = new("Anti-Analysis", "High-res timing for anti-analysis", 3),

        // Persistence APIs
        ["RegSetValueExW"] = new("Persistence", "Sets registry value", 4),
        ["RegCreateKeyExW"] = new("Persistence", "Creates registry key", 4),
        ["CreateServiceW"] = new("Persistence", "Creates Windows service", 6),
        ["ChangeServiceConfig2W"] = new("Persistence", "Modifies service configuration", 6),
        ["WritePrivateProfileStringW"] = new("Persistence", "Writes to INI file", 3),

        // Network APIs (for C2 communication)
        ["InternetOpenA"] = new("Network/C2", "Opens internet connection", 3),
        ["InternetConnectA"] = new("Network/C2", "Connects to server", 4),
        ["HttpOpenRequestA"] = new("Network/C2", "Opens HTTP request", 3),
        ["HttpSendRequestA"] = new("Network/C2", "Sends HTTP request", 3),
        ["URLDownloadToFileA"] = new("Network/C2", "Downloads file from URL", 6),
        ["URLDownloadToFileW"] = new("Network/C2", "Downloads file from URL", 6),
        ["WinHttpOpen"] = new("Network/C2", "Opens WinHTTP session", 3),
        ["WinHttpConnect"] = new("Network/C2", "Connects to server", 4),
        ["WSAStartup"] = new("Network/C2", "Initializes Winsock", 2),
        ["socket"] = new("Network/C2", "Creates network socket", 2),
        ["connect"] = new("Network/C2", "Connects socket", 3),
        ["send"] = new("Network/C2", "Sends data over socket", 2),
        ["recv"] = new("Network/C2", "Receives data over socket", 2),

        // File/System Manipulation
        ["NtSetInformationFile"] = new("File Manipulation", "Native file manipulation", 5),
        ["ZwSetInformationFile"] = new("File Manipulation", "Native file manipulation", 5),
        ["MoveFileExW"] = new("File Manipulation", "Moves/renames files", 3),
        ["DeleteFileW"] = new("File Manipulation", "Deletes files", 3),
        ["CreateFileW"] = new("File Manipulation", "Creates/opens files", 2),
        ["SetFileAttributesW"] = new("File Manipulation", "Sets file attributes", 4),

        // Code Execution/Loading
        ["LoadLibraryA"] = new("Code Loading", "Loads DLL library", 3),
        ["LoadLibraryW"] = new("Code Loading", "Loads DLL library", 3),
        ["LoadLibraryExW"] = new("Code Loading", "Loads DLL with flags", 4),
        ["GetProcAddress"] = new("Code Loading", "Gets function address", 3),
        ["LdrLoadDll"] = new("Code Loading", "Native DLL loading", 6),
        ["NtLoadDriver"] = new("Code Loading", "Loads kernel driver", 9),

        // Cryptographic APIs (ransomware indicator)
        ["CryptAcquireContextA"] = new("Cryptography", "Acquires crypto context", 4),
        ["CryptGenRandom"] = new("Cryptography", "Generates random data", 3),
        ["CryptEncrypt"] = new("Cryptography", "Encrypts data", 5),
        ["CryptDecrypt"] = new("Cryptography", "Decrypts data", 4),
        ["CryptDeriveKey"] = new("Cryptography", "Derives encryption key", 5),
        ["BCryptEncrypt"] = new("Cryptography", "BCrypt encryption", 5),

        // Dangerous WMI operations
        ["CoCreateInstance"] = new("COM/WMI", "Creates COM object", 3),
        ["CoInitializeEx"] = new("COM/WMI", "Initializes COM", 2),
    };

    // Suspicious API combinations that strongly indicate malware
    private static readonly List<ApiCombination> SuspiciousCombinations = new()
    {
        new ApiCombination(
            "Process Injection Pattern",
            new[] { "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread" },
            25,
            "Classic process injection technique"
        ),
        new ApiCombination(
            "Process Hollowing Pattern",
            new[] { "NtUnmapViewOfSection", "VirtualAllocEx", "WriteProcessMemory", "SetThreadContext" },
            30,
            "Process hollowing/RunPE technique"
        ),
        new ApiCombination(
            "Credential Dumping Pattern",
            new[] { "OpenProcess", "ReadProcessMemory", "LsaRetrievePrivateData" },
            25,
            "Credential dumping technique"
        ),
        new ApiCombination(
            "Keylogger Pattern",
            new[] { "SetWindowsHookExA", "GetKeyState", "GetAsyncKeyState" },
            20,
            "Keyboard hooking/logging"
        ),
        new ApiCombination(
            "Ransomware Pattern",
            new[] { "CryptAcquireContextA", "CryptEncrypt", "FindFirstFileW", "FindNextFileW" },
            30,
            "File encryption pattern (ransomware)"
        ),
        new ApiCombination(
            "Download & Execute Pattern",
            new[] { "URLDownloadToFileA", "ShellExecuteA" },
            20,
            "Downloads and executes payload"
        ),
        new ApiCombination(
            "Anti-Debug Pattern",
            new[] { "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess" },
            15,
            "Multiple anti-debugging checks"
        ),
        new ApiCombination(
            "Reflective Loading Pattern",
            new[] { "VirtualAlloc", "GetProcAddress", "LoadLibraryA" },
            15,
            "Reflective DLL loading"
        ),
    };

    // Suspicious strings commonly found in malware
    private static readonly Dictionary<string, int> SuspiciousStrings = new(StringComparer.OrdinalIgnoreCase)
    {
        // C2 indicators
        ["User-Agent:"] = 3,
        ["POST /"] = 3,
        ["GET /"] = 2,
        ["cmd.exe"] = 5,
        ["powershell"] = 6,
        ["powershell.exe"] = 6,
        ["-enc "] = 7,
        ["-encodedcommand"] = 8,
        ["-windowstyle hidden"] = 8,
        ["bypass"] = 4,
        ["downloadstring"] = 7,
        ["downloadfile"] = 7,
        ["iex("] = 8,
        ["invoke-expression"] = 8,
        ["invoke-webrequest"] = 6,
        ["start-process"] = 5,
        ["new-object"] = 4,
        ["net.webclient"] = 7,

        // Registry persistence
        ["SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"] = 7,
        ["SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"] = 7,
        ["CurrentVersion\\Explorer\\Shell Folders"] = 5,

        // Suspicious paths
        ["\\AppData\\Local\\Temp\\"] = 3,
        ["\\Temp\\"] = 2,
        ["%TEMP%"] = 3,
        ["%APPDATA%"] = 2,

        // Ransomware indicators
        [".encrypted"] = 6,
        [".locked"] = 6,
        ["YOUR FILES HAVE BEEN ENCRYPTED"] = 10,
        ["bitcoin"] = 5,
        ["ransom"] = 7,
        ["decrypt"] = 4,

        // Backdoor indicators
        ["reverse shell"] = 9,
        ["bind shell"] = 9,
        ["meterpreter"] = 10,
        ["mimikatz"] = 10,

        // Anti-AV
        ["taskkill /f /im"] = 8,
        ["sc stop"] = 6,
        ["net stop"] = 6,
        ["DisableAntiSpyware"] = 9,

        // Obfuscation indicators
        ["chr("] = 3,
        ["frombase64string"] = 6,
        ["convert]::frombase64string"] = 7,
        ["[system.text.encoding]"] = 4,
    };

    public BehavioralAnalyzer(ILogger<BehavioralAnalyzer>? logger = null)
    {
        _logger = logger;
    }

    /// <summary>
    /// Analyzes a file for suspicious behavioral patterns
    /// </summary>
    public BehavioralAnalysisResult AnalyzeFile(string filePath)
    {
        var result = new BehavioralAnalysisResult
        {
            FilePath = filePath,
            AnalyzedAt = DateTime.UtcNow
        };

        try
        {
            if (!File.Exists(filePath))
            {
                result.Error = "File not found";
                return result;
            }

            var fileInfo = new FileInfo(filePath);

            // Skip files larger than 50MB for performance
            if (fileInfo.Length > 50 * 1024 * 1024)
            {
                result.Error = "File too large for behavioral analysis";
                return result;
            }

            byte[] fileBytes;
            try
            {
                fileBytes = File.ReadAllBytes(filePath);
            }
            catch (Exception ex)
            {
                result.Error = $"Cannot read file: {ex.Message}";
                return result;
            }

            // Check if it's a PE file
            bool isPeFile = fileBytes.Length > 2 && fileBytes[0] == 0x4D && fileBytes[1] == 0x5A;

            if (isPeFile)
            {
                // Analyze PE imports
                AnalyzePeImports(fileBytes, result);
            }

            // Analyze strings in the file
            AnalyzeStrings(fileBytes, result);

            // Calculate final score
            result.TotalScore = CalculateTotalScore(result);
            result.RiskLevel = DetermineRiskLevel(result.TotalScore);

            _logger?.LogDebug("Behavioral analysis of {FilePath}: Score={Score}, Risk={Risk}",
                filePath, result.TotalScore, result.RiskLevel);
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Error analyzing file: {FilePath}", filePath);
            result.Error = ex.Message;
        }

        return result;
    }

    /// <summary>
    /// Analyzes PE imports for suspicious APIs
    /// </summary>
    private void AnalyzePeImports(byte[] fileBytes, BehavioralAnalysisResult result)
    {
        try
        {
            // Extract strings that look like API names (simple approach)
            var strings = ExtractStrings(fileBytes, 4);
            var foundApis = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (var str in strings)
            {
                if (SuspiciousApis.TryGetValue(str, out var apiInfo))
                {
                    foundApis.Add(str);
                    result.SuspiciousApis.Add(new DetectedApi
                    {
                        Name = str,
                        Category = apiInfo.Category,
                        Description = apiInfo.Description,
                        Score = apiInfo.Score
                    });
                }
            }

            // Check for suspicious combinations
            foreach (var combo in SuspiciousCombinations)
            {
                int matchCount = combo.RequiredApis.Count(api => foundApis.Contains(api));
                if (matchCount >= combo.RequiredApis.Length - 1) // Allow one missing
                {
                    double matchRatio = (double)matchCount / combo.RequiredApis.Length;
                    int adjustedScore = (int)(combo.Score * matchRatio);

                    result.DetectedPatterns.Add(new DetectedPattern
                    {
                        Name = combo.Name,
                        Description = combo.Description,
                        MatchedApis = combo.RequiredApis.Where(a => foundApis.Contains(a)).ToList(),
                        Score = adjustedScore
                    });
                }
            }
        }
        catch (Exception ex)
        {
            _logger?.LogWarning(ex, "Error analyzing PE imports");
        }
    }

    /// <summary>
    /// Analyzes strings in the file for suspicious content
    /// </summary>
    private void AnalyzeStrings(byte[] fileBytes, BehavioralAnalysisResult result)
    {
        try
        {
            var strings = ExtractStrings(fileBytes, 5);
            var fileContent = string.Join(" ", strings);

            foreach (var (pattern, score) in SuspiciousStrings)
            {
                if (fileContent.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                {
                    result.SuspiciousStrings.Add(new DetectedString
                    {
                        Pattern = pattern,
                        Score = score
                    });
                }
            }

            // Check for Base64-encoded content
            foreach (var str in strings)
            {
                if (str.Length > 50 && IsLikelyBase64(str))
                {
                    try
                    {
                        var decoded = Convert.FromBase64String(str);
                        var decodedStr = Encoding.UTF8.GetString(decoded);

                        // Check if decoded content contains suspicious strings
                        foreach (var (pattern, score) in SuspiciousStrings)
                        {
                            if (decodedStr.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                            {
                                result.SuspiciousStrings.Add(new DetectedString
                                {
                                    Pattern = $"Base64-encoded: {pattern}",
                                    Score = score + 3 // Extra points for obfuscation
                                });
                            }
                        }

                        // Check for PowerShell commands in Base64
                        if (decodedStr.Contains("powershell", StringComparison.OrdinalIgnoreCase) ||
                            decodedStr.Contains("invoke-", StringComparison.OrdinalIgnoreCase))
                        {
                            result.SuspiciousStrings.Add(new DetectedString
                            {
                                Pattern = "Base64-encoded PowerShell command",
                                Score = 10
                            });
                        }
                    }
                    catch
                    {
                        // Not valid Base64
                    }
                }
            }

            // Check for obfuscated PowerShell patterns
            if (fileContent.Contains("^", StringComparison.Ordinal) &&
                fileContent.Contains("cmd", StringComparison.OrdinalIgnoreCase))
            {
                result.SuspiciousStrings.Add(new DetectedString
                {
                    Pattern = "Caret-obfuscated command",
                    Score = 6
                });
            }

            // Check for suspicious URL patterns
            foreach (var str in strings)
            {
                if (str.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
                    str.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                {
                    // Check for IP-based URLs (often malicious)
                    if (System.Text.RegularExpressions.Regex.IsMatch(str, @"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"))
                    {
                        result.SuspiciousStrings.Add(new DetectedString
                        {
                            Pattern = $"IP-based URL: {str.Substring(0, Math.Min(50, str.Length))}...",
                            Score = 5
                        });
                    }

                    // Check for suspicious file downloads
                    if (str.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ||
                        str.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) ||
                        str.EndsWith(".ps1", StringComparison.OrdinalIgnoreCase))
                    {
                        result.SuspiciousStrings.Add(new DetectedString
                        {
                            Pattern = $"Executable download URL: {str.Substring(0, Math.Min(50, str.Length))}...",
                            Score = 7
                        });
                    }
                }
            }
        }
        catch (Exception ex)
        {
            _logger?.LogWarning(ex, "Error analyzing strings");
        }
    }

    /// <summary>
    /// Extracts ASCII and Unicode strings from binary data
    /// </summary>
    private List<string> ExtractStrings(byte[] data, int minLength)
    {
        var strings = new List<string>();
        var currentString = new StringBuilder();

        // Extract ASCII strings
        foreach (byte b in data)
        {
            if (b >= 32 && b < 127)
            {
                currentString.Append((char)b);
            }
            else
            {
                if (currentString.Length >= minLength)
                {
                    strings.Add(currentString.ToString());
                }
                currentString.Clear();
            }
        }
        if (currentString.Length >= minLength)
        {
            strings.Add(currentString.ToString());
        }

        // Extract Unicode strings (simplified - every other byte for UTF-16LE)
        currentString.Clear();
        for (int i = 0; i < data.Length - 1; i += 2)
        {
            if (data[i] >= 32 && data[i] < 127 && data[i + 1] == 0)
            {
                currentString.Append((char)data[i]);
            }
            else
            {
                if (currentString.Length >= minLength)
                {
                    strings.Add(currentString.ToString());
                }
                currentString.Clear();
            }
        }
        if (currentString.Length >= minLength)
        {
            strings.Add(currentString.ToString());
        }

        return strings.Distinct().ToList();
    }

    /// <summary>
    /// Checks if a string is likely Base64 encoded
    /// </summary>
    private bool IsLikelyBase64(string str)
    {
        if (string.IsNullOrEmpty(str) || str.Length < 20)
            return false;

        // Check for valid Base64 characters
        if (!System.Text.RegularExpressions.Regex.IsMatch(str, @"^[A-Za-z0-9+/=]+$"))
            return false;

        // Check for reasonable entropy (Base64 should have high entropy)
        var charCounts = str.GroupBy(c => c).ToDictionary(g => g.Key, g => g.Count());
        double entropy = 0;
        foreach (var count in charCounts.Values)
        {
            double p = (double)count / str.Length;
            entropy -= p * Math.Log2(p);
        }

        return entropy > 4.0; // Base64 typically has entropy > 4
    }

    /// <summary>
    /// Calculates total score from all findings
    /// </summary>
    private int CalculateTotalScore(BehavioralAnalysisResult result)
    {
        int score = 0;

        // Add API scores (but cap individual API score contribution)
        score += Math.Min(result.SuspiciousApis.Sum(a => a.Score), 50);

        // Add pattern scores (high priority)
        score += result.DetectedPatterns.Sum(p => p.Score);

        // Add string scores (but cap contribution)
        score += Math.Min(result.SuspiciousStrings.Sum(s => s.Score), 40);

        return score;
    }

    /// <summary>
    /// Determines risk level based on score
    /// </summary>
    private RiskLevel DetermineRiskLevel(int score)
    {
        return score switch
        {
            >= 50 => RiskLevel.Critical,
            >= 30 => RiskLevel.High,
            >= 15 => RiskLevel.Medium,
            >= 5 => RiskLevel.Low,
            _ => RiskLevel.Safe
        };
    }

    /// <summary>
    /// Analyzes a running process for suspicious behavior
    /// </summary>
    public ProcessBehaviorResult AnalyzeProcess(int processId)
    {
        var result = new ProcessBehaviorResult
        {
            ProcessId = processId,
            AnalyzedAt = DateTime.UtcNow
        };

        try
        {
            var process = Process.GetProcessById(processId);
            result.ProcessName = process.ProcessName;

            // Get loaded modules
            try
            {
                foreach (ProcessModule module in process.Modules)
                {
                    var modulePath = module.FileName;

                    // Check for suspicious DLLs
                    if (IsSuspiciousModule(modulePath))
                    {
                        result.SuspiciousModules.Add(new SuspiciousModule
                        {
                            Path = modulePath,
                            Reason = GetModuleSuspicionReason(modulePath)
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                result.Notes.Add($"Cannot enumerate modules: {ex.Message}");
            }

            // Check command line
            try
            {
                var commandLine = GetProcessCommandLine(processId);
                if (!string.IsNullOrEmpty(commandLine))
                {
                    result.CommandLine = commandLine;

                    // Check for suspicious command line patterns
                    foreach (var (pattern, score) in SuspiciousStrings)
                    {
                        if (commandLine.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                        {
                            result.SuspiciousCommandLinePatterns.Add(new DetectedString
                            {
                                Pattern = pattern,
                                Score = score
                            });
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                result.Notes.Add($"Cannot get command line: {ex.Message}");
            }

            // Calculate risk
            result.TotalScore = result.SuspiciousModules.Count * 10 +
                               result.SuspiciousCommandLinePatterns.Sum(p => p.Score);
            result.RiskLevel = DetermineRiskLevel(result.TotalScore);
        }
        catch (Exception ex)
        {
            result.Error = ex.Message;
        }

        return result;
    }

    private bool IsSuspiciousModule(string path)
    {
        if (string.IsNullOrEmpty(path))
            return false;

        var fileName = Path.GetFileName(path).ToLowerInvariant();
        var directory = Path.GetDirectoryName(path)?.ToLowerInvariant() ?? "";

        // DLL in temp folder is suspicious
        if (directory.Contains("\\temp\\") || directory.Contains("\\tmp\\"))
            return true;

        // DLL in user's AppData that's not in a known app folder
        if (directory.Contains("\\appdata\\") && !directory.Contains("\\microsoft\\"))
            return true;

        // Known malicious DLL names
        var suspiciousDlls = new[] { "inject.dll", "hook.dll", "payload.dll", "loader.dll" };
        if (suspiciousDlls.Any(dll => fileName.Contains(dll)))
            return true;

        return false;
    }

    private string GetModuleSuspicionReason(string path)
    {
        var directory = Path.GetDirectoryName(path)?.ToLowerInvariant() ?? "";

        if (directory.Contains("\\temp\\") || directory.Contains("\\tmp\\"))
            return "DLL loaded from temporary directory";
        if (directory.Contains("\\appdata\\"))
            return "DLL loaded from AppData directory";

        return "Suspicious DLL name";
    }

    private string? GetProcessCommandLine(int processId)
    {
        try
        {
            using var searcher = new System.Management.ManagementObjectSearcher(
                $"SELECT CommandLine FROM Win32_Process WHERE ProcessId = {processId}");
            using var results = searcher.Get();
            foreach (var item in results)
            {
                return item["CommandLine"]?.ToString();
            }
        }
        catch
        {
            // WMI not available or access denied
        }
        return null;
    }
}

#region Data Models

public record SuspiciousApiInfo(string Category, string Description, int Score);

public class ApiCombination
{
    public string Name { get; }
    public string[] RequiredApis { get; }
    public int Score { get; }
    public string Description { get; }

    public ApiCombination(string name, string[] requiredApis, int score, string description)
    {
        Name = name;
        RequiredApis = requiredApis;
        Score = score;
        Description = description;
    }
}

public class BehavioralAnalysisResult
{
    public string FilePath { get; set; } = "";
    public DateTime AnalyzedAt { get; set; }
    public string? Error { get; set; }
    public List<DetectedApi> SuspiciousApis { get; set; } = new();
    public List<DetectedPattern> DetectedPatterns { get; set; } = new();
    public List<DetectedString> SuspiciousStrings { get; set; } = new();
    public int TotalScore { get; set; }
    public RiskLevel RiskLevel { get; set; }

    public bool IsSuspicious => TotalScore >= 15;
    public bool IsMalicious => TotalScore >= 30;
}

public class DetectedApi
{
    public string Name { get; set; } = "";
    public string Category { get; set; } = "";
    public string Description { get; set; } = "";
    public int Score { get; set; }
}

public class DetectedPattern
{
    public string Name { get; set; } = "";
    public string Description { get; set; } = "";
    public List<string> MatchedApis { get; set; } = new();
    public int Score { get; set; }
}

public class DetectedString
{
    public string Pattern { get; set; } = "";
    public int Score { get; set; }
}

public class ProcessBehaviorResult
{
    public int ProcessId { get; set; }
    public string ProcessName { get; set; } = "";
    public string? CommandLine { get; set; }
    public DateTime AnalyzedAt { get; set; }
    public string? Error { get; set; }
    public List<SuspiciousModule> SuspiciousModules { get; set; } = new();
    public List<DetectedString> SuspiciousCommandLinePatterns { get; set; } = new();
    public List<string> Notes { get; set; } = new();
    public int TotalScore { get; set; }
    public RiskLevel RiskLevel { get; set; }
}

public class SuspiciousModule
{
    public string Path { get; set; } = "";
    public string Reason { get; set; } = "";
}

public enum RiskLevel
{
    Safe,
    Low,
    Medium,
    High,
    Critical
}

#endregion
