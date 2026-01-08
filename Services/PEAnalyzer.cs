using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace SkidrowKiller.Services
{
    /// <summary>
    /// Professional PE (Portable Executable) file analyzer.
    /// Analyzes Windows executables for suspicious characteristics,
    /// packing, entropy, imports, and malware indicators.
    /// </summary>
    public class PEAnalyzer
    {
        private readonly MalwareSignatureDatabase _signatureDb;

        // PE signature constants
        private const ushort DOS_SIGNATURE = 0x5A4D;        // "MZ"
        private const uint PE_SIGNATURE = 0x00004550;       // "PE\0\0"
        private const ushort PE32_MAGIC = 0x10B;
        private const ushort PE64_MAGIC = 0x20B;

        // Entropy thresholds
        private const double HIGH_ENTROPY_THRESHOLD = 7.0;
        private const double SUSPICIOUS_ENTROPY_THRESHOLD = 6.5;
        private const double PACKED_ENTROPY_THRESHOLD = 7.2;

        // Section characteristics flags
        private const uint IMAGE_SCN_MEM_EXECUTE = 0x20000000;
        private const uint IMAGE_SCN_MEM_READ = 0x40000000;
        private const uint IMAGE_SCN_MEM_WRITE = 0x80000000;
        private const uint IMAGE_SCN_CNT_CODE = 0x00000020;
        private const uint IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040;
        private const uint IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080;

        public PEAnalyzer(MalwareSignatureDatabase signatureDb)
        {
            _signatureDb = signatureDb;
        }

        public async Task<PEAnalysisResult> AnalyzeAsync(string filePath)
        {
            var result = new PEAnalysisResult { FilePath = filePath };

            if (!File.Exists(filePath))
            {
                result.IsValid = false;
                result.ErrorMessage = "File not found";
                return result;
            }

            try
            {
                var fileInfo = new FileInfo(filePath);
                result.FileSize = fileInfo.Length;

                if (fileInfo.Length < 64) // Minimum PE size
                {
                    result.IsValid = false;
                    result.ErrorMessage = "File too small to be a valid PE";
                    return result;
                }

                // Read file content
                var content = await File.ReadAllBytesAsync(filePath);

                // Parse PE structure
                if (!ParsePEHeader(content, result))
                {
                    result.IsValid = false;
                    return result;
                }

                // Analyze sections
                AnalyzeSections(content, result);

                // Calculate entropy
                CalculateEntropy(content, result);

                // Analyze imports
                AnalyzeImports(content, result);

                // Detect packers
                DetectPackers(content, result);

                // Check for suspicious characteristics
                AnalyzeSuspiciousCharacteristics(content, result);

                // Calculate overall threat score
                CalculateThreatScore(result);

                result.IsValid = true;
            }
            catch (Exception ex)
            {
                result.IsValid = false;
                result.ErrorMessage = $"Analysis failed: {ex.Message}";
            }

            return result;
        }

        private bool ParsePEHeader(byte[] content, PEAnalysisResult result)
        {
            try
            {
                // Check DOS header
                if (content.Length < 64)
                    return false;

                var dosSignature = BitConverter.ToUInt16(content, 0);
                if (dosSignature != DOS_SIGNATURE)
                {
                    result.ErrorMessage = "Invalid DOS signature";
                    return false;
                }

                // Get PE header offset from DOS header
                var peOffset = BitConverter.ToInt32(content, 0x3C);
                if (peOffset < 0 || peOffset + 24 > content.Length)
                {
                    result.ErrorMessage = "Invalid PE header offset";
                    return false;
                }

                // Check PE signature
                var peSignature = BitConverter.ToUInt32(content, peOffset);
                if (peSignature != PE_SIGNATURE)
                {
                    result.ErrorMessage = "Invalid PE signature";
                    return false;
                }

                result.PEHeaderOffset = peOffset;

                // Parse COFF header
                var coffHeaderOffset = peOffset + 4;
                result.Machine = BitConverter.ToUInt16(content, coffHeaderOffset);
                result.NumberOfSections = BitConverter.ToUInt16(content, coffHeaderOffset + 2);
                result.TimeDateStamp = BitConverter.ToUInt32(content, coffHeaderOffset + 4);
                result.Characteristics = BitConverter.ToUInt16(content, coffHeaderOffset + 18);

                // Convert timestamp to DateTime
                result.CompileTime = DateTimeOffset.FromUnixTimeSeconds(result.TimeDateStamp).DateTime;

                // Parse Optional Header
                var optionalHeaderOffset = coffHeaderOffset + 20;
                var optionalMagic = BitConverter.ToUInt16(content, optionalHeaderOffset);

                result.Is64Bit = optionalMagic == PE64_MAGIC;
                result.IsDotNet = false;

                if (optionalMagic == PE32_MAGIC)
                {
                    // PE32
                    result.ImageBase = BitConverter.ToUInt32(content, optionalHeaderOffset + 28);
                    result.EntryPoint = BitConverter.ToUInt32(content, optionalHeaderOffset + 16);
                    result.Subsystem = BitConverter.ToUInt16(content, optionalHeaderOffset + 68);

                    // Check for .NET
                    var cliHeaderRva = BitConverter.ToUInt32(content, optionalHeaderOffset + 208);
                    result.IsDotNet = cliHeaderRva != 0;
                }
                else if (optionalMagic == PE64_MAGIC)
                {
                    // PE64
                    result.ImageBase = BitConverter.ToUInt64(content, optionalHeaderOffset + 24);
                    result.EntryPoint = BitConverter.ToUInt32(content, optionalHeaderOffset + 16);
                    result.Subsystem = BitConverter.ToUInt16(content, optionalHeaderOffset + 68);

                    // Check for .NET
                    var cliHeaderRva = BitConverter.ToUInt32(content, optionalHeaderOffset + 224);
                    result.IsDotNet = cliHeaderRva != 0;
                }

                // Determine subsystem type
                result.SubsystemName = result.Subsystem switch
                {
                    1 => "Native",
                    2 => "Windows GUI",
                    3 => "Windows Console",
                    5 => "OS/2 Console",
                    7 => "POSIX Console",
                    9 => "Windows CE GUI",
                    10 => "EFI Application",
                    11 => "EFI Boot Service Driver",
                    12 => "EFI Runtime Driver",
                    13 => "EFI ROM",
                    14 => "Xbox",
                    16 => "Windows Boot Application",
                    _ => $"Unknown ({result.Subsystem})"
                };

                // Determine machine type
                result.MachineType = result.Machine switch
                {
                    0x14c => "x86",
                    0x8664 => "x64",
                    0x1c0 => "ARM",
                    0xaa64 => "ARM64",
                    _ => $"Unknown (0x{result.Machine:X})"
                };

                return true;
            }
            catch
            {
                result.ErrorMessage = "Failed to parse PE header";
                return false;
            }
        }

        private void AnalyzeSections(byte[] content, PEAnalysisResult result)
        {
            try
            {
                var sectionHeaderOffset = result.PEHeaderOffset + 24 +
                    (result.Is64Bit ? 240 : 224); // Size of optional header

                for (var i = 0; i < result.NumberOfSections && sectionHeaderOffset + 40 <= content.Length; i++)
                {
                    var section = new PESection
                    {
                        Name = Encoding.ASCII.GetString(content, sectionHeaderOffset, 8).TrimEnd('\0'),
                        VirtualSize = BitConverter.ToUInt32(content, sectionHeaderOffset + 8),
                        VirtualAddress = BitConverter.ToUInt32(content, sectionHeaderOffset + 12),
                        RawDataSize = BitConverter.ToUInt32(content, sectionHeaderOffset + 16),
                        RawDataPointer = BitConverter.ToUInt32(content, sectionHeaderOffset + 20),
                        Characteristics = BitConverter.ToUInt32(content, sectionHeaderOffset + 36)
                    };

                    // Calculate section entropy
                    if (section.RawDataPointer > 0 && section.RawDataSize > 0 &&
                        section.RawDataPointer + section.RawDataSize <= content.Length)
                    {
                        var sectionData = new byte[section.RawDataSize];
                        Array.Copy(content, section.RawDataPointer, sectionData, 0, section.RawDataSize);
                        section.Entropy = CalculateShannonEntropy(sectionData);
                    }

                    // Check for suspicious section characteristics
                    var isExecutable = (section.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
                    var isWritable = (section.Characteristics & IMAGE_SCN_MEM_WRITE) != 0;

                    if (isExecutable && isWritable)
                    {
                        section.IsSuspicious = true;
                        result.SuspiciousIndicators.Add($"Section '{section.Name}' is both executable and writable (RWX)");
                    }

                    if (section.Entropy > SUSPICIOUS_ENTROPY_THRESHOLD)
                    {
                        section.IsHighEntropy = true;
                        if (section.Entropy > PACKED_ENTROPY_THRESHOLD)
                        {
                            result.SuspiciousIndicators.Add($"Section '{section.Name}' has very high entropy ({section.Entropy:F2}) - likely packed/encrypted");
                        }
                    }

                    result.Sections.Add(section);
                    sectionHeaderOffset += 40;
                }

                // Check for suspicious section names
                var suspiciousSectionNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
                {
                    ".upx0", ".upx1", ".upx2", "UPX0", "UPX1", "UPX2",
                    ".aspack", ".adata", ".ASPack",
                    ".nsp0", ".nsp1", ".nsp2", // NSPack
                    ".vmp0", ".vmp1", // VMProtect
                    ".themida", ".winlice",
                    ".packed", ".encrypt", ".enigma",
                    ".spack", ".pec", ".petite",
                    ".mpress", ".MPRESS"
                };

                foreach (var section in result.Sections)
                {
                    if (suspiciousSectionNames.Contains(section.Name))
                    {
                        result.IsPacked = true;
                        result.PackerName = GetPackerNameFromSection(section.Name);
                        result.SuspiciousIndicators.Add($"Packer section detected: {section.Name}");
                    }
                }
            }
            catch { }
        }

        private string GetPackerNameFromSection(string sectionName)
        {
            var lower = sectionName.ToLower();
            if (lower.Contains("upx")) return "UPX";
            if (lower.Contains("aspack")) return "ASPack";
            if (lower.Contains("nsp")) return "NSPack";
            if (lower.Contains("vmp")) return "VMProtect";
            if (lower.Contains("themida")) return "Themida";
            if (lower.Contains("mpress")) return "MPRESS";
            if (lower.Contains("petite")) return "Petite";
            if (lower.Contains("enigma")) return "Enigma Protector";
            return "Unknown Packer";
        }

        private void CalculateEntropy(byte[] content, PEAnalysisResult result)
        {
            result.OverallEntropy = CalculateShannonEntropy(content);

            if (result.OverallEntropy > PACKED_ENTROPY_THRESHOLD)
            {
                result.IsPacked = true;
                result.SuspiciousIndicators.Add($"Very high overall entropy ({result.OverallEntropy:F2}) - likely packed or encrypted");
            }
            else if (result.OverallEntropy > HIGH_ENTROPY_THRESHOLD)
            {
                result.SuspiciousIndicators.Add($"High overall entropy ({result.OverallEntropy:F2}) - may contain encrypted/compressed data");
            }
        }

        private double CalculateShannonEntropy(byte[] data)
        {
            if (data.Length == 0) return 0;

            var frequency = new int[256];
            foreach (var b in data)
            {
                frequency[b]++;
            }

            double entropy = 0;
            var length = (double)data.Length;

            for (var i = 0; i < 256; i++)
            {
                if (frequency[i] > 0)
                {
                    var probability = frequency[i] / length;
                    entropy -= probability * Math.Log2(probability);
                }
            }

            return entropy;
        }

        private void AnalyzeImports(byte[] content, PEAnalysisResult result)
        {
            try
            {
                // This is a simplified import analysis
                // A full implementation would parse the import directory table

                var suspiciousImports = _signatureDb.GetSuspiciousImports();
                var textContent = Encoding.ASCII.GetString(content);

                foreach (var import in suspiciousImports)
                {
                    if (textContent.Contains(import))
                    {
                        result.SuspiciousImports.Add(import);
                    }
                }

                // Check for common malware imports
                var criticalImports = new Dictionary<string, string>
                {
                    { "CreateRemoteThread", "Process Injection" },
                    { "VirtualAllocEx", "Process Injection" },
                    { "WriteProcessMemory", "Process Injection" },
                    { "NtUnmapViewOfSection", "Process Hollowing" },
                    { "GetAsyncKeyState", "Keylogging" },
                    { "SetWindowsHookEx", "Hooking/Keylogging" },
                    { "CryptEncrypt", "Encryption (possible ransomware)" },
                    { "InternetOpenUrl", "Network Communication" },
                    { "URLDownloadToFile", "Download Capability" },
                    { "RegSetValueEx", "Registry Modification" },
                    { "CreateService", "Service Installation" },
                };

                foreach (var (import, category) in criticalImports)
                {
                    if (result.SuspiciousImports.Contains(import))
                    {
                        result.ImportCategories[import] = category;
                    }
                }

                // Analyze import combinations
                if (result.SuspiciousImports.Contains("VirtualAllocEx") &&
                    result.SuspiciousImports.Contains("WriteProcessMemory") &&
                    result.SuspiciousImports.Contains("CreateRemoteThread"))
                {
                    result.SuspiciousIndicators.Add("Classic process injection pattern detected (VirtualAllocEx + WriteProcessMemory + CreateRemoteThread)");
                    result.DetectedTechniques.Add("Process Injection");
                }

                if (result.SuspiciousImports.Contains("GetAsyncKeyState") ||
                    result.SuspiciousImports.Contains("GetKeyboardState"))
                {
                    result.SuspiciousIndicators.Add("Keylogging capability detected");
                    result.DetectedTechniques.Add("Keylogging");
                }

                if (result.SuspiciousImports.Contains("CryptEncrypt") ||
                    result.SuspiciousImports.Contains("CryptGenKey"))
                {
                    // Check for other ransomware indicators
                    if (textContent.Contains("encrypt", StringComparison.OrdinalIgnoreCase) ||
                        textContent.Contains("ransom", StringComparison.OrdinalIgnoreCase) ||
                        textContent.Contains(".locked") ||
                        textContent.Contains("bitcoin", StringComparison.OrdinalIgnoreCase))
                    {
                        result.SuspiciousIndicators.Add("Potential ransomware: encryption APIs with ransom indicators");
                        result.DetectedTechniques.Add("Ransomware");
                    }
                }

                if (result.SuspiciousImports.Contains("IsDebuggerPresent") ||
                    result.SuspiciousImports.Contains("CheckRemoteDebuggerPresent") ||
                    result.SuspiciousImports.Contains("NtQueryInformationProcess"))
                {
                    result.SuspiciousIndicators.Add("Anti-debugging techniques detected");
                    result.DetectedTechniques.Add("Anti-Debug");
                }
            }
            catch { }
        }

        private void DetectPackers(byte[] content, PEAnalysisResult result)
        {
            var textContent = Encoding.ASCII.GetString(content);

            // Packer signatures
            var packerSignatures = new Dictionary<string, string>
            {
                { "UPX0", "UPX" },
                { "UPX1", "UPX" },
                { "UPX!", "UPX" },
                { "This program cannot be run in DOS mode", "Standard" }, // Not packed, just checking
                { ".aspack", "ASPack" },
                { "ASPack", "ASPack" },
                { "PECompact", "PECompact" },
                { "MPRESS", "MPRESS" },
                { "Themida", "Themida" },
                { "VMProtect", "VMProtect" },
                { "Enigma protector", "Enigma Protector" },
                { ".nsp", "NSPack" },
                { "PEtite", "Petite" },
                { "FSG!", "FSG" },
                { "MEW", "MEW" },
                { ".MPRESS", "MPRESS" },
                { "kkrunchy", "kkrunchy" },
            };

            foreach (var (signature, packerName) in packerSignatures)
            {
                if (textContent.Contains(signature, StringComparison.OrdinalIgnoreCase))
                {
                    if (packerName != "Standard")
                    {
                        result.IsPacked = true;
                        result.PackerName = packerName;
                        result.SuspiciousIndicators.Add($"Packer detected: {packerName}");
                        break;
                    }
                }
            }

            // Check for .NET obfuscators
            if (result.IsDotNet)
            {
                var obfuscators = new[] { "ConfuserEx", "Dotfuscator", "Agile.NET", "Babel", "Eazfuscator", "SmartAssembly", ".NET Reactor", "Crypto Obfuscator" };
                foreach (var obfuscator in obfuscators)
                {
                    if (textContent.Contains(obfuscator, StringComparison.OrdinalIgnoreCase))
                    {
                        result.IsObfuscated = true;
                        result.ObfuscatorName = obfuscator;
                        result.SuspiciousIndicators.Add($".NET obfuscator detected: {obfuscator}");
                        break;
                    }
                }
            }
        }

        private void AnalyzeSuspiciousCharacteristics(byte[] content, PEAnalysisResult result)
        {
            // Check compile time
            if (result.CompileTime.Year < 2000 || result.CompileTime > DateTime.Now.AddYears(1))
            {
                result.SuspiciousIndicators.Add($"Suspicious compile timestamp: {result.CompileTime}");
            }

            // Check for small code section with large data section
            var codeSection = result.Sections.FirstOrDefault(s => s.Name == ".text");
            var dataSection = result.Sections.FirstOrDefault(s => s.Name == ".data" || s.Name == ".rdata");

            if (codeSection != null && dataSection != null)
            {
                if (codeSection.RawDataSize < 1024 && dataSection.RawDataSize > 100000)
                {
                    result.SuspiciousIndicators.Add("Unusually small code section with large data section - possible shellcode loader");
                }
            }

            // Check for resources with high entropy
            var rsrcSection = result.Sections.FirstOrDefault(s => s.Name == ".rsrc");
            if (rsrcSection != null && rsrcSection.Entropy > HIGH_ENTROPY_THRESHOLD)
            {
                result.SuspiciousIndicators.Add($"Resource section has high entropy ({rsrcSection.Entropy:F2}) - may contain encrypted payload");
            }

            // Check for suspicious strings
            var textContent = Encoding.ASCII.GetString(content);

            var suspiciousStrings = new[]
            {
                ("powershell", "PowerShell execution capability"),
                ("cmd.exe /c", "Command execution capability"),
                ("-enc ", "Encoded PowerShell command"),
                ("Invoke-Expression", "PowerShell code execution"),
                ("DownloadString", "Remote file download"),
                ("WebClient", ".NET download capability"),
                ("Hidden", "Hidden window execution"),
                ("bypass", "Security bypass attempt"),
                ("amsi", "AMSI bypass attempt"),
                ("defender", "Windows Defender manipulation"),
                ("/c whoami", "System reconnaissance"),
                ("net user", "User enumeration"),
                ("mimikatz", "Credential theft tool"),
                ("lsass", "Credential theft target"),
            };

            foreach (var (pattern, description) in suspiciousStrings)
            {
                if (textContent.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                {
                    result.SuspiciousStrings.Add(pattern);
                    result.SuspiciousIndicators.Add($"Suspicious string found: {pattern} ({description})");
                }
            }

            // Check for embedded executables
            var mzCount = 0;
            for (var i = 0; i < content.Length - 1; i++)
            {
                if (content[i] == 0x4D && content[i + 1] == 0x5A) // "MZ"
                {
                    mzCount++;
                }
            }

            if (mzCount > 1)
            {
                result.SuspiciousIndicators.Add($"Multiple embedded executables detected ({mzCount} MZ headers)");
                result.HasEmbeddedExecutable = true;
            }

            // Check for overlay data (data after PE)
            var lastSection = result.Sections.OrderByDescending(s => s.RawDataPointer + s.RawDataSize).FirstOrDefault();
            if (lastSection != null)
            {
                var peEndOffset = lastSection.RawDataPointer + lastSection.RawDataSize;
                if (content.Length > peEndOffset + 1024) // More than 1KB of overlay
                {
                    result.HasOverlay = true;
                    result.OverlaySize = content.Length - (int)peEndOffset;
                    result.SuspiciousIndicators.Add($"Large overlay data detected ({result.OverlaySize} bytes) - may contain payload");
                }
            }
        }

        private void CalculateThreatScore(PEAnalysisResult result)
        {
            var score = 0;

            // Base scoring
            if (result.IsPacked) score += 15;
            if (result.IsObfuscated) score += 10;
            if (result.HasEmbeddedExecutable) score += 25;
            if (result.HasOverlay && result.OverlaySize > 10000) score += 15;

            // Entropy scoring
            if (result.OverallEntropy > PACKED_ENTROPY_THRESHOLD) score += 20;
            else if (result.OverallEntropy > HIGH_ENTROPY_THRESHOLD) score += 10;

            // Section scoring
            score += result.Sections.Count(s => s.IsSuspicious) * 15;
            score += result.Sections.Count(s => s.IsHighEntropy) * 10;

            // Import scoring
            score += Math.Min(result.SuspiciousImports.Count * 5, 30);

            // Technique scoring
            if (result.DetectedTechniques.Contains("Process Injection")) score += 30;
            if (result.DetectedTechniques.Contains("Keylogging")) score += 25;
            if (result.DetectedTechniques.Contains("Ransomware")) score += 40;
            if (result.DetectedTechniques.Contains("Anti-Debug")) score += 10;

            // Suspicious strings/indicators
            score += Math.Min(result.SuspiciousIndicators.Count * 3, 25);
            score += Math.Min(result.SuspiciousStrings.Count * 5, 20);

            result.ThreatScore = Math.Min(score, 100);

            // Determine threat level
            result.ThreatLevel = result.ThreatScore switch
            {
                >= 80 => PEThreatLevel.Critical,
                >= 60 => PEThreatLevel.High,
                >= 40 => PEThreatLevel.Medium,
                >= 20 => PEThreatLevel.Low,
                _ => PEThreatLevel.Clean
            };
        }

        /// <summary>
        /// Quick analysis for real-time protection (lighter weight)
        /// </summary>
        public async Task<QuickPEResult> QuickAnalyzeAsync(string filePath)
        {
            var result = new QuickPEResult { FilePath = filePath };

            try
            {
                var content = await File.ReadAllBytesAsync(filePath);

                // Check if valid PE
                if (content.Length < 64 || BitConverter.ToUInt16(content, 0) != DOS_SIGNATURE)
                {
                    result.IsValidPE = false;
                    return result;
                }

                result.IsValidPE = true;

                // Quick entropy check
                result.Entropy = CalculateShannonEntropy(content);
                result.IsHighEntropy = result.Entropy > HIGH_ENTROPY_THRESHOLD;

                // Quick packer check
                var text = Encoding.ASCII.GetString(content, 0, Math.Min(content.Length, 4096));
                result.IsPacked = text.Contains("UPX") || text.Contains("ASPack") ||
                                 text.Contains("Themida") || text.Contains("VMProtect");

                // Quick threat assessment
                result.IsSuspicious = result.IsHighEntropy || result.IsPacked;
            }
            catch
            {
                result.IsValidPE = false;
            }

            return result;
        }
    }

    #region Result Classes

    public enum PEThreatLevel
    {
        Clean,
        Low,
        Medium,
        High,
        Critical
    }

    public class PEAnalysisResult
    {
        public string FilePath { get; set; } = string.Empty;
        public bool IsValid { get; set; }
        public string? ErrorMessage { get; set; }

        // Basic PE info
        public long FileSize { get; set; }
        public int PEHeaderOffset { get; set; }
        public bool Is64Bit { get; set; }
        public bool IsDotNet { get; set; }
        public ushort Machine { get; set; }
        public string MachineType { get; set; } = string.Empty;
        public ushort NumberOfSections { get; set; }
        public uint TimeDateStamp { get; set; }
        public DateTime CompileTime { get; set; }
        public ushort Characteristics { get; set; }
        public ulong ImageBase { get; set; }
        public uint EntryPoint { get; set; }
        public ushort Subsystem { get; set; }
        public string SubsystemName { get; set; } = string.Empty;

        // Analysis results
        public List<PESection> Sections { get; set; } = new();
        public double OverallEntropy { get; set; }
        public bool IsPacked { get; set; }
        public string? PackerName { get; set; }
        public bool IsObfuscated { get; set; }
        public string? ObfuscatorName { get; set; }
        public bool HasEmbeddedExecutable { get; set; }
        public bool HasOverlay { get; set; }
        public int OverlaySize { get; set; }

        // Suspicious indicators
        public List<string> SuspiciousImports { get; set; } = new();
        public Dictionary<string, string> ImportCategories { get; set; } = new();
        public List<string> SuspiciousIndicators { get; set; } = new();
        public List<string> SuspiciousStrings { get; set; } = new();
        public List<string> DetectedTechniques { get; set; } = new();

        // Threat assessment
        public int ThreatScore { get; set; }
        public PEThreatLevel ThreatLevel { get; set; }
    }

    public class PESection
    {
        public string Name { get; set; } = string.Empty;
        public uint VirtualSize { get; set; }
        public uint VirtualAddress { get; set; }
        public uint RawDataSize { get; set; }
        public uint RawDataPointer { get; set; }
        public uint Characteristics { get; set; }
        public double Entropy { get; set; }
        public bool IsSuspicious { get; set; }
        public bool IsHighEntropy { get; set; }
    }

    public class QuickPEResult
    {
        public string FilePath { get; set; } = string.Empty;
        public bool IsValidPE { get; set; }
        public double Entropy { get; set; }
        public bool IsHighEntropy { get; set; }
        public bool IsPacked { get; set; }
        public bool IsSuspicious { get; set; }
    }

    #endregion
}
