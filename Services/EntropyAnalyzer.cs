using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace SkidrowKiller.Services;

/// <summary>
/// Analyzes file entropy to detect packed, encrypted, or obfuscated malware.
/// High entropy (close to 8.0) often indicates encryption, compression, or packing.
/// </summary>
public class EntropyAnalyzer
{
    private readonly ILogger<EntropyAnalyzer>? _logger;

    // Entropy thresholds
    private const double HighEntropyThreshold = 7.2;
    private const double VeryHighEntropyThreshold = 7.6;
    private const double SuspiciousEntropyThreshold = 6.8;

    // Known packer signatures (magic bytes at specific offsets)
    private static readonly Dictionary<string, (byte[] Signature, int Offset)> PackerSignatures = new()
    {
        // UPX packer
        ["UPX"] = (new byte[] { 0x55, 0x50, 0x58, 0x30 }, 0), // "UPX0"
        ["UPX!"] = (new byte[] { 0x55, 0x50, 0x58, 0x21 }, 0), // "UPX!"

        // ASPack
        ["ASPack"] = (new byte[] { 0x60, 0xE8, 0x03, 0x00, 0x00, 0x00 }, -1),

        // PECompact
        ["PECompact"] = (new byte[] { 0xB8, 0x00, 0x00, 0x00, 0x00, 0x50, 0x64 }, -1),

        // MPRESS
        ["MPRESS"] = (new byte[] { 0x4D, 0x50, 0x52, 0x45, 0x53, 0x53 }, -1),

        // NSPack
        ["NSPack"] = (new byte[] { 0x4E, 0x53, 0x50, 0x61, 0x63, 0x6B }, -1),
    };

    // Section names commonly used by packers
    private static readonly HashSet<string> PackerSectionNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "UPX0", "UPX1", "UPX2", "UPX!",
        ".aspack", ".adata",
        ".MPRESS1", ".MPRESS2",
        ".nsp0", ".nsp1", ".nsp2",
        ".themida", ".winlice",
        ".vmp0", ".vmp1", ".vmp2", // VMProtect
        ".enigma1", ".enigma2",
        ".petite",
        ".packed", ".RLPack",
        "pec1", "pec2", "PECompact2",
        ".spack", ".svkp",
        ".perplex", ".shrink",
    };

    public EntropyAnalyzer(ILogger<EntropyAnalyzer>? logger = null)
    {
        _logger = logger;
    }

    /// <summary>
    /// Calculates Shannon entropy for a byte array
    /// </summary>
    public double CalculateEntropy(byte[] data)
    {
        if (data == null || data.Length == 0)
            return 0;

        // Count frequency of each byte value
        var frequencies = new int[256];
        foreach (byte b in data)
        {
            frequencies[b]++;
        }

        // Calculate entropy using Shannon formula
        double entropy = 0;
        double dataLength = data.Length;

        for (int i = 0; i < 256; i++)
        {
            if (frequencies[i] > 0)
            {
                double probability = frequencies[i] / dataLength;
                entropy -= probability * Math.Log2(probability);
            }
        }

        return entropy;
    }

    /// <summary>
    /// Analyzes a file for entropy-based indicators of packing/encryption
    /// </summary>
    public async Task<EntropyAnalysisResult> AnalyzeFileAsync(string filePath)
    {
        var result = new EntropyAnalysisResult
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
            result.FileSize = fileInfo.Length;

            // Skip very large files
            if (fileInfo.Length > 100 * 1024 * 1024) // 100MB
            {
                result.Error = "File too large for entropy analysis";
                return result;
            }

            byte[] fileData;
            try
            {
                fileData = await File.ReadAllBytesAsync(filePath);
            }
            catch (Exception ex)
            {
                result.Error = $"Cannot read file: {ex.Message}";
                return result;
            }

            // Calculate overall entropy
            result.OverallEntropy = CalculateEntropy(fileData);

            // Check if it's a PE file
            if (fileData.Length > 64 && fileData[0] == 0x4D && fileData[1] == 0x5A)
            {
                result.IsPEFile = true;
                await AnalyzePEFileAsync(fileData, result);
            }
            else
            {
                // Analyze as generic file
                AnalyzeGenericFile(fileData, result);
            }

            // Check for known packer signatures
            CheckPackerSignatures(fileData, result);

            // Calculate threat score based on findings
            result.ThreatScore = CalculateThreatScore(result);
            result.IsSuspicious = result.ThreatScore >= 30;
            result.IsLikelyPacked = result.IsPacked || result.OverallEntropy >= HighEntropyThreshold;

            _logger?.LogDebug("Entropy analysis of {FilePath}: Overall={Entropy:F2}, Score={Score}",
                filePath, result.OverallEntropy, result.ThreatScore);
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Error analyzing file entropy: {FilePath}", filePath);
            result.Error = ex.Message;
        }

        return result;
    }

    private async Task AnalyzePEFileAsync(byte[] data, EntropyAnalysisResult result)
    {
        try
        {
            // Get PE header offset
            if (data.Length < 64) return;

            int peOffset = BitConverter.ToInt32(data, 0x3C);
            if (peOffset < 0 || peOffset + 24 >= data.Length) return;

            // Verify PE signature
            if (data[peOffset] != 0x50 || data[peOffset + 1] != 0x45) return;

            // Get number of sections
            int numberOfSections = BitConverter.ToUInt16(data, peOffset + 6);
            int optionalHeaderSize = BitConverter.ToUInt16(data, peOffset + 20);
            int sectionTableOffset = peOffset + 24 + optionalHeaderSize;

            // Analyze each section
            for (int i = 0; i < numberOfSections; i++)
            {
                int sectionOffset = sectionTableOffset + (i * 40);
                if (sectionOffset + 40 > data.Length) break;

                var sectionInfo = new PESectionInfo();

                // Get section name (8 bytes, null-padded)
                byte[] nameBytes = new byte[8];
                Array.Copy(data, sectionOffset, nameBytes, 0, 8);
                sectionInfo.Name = System.Text.Encoding.ASCII.GetString(nameBytes).TrimEnd('\0');

                // Get section info
                sectionInfo.VirtualSize = BitConverter.ToUInt32(data, sectionOffset + 8);
                sectionInfo.VirtualAddress = BitConverter.ToUInt32(data, sectionOffset + 12);
                sectionInfo.RawSize = BitConverter.ToUInt32(data, sectionOffset + 16);
                sectionInfo.RawOffset = BitConverter.ToUInt32(data, sectionOffset + 20);
                sectionInfo.Characteristics = BitConverter.ToUInt32(data, sectionOffset + 36);

                // Calculate section entropy
                if (sectionInfo.RawSize > 0 && sectionInfo.RawOffset + sectionInfo.RawSize <= data.Length)
                {
                    byte[] sectionData = new byte[sectionInfo.RawSize];
                    Array.Copy(data, (int)sectionInfo.RawOffset, sectionData, 0, (int)sectionInfo.RawSize);
                    sectionInfo.Entropy = CalculateEntropy(sectionData);
                }

                // Check for executable sections with high entropy
                bool isExecutable = (sectionInfo.Characteristics & 0x20000000) != 0 || // IMAGE_SCN_MEM_EXECUTE
                                   (sectionInfo.Characteristics & 0x00000020) != 0;    // IMAGE_SCN_CNT_CODE

                if (isExecutable && sectionInfo.Entropy >= HighEntropyThreshold)
                {
                    result.HighEntropySections.Add(sectionInfo.Name);
                    result.Indicators.Add($"Executable section '{sectionInfo.Name}' has high entropy ({sectionInfo.Entropy:F2})");
                }

                // Check for packer section names
                if (PackerSectionNames.Contains(sectionInfo.Name))
                {
                    result.IsPacked = true;
                    result.PackerName = GetPackerFromSectionName(sectionInfo.Name);
                    result.Indicators.Add($"Packer section detected: {sectionInfo.Name}");
                }

                result.Sections.Add(sectionInfo);
            }

            // Calculate code-to-data ratio
            var executableSections = result.Sections.Where(s =>
                (s.Characteristics & 0x20000000) != 0 || (s.Characteristics & 0x00000020) != 0).ToList();

            if (executableSections.Any())
            {
                double avgCodeEntropy = executableSections.Average(s => s.Entropy);
                result.AverageCodeEntropy = avgCodeEntropy;

                if (avgCodeEntropy >= VeryHighEntropyThreshold)
                {
                    result.Indicators.Add($"Very high average code entropy: {avgCodeEntropy:F2}");
                }
            }

            // Check for anomalies
            CheckPEAnomalies(data, result);
        }
        catch (Exception ex)
        {
            result.Indicators.Add($"PE analysis error: {ex.Message}");
        }

        await Task.CompletedTask;
    }

    private void AnalyzeGenericFile(byte[] data, EntropyAnalysisResult result)
    {
        // Analyze entropy distribution across the file
        int chunkSize = Math.Max(1024, data.Length / 10);
        var chunkEntropies = new List<double>();

        for (int i = 0; i < data.Length; i += chunkSize)
        {
            int size = Math.Min(chunkSize, data.Length - i);
            byte[] chunk = new byte[size];
            Array.Copy(data, i, chunk, 0, size);
            chunkEntropies.Add(CalculateEntropy(chunk));
        }

        if (chunkEntropies.Count > 0)
        {
            result.AverageCodeEntropy = chunkEntropies.Average();

            // Check for uniform high entropy (typical of encryption)
            if (chunkEntropies.All(e => e >= HighEntropyThreshold))
            {
                result.Indicators.Add("Uniformly high entropy throughout file (possible encryption)");
            }

            // Check for entropy anomalies (drops/spikes)
            if (chunkEntropies.Max() - chunkEntropies.Min() > 2.0)
            {
                result.Indicators.Add("Significant entropy variation (possible embedded data)");
            }
        }
    }

    private void CheckPackerSignatures(byte[] data, EntropyAnalysisResult result)
    {
        // Search for packer signatures in the file
        foreach (var (packerName, (signature, offset)) in PackerSignatures)
        {
            if (offset >= 0)
            {
                // Check at specific offset
                if (offset + signature.Length <= data.Length)
                {
                    bool match = true;
                    for (int i = 0; i < signature.Length && match; i++)
                    {
                        if (data[offset + i] != signature[i])
                            match = false;
                    }
                    if (match)
                    {
                        result.IsPacked = true;
                        result.PackerName = packerName;
                        result.Indicators.Add($"Packer signature found: {packerName}");
                        return;
                    }
                }
            }
            else
            {
                // Search anywhere in the first 10KB
                int searchLimit = Math.Min(10240, data.Length - signature.Length);
                for (int i = 0; i < searchLimit; i++)
                {
                    bool match = true;
                    for (int j = 0; j < signature.Length && match; j++)
                    {
                        if (data[i + j] != signature[j])
                            match = false;
                    }
                    if (match)
                    {
                        result.IsPacked = true;
                        result.PackerName = packerName;
                        result.Indicators.Add($"Packer signature found: {packerName}");
                        return;
                    }
                }
            }
        }

        // Check for common packer strings
        var fileContent = System.Text.Encoding.ASCII.GetString(data);

        var packerStrings = new Dictionary<string, string>
        {
            ["UPX"] = "UPX!",
            ["VMProtect"] = "VMProtect",
            ["Themida"] = "Themida",
            ["Enigma Protector"] = "Enigma protector",
            ["ASPack"] = "ASPack",
            ["PECompact"] = "PECompact",
            ["Armadillo"] = "Armadillo",
            ["ExeCryptor"] = "ExeCryptor",
            ["Obsidium"] = "Obsidium",
        };

        foreach (var (packer, searchString) in packerStrings)
        {
            if (fileContent.Contains(searchString, StringComparison.OrdinalIgnoreCase))
            {
                result.IsPacked = true;
                result.PackerName = packer;
                result.Indicators.Add($"Packer string found: {packer}");
                return;
            }
        }
    }

    private void CheckPEAnomalies(byte[] data, EntropyAnalysisResult result)
    {
        // Check for sections with size of 0 but virtual size > 0 (unpacking stub)
        foreach (var section in result.Sections)
        {
            if (section.RawSize == 0 && section.VirtualSize > 0)
            {
                result.Indicators.Add($"Section '{section.Name}' has no raw data but virtual size {section.VirtualSize}");
            }

            // Check for writable and executable sections (W^X violation)
            bool isWritable = (section.Characteristics & 0x80000000) != 0; // IMAGE_SCN_MEM_WRITE
            bool isExecutable = (section.Characteristics & 0x20000000) != 0; // IMAGE_SCN_MEM_EXECUTE

            if (isWritable && isExecutable)
            {
                result.Indicators.Add($"Section '{section.Name}' is both writable and executable (W^X violation)");
            }
        }

        // Check for very small code sections with high entropy
        var smallHighEntropySections = result.Sections
            .Where(s => s.RawSize < 4096 && s.Entropy >= VeryHighEntropyThreshold)
            .ToList();

        if (smallHighEntropySections.Any())
        {
            result.Indicators.Add($"Small sections with very high entropy detected (possible shellcode)");
        }
    }

    private string GetPackerFromSectionName(string sectionName)
    {
        var name = sectionName.ToLower();
        if (name.StartsWith("upx")) return "UPX";
        if (name.Contains("themida") || name.Contains("winlice")) return "Themida/WinLicense";
        if (name.StartsWith(".vmp")) return "VMProtect";
        if (name.Contains("enigma")) return "Enigma Protector";
        if (name.Contains("aspack") || name.Contains("adata")) return "ASPack";
        if (name.StartsWith(".mpress")) return "MPRESS";
        if (name.StartsWith(".nsp") || name.Contains("nspack")) return "NsPack";
        if (name.Contains("petite")) return "Petite";
        if (name.Contains("pec") || name.Contains("pecompact")) return "PECompact";
        if (name.Contains("rlpack")) return "RLPack";
        if (name.Contains("svkp")) return "SVKProtector";
        return "Unknown Packer";
    }

    private int CalculateThreatScore(EntropyAnalysisResult result)
    {
        int score = 0;

        // Base entropy score
        if (result.OverallEntropy >= VeryHighEntropyThreshold)
            score += 30;
        else if (result.OverallEntropy >= HighEntropyThreshold)
            score += 20;
        else if (result.OverallEntropy >= SuspiciousEntropyThreshold)
            score += 10;

        // Packing detection
        if (result.IsPacked)
        {
            score += 25;

            // Some packers are more suspicious than others
            if (result.PackerName?.Contains("VMProtect") == true ||
                result.PackerName?.Contains("Themida") == true ||
                result.PackerName?.Contains("Enigma") == true)
            {
                score += 15; // Commercial protectors often used by malware
            }
        }

        // High entropy sections
        score += result.HighEntropySections.Count * 10;

        // W^X violations and other anomalies
        score += result.Indicators.Count(i => i.Contains("W^X")) * 15;
        score += result.Indicators.Count(i => i.Contains("shellcode")) * 20;
        score += result.Indicators.Count(i => i.Contains("encryption")) * 10;

        return Math.Min(score, 100);
    }
}

#region Data Models

public class EntropyAnalysisResult
{
    public string FilePath { get; set; } = "";
    public DateTime AnalyzedAt { get; set; }
    public long FileSize { get; set; }
    public string? Error { get; set; }

    public double OverallEntropy { get; set; }
    public double AverageCodeEntropy { get; set; }

    public bool IsPEFile { get; set; }
    public bool IsPacked { get; set; }
    public string? PackerName { get; set; }

    public List<PESectionInfo> Sections { get; set; } = new();
    public List<string> HighEntropySections { get; set; } = new();
    public List<string> Indicators { get; set; } = new();

    public int ThreatScore { get; set; }
    public bool IsSuspicious { get; set; }
    public bool IsLikelyPacked { get; set; }
}

public class PESectionInfo
{
    public string Name { get; set; } = "";
    public uint VirtualSize { get; set; }
    public uint VirtualAddress { get; set; }
    public uint RawSize { get; set; }
    public uint RawOffset { get; set; }
    public uint Characteristics { get; set; }
    public double Entropy { get; set; }
}

#endregion
