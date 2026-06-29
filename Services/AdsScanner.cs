using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;

namespace SkidrowKiller.Services
{
    /// <summary>
    /// Detects NTFS Alternate Data Streams (ADS) and reads the Mark-of-the-Web (Zone.Identifier).
    ///
    /// ADS is a classic Windows hiding technique: an innocent-looking file (report.pdf) can carry a
    /// second hidden executable behind it (report.pdf:payload.exe) that most tools never look at.
    /// The Zone.Identifier stream tells us whether a file was downloaded from the internet, which
    /// (combined with unsigned/executable) is a strong "treat this with suspicion" signal.
    /// </summary>
    public static class AdsScanner
    {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct WIN32_FIND_STREAM_DATA
        {
            public long StreamSize;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 296)]
            public string cStreamName;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr FindFirstStreamW(string lpFileName, int infoLevel,
            out WIN32_FIND_STREAM_DATA lpFindStreamData, int dwFlags);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool FindNextStreamW(IntPtr hFindStream, out WIN32_FIND_STREAM_DATA lpFindStreamData);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool FindClose(IntPtr handle);

        private static readonly IntPtr InvalidHandle = new(-1);
        private const int FindStreamInfoStandard = 0;

        private static readonly string[] ExecutableExtensions =
            { ".exe", ".dll", ".scr", ".com", ".sys", ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".msi" };

        public class AdsStream
        {
            public string Name { get; set; } = "";   // logical stream name, e.g. "payload.exe"
            public long Size { get; set; }
            public bool IsExecutableLike { get; set; }
        }

        public class AdsResult
        {
            public List<AdsStream> Streams { get; } = new();
            public bool DownloadedFromInternet { get; set; }
            public string? ReferrerUrl { get; set; }
            public bool HasHiddenExecutableStream => Streams.Any(s => s.IsExecutableLike);
        }

        /// <summary>Enumerate non-default streams on a file and read its Mark-of-the-Web, if any.</summary>
        public static AdsResult ScanFile(string filePath)
        {
            var result = new AdsResult();
            if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath)) return result;

            IntPtr handle = InvalidHandle;
            try
            {
                handle = FindFirstStreamW(filePath, FindStreamInfoStandard, out var data, 0);
                if (handle == InvalidHandle) return result;

                do
                {
                    // cStreamName looks like ":streamName:$DATA"; "::$DATA" is the normal file content.
                    var raw = data.cStreamName ?? "";
                    if (raw == "::$DATA" || string.IsNullOrEmpty(raw)) continue;

                    var logical = raw.Trim(':');
                    var dataIdx = logical.IndexOf(":$DATA", StringComparison.OrdinalIgnoreCase);
                    if (dataIdx >= 0) logical = logical[..dataIdx];
                    if (string.IsNullOrEmpty(logical)) continue;

                    if (logical.Equals("Zone.Identifier", StringComparison.OrdinalIgnoreCase))
                    {
                        ReadZoneIdentifier(filePath, result);
                        continue; // Zone.Identifier itself is benign metadata
                    }

                    var execLike = ExecutableExtensions.Any(e => logical.EndsWith(e, StringComparison.OrdinalIgnoreCase))
                                   || data.StreamSize > 4096; // sizeable hidden stream is itself suspicious
                    result.Streams.Add(new AdsStream
                    {
                        Name = logical,
                        Size = data.StreamSize,
                        IsExecutableLike = execLike
                    });
                }
                while (FindNextStreamW(handle, out data));
            }
            catch
            {
                // ADS unsupported (non-NTFS) or access denied → just return what we have.
            }
            finally
            {
                if (handle != InvalidHandle) FindClose(handle);
            }

            return result;
        }

        private static void ReadZoneIdentifier(string filePath, AdsResult result)
        {
            try
            {
                using var fs = new FileStream(filePath + ":Zone.Identifier", FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var reader = new StreamReader(fs);
                string? line;
                while ((line = reader.ReadLine()) != null)
                {
                    var t = line.Trim();
                    if (t.StartsWith("ZoneId=", StringComparison.OrdinalIgnoreCase))
                    {
                        if (int.TryParse(t.AsSpan(7), out var zone))
                            result.DownloadedFromInternet = zone >= 3; // 3 = Internet, 4 = Untrusted
                    }
                    else if (t.StartsWith("ReferrerUrl=", StringComparison.OrdinalIgnoreCase))
                    {
                        result.ReferrerUrl = t[12..];
                    }
                    else if (t.StartsWith("HostUrl=", StringComparison.OrdinalIgnoreCase) && string.IsNullOrEmpty(result.ReferrerUrl))
                    {
                        result.ReferrerUrl = t[8..];
                    }
                }
            }
            catch { /* no readable Zone.Identifier */ }
        }
    }
}
