using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SkidrowKiller.Models;

namespace SkidrowKiller.Services
{
    /// <summary>
    /// Scan Report Service - Generates and exports scan reports in various formats.
    /// Supports HTML, PDF (via HTML print), TXT, CSV, and JSON formats.
    /// </summary>
    public class ScanReportService
    {
        private readonly string _reportsFolder;

        public event EventHandler<string>? LogAdded;

        public ScanReportService()
        {
            _reportsFolder = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "SkidrowKiller",
                "Reports"
            );

            if (!Directory.Exists(_reportsFolder))
            {
                Directory.CreateDirectory(_reportsFolder);
            }
        }

        public async Task<string> GenerateReportAsync(ScanReportData data, ReportFormat format)
        {
            var fileName = $"ScanReport_{DateTime.Now:yyyyMMdd_HHmmss}";
            var extension = format switch
            {
                ReportFormat.Html => ".html",
                ReportFormat.Text => ".txt",
                ReportFormat.Csv => ".csv",
                ReportFormat.Json => ".json",
                _ => ".html"
            };

            var filePath = Path.Combine(_reportsFolder, fileName + extension);

            var content = format switch
            {
                ReportFormat.Html => GenerateHtmlReport(data),
                ReportFormat.Text => GenerateTextReport(data),
                ReportFormat.Csv => GenerateCsvReport(data),
                ReportFormat.Json => GenerateJsonReport(data),
                _ => GenerateHtmlReport(data)
            };

            await File.WriteAllTextAsync(filePath, content);
            RaiseLog($"📄 Report generated: {filePath}");

            return filePath;
        }

        public string GetReportsFolder() => _reportsFolder;

        public List<string> GetSavedReports()
        {
            return Directory.GetFiles(_reportsFolder)
                .OrderByDescending(f => File.GetCreationTime(f))
                .ToList();
        }

        #region HTML Report

        private string GenerateHtmlReport(ScanReportData data)
        {
            var sb = new StringBuilder();

            sb.AppendLine("<!DOCTYPE html>");
            sb.AppendLine("<html lang='en'>");
            sb.AppendLine("<head>");
            sb.AppendLine("  <meta charset='UTF-8'>");
            sb.AppendLine("  <meta name='viewport' content='width=device-width, initial-scale=1.0'>");
            sb.AppendLine($"  <title>Scan Report - {data.ScanDate:yyyy-MM-dd}</title>");
            sb.AppendLine("  <style>");
            sb.AppendLine(GetCssStyles());
            sb.AppendLine("  </style>");
            sb.AppendLine("</head>");
            sb.AppendLine("<body>");

            // Header
            sb.AppendLine("  <div class='header'>");
            sb.AppendLine("    <div class='logo'>🛡️ Skidrow Killer</div>");
            sb.AppendLine("    <div class='title'>Security Scan Report</div>");
            sb.AppendLine($"    <div class='date'>{data.ScanDate:dddd, MMMM d, yyyy 'at' h:mm tt}</div>");
            sb.AppendLine("  </div>");

            // Summary
            sb.AppendLine("  <div class='summary'>");
            sb.AppendLine("    <h2>Scan Summary</h2>");
            sb.AppendLine("    <div class='summary-grid'>");
            sb.AppendLine($"      <div class='summary-item'><span class='label'>Scan Type</span><span class='value'>{data.ScanType}</span></div>");
            sb.AppendLine($"      <div class='summary-item'><span class='label'>Duration</span><span class='value'>{data.Duration:hh\\:mm\\:ss}</span></div>");
            sb.AppendLine($"      <div class='summary-item'><span class='label'>Items Scanned</span><span class='value'>{data.ItemsScanned:N0}</span></div>");
            sb.AppendLine($"      <div class='summary-item {(data.ThreatsFound > 0 ? "danger" : "safe")}'><span class='label'>Threats Found</span><span class='value'>{data.ThreatsFound}</span></div>");
            sb.AppendLine($"      <div class='summary-item'><span class='label'>Threats Removed</span><span class='value'>{data.ThreatsRemoved}</span></div>");
            sb.AppendLine($"      <div class='summary-item'><span class='label'>Threats Quarantined</span><span class='value'>{data.ThreatsQuarantined}</span></div>");
            sb.AppendLine("    </div>");
            sb.AppendLine("  </div>");

            // Status
            var statusClass = data.ThreatsFound == 0 ? "safe" : (data.ThreatsRemoved == data.ThreatsFound ? "warning" : "danger");
            var statusIcon = data.ThreatsFound == 0 ? "✅" : (data.ThreatsRemoved == data.ThreatsFound ? "⚠️" : "🚨");
            var statusText = data.ThreatsFound == 0 ? "Your system is clean!" :
                (data.ThreatsRemoved == data.ThreatsFound ? "All threats have been handled." : "Some threats require attention!");

            sb.AppendLine($"  <div class='status {statusClass}'>");
            sb.AppendLine($"    <span class='icon'>{statusIcon}</span>");
            sb.AppendLine($"    <span class='text'>{statusText}</span>");
            sb.AppendLine("  </div>");

            // Threats List
            if (data.Threats.Count > 0)
            {
                sb.AppendLine("  <div class='threats'>");
                sb.AppendLine("    <h2>Detected Threats</h2>");
                sb.AppendLine("    <table>");
                sb.AppendLine("      <thead>");
                sb.AppendLine("        <tr>");
                sb.AppendLine("          <th>Severity</th>");
                sb.AppendLine("          <th>Name</th>");
                sb.AppendLine("          <th>Type</th>");
                sb.AppendLine("          <th>Location</th>");
                sb.AppendLine("          <th>Status</th>");
                sb.AppendLine("        </tr>");
                sb.AppendLine("      </thead>");
                sb.AppendLine("      <tbody>");

                foreach (var threat in data.Threats.OrderByDescending(t => t.Severity))
                {
                    var severityClass = threat.Severity switch
                    {
                        ThreatSeverity.Critical => "critical",
                        ThreatSeverity.High => "high",
                        ThreatSeverity.Medium => "medium",
                        _ => "low"
                    };

                    var status = threat.IsBackedUp ? "Quarantined" : "Detected";

                    sb.AppendLine("        <tr>");
                    sb.AppendLine($"          <td class='severity {severityClass}'>{threat.Severity}</td>");
                    sb.AppendLine($"          <td class='name'>{EscapeHtml(threat.Name)}</td>");
                    sb.AppendLine($"          <td>{threat.Type}</td>");
                    sb.AppendLine($"          <td class='location' title='{EscapeHtml(threat.Path)}'>{TruncatePath(threat.Path)}</td>");
                    sb.AppendLine($"          <td class='{(threat.IsBackedUp ? "removed" : "pending")}'>{status}</td>");
                    sb.AppendLine("        </tr>");
                }

                sb.AppendLine("      </tbody>");
                sb.AppendLine("    </table>");
                sb.AppendLine("  </div>");
            }

            // Scanned Paths
            if (data.ScannedPaths.Count > 0)
            {
                sb.AppendLine("  <div class='paths'>");
                sb.AppendLine("    <h2>Scanned Locations</h2>");
                sb.AppendLine("    <ul>");
                foreach (var path in data.ScannedPaths)
                {
                    sb.AppendLine($"      <li>{EscapeHtml(path)}</li>");
                }
                sb.AppendLine("    </ul>");
                sb.AppendLine("  </div>");
            }

            // Footer
            sb.AppendLine("  <div class='footer'>");
            sb.AppendLine($"    <p>Report generated by Skidrow Killer v{data.AppVersion}</p>");
            sb.AppendLine($"    <p>Computer: {Environment.MachineName} | User: {Environment.UserName}</p>");
            sb.AppendLine("  </div>");

            sb.AppendLine("</body>");
            sb.AppendLine("</html>");

            return sb.ToString();
        }

        private string GetCssStyles()
        {
            return @"
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0d1117; color: #c9d1d9; padding: 40px; }
        .header { text-align: center; margin-bottom: 40px; padding: 30px; background: linear-gradient(135deg, #161b22, #21262d); border-radius: 16px; border: 1px solid #30363d; }
        .logo { font-size: 48px; margin-bottom: 10px; }
        .title { font-size: 28px; font-weight: bold; color: #58a6ff; }
        .date { color: #8b949e; margin-top: 10px; }
        .summary { background: #161b22; border-radius: 12px; padding: 24px; margin-bottom: 24px; border: 1px solid #30363d; }
        .summary h2 { color: #58a6ff; margin-bottom: 20px; }
        .summary-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; }
        .summary-item { background: #21262d; padding: 16px; border-radius: 8px; text-align: center; }
        .summary-item .label { display: block; color: #8b949e; font-size: 12px; text-transform: uppercase; margin-bottom: 8px; }
        .summary-item .value { font-size: 24px; font-weight: bold; color: #c9d1d9; }
        .summary-item.safe .value { color: #3fb950; }
        .summary-item.danger .value { color: #f85149; }
        .status { padding: 20px; border-radius: 12px; text-align: center; margin-bottom: 24px; display: flex; align-items: center; justify-content: center; gap: 12px; }
        .status.safe { background: rgba(63, 185, 80, 0.1); border: 1px solid #3fb950; }
        .status.warning { background: rgba(210, 153, 34, 0.1); border: 1px solid #d29922; }
        .status.danger { background: rgba(248, 81, 73, 0.1); border: 1px solid #f85149; }
        .status .icon { font-size: 32px; }
        .status .text { font-size: 18px; font-weight: 500; }
        .threats { background: #161b22; border-radius: 12px; padding: 24px; margin-bottom: 24px; border: 1px solid #30363d; }
        .threats h2 { color: #f85149; margin-bottom: 20px; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #30363d; }
        th { background: #21262d; color: #8b949e; font-size: 12px; text-transform: uppercase; }
        .severity { font-weight: bold; border-radius: 4px; padding: 4px 8px; text-align: center; }
        .severity.critical { background: #f85149; color: white; }
        .severity.high { background: #da3633; color: white; }
        .severity.medium { background: #d29922; color: white; }
        .severity.low { background: #3fb950; color: white; }
        .name { font-weight: 500; }
        .location { font-family: monospace; font-size: 12px; color: #8b949e; max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .removed { color: #3fb950; }
        .pending { color: #d29922; }
        .paths { background: #161b22; border-radius: 12px; padding: 24px; margin-bottom: 24px; border: 1px solid #30363d; }
        .paths h2 { color: #58a6ff; margin-bottom: 16px; }
        .paths ul { list-style: none; }
        .paths li { padding: 8px; font-family: monospace; font-size: 13px; color: #8b949e; border-bottom: 1px solid #21262d; }
        .footer { text-align: center; padding: 24px; color: #8b949e; font-size: 12px; }
        @media print { body { background: white; color: black; } .header { background: #f5f5f5; } }
            ";
        }

        private string EscapeHtml(string text)
        {
            return text
                .Replace("&", "&amp;")
                .Replace("<", "&lt;")
                .Replace(">", "&gt;")
                .Replace("\"", "&quot;")
                .Replace("'", "&#39;");
        }

        private string TruncatePath(string path)
        {
            if (path.Length <= 50) return path;
            return "..." + path.Substring(path.Length - 47);
        }

        #endregion

        #region Text Report

        private string GenerateTextReport(ScanReportData data)
        {
            var sb = new StringBuilder();
            var separator = new string('=', 70);
            var line = new string('-', 70);

            sb.AppendLine(separator);
            sb.AppendLine("                    SKIDROW KILLER SCAN REPORT");
            sb.AppendLine(separator);
            sb.AppendLine();
            sb.AppendLine($"  Scan Date:        {data.ScanDate:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine($"  Scan Type:        {data.ScanType}");
            sb.AppendLine($"  Duration:         {data.Duration:hh\\:mm\\:ss}");
            sb.AppendLine($"  Computer:         {Environment.MachineName}");
            sb.AppendLine($"  User:             {Environment.UserName}");
            sb.AppendLine();
            sb.AppendLine(line);
            sb.AppendLine("  SUMMARY");
            sb.AppendLine(line);
            sb.AppendLine();
            sb.AppendLine($"  Items Scanned:      {data.ItemsScanned:N0}");
            sb.AppendLine($"  Threats Found:      {data.ThreatsFound}");
            sb.AppendLine($"  Threats Removed:    {data.ThreatsRemoved}");
            sb.AppendLine($"  Threats Quarantined:{data.ThreatsQuarantined}");
            sb.AppendLine();

            if (data.ThreatsFound == 0)
            {
                sb.AppendLine("  [OK] Your system is clean! No threats detected.");
            }
            else
            {
                sb.AppendLine(line);
                sb.AppendLine("  DETECTED THREATS");
                sb.AppendLine(line);
                sb.AppendLine();

                foreach (var threat in data.Threats.OrderByDescending(t => t.Severity))
                {
                    var status = threat.IsBackedUp ? "Quarantined" : "Detected";
                    sb.AppendLine($"  [{threat.Severity}] {threat.Name}");
                    sb.AppendLine($"    Type:     {threat.Type}");
                    sb.AppendLine($"    Location: {threat.Path}");
                    sb.AppendLine($"    Status:   {status}");
                    sb.AppendLine();
                }
            }

            if (data.ScannedPaths.Count > 0)
            {
                sb.AppendLine(line);
                sb.AppendLine("  SCANNED LOCATIONS");
                sb.AppendLine(line);
                sb.AppendLine();
                foreach (var path in data.ScannedPaths)
                {
                    sb.AppendLine($"  - {path}");
                }
                sb.AppendLine();
            }

            sb.AppendLine(separator);
            sb.AppendLine($"  Report generated by Skidrow Killer v{data.AppVersion}");
            sb.AppendLine(separator);

            return sb.ToString();
        }

        #endregion

        #region CSV Report

        private string GenerateCsvReport(ScanReportData data)
        {
            var sb = new StringBuilder();

            // Header
            sb.AppendLine("Severity,Name,Type,Location,Status,Score,DetectionDate");

            // Data rows
            foreach (var threat in data.Threats)
            {
                var status = threat.IsBackedUp ? "Quarantined" : "Detected";
                sb.AppendLine($"\"{threat.Severity}\",\"{EscapeCsv(threat.Name)}\",\"{threat.Type}\",\"{EscapeCsv(threat.Path)}\",\"{status}\",{threat.Score},\"{data.ScanDate:yyyy-MM-dd HH:mm:ss}\"");
            }

            return sb.ToString();
        }

        private string EscapeCsv(string text)
        {
            return text.Replace("\"", "\"\"");
        }

        #endregion

        #region JSON Report

        private string GenerateJsonReport(ScanReportData data)
        {
            var report = new
            {
                reportInfo = new
                {
                    generatedAt = data.ScanDate,
                    appVersion = data.AppVersion,
                    computer = Environment.MachineName,
                    user = Environment.UserName
                },
                scanSummary = new
                {
                    scanType = data.ScanType,
                    duration = data.Duration.ToString(),
                    itemsScanned = data.ItemsScanned,
                    threatsFound = data.ThreatsFound,
                    threatsRemoved = data.ThreatsRemoved,
                    threatsQuarantined = data.ThreatsQuarantined
                },
                threats = data.Threats.Select(t => new
                {
                    severity = t.Severity.ToString(),
                    name = t.Name,
                    type = t.Type.ToString(),
                    location = t.Path,
                    status = t.IsBackedUp ? "Quarantined" : "Detected",
                    score = t.Score,
                    matchedPatterns = t.MatchedPatterns
                }),
                scannedPaths = data.ScannedPaths
            };

            return System.Text.Json.JsonSerializer.Serialize(report, new System.Text.Json.JsonSerializerOptions
            {
                WriteIndented = true
            });
        }

        #endregion

        private void RaiseLog(string message)
        {
            LogAdded?.Invoke(this, message);
        }
    }

    public class ScanReportData
    {
        public DateTime ScanDate { get; set; } = DateTime.Now;
        public string ScanType { get; set; } = "Quick Scan";
        public TimeSpan Duration { get; set; }
        public int ItemsScanned { get; set; }
        public int ThreatsFound => Threats.Count;
        public int ThreatsRemoved { get; set; }
        public int ThreatsQuarantined { get; set; }
        public List<ThreatInfo> Threats { get; set; } = new();
        public List<string> ScannedPaths { get; set; } = new();
        public string AppVersion { get; set; } = "3.3.0";
    }

    public enum ReportFormat
    {
        Html,
        Text,
        Csv,
        Json
    }
}
