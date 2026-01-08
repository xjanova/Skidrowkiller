using System;
using System.IO;
using System.Text;

namespace SkidrowKiller
{
    public class LogWriter : IDisposable
    {
        private readonly string logFilePath;
        private readonly StreamWriter? writer;
        private readonly object lockObject = new object();
        private bool disposed = false;

        public string LogFilePath => logFilePath;

        public LogWriter()
        {
            string logDirectory = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                "SkidrowKiller",
                "Logs"
            );

            Directory.CreateDirectory(logDirectory);

            string timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
            logFilePath = Path.Combine(logDirectory, $"scan_{timestamp}.log");

            try
            {
                writer = new StreamWriter(logFilePath, append: false, Encoding.UTF8)
                {
                    AutoFlush = true
                };

                WriteHeader();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to create log file: {ex.Message}");
            }
        }

        private void WriteHeader()
        {
            if (writer == null) return;

            lock (lockObject)
            {
                writer.WriteLine("================================================================================");
                writer.WriteLine("                    SKIDROW KILLER - MALWARE SCAN LOG");
                writer.WriteLine("================================================================================");
                writer.WriteLine($"Scan Started: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
                writer.WriteLine($"Machine Name: {Environment.MachineName}");
                writer.WriteLine($"User Name: {Environment.UserName}");
                writer.WriteLine($"OS Version: {Environment.OSVersion}");
                writer.WriteLine($"Is 64-bit OS: {Environment.Is64BitOperatingSystem}");
                writer.WriteLine("================================================================================");
                writer.WriteLine();
            }
        }

        public void WriteLine(string message)
        {
            if (writer == null || disposed) return;

            lock (lockObject)
            {
                try
                {
                    writer.WriteLine($"[{DateTime.Now:HH:mm:ss}] {message}");
                }
                catch
                {
                    // Silently fail if unable to write
                }
            }
        }

        public void WriteSection(string sectionName)
        {
            if (writer == null || disposed) return;

            lock (lockObject)
            {
                try
                {
                    writer.WriteLine();
                    writer.WriteLine(new string('=', 80));
                    writer.WriteLine($"  {sectionName}");
                    writer.WriteLine(new string('=', 80));
                    writer.WriteLine();
                }
                catch
                {
                    // Silently fail if unable to write
                }
            }
        }

        public void WriteSummary(long totalScanned, int threatsFound, int threatsRemoved, int failed)
        {
            if (writer == null || disposed) return;

            lock (lockObject)
            {
                try
                {
                    writer.WriteLine();
                    writer.WriteLine(new string('=', 80));
                    writer.WriteLine("                           SCAN SUMMARY");
                    writer.WriteLine(new string('=', 80));
                    writer.WriteLine($"Scan Completed: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
                    writer.WriteLine();
                    writer.WriteLine($"Total Items Scanned:     {totalScanned:N0}");
                    writer.WriteLine($"Threats Found:           {threatsFound}");
                    writer.WriteLine($"Threats Removed/Killed:  {threatsRemoved}");
                    writer.WriteLine($"Failed to Remove/Kill:   {failed}");
                    writer.WriteLine(new string('=', 80));
                    writer.WriteLine();
                    writer.WriteLine("Log file saved successfully.");
                    writer.WriteLine($"Location: {logFilePath}");
                    writer.WriteLine(new string('=', 80));
                }
                catch
                {
                    // Silently fail if unable to write
                }
            }
        }

        public void Dispose()
        {
            if (disposed) return;

            lock (lockObject)
            {
                try
                {
                    writer?.WriteLine();
                    writer?.WriteLine($"Log closed at: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
                    writer?.Close();
                    writer?.Dispose();
                }
                catch
                {
                    // Silently fail
                }

                disposed = true;
            }
        }
    }
}
