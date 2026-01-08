using System.IO;
using Serilog;
using Serilog.Events;

namespace SkidrowKiller.Services
{
    /// <summary>
    /// Centralized logging service using Serilog
    /// </summary>
    public static class LoggingService
    {
        private static bool _isInitialized;
        private static readonly object _lock = new();

        /// <summary>
        /// Initialize the logging service
        /// </summary>
        public static void Initialize()
        {
            if (_isInitialized) return;

            lock (_lock)
            {
                if (_isInitialized) return;

                var settings = AppConfiguration.Settings.Logging;
                var logDirectory = AppConfiguration.GetLogDirectory();

                // Ensure log directory exists
                if (!Directory.Exists(logDirectory))
                {
                    Directory.CreateDirectory(logDirectory);
                }

                var logFilePath = Path.Combine(logDirectory, "skidrowkiller-.log");

                var logConfig = new LoggerConfiguration()
                    .MinimumLevel.Is(ParseLogLevel(settings.MinimumLevel))
                    .Enrich.WithProperty("Application", AppConfiguration.Settings.Application.Name)
                    .Enrich.WithProperty("Version", AppConfiguration.Settings.Application.Version)
                    .Enrich.WithProperty("Environment", AppConfiguration.Settings.Application.Environment);

                // File logging
                if (settings.EnableFileLogging)
                {
                    logConfig.WriteTo.File(
                        logFilePath,
                        rollingInterval: RollingInterval.Day,
                        retainedFileCountLimit: settings.LogRetentionDays,
                        fileSizeLimitBytes: settings.LogFileSizeLimitMB * 1024 * 1024,
                        rollOnFileSizeLimit: true,
                        outputTemplate: "[{Timestamp:yyyy-MM-dd HH:mm:ss.fff}] [{Level:u3}] {Message:lj}{NewLine}{Exception}"
                    );
                }

                // Console logging (for debugging)
                if (settings.EnableConsoleLogging)
                {
                    logConfig.WriteTo.Console(
                        outputTemplate: "[{Timestamp:HH:mm:ss}] [{Level:u3}] {Message:lj}{NewLine}{Exception}"
                    );
                }

                Log.Logger = logConfig.CreateLogger();
                _isInitialized = true;

                Log.Information("Logging service initialized. Environment: {Environment}, Version: {Version}",
                    AppConfiguration.Settings.Application.Environment,
                    AppConfiguration.Settings.Application.Version);
            }
        }

        /// <summary>
        /// Shutdown the logging service and flush pending logs
        /// </summary>
        public static void Shutdown()
        {
            Log.Information("Logging service shutting down");
            Log.CloseAndFlush();
            _isInitialized = false;
        }

        private static LogEventLevel ParseLogLevel(string level)
        {
            return level.ToLower() switch
            {
                "verbose" or "trace" => LogEventLevel.Verbose,
                "debug" => LogEventLevel.Debug,
                "information" or "info" => LogEventLevel.Information,
                "warning" or "warn" => LogEventLevel.Warning,
                "error" => LogEventLevel.Error,
                "fatal" or "critical" => LogEventLevel.Fatal,
                _ => LogEventLevel.Information
            };
        }

        // Convenience methods
        public static void Verbose(string message, params object[] args) => Log.Verbose(message, args);
        public static void Debug(string message, params object[] args) => Log.Debug(message, args);
        public static void Info(string message, params object[] args) => Log.Information(message, args);
        public static void Warning(string message, params object[] args) => Log.Warning(message, args);
        public static void Error(string message, params object[] args) => Log.Error(message, args);
        public static void Error(Exception ex, string message, params object[] args) => Log.Error(ex, message, args);
        public static void Fatal(string message, params object[] args) => Log.Fatal(message, args);
        public static void Fatal(Exception ex, string message, params object[] args) => Log.Fatal(ex, message, args);

        /// <summary>
        /// Create a contextual logger for a specific class
        /// </summary>
        public static ILogger ForContext<T>() => Log.ForContext<T>();
        public static ILogger ForContext(Type type) => Log.ForContext(type);
        public static ILogger ForContext(string propertyName, object value) => Log.ForContext(propertyName, value);
    }

    /// <summary>
    /// Extension methods for logging with context
    /// </summary>
    public static class LoggingExtensions
    {
        public static void LogScanStart(this ILogger logger, string scanType)
        {
            logger.Information("Starting {ScanType} scan", scanType);
        }

        public static void LogScanComplete(this ILogger logger, string scanType, int threatsFound, TimeSpan duration)
        {
            logger.Information("Completed {ScanType} scan. Threats found: {ThreatCount}, Duration: {Duration:c}",
                scanType, threatsFound, duration);
        }

        public static void LogThreatFound(this ILogger logger, string threatPath, string severity, int score)
        {
            logger.Warning("Threat detected: {ThreatPath}, Severity: {Severity}, Score: {Score}",
                threatPath, severity, score);
        }

        public static void LogThreatRemoved(this ILogger logger, string threatPath, bool success)
        {
            if (success)
                logger.Information("Threat removed successfully: {ThreatPath}", threatPath);
            else
                logger.Error("Failed to remove threat: {ThreatPath}", threatPath);
        }

        public static void LogProtectionAlert(this ILogger logger, string processName, int processId, string status)
        {
            logger.Warning("Protection alert - Process: {ProcessName}, PID: {ProcessId}, Status: {Status}",
                processName, processId, status);
        }

        public static void LogBackup(this ILogger logger, string originalPath, string backupPath, bool success)
        {
            if (success)
                logger.Information("Backup created: {OriginalPath} -> {BackupPath}", originalPath, backupPath);
            else
                logger.Error("Backup failed: {OriginalPath}", originalPath);
        }
    }
}
