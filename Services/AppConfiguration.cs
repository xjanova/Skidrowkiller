using System.IO;
using Microsoft.Extensions.Configuration;

namespace SkidrowKiller.Services
{
    /// <summary>
    /// Application configuration settings loaded from appsettings.json
    /// </summary>
    public class AppSettings
    {
        public ApplicationSettings Application { get; set; } = new();
        public ScanningSettings Scanning { get; set; } = new();
        public ProtectionSettings Protection { get; set; } = new();
        public BackupSettings Backup { get; set; } = new();
        public LoggingSettings Logging { get; set; } = new();
        public UpdateSettings Updates { get; set; } = new();
        public ThreatAnalysisSettings ThreatAnalysis { get; set; } = new();
    }

    public class ApplicationSettings
    {
        public string Name { get; set; } = "Skidrow Killer";
        public string Version { get; set; } = "2.1.0";
        public string Environment { get; set; } = "Development";
        public bool IsProduction => Environment.Equals("Production", StringComparison.OrdinalIgnoreCase);
    }

    public class ScanningSettings
    {
        public int MaxConcurrentScans { get; set; } = 1;
        public int ScanTimeoutMinutes { get; set; } = 60;
        public bool EnableFileScan { get; set; } = true;
        public bool EnableRegistryScan { get; set; } = true;
        public bool EnableProcessScan { get; set; } = true;
        public string[] ExcludedDriveTypes { get; set; } = { "Network", "CDRom" };
        public int MaxFileSizeMB { get; set; } = 100;
        public int ProgressUpdateIntervalMs { get; set; } = 100;
    }

    public class ProtectionSettings
    {
        public bool Enabled { get; set; } = true;
        public int MonitorIntervalSeconds { get; set; } = 3;
        public int AutoResetStatusSeconds { get; set; } = 30;
        public int[] SuspiciousPorts { get; set; } = { 4444, 5555, 6666, 7777, 8888, 9999, 31337, 12345, 65535 };
    }

    public class BackupSettings
    {
        public bool Enabled { get; set; } = true;
        public bool BackupBeforeRemove { get; set; } = true;
        public int RetentionDays { get; set; } = 7;
        public int MaxBackupSizeMB { get; set; } = 1024;
    }

    public class LoggingSettings
    {
        public string MinimumLevel { get; set; } = "Information";
        public bool EnableFileLogging { get; set; } = true;
        public bool EnableConsoleLogging { get; set; } = false;
        public int LogRetentionDays { get; set; } = 30;
        public int LogFileSizeLimitMB { get; set; } = 10;
        public string LogPath { get; set; } = "Logs";
    }

    public class UpdateSettings
    {
        public bool CheckForUpdatesOnStartup { get; set; } = true;
        public string UpdateCheckUrl { get; set; } = "";
        public bool AutoDownloadUpdates { get; set; } = false;
    }

    public class ThreatAnalysisSettings
    {
        public int MinimumScoreToReport { get; set; } = 20;
        public int CriticalScoreThreshold { get; set; } = 80;
        public int HighScoreThreshold { get; set; } = 60;
        public int MediumScoreThreshold { get; set; } = 40;
        public int LowScoreThreshold { get; set; } = 20;
        public bool EnableBoosterPatterns { get; set; } = true;
        public bool EnableSafeContextReduction { get; set; } = true;
        public double CautionDirectoryMultiplier { get; set; } = 0.7;
    }

    /// <summary>
    /// Centralized configuration manager for the application
    /// </summary>
    public static class AppConfiguration
    {
        private static IConfiguration? _configuration;
        private static AppSettings? _settings;
        private static readonly object _lock = new();

        public static AppSettings Settings
        {
            get
            {
                if (_settings == null)
                {
                    lock (_lock)
                    {
                        _settings ??= LoadSettings();
                    }
                }
                return _settings;
            }
        }

        public static IConfiguration Configuration
        {
            get
            {
                if (_configuration == null)
                {
                    lock (_lock)
                    {
                        _configuration ??= BuildConfiguration();
                    }
                }
                return _configuration;
            }
        }

        private static IConfiguration BuildConfiguration()
        {
            var basePath = AppDomain.CurrentDomain.BaseDirectory;
            var environment = System.Environment.GetEnvironmentVariable("SKIDROWKILLER_ENVIRONMENT") ?? "Development";

            var builder = new ConfigurationBuilder()
                .SetBasePath(basePath)
                .AddJsonFile("appsettings.json", optional: true, reloadOnChange: true)
                .AddJsonFile($"appsettings.{environment}.json", optional: true, reloadOnChange: true);

            return builder.Build();
        }

        private static AppSettings LoadSettings()
        {
            var settings = new AppSettings();
            Configuration.Bind(settings);
            return settings;
        }

        /// <summary>
        /// Reload configuration from files
        /// </summary>
        public static void Reload()
        {
            lock (_lock)
            {
                _configuration = BuildConfiguration();
                _settings = LoadSettings();
            }
        }

        /// <summary>
        /// Get a specific configuration section
        /// </summary>
        public static T GetSection<T>(string sectionName) where T : new()
        {
            var section = new T();
            Configuration.GetSection(sectionName).Bind(section);
            return section;
        }

        /// <summary>
        /// Get application version from configuration or assembly
        /// </summary>
        public static string GetVersion()
        {
            return Settings.Application.Version;
        }

        /// <summary>
        /// Check if running in production environment
        /// </summary>
        public static bool IsProduction => Settings.Application.IsProduction;

        /// <summary>
        /// Get the log directory path
        /// </summary>
        public static string GetLogDirectory()
        {
            var logPath = Settings.Logging.LogPath;
            if (Path.IsPathRooted(logPath))
                return logPath;

            return Path.Combine(
                System.Environment.GetFolderPath(System.Environment.SpecialFolder.LocalApplicationData),
                "SkidrowKiller",
                logPath
            );
        }
    }
}
