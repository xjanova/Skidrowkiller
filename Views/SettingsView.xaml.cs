using System;
using System.Diagnostics;
using System.IO;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using Microsoft.Win32;
using SkidrowKiller.Services;
using Serilog;

namespace SkidrowKiller.Views
{
    public partial class SettingsView : Page
    {
        private readonly ILogger _logger;
        private readonly SettingsDatabase _settingsDb;
        private readonly DatabaseService _databaseService;
        private ThreatIntelligenceService? _threatIntelService;
        private LicenseService? _licenseService;
        private UserSettings _settings;
        private bool _isLoading = true;
        private bool _hasChanges;

        // Event to request navigation to ThreatIntelligenceView
        public event EventHandler? NavigateToThreatIntelRequested;

        public SettingsView(SettingsDatabase settingsDb)
        {
            InitializeComponent();
            _logger = LoggingService.ForContext<SettingsView>();
            _settingsDb = settingsDb;

            _databaseService = new DatabaseService();
            _databaseService.UpdateProgress += DatabaseService_UpdateProgress;
            _databaseService.DatabaseUpdated += DatabaseService_Updated;

            _settings = LoadSettings();
            ApplySettingsToUI();
            UpdatePaths();
            UpdateVersionInfo();
            UpdateDatabaseInfo();
            UpdateThreatIntelInfo();

            _isLoading = false;
        }

        /// <summary>
        /// Inject the shared ThreatIntelligenceService and LicenseService
        /// </summary>
        public void SetServices(ThreatIntelligenceService? threatIntel, LicenseService? license)
        {
            _threatIntelService = threatIntel;
            _licenseService = license;

            if (_threatIntelService != null)
            {
                _threatIntelService.UpdateCompleted += ThreatIntel_UpdateCompleted;
                _threatIntelService.ProgressChanged += ThreatIntel_ProgressChanged;
            }

            UpdateThreatIntelInfo();
        }

        private UserSettings LoadSettings()
        {
            try
            {
                // Load settings from SQLite database
                return new UserSettings
                {
                    // General
                    StartWithWindows = _settingsDb.GetSetting<bool>("StartWithWindows", false),
                    StartMinimized = _settingsDb.GetSetting<bool>("StartMinimized", false),
                    CheckForUpdates = _settingsDb.GetSetting<bool>("CheckForUpdates", true),

                    // Real-time Protection
                    RealtimeProtection = _settingsDb.GetSetting<bool>("RealtimeProtection", true),
                    MonitorProcesses = _settingsDb.GetSetting<bool>("MonitorProcesses", true),
                    MonitorNetwork = _settingsDb.GetSetting<bool>("MonitorNetwork", true),
                    ShowNotifications = _settingsDb.GetSetting<bool>("ShowNotifications", true),

                    // Scanning
                    ScanFiles = _settingsDb.GetSetting<bool>("ScanFiles", true),
                    ScanRegistry = _settingsDb.GetSetting<bool>("ScanRegistry", true),
                    ScanProcesses = _settingsDb.GetSetting<bool>("ScanProcesses", true),
                    ScanNetworkDrives = _settingsDb.GetSetting<bool>("ScanNetworkDrives", false),

                    // Threat Actions
                    ThreatAction = _settingsDb.GetSetting<int>("ThreatAction", 0),
                    BackupBeforeDelete = _settingsDb.GetSetting<bool>("BackupBeforeDelete", true),
                    QuarantineOnly = _settingsDb.GetSetting<bool>("QuarantineOnly", false),
                    SensitivityLevel = _settingsDb.GetSetting<int>("SensitivityLevel", 1),

                    // Backup & Quarantine
                    BackupRetentionIndex = _settingsDb.GetSetting<int>("BackupRetentionIndex", 2),
                    MaxBackupSizeIndex = _settingsDb.GetSetting<int>("MaxBackupSizeIndex", 1),

                    // Logging
                    EnableLogging = _settingsDb.GetSetting<bool>("EnableLogging", true),
                    LogLevelIndex = _settingsDb.GetSetting<int>("LogLevelIndex", 1),

                    // Database & Updates
                    AutoUpdateDatabase = _settingsDb.GetSetting<bool>("AutoUpdateDatabase", true),
                    UpdateFrequencyIndex = _settingsDb.GetSetting<int>("UpdateFrequencyIndex", 1),

                    // Gaming Mode
                    GamingModeEnabled = _settingsDb.GetSetting<bool>("GamingModeEnabled", false),
                    AutoDetectGames = _settingsDb.GetSetting<bool>("AutoDetectGames", true),
                    SuppressGamingNotifications = _settingsDb.GetSetting<bool>("SuppressGamingNotifications", true),

                    // USB Protection
                    AutoScanUsb = _settingsDb.GetSetting<bool>("AutoScanUsb", true),
                    BlockAutorun = _settingsDb.GetSetting<bool>("BlockAutorun", true),

                    // Ransomware Protection
                    RansomwareProtection = _settingsDb.GetSetting<bool>("RansomwareProtection", true),
                    HoneypotFiles = _settingsDb.GetSetting<bool>("HoneypotFiles", true),

                    // Scheduled Scans
                    ScheduledScansEnabled = _settingsDb.GetSetting<bool>("ScheduledScansEnabled", false),

                    // Startup Services
                    StartupRealtimeProtection = _settingsDb.GetSetting<bool>("StartupRealtimeProtection", true),
                    StartupGamingMode = _settingsDb.GetSetting<bool>("StartupGamingMode", true),
                    StartupUsbProtection = _settingsDb.GetSetting<bool>("StartupUsbProtection", true),
                    StartupRansomwareProtection = _settingsDb.GetSetting<bool>("StartupRansomwareProtection", true),
                    StartupScheduledScans = _settingsDb.GetSetting<bool>("StartupScheduledScans", false),
                    StartupSelfProtection = _settingsDb.GetSetting<bool>("StartupSelfProtection", true)
                };
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Failed to load user settings from SQLite");
                return new UserSettings();
            }
        }

        private void SaveSettingsToFile()
        {
            try
            {
                // Save all settings to SQLite database
                _settingsDb.SetSetting("StartWithWindows", _settings.StartWithWindows, "general");
                _settingsDb.SetSetting("StartMinimized", _settings.StartMinimized, "general");
                _settingsDb.SetSetting("CheckForUpdates", _settings.CheckForUpdates, "general");

                _settingsDb.SetSetting("RealtimeProtection", _settings.RealtimeProtection, "protection");
                _settingsDb.SetSetting("MonitorProcesses", _settings.MonitorProcesses, "protection");
                _settingsDb.SetSetting("MonitorNetwork", _settings.MonitorNetwork, "protection");
                _settingsDb.SetSetting("ShowNotifications", _settings.ShowNotifications, "protection");

                _settingsDb.SetSetting("ScanFiles", _settings.ScanFiles, "scanning");
                _settingsDb.SetSetting("ScanRegistry", _settings.ScanRegistry, "scanning");
                _settingsDb.SetSetting("ScanProcesses", _settings.ScanProcesses, "scanning");
                _settingsDb.SetSetting("ScanNetworkDrives", _settings.ScanNetworkDrives, "scanning");

                _settingsDb.SetSetting("ThreatAction", _settings.ThreatAction, "threats");
                _settingsDb.SetSetting("BackupBeforeDelete", _settings.BackupBeforeDelete, "threats");
                _settingsDb.SetSetting("QuarantineOnly", _settings.QuarantineOnly, "threats");
                _settingsDb.SetSetting("SensitivityLevel", _settings.SensitivityLevel, "threats");

                _settingsDb.SetSetting("BackupRetentionIndex", _settings.BackupRetentionIndex, "backup");
                _settingsDb.SetSetting("MaxBackupSizeIndex", _settings.MaxBackupSizeIndex, "backup");

                _settingsDb.SetSetting("EnableLogging", _settings.EnableLogging, "logging");
                _settingsDb.SetSetting("LogLevelIndex", _settings.LogLevelIndex, "logging");

                _settingsDb.SetSetting("AutoUpdateDatabase", _settings.AutoUpdateDatabase, "updates");
                _settingsDb.SetSetting("UpdateFrequencyIndex", _settings.UpdateFrequencyIndex, "updates");

                _settingsDb.SetSetting("GamingModeEnabled", _settings.GamingModeEnabled, "gaming");
                _settingsDb.SetSetting("AutoDetectGames", _settings.AutoDetectGames, "gaming");
                _settingsDb.SetSetting("SuppressGamingNotifications", _settings.SuppressGamingNotifications, "gaming");

                // USB Protection
                _settingsDb.SetSetting("AutoScanUsb", _settings.AutoScanUsb, "usb");
                _settingsDb.SetSetting("BlockAutorun", _settings.BlockAutorun, "usb");

                // Ransomware Protection
                _settingsDb.SetSetting("RansomwareProtection", _settings.RansomwareProtection, "ransomware");
                _settingsDb.SetSetting("HoneypotFiles", _settings.HoneypotFiles, "ransomware");

                // Scheduled Scans
                _settingsDb.SetSetting("ScheduledScansEnabled", _settings.ScheduledScansEnabled, "scanning");

                // Startup Services
                _settingsDb.SetSetting("StartupRealtimeProtection", _settings.StartupRealtimeProtection, "startup");
                _settingsDb.SetSetting("StartupGamingMode", _settings.StartupGamingMode, "startup");
                _settingsDb.SetSetting("StartupUsbProtection", _settings.StartupUsbProtection, "startup");
                _settingsDb.SetSetting("StartupRansomwareProtection", _settings.StartupRansomwareProtection, "startup");
                _settingsDb.SetSetting("StartupScheduledScans", _settings.StartupScheduledScans, "startup");
                _settingsDb.SetSetting("StartupSelfProtection", _settings.StartupSelfProtection, "startup");

                // Apply startup setting
                ApplyStartupSetting();

                _logger.Information("Settings saved to SQLite successfully");
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Failed to save user settings to SQLite");
                throw;
            }
        }

        private void ApplySettingsToUI()
        {
            // General
            ChkStartWithWindows.IsChecked = _settings.StartWithWindows;
            ChkStartMinimized.IsChecked = _settings.StartMinimized;
            ChkCheckUpdates.IsChecked = _settings.CheckForUpdates;

            // Real-time Protection
            ChkRealtimeProtection.IsChecked = _settings.RealtimeProtection;
            ChkMonitorProcesses.IsChecked = _settings.MonitorProcesses;
            ChkMonitorNetwork.IsChecked = _settings.MonitorNetwork;
            ChkShowNotifications.IsChecked = _settings.ShowNotifications;

            // Scanning
            ChkScanFiles.IsChecked = _settings.ScanFiles;
            ChkScanRegistry.IsChecked = _settings.ScanRegistry;
            ChkScanProcesses.IsChecked = _settings.ScanProcesses;
            ChkScanNetworkDrives.IsChecked = _settings.ScanNetworkDrives;

            // Threat Actions
            CmbThreatAction.SelectedIndex = _settings.ThreatAction;
            ChkBackupBeforeDelete.IsChecked = _settings.BackupBeforeDelete;
            ChkQuarantineOnly.IsChecked = _settings.QuarantineOnly;
            CmbSensitivity.SelectedIndex = _settings.SensitivityLevel;

            // Backup & Quarantine
            CmbBackupRetention.SelectedIndex = _settings.BackupRetentionIndex;
            CmbMaxBackupSize.SelectedIndex = _settings.MaxBackupSizeIndex;

            // Logging
            ChkEnableLogging.IsChecked = _settings.EnableLogging;
            CmbLogLevel.SelectedIndex = _settings.LogLevelIndex;

            // Database & Updates
            ChkAutoUpdateDb.IsChecked = _settings.AutoUpdateDatabase;
            CmbUpdateFrequency.SelectedIndex = _settings.UpdateFrequencyIndex;

            // Gaming Mode
            ChkGamingMode.IsChecked = _settings.GamingModeEnabled;
            ChkAutoDetectGames.IsChecked = _settings.AutoDetectGames;
            ChkSuppressGamingNotifications.IsChecked = _settings.SuppressGamingNotifications;

            // USB Protection
            ChkAutoScanUsb.IsChecked = _settings.AutoScanUsb;
            ChkBlockAutorun.IsChecked = _settings.BlockAutorun;

            // Ransomware Protection
            ChkRansomwareProtection.IsChecked = _settings.RansomwareProtection;
            ChkHoneypotFiles.IsChecked = _settings.HoneypotFiles;

            // Scheduled Scans
            ChkScheduledScans.IsChecked = _settings.ScheduledScansEnabled;

            // Startup Services
            ChkStartupRealtimeProtection.IsChecked = _settings.StartupRealtimeProtection;
            ChkStartupGamingMode.IsChecked = _settings.StartupGamingMode;
            ChkStartupUsbProtection.IsChecked = _settings.StartupUsbProtection;
            ChkStartupRansomwareProtection.IsChecked = _settings.StartupRansomwareProtection;
            ChkStartupScheduledScans.IsChecked = _settings.StartupScheduledScans;
            ChkStartupSelfProtection.IsChecked = _settings.StartupSelfProtection;
        }

        private void ApplyUIToSettings()
        {
            // General
            _settings.StartWithWindows = ChkStartWithWindows.IsChecked ?? false;
            _settings.StartMinimized = ChkStartMinimized.IsChecked ?? false;
            _settings.CheckForUpdates = ChkCheckUpdates.IsChecked ?? true;

            // Real-time Protection
            _settings.RealtimeProtection = ChkRealtimeProtection.IsChecked ?? true;
            _settings.MonitorProcesses = ChkMonitorProcesses.IsChecked ?? true;
            _settings.MonitorNetwork = ChkMonitorNetwork.IsChecked ?? true;
            _settings.ShowNotifications = ChkShowNotifications.IsChecked ?? true;

            // Scanning
            _settings.ScanFiles = ChkScanFiles.IsChecked ?? true;
            _settings.ScanRegistry = ChkScanRegistry.IsChecked ?? true;
            _settings.ScanProcesses = ChkScanProcesses.IsChecked ?? true;
            _settings.ScanNetworkDrives = ChkScanNetworkDrives.IsChecked ?? false;

            // Threat Actions
            _settings.ThreatAction = CmbThreatAction.SelectedIndex;
            _settings.BackupBeforeDelete = ChkBackupBeforeDelete.IsChecked ?? true;
            _settings.QuarantineOnly = ChkQuarantineOnly.IsChecked ?? true;
            _settings.SensitivityLevel = CmbSensitivity.SelectedIndex;

            // Backup & Quarantine
            _settings.BackupRetentionIndex = CmbBackupRetention.SelectedIndex;
            _settings.MaxBackupSizeIndex = CmbMaxBackupSize.SelectedIndex;

            // Logging
            _settings.EnableLogging = ChkEnableLogging.IsChecked ?? true;
            _settings.LogLevelIndex = CmbLogLevel.SelectedIndex;

            // Database & Updates
            _settings.AutoUpdateDatabase = ChkAutoUpdateDb.IsChecked ?? true;
            _settings.UpdateFrequencyIndex = CmbUpdateFrequency.SelectedIndex;

            // Gaming Mode
            _settings.GamingModeEnabled = ChkGamingMode.IsChecked ?? true;
            _settings.AutoDetectGames = ChkAutoDetectGames.IsChecked ?? true;
            _settings.SuppressGamingNotifications = ChkSuppressGamingNotifications.IsChecked ?? true;

            // USB Protection
            _settings.AutoScanUsb = ChkAutoScanUsb.IsChecked ?? true;
            _settings.BlockAutorun = ChkBlockAutorun.IsChecked ?? true;

            // Ransomware Protection
            _settings.RansomwareProtection = ChkRansomwareProtection.IsChecked ?? true;
            _settings.HoneypotFiles = ChkHoneypotFiles.IsChecked ?? true;

            // Scheduled Scans
            _settings.ScheduledScansEnabled = ChkScheduledScans.IsChecked ?? false;

            // Startup Services
            _settings.StartupRealtimeProtection = ChkStartupRealtimeProtection.IsChecked ?? true;
            _settings.StartupGamingMode = ChkStartupGamingMode.IsChecked ?? true;
            _settings.StartupUsbProtection = ChkStartupUsbProtection.IsChecked ?? true;
            _settings.StartupRansomwareProtection = ChkStartupRansomwareProtection.IsChecked ?? true;
            _settings.StartupScheduledScans = ChkStartupScheduledScans.IsChecked ?? false;
            _settings.StartupSelfProtection = ChkStartupSelfProtection.IsChecked ?? true;
        }

        private void UpdatePaths()
        {
            var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            TxtQuarantinePath.Text = Path.Combine(localAppData, "SkidrowKiller", "Quarantine");
            TxtLogPath.Text = Path.Combine(localAppData, "SkidrowKiller", "Logs");
        }

        private void UpdateVersionInfo()
        {
            TxtVersion.Text = $"Version {UpdateService.GetCurrentVersion()}";
        }

        private void ApplyStartupSetting()
        {
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(
                    @"Software\Microsoft\Windows\CurrentVersion\Run", true);

                if (key == null) return;

                if (_settings.StartWithWindows)
                {
                    var exePath = Process.GetCurrentProcess().MainModule?.FileName;
                    if (!string.IsNullOrEmpty(exePath))
                    {
                        var args = _settings.StartMinimized ? " --minimized" : "";
                        key.SetValue("SkidrowKiller", $"\"{exePath}\"{args}");
                    }
                }
                else
                {
                    key.DeleteValue("SkidrowKiller", false);
                }
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Failed to set startup registry");
            }
        }

        private void Setting_Changed(object sender, RoutedEventArgs e)
        {
            if (_isLoading) return;
            _hasChanges = true;
            TxtSaveStatus.Text = "You have unsaved changes";
            TxtSaveStatus.Foreground = (System.Windows.Media.Brush)FindResource("WarningBrush");
        }

        private void Setting_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (_isLoading) return;
            _hasChanges = true;
            TxtSaveStatus.Text = "You have unsaved changes";
            TxtSaveStatus.Foreground = (System.Windows.Media.Brush)FindResource("WarningBrush");
        }

        private void SaveSettings_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                ApplyUIToSettings();
                SaveSettingsToFile();

                _hasChanges = false;
                TxtSaveStatus.Text = "Settings saved successfully!";
                TxtSaveStatus.Foreground = (System.Windows.Media.Brush)FindResource("SuccessBrush");

                // Clear status after 3 seconds
                var timer = new System.Windows.Threading.DispatcherTimer
                {
                    Interval = TimeSpan.FromSeconds(3)
                };
                timer.Tick += (s, args) =>
                {
                    timer.Stop();
                    if (!_hasChanges)
                    {
                        TxtSaveStatus.Text = "";
                    }
                };
                timer.Start();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to save settings: {ex.Message}", "Error",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void ResetDefaults_Click(object sender, RoutedEventArgs e)
        {
            var result = MessageBox.Show(
                "Are you sure you want to reset all settings to defaults?",
                "Reset Settings",
                MessageBoxButton.YesNo,
                MessageBoxImage.Question);

            if (result == MessageBoxResult.Yes)
            {
                _settings = new UserSettings();
                _isLoading = true;
                ApplySettingsToUI();
                _isLoading = false;
                _hasChanges = true;
                TxtSaveStatus.Text = "Settings reset - click Save to apply";
                TxtSaveStatus.Foreground = (System.Windows.Media.Brush)FindResource("WarningBrush");
            }
        }

        private async void CheckForUpdates_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var updateService = new UpdateService();
                var updateInfo = await updateService.CheckForUpdatesAsync();

                if (updateInfo != null)
                {
                    var result = MessageBox.Show(
                        $"A new version is available!\n\n" +
                        $"Current: v{updateInfo.CurrentVersion}\n" +
                        $"Latest: v{updateInfo.LatestVersion}\n\n" +
                        "Would you like to download it?",
                        "Update Available",
                        MessageBoxButton.YesNo,
                        MessageBoxImage.Information);

                    if (result == MessageBoxResult.Yes && !string.IsNullOrEmpty(updateInfo.ReleaseUrl))
                    {
                        Process.Start(new ProcessStartInfo
                        {
                            FileName = updateInfo.ReleaseUrl,
                            UseShellExecute = true
                        });
                    }
                }
                else
                {
                    MessageBox.Show(
                        $"You are using the latest version (v{UpdateService.GetCurrentVersion()})",
                        "No Updates",
                        MessageBoxButton.OK,
                        MessageBoxImage.Information);
                }

                updateService.Dispose();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to check for updates: {ex.Message}", "Error",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void OpenQuarantineFolder_Click(object sender, RoutedEventArgs e)
        {
            OpenFolder(TxtQuarantinePath.Text);
        }

        private void OpenLogFolder_Click(object sender, RoutedEventArgs e)
        {
            OpenFolder(TxtLogPath.Text);
        }

        private void OpenFolder(string path)
        {
            try
            {
                if (!Directory.Exists(path))
                {
                    Directory.CreateDirectory(path);
                }

                Process.Start(new ProcessStartInfo
                {
                    FileName = path,
                    UseShellExecute = true
                });
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to open folder: {ex.Message}", "Error",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void UpdateDatabaseInfo()
        {
            // Legacy database info - now primarily uses ThreatIntelligenceService
            var info = _databaseService.CurrentInfo;
            UpdateDatabaseStatus(info.Status);
        }

        private void UpdateThreatIntelInfo()
        {
            if (_threatIntelService == null)
            {
                // Show default values when service not injected
                TxtDbHashes.Text = "0";
                TxtDbUrls.Text = "0";
                TxtDbIPs.Text = "0";
                TxtDbYara.Text = "0";
                TxtDbLastUpdate.Text = "Last updated: Never";
                TxtCurrentTier.Text = "Free";
                TxtAvailableFeeds.Text = " (5/12 feeds)";
                return;
            }

            var stats = _threatIntelService.Stats;
            TxtDbHashes.Text = stats.TotalHashes.ToString("N0");
            TxtDbUrls.Text = stats.TotalUrls.ToString("N0");
            TxtDbIPs.Text = stats.TotalIPs.ToString("N0");
            TxtDbYara.Text = stats.TotalYaraRules.ToString("N0");

            // Last update
            if (_threatIntelService.LastUpdate != DateTime.MinValue)
            {
                TxtDbLastUpdate.Text = $"Last updated: {_threatIntelService.LastUpdate:g}";
            }
            else
            {
                TxtDbLastUpdate.Text = "Last updated: Never";
            }

            // Tier info
            var tier = _licenseService?.GetCurrentTier() ?? LicenseTier.Free;
            var isTrial = _licenseService?.IsTrial ?? false;
            var allFeeds = _threatIntelService.GetFeeds();
            var availableFeeds = _threatIntelService.GetFeedsForTier(tier);

            // Show tier name with (TRIAL) suffix if on trial
            var tierName = tier switch
            {
                LicenseTier.Free => "Free",
                LicenseTier.Pro => "Pro",
                LicenseTier.Enterprise => "Enterprise",
                _ => "Free"
            };
            TxtCurrentTier.Text = isTrial ? $"{tierName} (TRIAL)" : tierName;

            // Update tier badge color - gold for Enterprise, orange tint for Trial
            TierBadge.Background = tier switch
            {
                LicenseTier.Free => (System.Windows.Media.Brush)FindResource("TextTertiaryBrush"),
                LicenseTier.Pro => (System.Windows.Media.Brush)FindResource("AccentPrimaryBrush"),
                LicenseTier.Enterprise => isTrial
                    ? (System.Windows.Media.Brush)FindResource("WarningBrush") // Orange for trial
                    : new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(255, 215, 0)), // Gold for paid
                _ => (System.Windows.Media.Brush)FindResource("TextTertiaryBrush")
            };

            TxtAvailableFeeds.Text = $" ({availableFeeds.Count}/{allFeeds.Count} feeds)";

            // Update status based on data
            if (stats.TotalHashes > 0 || stats.TotalUrls > 0)
            {
                TxtDbStatus.Text = "Threat database loaded";
                TxtDbStatus.Foreground = (System.Windows.Media.Brush)FindResource("GreenPrimaryBrush");
                DbStatusIcon.Fill = (System.Windows.Media.Brush)FindResource("GreenPrimaryBrush");
                DbStatusIcon.Data = System.Windows.Media.Geometry.Parse("M12,2C6.48,2 2,6.48 2,12C2,17.52 6.48,22 12,22C17.52,22 22,17.52 22,12C22,6.48 17.52,2 12,2M10,17L5,12L6.41,10.59L10,14.17L17.59,6.58L19,8L10,17Z");
            }
            else
            {
                TxtDbStatus.Text = "Click 'Update All' to download threat intelligence";
                TxtDbStatus.Foreground = (System.Windows.Media.Brush)FindResource("TextSecondaryBrush");
                DbStatusIcon.Fill = (System.Windows.Media.Brush)FindResource("TextSecondaryBrush");
                DbStatusIcon.Data = System.Windows.Media.Geometry.Parse("M13,13H11V7H13M13,17H11V15H13M12,2A10,10 0 0,0 2,12A10,10 0 0,0 12,22A10,10 0 0,0 22,12A10,10 0 0,0 12,2Z");
            }
        }

        private void ThreatIntel_ProgressChanged(object? sender, ThreatIntelProgressEventArgs e)
        {
            Dispatcher.Invoke(() =>
            {
                TxtDbStatus.Text = $"{e.Status} ({e.PercentComplete}%)";
                TxtDbStatus.Foreground = (System.Windows.Media.Brush)FindResource("CyanPrimaryBrush");
            });
        }

        private void ThreatIntel_UpdateCompleted(object? sender, ThreatIntelCompleteEventArgs e)
        {
            Dispatcher.Invoke(() =>
            {
                UpdateThreatIntelInfo();

                if (e.Result.Success)
                {
                    TxtDbStatus.Text = $"Updated! +{e.Result.NewHashes:N0} hashes, +{e.Result.NewUrls:N0} URLs";
                    TxtDbStatus.Foreground = (System.Windows.Media.Brush)FindResource("GreenPrimaryBrush");
                }
                else
                {
                    TxtDbStatus.Text = $"Update completed with {e.Result.FeedsFailed} errors";
                    TxtDbStatus.Foreground = (System.Windows.Media.Brush)FindResource("WarningBrush");
                }
            });
        }

        private void UpdateDatabaseStatus(DatabaseStatus status)
        {
            switch (status)
            {
                case DatabaseStatus.UpToDate:
                    TxtDbStatus.Text = "Database is up to date";
                    TxtDbStatus.Foreground = (System.Windows.Media.Brush)FindResource("GreenPrimaryBrush");
                    DbStatusIcon.Fill = (System.Windows.Media.Brush)FindResource("GreenPrimaryBrush");
                    DbStatusIcon.Data = System.Windows.Media.Geometry.Parse("M12,2C6.48,2 2,6.48 2,12C2,17.52 6.48,22 12,22C17.52,22 22,17.52 22,12C22,6.48 17.52,2 12,2M10,17L5,12L6.41,10.59L10,14.17L17.59,6.58L19,8L10,17Z");
                    break;
                case DatabaseStatus.UpdateAvailable:
                    TxtDbStatus.Text = "Update available";
                    TxtDbStatus.Foreground = (System.Windows.Media.Brush)FindResource("WarningBrush");
                    DbStatusIcon.Fill = (System.Windows.Media.Brush)FindResource("WarningBrush");
                    DbStatusIcon.Data = System.Windows.Media.Geometry.Parse("M13,13H11V7H13M13,17H11V15H13M12,2A10,10 0 0,0 2,12A10,10 0 0,0 12,22A10,10 0 0,0 22,12A10,10 0 0,0 12,2Z");
                    break;
                case DatabaseStatus.Updating:
                    TxtDbStatus.Text = "Updating database...";
                    TxtDbStatus.Foreground = (System.Windows.Media.Brush)FindResource("CyanPrimaryBrush");
                    DbStatusIcon.Fill = (System.Windows.Media.Brush)FindResource("CyanPrimaryBrush");
                    DbStatusIcon.Data = System.Windows.Media.Geometry.Parse("M17.65,6.35C16.2,4.9 14.21,4 12,4A8,8 0 0,0 4,12A8,8 0 0,0 12,20C15.73,20 18.84,17.45 19.73,14H17.65C16.83,16.33 14.61,18 12,18A6,6 0 0,1 6,12A6,6 0 0,1 12,6C13.66,6 15.14,6.69 16.22,7.78L13,11H20V4L17.65,6.35Z");
                    break;
                case DatabaseStatus.Error:
                    TxtDbStatus.Text = "Error checking for updates";
                    TxtDbStatus.Foreground = (System.Windows.Media.Brush)FindResource("DangerBrush");
                    DbStatusIcon.Fill = (System.Windows.Media.Brush)FindResource("DangerBrush");
                    DbStatusIcon.Data = System.Windows.Media.Geometry.Parse("M12,2C6.47,2 2,6.47 2,12C2,17.53 6.47,22 12,22C17.53,22 22,17.53 22,12C22,6.47 17.53,2 12,2M12,20C7.59,20 4,16.41 4,12C4,7.59 7.59,4 12,4C16.41,4 20,7.59 20,12C20,16.41 16.41,20 12,20M16.59,7.58L10,14.17L7.41,11.59L6,13L10,17L18,9L16.59,7.58Z");
                    break;
                case DatabaseStatus.Offline:
                    TxtDbStatus.Text = "Offline - using cached database";
                    TxtDbStatus.Foreground = (System.Windows.Media.Brush)FindResource("TextTertiaryBrush");
                    DbStatusIcon.Fill = (System.Windows.Media.Brush)FindResource("TextTertiaryBrush");
                    DbStatusIcon.Data = System.Windows.Media.Geometry.Parse("M12,2A10,10 0 0,0 2,12A10,10 0 0,0 12,22A10,10 0 0,0 22,12A10,10 0 0,0 12,2M12,20A8,8 0 0,1 4,12A8,8 0 0,1 12,4A8,8 0 0,1 20,12A8,8 0 0,1 12,20Z");
                    break;
            }
        }

        private async void UpdateDatabase_Click(object sender, RoutedEventArgs e)
        {
            BtnUpdateDatabase.IsEnabled = false;

            try
            {
                // Use ThreatIntelligenceService if available
                if (_threatIntelService != null)
                {
                    var tier = _licenseService?.GetCurrentTier() ?? LicenseTier.Free;

                    TxtDbStatus.Text = "Updating threat intelligence...";
                    TxtDbStatus.Foreground = (System.Windows.Media.Brush)FindResource("CyanPrimaryBrush");
                    DbStatusIcon.Fill = (System.Windows.Media.Brush)FindResource("CyanPrimaryBrush");
                    DbStatusIcon.Data = System.Windows.Media.Geometry.Parse("M17.65,6.35C16.2,4.9 14.21,4 12,4A8,8 0 0,0 4,12A8,8 0 0,0 12,20C15.73,20 18.84,17.45 19.73,14H17.65C16.83,16.33 14.61,18 12,18A6,6 0 0,1 6,12A6,6 0 0,1 12,6C13.66,6 15.14,6.69 16.22,7.78L13,11H20V4L17.65,6.35Z");

                    await _threatIntelService.UpdateAllAsync(tier);

                    // UpdateThreatIntelInfo will be called by ThreatIntel_UpdateCompleted event
                }
                else
                {
                    // Fallback to legacy database service
                    UpdateDatabaseStatus(DatabaseStatus.Updating);
                    var result = await _databaseService.UpdateDatabaseAsync();

                    if (result.Success)
                    {
                        UpdateDatabaseInfo();
                        TxtDbStatus.Text = result.Message ?? "Database updated successfully";
                        TxtDbStatus.Foreground = (System.Windows.Media.Brush)FindResource("GreenPrimaryBrush");
                    }
                    else
                    {
                        UpdateDatabaseStatus(DatabaseStatus.Error);
                        TxtDbStatus.Text = result.Message ?? "Update failed";
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Database update failed");
                TxtDbStatus.Text = $"Error: {ex.Message}";
                TxtDbStatus.Foreground = (System.Windows.Media.Brush)FindResource("DangerBrush");
                DbStatusIcon.Fill = (System.Windows.Media.Brush)FindResource("DangerBrush");
            }
            finally
            {
                BtnUpdateDatabase.IsEnabled = true;
            }
        }

        private void DatabaseService_UpdateProgress(object? sender, DatabaseUpdateEventArgs e)
        {
            Dispatcher.Invoke(() =>
            {
                TxtDbStatus.Text = $"{e.Stage} ({e.Progress}%)";
            });
        }

        private void DatabaseService_Updated(object? sender, DatabaseInfo info)
        {
            Dispatcher.Invoke(() =>
            {
                UpdateDatabaseInfo();
            });
        }

        private void ManageThreatIntel_Click(object sender, RoutedEventArgs e)
        {
            // Request navigation to ThreatIntelligenceView
            NavigateToThreatIntelRequested?.Invoke(this, EventArgs.Empty);
        }

        private void ManageProtectedFolders_Click(object sender, RoutedEventArgs e)
        {
            MessageBox.Show(
                "Protected folders:\n\n" +
                "• Documents\n• Pictures\n• Videos\n• Music\n• Desktop\n• Downloads\n\n" +
                "These folders are monitored for ransomware activity.",
                "Protected Folders",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
        }

        private void ConfigureSchedule_Click(object sender, RoutedEventArgs e)
        {
            MessageBox.Show(
                "Scheduled Scan Configuration\n\n" +
                "Default schedule: Daily at 12:00 PM\n\n" +
                "To modify schedules, go to the Scan page and configure your preferred scan times.",
                "Scheduled Scans",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
        }

    }

    /// <summary>
    /// User settings model for persistence
    /// </summary>
    public class UserSettings
    {
        // General
        public bool StartWithWindows { get; set; } = false;
        public bool StartMinimized { get; set; } = false;
        public bool CheckForUpdates { get; set; } = true;

        // Real-time Protection
        public bool RealtimeProtection { get; set; } = true;
        public bool MonitorProcesses { get; set; } = true;
        public bool MonitorNetwork { get; set; } = true;
        public bool ShowNotifications { get; set; } = true;

        // Scanning
        public bool ScanFiles { get; set; } = true;
        public bool ScanRegistry { get; set; } = true;
        public bool ScanProcesses { get; set; } = true;
        public bool ScanNetworkDrives { get; set; } = false;

        // Threat Actions
        public int ThreatAction { get; set; } = 0; // 0 = Ask, 1 = Quarantine, 2 = Delete, 3 = Ignore
        public bool BackupBeforeDelete { get; set; } = true;
        public bool QuarantineOnly { get; set; } = true;
        public int SensitivityLevel { get; set; } = 1; // 0 = Very High, 1 = High, 2 = Medium, 3 = Low

        // Backup & Quarantine
        public int BackupRetentionIndex { get; set; } = 1; // 7 days
        public int MaxBackupSizeIndex { get; set; } = 1; // 1 GB

        // Logging
        public bool EnableLogging { get; set; } = true;
        public int LogLevelIndex { get; set; } = 2; // Normal

        // Database & Updates
        public bool AutoUpdateDatabase { get; set; } = true;
        public int UpdateFrequencyIndex { get; set; } = 1; // 0 = Every hour, 1 = Every 6 hours, 2 = Every 12 hours, 3 = Daily

        // Gaming Mode
        public bool GamingModeEnabled { get; set; } = true;
        public bool AutoDetectGames { get; set; } = true;
        public bool SuppressGamingNotifications { get; set; } = true;

        // USB Protection
        public bool AutoScanUsb { get; set; } = true;
        public bool BlockAutorun { get; set; } = true;

        // Ransomware Protection
        public bool RansomwareProtection { get; set; } = true;
        public bool HoneypotFiles { get; set; } = true;

        // Scheduled Scans
        public bool ScheduledScansEnabled { get; set; } = false;

        // Startup Services
        public bool StartupRealtimeProtection { get; set; } = true;
        public bool StartupGamingMode { get; set; } = true;
        public bool StartupUsbProtection { get; set; } = true;
        public bool StartupRansomwareProtection { get; set; } = true;
        public bool StartupScheduledScans { get; set; } = false;
        public bool StartupSelfProtection { get; set; } = true;

        // Helper methods
        public int GetBackupRetentionDays()
        {
            return BackupRetentionIndex switch
            {
                0 => 3,
                1 => 7,
                2 => 14,
                3 => 30,
                4 => -1, // Never
                _ => 7
            };
        }

        public int GetMaxBackupSizeMB()
        {
            return MaxBackupSizeIndex switch
            {
                0 => 500,
                1 => 1024,
                2 => 2048,
                3 => 5120,
                4 => -1, // Unlimited
                _ => 1024
            };
        }

        public int GetMinimumThreatScore()
        {
            return SensitivityLevel switch
            {
                0 => 10,
                1 => 20,
                2 => 40,
                3 => 60,
                _ => 20
            };
        }

        public int GetUpdateFrequencyHours()
        {
            return UpdateFrequencyIndex switch
            {
                0 => 1,
                1 => 6,
                2 => 12,
                3 => 24,
                _ => 6
            };
        }
    }
}
