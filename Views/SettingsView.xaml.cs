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
        private readonly string _settingsPath;
        private readonly DatabaseService _databaseService;
        private UserSettings _settings;
        private bool _isLoading = true;
        private bool _hasChanges;

        public SettingsView()
        {
            InitializeComponent();
            _logger = LoggingService.ForContext<SettingsView>();
            _settingsPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "SkidrowKiller",
                "user_settings.json"
            );

            _databaseService = new DatabaseService();
            _databaseService.UpdateProgress += DatabaseService_UpdateProgress;
            _databaseService.DatabaseUpdated += DatabaseService_Updated;

            _settings = LoadSettings();
            ApplySettingsToUI();
            UpdatePaths();
            UpdateVersionInfo();
            UpdateDatabaseInfo();

            _isLoading = false;
        }

        private UserSettings LoadSettings()
        {
            try
            {
                if (File.Exists(_settingsPath))
                {
                    var json = File.ReadAllText(_settingsPath);
                    return JsonSerializer.Deserialize<UserSettings>(json) ?? new UserSettings();
                }
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Failed to load user settings");
            }
            return new UserSettings();
        }

        private void SaveSettingsToFile()
        {
            try
            {
                var directory = Path.GetDirectoryName(_settingsPath);
                if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
                {
                    Directory.CreateDirectory(directory);
                }

                var json = JsonSerializer.Serialize(_settings, new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(_settingsPath, json);

                // Apply startup setting
                ApplyStartupSetting();

                _logger.Information("Settings saved successfully");
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Failed to save user settings");
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
            var info = _databaseService.CurrentInfo;
            TxtDbVersion.Text = info.Version;
            TxtDbLastUpdate.Text = _databaseService.GetFormattedLastUpdate();
            TxtDbSignatures.Text = _databaseService.GetFormattedSignatureCount();

            UpdateDatabaseStatus(info.Status);
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
                UpdateDatabaseStatus(DatabaseStatus.Updating);

                var result = await _databaseService.SimulateUpdateAsync();

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
            catch (Exception ex)
            {
                _logger.Error(ex, "Database update failed");
                UpdateDatabaseStatus(DatabaseStatus.Error);
                TxtDbStatus.Text = $"Error: {ex.Message}";
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
