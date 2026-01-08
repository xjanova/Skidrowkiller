using System;
using System.Diagnostics;
using System.IO;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using Microsoft.Win32;
using SkidrowKiller.Services;
using Serilog;

namespace SkidrowKiller.Views
{
    public partial class SettingsView : Page
    {
        private readonly ILogger _logger;
        private readonly string _settingsPath;
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

            _settings = LoadSettings();
            ApplySettingsToUI();
            UpdatePaths();
            UpdateVersionInfo();

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
    }
}
