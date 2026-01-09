using System;
using System.Diagnostics;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using SkidrowKiller.Services;
using SkidrowKiller.Views;
using Serilog;

namespace SkidrowKiller
{
    public partial class MainWindow : Window, IDisposable
    {
        private readonly WhitelistManager _whitelistManager;
        private readonly BackupManager _backupManager;
        private readonly ThreatAnalyzer _analyzer;
        private readonly SafeScanner _scanner;
        private readonly ProtectionService _protection;
        private readonly QuarantineService _quarantine;
        private readonly LicenseService _licenseService;
        private readonly NetworkProtectionService _networkProtection;
        private readonly SelfProtectionService _selfProtection;
        private readonly GamingModeService _gamingMode;
        private readonly UsbScanService _usbScan;
        private readonly RansomwareProtectionService _ransomwareProtection;
        private readonly ScheduledScanService _scheduledScan;
        private readonly BrowserProtectionService _browserProtection;
        private readonly ILogger _logger;

        private Button? _activeNavButton;
        private ScanView? _scanView;
        private MonitorView? _monitorView;
        private ThreatsView? _threatsView;
        private WhitelistView? _whitelistView;
        private BackupsView? _backupsView;
        private QuarantineView? _quarantineView;
        private SettingsView? _settingsView;
        private LicenseView? _licenseView;
        private NetworkProtectionView? _networkProtectionView;
        private BrowserProtectionView? _browserProtectionView;
        private SystemCleanupView? _systemCleanupView;
        private bool _disposed;

        public MainWindow()
        {
            InitializeComponent();

            _logger = LoggingService.ForContext<MainWindow>();
            _logger.Information("Initializing MainWindow");

            try
            {
                // Initialize services
                _whitelistManager = new WhitelistManager();
                _backupManager = new BackupManager();
                _analyzer = new ThreatAnalyzer(_whitelistManager);
                _scanner = new SafeScanner(_analyzer, _whitelistManager, _backupManager);
                _protection = new ProtectionService(_analyzer, _whitelistManager);
                _quarantine = new QuarantineService();
                _licenseService = new LicenseService();
                _networkProtection = new NetworkProtectionService(_analyzer);
                _selfProtection = new SelfProtectionService();
                _gamingMode = new GamingModeService(_protection);
                _usbScan = new UsbScanService(_scanner, _analyzer);
                _ransomwareProtection = new RansomwareProtectionService();
                _scheduledScan = new ScheduledScanService(_scanner);
                _browserProtection = new BrowserProtectionService();

                // Subscribe to events
                _scanner.ThreatFound += Scanner_ThreatFound;
                _protection.StatusChanged += Protection_StatusChanged;
                _licenseService.LicenseStatusChanged += LicenseService_StatusChanged;
                _selfProtection.TamperAttemptDetected += SelfProtection_TamperAttemptDetected;

                // Initialize views
                _scanView = new ScanView(_scanner, _whitelistManager, _backupManager);
                _monitorView = new MonitorView(_protection);
                _threatsView = new ThreatsView(_scanner, _whitelistManager, _backupManager, _quarantine);
                _whitelistView = new WhitelistView(_whitelistManager);
                _backupsView = new BackupsView(_backupManager);
                _quarantineView = new QuarantineView(_quarantine);
                _settingsView = new SettingsView();
                _licenseView = new LicenseView(_licenseService);
                _networkProtectionView = new NetworkProtectionView(_networkProtection, _analyzer);
                _browserProtectionView = new BrowserProtectionView(_browserProtection);
                _systemCleanupView = new SystemCleanupView();

                // Update license badge
                UpdateLicenseBadge();

                // Navigate to scan view by default
                _activeNavButton = NavScan;
                MainFrame.Navigate(_scanView);

                // Start protection service if enabled
                if (AppConfiguration.Settings.Protection.Enabled)
                {
                    _protection.Start();
                    _monitorView?.RefreshUI();
                    _logger.Information("Real-time protection started");
                }

                // Initialize and enable self-protection
                _ = InitializeSelfProtectionAsync();

                // Start new services based on user settings
                _ = InitializeNewServicesAsync();

                // Update title with version
                var version = UpdateService.GetCurrentVersion();
                Title = $"Skidrow Killer v{version}";
                VersionText.Text = $" v{version}";

                _logger.Information("MainWindow initialized successfully");
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Failed to initialize MainWindow");
                throw;
            }
        }

        private void Scanner_ThreatFound(object? sender, Models.ThreatInfo threat)
        {
            Dispatcher.Invoke(() =>
            {
                ThreatCountBadge.Visibility = Visibility.Visible;
                ThreatCountText.Text = _scanner.IsScanning ? "!" : "1";
            });
        }

        private void Protection_StatusChanged(object? sender, ProtectionStatus status)
        {
            Dispatcher.Invoke(() =>
            {
                switch (status)
                {
                    case ProtectionStatus.Safe:
                        StatusIndicator.Fill = (Brush)FindResource("SuccessBrush");
                        StatusText.Text = "Protected";
                        StatusText.Foreground = (Brush)FindResource("SuccessBrush");
                        break;
                    case ProtectionStatus.Warning:
                        StatusIndicator.Fill = (Brush)FindResource("WarningBrush");
                        StatusText.Text = "Warning";
                        StatusText.Foreground = (Brush)FindResource("WarningBrush");
                        break;
                    case ProtectionStatus.Critical:
                        StatusIndicator.Fill = (Brush)FindResource("DangerBrush");
                        StatusText.Text = "Threat Detected!";
                        StatusText.Foreground = (Brush)FindResource("DangerBrush");
                        break;
                }
            });
        }

        private void NavButton_Click(object sender, RoutedEventArgs e)
        {
            if (sender is not Button button) return;

            // Update styles
            if (_activeNavButton != null)
            {
                _activeNavButton.Style = (Style)FindResource("NavButtonStyle");
            }
            button.Style = (Style)FindResource("NavButtonActiveStyle");
            _activeNavButton = button;

            // Navigate
            var tag = button.Tag?.ToString();
            switch (tag)
            {
                case "Scan":
                    MainFrame.Navigate(_scanView);
                    break;
                case "Monitor":
                    MainFrame.Navigate(_monitorView);
                    break;
                case "Network":
                    MainFrame.Navigate(_networkProtectionView);
                    _networkProtectionView?.RefreshUI();
                    break;
                case "Browser":
                    MainFrame.Navigate(_browserProtectionView);
                    _browserProtectionView?.RefreshBrowserList();
                    break;
                case "Cleanup":
                    MainFrame.Navigate(_systemCleanupView);
                    break;
                case "Threats":
                    MainFrame.Navigate(_threatsView);
                    _threatsView?.RefreshThreats();
                    break;
                case "Whitelist":
                    MainFrame.Navigate(_whitelistView);
                    _whitelistView?.RefreshWhitelist();
                    break;
                case "Backups":
                    MainFrame.Navigate(_backupsView);
                    _backupsView?.RefreshBackups();
                    break;
                case "Quarantine":
                    MainFrame.Navigate(_quarantineView);
                    _quarantineView?.RefreshQuarantine();
                    break;
                case "License":
                    MainFrame.Navigate(_licenseView);
                    _licenseView?.RefreshLicense();
                    break;
                case "Settings":
                    MainFrame.Navigate(_settingsView);
                    break;
            }
        }

        private void LicenseService_StatusChanged(object? sender, LicenseStatus status)
        {
            Dispatcher.Invoke(() => UpdateLicenseBadge());
        }

        private async Task InitializeSelfProtectionAsync()
        {
            try
            {
                _logger.Information("Initializing self-protection system...");
                await _selfProtection.InitializeAsync();
                _selfProtection.EnableProtection();
                _logger.Information("Self-protection enabled - Skidrow Killer is protected from malware attacks");
            }
            catch (Exception ex)
            {
                _logger.Warning(ex, "Self-protection initialization warning");
            }
        }

        private async Task InitializeNewServicesAsync()
        {
            try
            {
                // Load user settings
                var settingsPath = System.IO.Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "SkidrowKiller", "user_settings.json");

                Views.UserSettings? settings = null;
                if (System.IO.File.Exists(settingsPath))
                {
                    var json = await System.IO.File.ReadAllTextAsync(settingsPath);
                    settings = System.Text.Json.JsonSerializer.Deserialize<Views.UserSettings>(json);
                }
                settings ??= new Views.UserSettings();

                // Start Gaming Mode if enabled
                if (settings.GamingModeEnabled)
                {
                    _gamingMode.AutoDetectEnabled = settings.AutoDetectGames;
                    _gamingMode.SuppressNotifications = settings.SuppressGamingNotifications;
                    _gamingMode.Start();
                    _logger.Information("Gaming Mode service started");
                }

                // Start USB Scan if enabled
                if (settings.AutoScanUsb)
                {
                    _usbScan.AutoScanEnabled = settings.AutoScanUsb;
                    _usbScan.BlockAutorun = settings.BlockAutorun;
                    _usbScan.Start();
                    _logger.Information("USB Auto-Scan service started");
                }

                // Start Ransomware Protection if enabled
                if (settings.RansomwareProtection)
                {
                    _ransomwareProtection.Start();
                    _logger.Information("Ransomware Protection service started");
                }

                // Start Scheduled Scans if enabled
                if (settings.ScheduledScansEnabled)
                {
                    _scheduledScan.Start();
                    _logger.Information("Scheduled Scan service started");
                }
            }
            catch (Exception ex)
            {
                _logger.Warning(ex, "Error initializing new services");
            }
        }

        private void SelfProtection_TamperAttemptDetected(object? sender, TamperAttempt attempt)
        {
            Dispatcher.Invoke(() =>
            {
                _logger.Warning("TAMPER ATTEMPT BLOCKED: {Type} - {Description}", attempt.Type, attempt.Description);

                // Show critical status when tamper detected
                StatusIndicator.Fill = (Brush)FindResource("DangerBrush");
                StatusText.Text = "Tamper Blocked!";
                StatusText.Foreground = (Brush)FindResource("DangerBrush");

                // Show notification badge
                ThreatCountBadge.Visibility = Visibility.Visible;
                ThreatCountText.Text = "!";
            });
        }

        private void UpdateLicenseBadge()
        {
            if (_licenseService.IsLicensed && !_licenseService.IsTrial)
            {
                LicenseBadge.Visibility = Visibility.Visible;
                LicenseBadge.Background = (Brush)FindResource("GreenPrimaryBrush");
                LicenseBadgeText.Text = "PRO";
                LicenseBadgeText.Foreground = Brushes.White;
            }
            else if (_licenseService.IsTrial && _licenseService.IsLicensed)
            {
                LicenseBadge.Visibility = Visibility.Visible;
                LicenseBadge.Background = (Brush)FindResource("WarningBrush");
                LicenseBadgeText.Text = "TRIAL";
                LicenseBadgeText.Foreground = Brushes.Black;
            }
            else
            {
                LicenseBadge.Visibility = Visibility.Collapsed;
            }
        }

        private void TitleBar_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
        {
            if (e.ClickCount == 2)
            {
                MaximizeButton_Click(sender, e);
            }
            else
            {
                DragMove();
            }
        }

        private void MinimizeButton_Click(object sender, RoutedEventArgs e)
        {
            WindowState = WindowState.Minimized;
        }

        private void MaximizeButton_Click(object sender, RoutedEventArgs e)
        {
            WindowState = WindowState == WindowState.Maximized
                ? WindowState.Normal
                : WindowState.Maximized;
        }

        private void CloseButton_Click(object sender, RoutedEventArgs e)
        {
            _logger.Information("Close button clicked");
            Close();
        }

        private void ThaipromptBanner_Click(object sender, MouseButtonEventArgs e)
        {
            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = "https://thaiprompt.online",
                    UseShellExecute = true
                });
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Failed to open Thaiprompt website");
            }
        }

        protected override void OnClosed(EventArgs e)
        {
            _logger.Information("MainWindow closing");
            Dispose();
            base.OnClosed(e);
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (_disposed) return;

            if (disposing)
            {
                _logger.Information("Disposing MainWindow resources");

                // Unsubscribe from events
                if (_scanner != null)
                {
                    _scanner.ThreatFound -= Scanner_ThreatFound;
                }

                if (_protection != null)
                {
                    _protection.StatusChanged -= Protection_StatusChanged;
                    _protection.Dispose();
                }

                // Dispose network protection
                _networkProtection?.Dispose();

                // Dispose browser protection
                _browserProtection?.Dispose();

                // Dispose self-protection
                if (_selfProtection != null)
                {
                    _selfProtection.TamperAttemptDetected -= SelfProtection_TamperAttemptDetected;
                    _selfProtection.Dispose();
                }

                // Dispose new services
                _gamingMode?.Dispose();
                _usbScan?.Dispose();
                _ransomwareProtection?.Dispose();
                _scheduledScan?.Dispose();

                // Dispose scanner if it implements IDisposable
                (_scanner as IDisposable)?.Dispose();
            }

            _disposed = true;
        }

        ~MainWindow()
        {
            Dispose(false);
        }
    }
}
