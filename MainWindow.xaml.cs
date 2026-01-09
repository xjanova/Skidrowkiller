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

        private readonly ThreatIntelligenceService _threatIntel;
        private readonly SettingsDatabase _settingsDb;

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
        private UsbProtectionView? _usbProtectionView;
        private RansomwareProtectionView? _ransomwareProtectionView;
        private ScheduledScanView? _scheduledScanView;
        private GamingModeView? _gamingModeView;
        private ThreatIntelligenceView? _threatIntelView;
        private System.Windows.Threading.DispatcherTimer? _statusBarTimer;
        private bool _disposed;

        public MainWindow()
        {
            InitializeComponent();

            _logger = LoggingService.ForContext<MainWindow>();
            _logger.Information("Initializing MainWindow");

            try
            {
                // Initialize database first (required for other services)
                _settingsDb = new SettingsDatabase();

                // Initialize services
                _whitelistManager = new WhitelistManager(_settingsDb);
                _backupManager = new BackupManager(_settingsDb);
                _analyzer = new ThreatAnalyzer(_whitelistManager);
                _scanner = new SafeScanner(_analyzer, _whitelistManager, _backupManager);
                _protection = new ProtectionService(_analyzer, _whitelistManager);
                _quarantine = new QuarantineService(_settingsDb);
                _licenseService = new LicenseService(_settingsDb);
                _networkProtection = new NetworkProtectionService(_analyzer);
                _selfProtection = new SelfProtectionService();
                _gamingMode = new GamingModeService(_protection);
                _usbScan = new UsbScanService(_scanner, _analyzer);
                _ransomwareProtection = new RansomwareProtectionService(_settingsDb);
                _scheduledScan = new ScheduledScanService(_scanner, _settingsDb);
                _browserProtection = new BrowserProtectionService();
                _threatIntel = new ThreatIntelligenceService();

                // Subscribe to events
                _scanner.ThreatFound += Scanner_ThreatFound;
                _protection.StatusChanged += Protection_StatusChanged;
                _licenseService.LicenseStatusChanged += LicenseService_StatusChanged;
                _selfProtection.TamperAttemptDetected += SelfProtection_TamperAttemptDetected;
                _threatIntel.UpdateCompleted += ThreatIntel_UpdateCompleted;

                // Initialize views
                _scanView = new ScanView(_scanner, _whitelistManager, _backupManager);
                _monitorView = new MonitorView(_protection);
                _threatsView = new ThreatsView(_scanner, _whitelistManager, _backupManager, _quarantine);
                _whitelistView = new WhitelistView(_whitelistManager);
                _backupsView = new BackupsView(_backupManager);
                _quarantineView = new QuarantineView(_quarantine);
                _settingsView = new SettingsView(_settingsDb);
                _settingsView.SetServices(_threatIntel, _licenseService);
                _settingsView.NavigateToThreatIntelRequested += SettingsView_NavigateToThreatIntel;
                _licenseView = new LicenseView(_licenseService);
                _networkProtectionView = new NetworkProtectionView(_networkProtection, _analyzer, _quarantine);
                _browserProtectionView = new BrowserProtectionView(_browserProtection);
                _systemCleanupView = new SystemCleanupView();
                _usbProtectionView = new UsbProtectionView(_usbScan);
                _ransomwareProtectionView = new RansomwareProtectionView(_ransomwareProtection);
                _scheduledScanView = new ScheduledScanView(_scheduledScan);
                _gamingModeView = new GamingModeView(_gamingMode);
                _threatIntelView = new ThreatIntelligenceView(_threatIntel, _licenseService);

                // Update license badge
                UpdateLicenseBadge();

                // Initialize and start status bar updates
                InitializeStatusBar();
                StartStatusBarTimer();

                // Navigate to scan view by default
                _activeNavButton = NavScan;
                MainFrame.Navigate(_scanView);

                // Start services based on user settings
                _ = InitializeAllServicesAsync();

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
                // Update all protection status indicators in status bar
                UpdateAllProtectionStatus();
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
                case "Usb":
                    MainFrame.Navigate(_usbProtectionView);
                    break;
                case "Ransomware":
                    MainFrame.Navigate(_ransomwareProtectionView);
                    break;
                case "Scheduled":
                    MainFrame.Navigate(_scheduledScanView);
                    break;
                case "Gaming":
                    MainFrame.Navigate(_gamingModeView);
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
                case "ThreatIntel":
                    MainFrame.Navigate(_threatIntelView);
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
            Dispatcher.Invoke(() =>
            {
                UpdateLicenseBadge();
                UpdateStatusBarLicense();
            });
        }

        private void ThreatIntel_UpdateCompleted(object? sender, ThreatIntelCompleteEventArgs e)
        {
            Dispatcher.Invoke(() =>
            {
                UpdateStatusBarThreatIntel();
                if (e.Result.Success)
                {
                    SetStatusBarMessage($"Threat Intel updated: +{e.Result.NewHashes:N0} hashes");
                }
            });
        }

        private async Task InitializeAllServicesAsync()
        {
            try
            {
                // Load user settings from SQLite database
                var settings = new Views.UserSettings
                {
                    // Startup Services
                    StartupRealtimeProtection = _settingsDb.GetSetting<bool>("StartupRealtimeProtection", true),
                    StartupGamingMode = _settingsDb.GetSetting<bool>("StartupGamingMode", true),
                    StartupUsbProtection = _settingsDb.GetSetting<bool>("StartupUsbProtection", true),
                    StartupRansomwareProtection = _settingsDb.GetSetting<bool>("StartupRansomwareProtection", true),
                    StartupScheduledScans = _settingsDb.GetSetting<bool>("StartupScheduledScans", false),
                    StartupSelfProtection = _settingsDb.GetSetting<bool>("StartupSelfProtection", true),

                    // Gaming Mode settings
                    AutoDetectGames = _settingsDb.GetSetting<bool>("AutoDetectGames", true),
                    SuppressGamingNotifications = _settingsDb.GetSetting<bool>("SuppressGamingNotifications", true),

                    // USB Protection settings
                    AutoScanUsb = _settingsDb.GetSetting<bool>("AutoScanUsb", true),
                    BlockAutorun = _settingsDb.GetSetting<bool>("BlockAutorun", true)
                };

                // Start Real-time Protection if enabled at startup
                if (settings.StartupRealtimeProtection)
                {
                    _protection.Start();
                    _monitorView?.RefreshUI();
                    _logger.Information("Real-time protection started");
                }

                // Start Self-Protection if enabled at startup
                if (settings.StartupSelfProtection)
                {
                    try
                    {
                        _logger.Information("Initializing self-protection system...");
                        await _selfProtection.InitializeAsync();
                        _selfProtection.EnableProtection();
                        _logger.Information("Self-protection enabled");
                    }
                    catch (Exception ex)
                    {
                        _logger.Warning(ex, "Self-protection initialization warning");
                    }
                }

                // Start Gaming Mode if enabled at startup
                if (settings.StartupGamingMode)
                {
                    _gamingMode.AutoDetectEnabled = settings.AutoDetectGames;
                    _gamingMode.SuppressNotifications = settings.SuppressGamingNotifications;
                    _gamingMode.Start();
                    _logger.Information("Gaming Mode service started");
                }

                // Start USB Protection if enabled at startup
                if (settings.StartupUsbProtection)
                {
                    _usbScan.AutoScanEnabled = settings.AutoScanUsb;
                    _usbScan.BlockAutorun = settings.BlockAutorun;
                    _usbScan.Start();
                    _logger.Information("USB Protection service started");
                }

                // Start Ransomware Protection if enabled at startup
                if (settings.StartupRansomwareProtection)
                {
                    _ransomwareProtection.Start();
                    _logger.Information("Ransomware Protection service started");
                }

                // Start Scheduled Scans if enabled at startup
                if (settings.StartupScheduledScans)
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

                // Show critical status in status bar
                ProtectionIndicator.Fill = (Brush)FindResource("DangerBrush");
                ProtectionStatusText.Text = "Tamper Blocked!";
                ProtectionStatusText.Foreground = (Brush)FindResource("DangerBrush");

                // Show notification badge
                ThreatCountBadge.Visibility = Visibility.Visible;
                ThreatCountText.Text = "!";
            });
        }

        private void UpdateLicenseBadge()
        {
            var tier = _licenseService.GetCurrentTier();

            if (tier == LicenseTier.Enterprise)
            {
                LicenseBadge.Visibility = Visibility.Visible;
                LicenseBadge.Background = new SolidColorBrush(Color.FromRgb(255, 215, 0)); // Gold
                LicenseBadgeText.Text = "ENTERPRISE";
                LicenseBadgeText.Foreground = Brushes.Black;
            }
            else if (tier == LicenseTier.Pro || (_licenseService.IsLicensed && !_licenseService.IsTrial))
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

        private void SettingsView_NavigateToThreatIntel(object? sender, EventArgs e)
        {
            // Navigate to ThreatIntelligence view when requested from Settings
            if (_activeNavButton != null)
            {
                _activeNavButton.Style = (Style)FindResource("NavButtonStyle");
            }

            // Find and activate the ThreatIntel nav button
            if (NavThreatIntel != null)
            {
                NavThreatIntel.Style = (Style)FindResource("NavButtonActiveStyle");
                _activeNavButton = NavThreatIntel;
            }

            MainFrame.Navigate(_threatIntelView);
        }

        #region Status Bar

        private void InitializeStatusBar()
        {
            UpdateStatusBarConnection();
            UpdateStatusBarLicense();
            UpdateStatusBarThreatIntel();
            UpdateAllProtectionStatus();
            UpdateStatusBarTime();
        }

        private void StartStatusBarTimer()
        {
            _statusBarTimer = new System.Windows.Threading.DispatcherTimer
            {
                Interval = TimeSpan.FromSeconds(1)
            };
            _statusBarTimer.Tick += StatusBarTimer_Tick;
            _statusBarTimer.Start();
        }

        private void StatusBarTimer_Tick(object? sender, EventArgs e)
        {
            UpdateStatusBarTime();
            // Update protection status every second to catch any changes
            UpdateAllProtectionStatus();
        }

        private void UpdateStatusBarConnection()
        {
            // Check internet connectivity
            try
            {
                var isOnline = System.Net.NetworkInformation.NetworkInterface.GetIsNetworkAvailable();
                if (isOnline)
                {
                    ConnectionIndicator.Fill = (Brush)FindResource("SuccessBrush");
                    ConnectionStatusText.Text = "Online";
                    ConnectionStatusText.Foreground = (Brush)FindResource("SuccessBrush");
                }
                else
                {
                    ConnectionIndicator.Fill = (Brush)FindResource("TextTertiaryBrush");
                    ConnectionStatusText.Text = "Offline";
                    ConnectionStatusText.Foreground = (Brush)FindResource("TextTertiaryBrush");
                }
            }
            catch
            {
                ConnectionIndicator.Fill = (Brush)FindResource("TextTertiaryBrush");
                ConnectionStatusText.Text = "Unknown";
                ConnectionStatusText.Foreground = (Brush)FindResource("TextTertiaryBrush");
            }
        }

        private void UpdateStatusBarLicense()
        {
            var tier = _licenseService.GetCurrentTier();
            var isTrial = _licenseService.IsTrial;

            if (isTrial)
            {
                var daysLeft = _licenseService.DaysRemaining;
                LicenseStatusText.Text = $"Trial ({daysLeft}d)";
                LicenseStatusText.Foreground = (Brush)FindResource("WarningBrush");
            }
            else if (tier == LicenseTier.Enterprise)
            {
                LicenseStatusText.Text = "Enterprise";
                LicenseStatusText.Foreground = new SolidColorBrush(Color.FromRgb(255, 215, 0));
            }
            else if (tier == LicenseTier.Pro)
            {
                LicenseStatusText.Text = "Pro";
                LicenseStatusText.Foreground = (Brush)FindResource("GreenPrimaryBrush");
            }
            else
            {
                LicenseStatusText.Text = "Free";
                LicenseStatusText.Foreground = (Brush)FindResource("TextSecondaryBrush");
            }
        }

        private void UpdateStatusBarThreatIntel()
        {
            var stats = _threatIntel.Stats;
            var totalItems = stats.TotalHashes + stats.TotalUrls + stats.TotalIPs;

            if (totalItems > 0)
            {
                if (totalItems >= 1000000)
                {
                    ThreatIntelHashCount.Text = $"{totalItems / 1000000.0:F1}M";
                }
                else if (totalItems >= 1000)
                {
                    ThreatIntelHashCount.Text = $"{totalItems / 1000.0:F1}K";
                }
                else
                {
                    ThreatIntelHashCount.Text = totalItems.ToString("N0");
                }
            }
            else
            {
                ThreatIntelHashCount.Text = "0";
            }
        }

        private void UpdateAllProtectionStatus()
        {
            var successBrush = (Brush)FindResource("SuccessBrush");
            var warningBrush = (Brush)FindResource("WarningBrush");
            var offBrush = (Brush)FindResource("TextTertiaryBrush");

            int activeCount = 0;

            // Real-time Protection
            var rtOn = _protection.IsRunning;
            StatusRealtimeIndicator.Fill = rtOn ? successBrush : offBrush;
            StatusRealtimeText.Foreground = rtOn ? successBrush : offBrush;
            StatusRealtime.ToolTip = rtOn ? "Real-time Protection: ON" : "Real-time Protection: OFF";
            if (rtOn) activeCount++;

            // USB Protection
            var usbOn = _usbScan.IsEnabled;
            StatusUsbIndicator.Fill = usbOn ? successBrush : offBrush;
            StatusUsbText.Foreground = usbOn ? successBrush : offBrush;
            StatusUsb.ToolTip = usbOn ? "USB Protection: ON" : "USB Protection: OFF";
            if (usbOn) activeCount++;

            // Ransomware Protection
            var rwOn = _ransomwareProtection.IsEnabled;
            StatusRansomwareIndicator.Fill = rwOn ? successBrush : offBrush;
            StatusRansomwareText.Foreground = rwOn ? successBrush : offBrush;
            StatusRansomware.ToolTip = rwOn ? "Ransomware Protection: ON" : "Ransomware Protection: OFF";
            if (rwOn) activeCount++;

            // Browser Protection
            var webOn = _browserProtection.IsEnabled;
            StatusBrowserIndicator.Fill = webOn ? successBrush : offBrush;
            StatusBrowserText.Foreground = webOn ? successBrush : offBrush;
            StatusBrowser.ToolTip = webOn ? "Browser Protection: ON" : "Browser Protection: OFF";
            if (webOn) activeCount++;

            // Gaming Mode
            var gameOn = _gamingMode.IsGamingMode;
            StatusGamingIndicator.Fill = gameOn ? warningBrush : offBrush;
            StatusGamingText.Foreground = gameOn ? warningBrush : offBrush;
            StatusGaming.ToolTip = gameOn ? "Gaming Mode: ACTIVE" : "Gaming Mode: OFF";

            // Overall Protection Status
            if (activeCount >= 3)
            {
                ProtectionIndicator.Fill = successBrush;
                ProtectionStatusText.Text = "Protected";
                ProtectionStatusText.Foreground = successBrush;
            }
            else if (activeCount >= 1)
            {
                ProtectionIndicator.Fill = warningBrush;
                ProtectionStatusText.Text = $"Partial ({activeCount}/4)";
                ProtectionStatusText.Foreground = warningBrush;
            }
            else
            {
                ProtectionIndicator.Fill = offBrush;
                ProtectionStatusText.Text = "Not Protected";
                ProtectionStatusText.Foreground = offBrush;
            }
        }

        private void UpdateStatusBarTime()
        {
            CurrentTimeText.Text = DateTime.Now.ToString("HH:mm:ss");
        }

        public void SetStatusBarMessage(string message)
        {
            StatusBarMessage.Text = message;
        }

        public void ClearStatusBarMessage()
        {
            StatusBarMessage.Text = "";
        }

        #endregion

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

                // Stop status bar timer
                if (_statusBarTimer != null)
                {
                    _statusBarTimer.Stop();
                    _statusBarTimer.Tick -= StatusBarTimer_Tick;
                    _statusBarTimer = null;
                }

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

                if (_threatIntel != null)
                {
                    _threatIntel.UpdateCompleted -= ThreatIntel_UpdateCompleted;
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

                // Dispose settings database
                _settingsDb?.Dispose();

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
