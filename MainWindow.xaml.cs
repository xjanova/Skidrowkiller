using System;
using System.Diagnostics;
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

                // Subscribe to events
                _scanner.ThreatFound += Scanner_ThreatFound;
                _protection.StatusChanged += Protection_StatusChanged;
                _licenseService.LicenseStatusChanged += LicenseService_StatusChanged;

                // Initialize views
                _scanView = new ScanView(_scanner, _whitelistManager, _backupManager);
                _monitorView = new MonitorView(_protection);
                _threatsView = new ThreatsView(_scanner, _whitelistManager, _backupManager, _quarantine);
                _whitelistView = new WhitelistView(_whitelistManager);
                _backupsView = new BackupsView(_backupManager);
                _quarantineView = new QuarantineView(_quarantine);
                _settingsView = new SettingsView();
                _licenseView = new LicenseView(_licenseService);

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

                // Update title with version
                Title = $"Skidrow Killer v{UpdateService.GetCurrentVersion()}";

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
