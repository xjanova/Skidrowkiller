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
        private readonly SignatureUpdateService _signatureUpdate;
        private readonly RealtimeProcessGuard _processGuard;
        private readonly DefenderIntegrationService _defender;
        private readonly SettingsDatabase _settingsDb;
        private readonly ReputationService _reputation;
        private readonly SelfTestService _selfTest;

        private Button? _activeNavButton;
        private HomeView? _homeView;
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

        /// <summary>Settings -> Real-time Protection -> Show notifications.</summary>
        private bool _showNotifications = true;

        /// <summary>Running total of threats found this session (badge counter).</summary>
        private int _sessionThreatCount;

        public MainWindow()
        {
            InitializeComponent();

            _logger = LoggingService.ForContext<MainWindow>();
            _logger.Information("Initializing MainWindow");

            try
            {
                // Initialize database first (required for other services)
                _settingsDb = new SettingsDatabase();

                // Local learning layer (reputation) — shared by analyzer, whitelist and quarantine
                _reputation = new ReputationService();

                // Defender coexistence (safe self-exclusion + status; never disables Defender)
                _defender = new DefenderIntegrationService();

                // Initialize services
                _whitelistManager = new WhitelistManager(_settingsDb, _reputation);
                _backupManager = new BackupManager(_settingsDb);
                _analyzer = new ThreatAnalyzer(_whitelistManager) { Reputation = _reputation };

                // A saved VirusTotal key has to reach the engine at startup - otherwise the cloud
                // layer only came alive after the user happened to open the Threat Intel screen.
                var vtKey = _settingsDb.GetSetting<string>("VirusTotalApiKey", string.Empty);
                if (!string.IsNullOrWhiteSpace(vtKey))
                    _analyzer.ConfigureVirusTotal(vtKey);
                _scanner = new SafeScanner(_analyzer, _whitelistManager, _backupManager);
                _protection = new ProtectionService(_analyzer, _whitelistManager);
                _processGuard = new RealtimeProcessGuard(_analyzer, _whitelistManager);
                _quarantine = new QuarantineService(_settingsDb, _reputation);
                _licenseService = new LicenseService(_settingsDb);
                _networkProtection = new NetworkProtectionService(_analyzer);
                _selfProtection = new SelfProtectionService();
                _gamingMode = new GamingModeService(_protection);
                _usbScan = new UsbScanService(_scanner, _analyzer);
                _ransomwareProtection = new RansomwareProtectionService(_settingsDb);
                _scheduledScan = new ScheduledScanService(_scanner, _settingsDb);
                _browserProtection = new BrowserProtectionService();
                _threatIntel = new ThreatIntelligenceService(_settingsDb);

                // Give the self-test the real services so it can prove scan / remove / quarantine /
                // library end-to-end, not just the pattern matcher.
                _selfTest = new SelfTestService(_analyzer, _quarantine, _whitelistManager, _backupManager, _threatIntel);

                // Signature (signatures.json) auto-updater — reloads the live DB after a verified download.
                _signatureUpdate = new SignatureUpdateService();
                _signatureUpdate.AttachSignatureDatabase(_analyzer.SignatureDatabase);
                var updCfg = AppConfiguration.Settings.Updates;
                if (!string.IsNullOrWhiteSpace(updCfg.UpdateCheckUrl))
                    _signatureUpdate.Configure(updCfg.UpdateCheckUrl);
                _signatureUpdate.AutoUpdate = updCfg.AutoDownloadUpdates;
                if (updCfg.AutoDownloadUpdates)
                    _signatureUpdate.StartAutoUpdate();

                // Subscribe to events
                _scanner.ThreatFound += Scanner_ThreatFound;
                _protection.StatusChanged += Protection_StatusChanged;
                _processGuard.ThreatDetected += ProcessGuard_ThreatDetected;
                _licenseService.LicenseStatusChanged += LicenseService_StatusChanged;
                _selfProtection.TamperAttemptDetected += SelfProtection_TamperAttemptDetected;
                _threatIntel.UpdateCompleted += ThreatIntel_UpdateCompleted;

                // Initialize views
                _homeView = new HomeView(_settingsDb, _quarantine, _threatIntel, _protection, _selfTest);
                _homeView.QuickScanRequested += (s, e) => NavButton_Click(NavScan, new RoutedEventArgs());
                _homeView.UpdateIntelRequested += (s, e) => NavButton_Click(NavThreatIntel, new RoutedEventArgs());
                _scanView = new ScanView(_scanner, _whitelistManager, _backupManager, _quarantine);
                _monitorView = new MonitorView(_protection);
                _threatsView = new ThreatsView(_scanner, _whitelistManager, _backupManager, _quarantine);
                _whitelistView = new WhitelistView(_whitelistManager);
                _backupsView = new BackupsView(_backupManager);
                _quarantineView = new QuarantineView(_quarantine);
                _settingsView = new SettingsView(_settingsDb);
                _settingsView.SetServices(_threatIntel, _licenseService);
                _settingsView.NavigateToThreatIntelRequested += SettingsView_NavigateToThreatIntel;
                _settingsView.SettingsApplied += SettingsView_SettingsApplied;
                _licenseView = new LicenseView(_licenseService);
                _networkProtectionView = new NetworkProtectionView(_networkProtection, _analyzer, _quarantine);
                _browserProtectionView = new BrowserProtectionView(_browserProtection);
                _systemCleanupView = new SystemCleanupView();
                _usbProtectionView = new UsbProtectionView(_usbScan);
                _ransomwareProtectionView = new RansomwareProtectionView(_ransomwareProtection);
                _scheduledScanView = new ScheduledScanView(_scheduledScan);
                _gamingModeView = new GamingModeView(_gamingMode);
                _threatIntelView = new ThreatIntelligenceView(_threatIntel, _licenseService, _analyzer, _settingsDb);

                // Update license badge
                UpdateLicenseBadge();

                // Initialize and start status bar updates
                InitializeStatusBar();
                StartStatusBarTimer();

                // Navigate to the Home dashboard by default
                _activeNavButton = NavHome;
                MainFrame.Navigate(_homeView);

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
            // The badge used to be hardcoded to "!" or "1" no matter how many threats were found.
            var count = System.Threading.Interlocked.Increment(ref _sessionThreatCount);
            Dispatcher.Invoke(() => ShowThreatBadge(count));
        }

        private void ProcessGuard_ThreatDetected(object? sender, Models.ThreatInfo threat)
        {
            var count = System.Threading.Interlocked.Increment(ref _sessionThreatCount);
            Dispatcher.Invoke(() =>
            {
                ShowThreatBadge(count);
                if (_showNotifications && !_gamingMode.NotificationsSuppressed)
                    SetStatusBarMessage($"Real-time: {threat.Name} — {threat.Description}");
            });
        }

        private void ShowThreatBadge(int count)
        {
            ThreatCountBadge.Visibility = Visibility.Visible;
            ThreatCountText.Text = count > 99 ? "99+" : count.ToString();
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
                case "Home":
                    MainFrame.Navigate(_homeView);
                    _homeView?.RefreshStats();
                    break;
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

        private void LoadVariantBlocklistsIntoAnalyzer()
        {
            try
            {
                _analyzer.SetBadImphashes(_threatIntel.GetBadImphashes());
                _analyzer.SetBadFuzzyHashes(_threatIntel.GetBadFuzzyHashes());
            }
            catch (Exception ex) { _logger.Debug(ex, "Loading variant blocklists failed"); }
        }

        private void ThreatIntel_UpdateCompleted(object? sender, ThreatIntelCompleteEventArgs e)
        {
            // Re-import the freshly downloaded hashes into the live scanner so an update takes effect now.
            _ = _threatIntel.ImportHashesIntoAsync(_analyzer.SignatureDatabase);
            LoadVariantBlocklistsIntoAnalyzer();

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
                // Let stale local reputation decay toward neutral so old mistakes heal over time.
                try { _reputation.DecayOldReputations(); } catch { /* non-critical */ }

                // Defender coexistence: stop Defender from quarantining OUR OWN app (self-exclusion only —
                // we never disable Defender's protection of the machine). Logs what AV is registered.
                try
                {
                    var defStatus = await _defender.GetStatusAsync();
                    _logger.Information("Defender status: realtime={RT}, tamperProtected={Tamper}, registeredAVs=[{AVs}], appExcluded={Excl}",
                        defStatus.DefenderRealtimeEnabled, defStatus.TamperProtectionEnabled,
                        string.Join(", ", defStatus.RegisteredAntiviruses), defStatus.SelfExcluded);

                    if (AppConfiguration.Settings.Defender.AddSelfExclusionOnStartup && !defStatus.SelfExcluded)
                        await _defender.EnsureSelfExclusionAsync();
                }
                catch (Exception ex) { _logger.Warning(ex, "Defender integration check failed"); }

                // Threat-intel library: make the downloaded hashes ACTUALLY used by the scanner, and
                // (optionally) refresh feeds in the background on startup.
                try
                {
                    var ti = AppConfiguration.Settings.ThreatIntel;
                    if (ti.AutoUpdateOnStartup)
                    {
                        _ = Task.Run(async () =>
                        {
                            try
                            {
                                await _threatIntel.UpdateAllAsync(_licenseService.GetCurrentTier());
                                await _threatIntel.ImportHashesIntoAsync(_analyzer.SignatureDatabase);
                                LoadVariantBlocklistsIntoAnalyzer();
                            }
                            catch (Exception ex) { _logger.Warning(ex, "Startup threat-intel update failed"); }
                        });
                    }
                    else
                    {
                        // Import whatever is already cached (no network).
                        _ = _threatIntel.ImportHashesIntoAsync(_analyzer.SignatureDatabase);
                        LoadVariantBlocklistsIntoAnalyzer();
                    }
                }
                catch (Exception ex) { _logger.Warning(ex, "Threat-intel startup wiring failed"); }

                // Load the FULL user settings (not just the six startup flags) and push every one of
                // them into the live services. Previously most of the Settings screen was write-only.
                var settings = Views.UserSettings.Load(_settingsDb);

                ApplyUserSettings(settings, isStartup: true);

                // Updates:CheckForUpdatesOnStartup and the user's "Check for updates" checkbox were
                // both ignored - the check fired unconditionally from App.OnStartup. Honour them now.
                if (AppConfiguration.Settings.Updates.CheckForUpdatesOnStartup && settings.CheckForUpdates)
                {
                    Dispatcher.Invoke(() => (Application.Current as App)?.RunStartupUpdateCheck());
                }
                else
                {
                    _logger.Information("Startup update check skipped (disabled in settings)");
                }

                // Self-protection has an async init, so it stays here rather than in the applier.
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
            }
            catch (Exception ex)
            {
                _logger.Warning(ex, "Error initializing new services");
            }
        }

        private void SettingsView_SettingsApplied(object? sender, Views.UserSettings settings)
        {
            try
            {
                ApplyUserSettings(settings, isStartup: false);
                SetStatusBarMessage("Settings applied");
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Failed to apply settings to running services");
                SetStatusBarMessage($"Some settings could not be applied: {ex.Message}");
            }
        }

        /// <summary>
        /// Push a settings snapshot into every running service.
        /// <paramref name="isStartup"/> selects the Startup* flags (which decide whether a service runs
        /// at all when the app launches); afterwards the live toggles are authoritative.
        /// </summary>
        private void ApplyUserSettings(Views.UserSettings settings, bool isStartup)
        {
            _showNotifications = settings.ShowNotifications;

            // --- Logging ---
            try
            {
                LoggingService.SetMinimumLevel(settings.GetLogLevel());
                LoggingService.SetLoggingEnabled(settings.EnableLogging);
            }
            catch (Exception ex) { _logger.Warning(ex, "Applying logging settings failed"); }

            // --- Detection sensitivity ---
            try { _analyzer.MinimumScoreToReport = settings.GetMinimumThreatScore(); }
            catch (Exception ex) { _logger.Warning(ex, "Applying sensitivity failed"); }

            // --- Backup retention / quota ---
            try
            {
                _backupManager.RetentionDays = settings.GetBackupRetentionDays();
                _backupManager.MaxBackupSizeMB = settings.GetMaxBackupSizeMB();
                _backupManager.CleanOldBackups();
            }
            catch (Exception ex) { _logger.Warning(ex, "Applying backup settings failed"); }

            // --- Scanning ---
            try
            {
                _scanner.ScanNetworkDrives = settings.ScanNetworkDrives;
                _scanView?.ApplyUserSettings(settings);
            }
            catch (Exception ex) { _logger.Warning(ex, "Applying scan settings failed"); }

            // --- Real-time protection ---
            try
            {
                _protection.ProcessMonitoringEnabled = settings.MonitorProcesses;
                _protection.NetworkMonitoringEnabled = settings.MonitorNetwork;
                _protection.FileMonitoringEnabled = true;
                _protection.RegistryMonitoringEnabled = true;

                var wantRealtime = isStartup
                    ? settings.StartupRealtimeProtection && settings.RealtimeProtection
                    : settings.RealtimeProtection;

                SetServiceState(wantRealtime, _protection.IsRunning,
                    () => { _protection.Start(); _processGuard.Start(); },
                    () => { _protection.Stop(); _processGuard.Stop(); },
                    "Real-time protection");

                _monitorView?.RefreshUI();
            }
            catch (Exception ex) { _logger.Warning(ex, "Applying real-time protection settings failed"); }

            // NOTE: "Monitor network activity" deliberately controls only the passive layer above.
            // Web protection is left to its own screen because starting it rewrites the system hosts
            // file, which is far too big a side effect for a checkbox in a settings list.

            // --- Gaming mode ---
            try
            {
                _gamingMode.AutoDetectEnabled = settings.AutoDetectGames;
                _gamingMode.SuppressNotifications = settings.SuppressGamingNotifications;

                var wantGaming = isStartup
                    ? settings.StartupGamingMode && settings.GamingModeEnabled
                    : settings.GamingModeEnabled;

                SetServiceState(wantGaming, _gamingMode.IsRunning,
                    () => _gamingMode.Start(), () => _gamingMode.Stop(), "Gaming Mode");
            }
            catch (Exception ex) { _logger.Warning(ex, "Applying gaming mode settings failed"); }

            // --- USB protection ---
            try
            {
                _usbScan.AutoScanEnabled = settings.AutoScanUsb;
                _usbScan.BlockAutorun = settings.BlockAutorun;

                // The Settings screen only offers a startup flag for USB (plus behaviour options),
                // so a later save adjusts behaviour without yanking the watcher up or down.
                if (isStartup)
                {
                    SetServiceState(settings.StartupUsbProtection, _usbScan.IsEnabled,
                        () => _usbScan.Start(), () => _usbScan.Stop(), "USB protection");
                }
            }
            catch (Exception ex) { _logger.Warning(ex, "Applying USB settings failed"); }

            // --- Ransomware protection ---
            try
            {
                _ransomwareProtection.HoneypotFilesEnabled = settings.HoneypotFiles;

                var wantRansomware = isStartup
                    ? settings.StartupRansomwareProtection && settings.RansomwareProtection
                    : settings.RansomwareProtection;

                SetServiceState(wantRansomware, _ransomwareProtection.IsEnabled,
                    () => _ransomwareProtection.Start(), () => _ransomwareProtection.Stop(),
                    "Ransomware protection");
            }
            catch (Exception ex) { _logger.Warning(ex, "Applying ransomware settings failed"); }

            // --- Scheduled scans ---
            try
            {
                var wantScheduled = isStartup
                    ? settings.StartupScheduledScans || settings.ScheduledScansEnabled
                    : settings.ScheduledScansEnabled;

                SetServiceState(wantScheduled, _scheduledScan.IsRunning,
                    () => _scheduledScan.Start(), () => _scheduledScan.Stop(), "Scheduled scans");
            }
            catch (Exception ex) { _logger.Warning(ex, "Applying scheduled scan settings failed"); }

            // --- Signature / threat-intel update cadence ---
            try
            {
                var hours = settings.GetUpdateFrequencyHours();

                _signatureUpdate.AutoUpdate = settings.AutoUpdateDatabase;
                _signatureUpdate.UpdateInterval = TimeSpan.FromHours(hours);

                if (settings.AutoUpdateDatabase)
                {
                    _signatureUpdate.StartAutoUpdate();
                    _threatIntel.StartAutoUpdate(TimeSpan.FromHours(hours), _licenseService.GetCurrentTier());
                }
                else
                {
                    _signatureUpdate.StopAutoUpdate();
                    _threatIntel.StopAutoUpdate();
                }
            }
            catch (Exception ex) { _logger.Warning(ex, "Applying update settings failed"); }

            _logger.Information("User settings applied to running services (startup={Startup})", isStartup);
        }

        /// <summary>Start or stop a service only when its desired state differs from the current one.</summary>
        private void SetServiceState(bool wanted, bool running, Action start, Action stop, string name)
        {
            if (wanted == running) return;

            if (wanted)
            {
                start();
                _logger.Information("{Service} started", name);
            }
            else
            {
                stop();
                _logger.Information("{Service} stopped", name);
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
                ShowThreatBadge(System.Threading.Interlocked.Increment(ref _sessionThreatCount));
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

        private int _statusBarTicks;

        private void StatusBarTimer_Tick(object? sender, EventArgs e)
        {
            UpdateStatusBarTime();
            // Update protection status every second to catch any changes
            UpdateAllProtectionStatus();

            // Connectivity was previously sampled once at startup, so the indicator stayed frozen on
            // whatever the state happened to be when the app launched. Re-check every 5 seconds.
            if (++_statusBarTicks % 5 == 0)
                UpdateStatusBarConnection();
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
                _signatureUpdate?.Dispose();
                _threatIntel?.Dispose();

                if (_processGuard != null)
                {
                    _processGuard.ThreatDetected -= ProcessGuard_ThreatDetected;
                    _processGuard.Dispose();
                }

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
