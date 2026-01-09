using System;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;
using SkidrowKiller.Services;

namespace SkidrowKiller.Views
{
    public partial class GamingModeView : Page
    {
        private readonly GamingModeService _gamingModeService;
        private readonly DispatcherTimer _updateTimer;
        private int _sessionCount;
        private TimeSpan _totalGamingTime;

        public GamingModeView(GamingModeService gamingModeService)
        {
            InitializeComponent();
            _gamingModeService = gamingModeService;

            // Subscribe to events
            _gamingModeService.GamingModeChanged += OnGamingModeChanged;
            _gamingModeService.LogAdded += OnLogAdded;

            // Initialize settings UI
            ChkAutoDetect.IsChecked = _gamingModeService.AutoDetectEnabled;
            ChkSuppressNotifications.IsChecked = _gamingModeService.SuppressNotifications;
            ChkReduceIntensity.IsChecked = _gamingModeService.ReduceScanIntensity;
            ChkPauseProtection.IsChecked = _gamingModeService.PauseProtection;

            // Setup update timer for duration display
            _updateTimer = new DispatcherTimer
            {
                Interval = TimeSpan.FromSeconds(1)
            };
            _updateTimer.Tick += UpdateTimer_Tick;

            UpdateUI();
        }

        private void UpdateUI()
        {
            Dispatcher.Invoke(() =>
            {
                if (_gamingModeService.IsGamingMode)
                {
                    // Active state
                    StatusBadge.Background = new LinearGradientBrush(
                        Color.FromRgb(99, 102, 241),
                        Color.FromRgb(139, 92, 246),
                        45);
                    StatusText.Text = "Active";

                    TxtGamingStatus.Text = "Gaming Mode Active";
                    TxtGamingStatus.Foreground = FindResource("AccentPrimaryBrush") as Brush;

                    TxtCurrentGame.Text = _gamingModeService.CurrentGame ?? "Unknown Game";
                    TxtDuration.Text = $"Duration: {_gamingModeService.GamingDuration:hh\\:mm\\:ss}";
                    TxtDuration.Visibility = Visibility.Visible;

                    BtnToggleIcon.Text = "⏹";
                    BtnToggleText.Text = "Deactivate";

                    GamingIcon.Text = "🎮";

                    // Update protection status
                    if (_gamingModeService.PauseProtection)
                    {
                        TxtProtectionStatus.Text = "Paused";
                        TxtProtectionStatus.Foreground = FindResource("WarningBrush") as Brush;
                        TxtProtectionDetail.Text = "During Gaming";
                    }
                    else
                    {
                        TxtProtectionStatus.Text = "Active";
                        TxtProtectionStatus.Foreground = FindResource("SuccessBrush") as Brush;
                        TxtProtectionDetail.Text = "Reduced Intensity";
                    }

                    _updateTimer.Start();
                }
                else
                {
                    // Inactive state
                    StatusBadge.Background = FindResource("TextTertiaryBrush") as Brush;
                    StatusText.Text = "Inactive";

                    TxtGamingStatus.Text = "Gaming Mode Inactive";
                    TxtGamingStatus.Foreground = FindResource("TextPrimaryBrush") as Brush;

                    TxtCurrentGame.Text = "No game detected";
                    TxtDuration.Visibility = Visibility.Collapsed;

                    BtnToggleIcon.Text = "▶";
                    BtnToggleText.Text = "Activate";

                    GamingIcon.Text = "🎮";

                    TxtProtectionStatus.Text = "Active";
                    TxtProtectionStatus.Foreground = FindResource("SuccessBrush") as Brush;
                    TxtProtectionDetail.Text = "Full Intensity";

                    _updateTimer.Stop();
                }

                // Update stats
                TxtSessionCount.Text = _sessionCount.ToString();
                TxtTotalTime.Text = $"{_totalGamingTime.TotalHours:F1}";

                // Update monitor button
                BtnStartMonitor.Content = _gamingModeService.AutoDetectEnabled ? "Stop Monitor" : "Start Monitor";
            });
        }

        private void UpdateTimer_Tick(object? sender, EventArgs e)
        {
            if (_gamingModeService.IsGamingMode)
            {
                TxtDuration.Text = $"Duration: {_gamingModeService.GamingDuration:hh\\:mm\\:ss}";
            }
        }

        #region Event Handlers

        private void OnGamingModeChanged(object? sender, GamingModeEventArgs e)
        {
            Dispatcher.Invoke(() =>
            {
                if (e.IsEnabled)
                {
                    _sessionCount++;
                }
                else
                {
                    _totalGamingTime += _gamingModeService.GamingDuration;
                }
                UpdateUI();
            });
        }

        private void OnLogAdded(object? sender, string e)
        {
            // Could add logging UI here if needed
        }

        #endregion

        #region UI Event Handlers

        private void BtnToggleGaming_Click(object sender, RoutedEventArgs e)
        {
            _gamingModeService.ToggleGamingMode();
            UpdateUI();
        }

        private void BtnStartMonitor_Click(object sender, RoutedEventArgs e)
        {
            _gamingModeService.AutoDetectEnabled = !_gamingModeService.AutoDetectEnabled;
            ChkAutoDetect.IsChecked = _gamingModeService.AutoDetectEnabled;
            UpdateUI();
        }

        private void ChkAutoDetect_Changed(object sender, RoutedEventArgs e)
        {
            if (_gamingModeService == null) return;
            _gamingModeService.AutoDetectEnabled = ChkAutoDetect.IsChecked == true;
            UpdateUI();
        }

        private void ChkSuppressNotifications_Changed(object sender, RoutedEventArgs e)
        {
            if (_gamingModeService == null) return;
            _gamingModeService.SuppressNotifications = ChkSuppressNotifications.IsChecked == true;
        }

        private void ChkReduceIntensity_Changed(object sender, RoutedEventArgs e)
        {
            if (_gamingModeService == null) return;
            _gamingModeService.ReduceScanIntensity = ChkReduceIntensity.IsChecked == true;
        }

        private void ChkPauseProtection_Changed(object sender, RoutedEventArgs e)
        {
            if (_gamingModeService == null) return;
            if (ChkPauseProtection.IsChecked == true)
            {
                var result = MessageBox.Show(
                    "Pausing protection during gaming is not recommended as it leaves your system vulnerable.\n\n" +
                    "Are you sure you want to enable this option?",
                    "Warning - Reduced Security",
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Warning);

                if (result != MessageBoxResult.Yes)
                {
                    ChkPauseProtection.IsChecked = false;
                    return;
                }
            }
            _gamingModeService.PauseProtection = ChkPauseProtection.IsChecked == true;
            UpdateUI();
        }

        #endregion
    }
}
