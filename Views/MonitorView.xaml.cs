using System;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Shapes;
using SkidrowKiller.Services;

namespace SkidrowKiller.Views
{
    public partial class MonitorView : Page, IDisposable
    {
        private readonly ProtectionService _protection;
        private CancellationTokenSource? _animationCts;
        private CancellationTokenSource? _statsCts;
        private bool _isDisposed;

        // Stats history for graphs (separate for each monitor type)
        private readonly double[] _processHistory = new double[8];
        private readonly double[] _networkHistory = new double[8];
        private readonly double[] _fileHistory = new double[8];
        private readonly double[] _registryHistory = new double[8];
        private int _historyIndex = 0;

        public MonitorView(ProtectionService protection)
        {
            InitializeComponent();
            _protection = protection;

            _protection.LogAdded += Protection_LogAdded;
            _protection.StatusChanged += Protection_StatusChanged;
            _protection.AlertRaised += Protection_AlertRaised;

            Loaded += MonitorView_Loaded;
            Unloaded += MonitorView_Unloaded;

            UpdateUI();
        }

        private void MonitorView_Loaded(object sender, RoutedEventArgs e)
        {
            if (_protection.IsRunning)
            {
                StartAnimations();
            }
            StartStatsUpdater();
        }

        private void MonitorView_Unloaded(object sender, RoutedEventArgs e)
        {
            StopAnimations();
            StopStatsUpdater();
        }

        #region Animations

        private void StartAnimations()
        {
            StopAnimations();
            _animationCts = new CancellationTokenSource();
            Task.Run(() => RunRotationAnimation(_animationCts.Token));
            Task.Run(() => RunScanLineAnimation(_animationCts.Token));
            Task.Run(() => RunGlowAnimation(_animationCts.Token));
        }

        private void StopAnimations()
        {
            _animationCts?.Cancel();
            _animationCts?.Dispose();
            _animationCts = null;
        }

        private async Task RunRotationAnimation(CancellationToken token)
        {
            double angle = 0;
            while (!token.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(50, token);
                    angle = (angle + 1) % 360;

                    await Dispatcher.InvokeAsync(() =>
                    {
                        if (RingRotation != null)
                            RingRotation.Angle = angle;
                    });
                }
                catch (OperationCanceledException) { break; }
                catch { }
            }
        }

        private async Task RunScanLineAnimation(CancellationToken token)
        {
            double y = 0;
            bool forward = true;

            await Dispatcher.InvokeAsync(() =>
            {
                if (ScanLine != null) ScanLine.Opacity = 0.8;
            });

            while (!token.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(30, token);

                    if (forward)
                    {
                        y += 2;
                        if (y >= 100) forward = false;
                    }
                    else
                    {
                        y -= 2;
                        if (y <= 0) forward = true;
                    }

                    await Dispatcher.InvokeAsync(() =>
                    {
                        if (ScanLineTransform != null)
                            ScanLineTransform.Y = y;
                    });
                }
                catch (OperationCanceledException) { break; }
                catch { }
            }
        }

        private async Task RunGlowAnimation(CancellationToken token)
        {
            double opacity = 0.3;
            bool increasing = true;

            while (!token.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(50, token);

                    if (increasing)
                    {
                        opacity += 0.01;
                        if (opacity >= 0.7) increasing = false;
                    }
                    else
                    {
                        opacity -= 0.01;
                        if (opacity <= 0.3) increasing = true;
                    }

                    await Dispatcher.InvokeAsync(() =>
                    {
                        if (ShieldGlow != null)
                            ShieldGlow.Opacity = opacity;
                    });
                }
                catch (OperationCanceledException) { break; }
                catch { }
            }
        }

        #endregion

        #region Stats Updater

        private void StartStatsUpdater()
        {
            StopStatsUpdater();
            _statsCts = new CancellationTokenSource();
            Task.Run(() => UpdateStatsLoop(_statsCts.Token));
        }

        private void StopStatsUpdater()
        {
            _statsCts?.Cancel();
            _statsCts?.Dispose();
            _statsCts = null;
        }

        private async Task UpdateStatsLoop(CancellationToken token)
        {
            var currentProcess = Process.GetCurrentProcess();

            while (!token.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(2000, token);

                    // Get REAL stats from protection service
                    var processCount = _protection.ProcessesScanned;
                    var networkCount = _protection.NetworkConnections;
                    var filesCount = _protection.FilesWatched;
                    var registryCount = _protection.RegistryKeysChecked;

                    // Update history for all 4 graphs
                    _processHistory[_historyIndex] = processCount;
                    _networkHistory[_historyIndex] = networkCount;
                    _fileHistory[_historyIndex] = filesCount;
                    _registryHistory[_historyIndex] = registryCount;
                    _historyIndex = (_historyIndex + 1) % 8;

                    // Get memory usage of this app
                    currentProcess.Refresh();
                    var memoryMb = currentProcess.WorkingSet64 / 1024 / 1024;

                    // Rough CPU estimate based on process activity
                    var cpuEstimate = _protection.IsRunning ? Math.Min(5, processCount / 50.0) : 0;

                    await Dispatcher.InvokeAsync(() =>
                    {
                        if (_isDisposed) return;

                        // Update stats cards with REAL values
                        ProcessCountLabel.Text = processCount.ToString();
                        NetworkCountLabel.Text = networkCount.ToString();
                        FileCountLabel.Text = filesCount.ToString();
                        RegistryCountLabel.Text = registryCount.ToString();

                        // Update status bar
                        CpuLabel.Text = $"{cpuEstimate:F1}%";
                        MemoryLabel.Text = $"{memoryMb} MB";
                        LastUpdateLabel.Text = DateTime.Now.ToString("HH:mm:ss");

                        // Alert and scanned counts
                        AlertCountLabel.Text = _protection.AlertCount.ToString();
                        ScannedCountLabel.Text = processCount.ToString();
                        BlockedCountLabel.Text = _protection.BlockedThreats.ToString();

                        if (_protection.IsRunning)
                        {
                            ActivityText.Text = $"Monitoring {processCount} processes, {networkCount} connections";
                        }
                        else
                        {
                            ActivityText.Text = "Protection disabled";
                        }

                        // Update all 4 graphs with real data
                        UpdateGraph(ProcessGraphLine, _processHistory, Math.Max(400, processCount * 1.5));
                        UpdateGraph(NetworkGraphLine, _networkHistory, Math.Max(100, networkCount * 1.5));
                        UpdateGraph(FileGraphLine, _fileHistory, Math.Max(50, filesCount * 1.5));
                        UpdateGraph(RegistryGraphLine, _registryHistory, Math.Max(20, registryCount * 1.5));
                    });
                }
                catch (OperationCanceledException) { break; }
                catch { }
            }
        }

        private void UpdateGraph(Polyline line, double[] history, double maxValue)
        {
            try
            {
                var points = new PointCollection();
                double width = 70;
                double height = 25;
                double step = width / 7;

                for (int i = 0; i < 8; i++)
                {
                    int idx = (_historyIndex + i) % 8;
                    double value = history[idx];
                    double normalizedY = height - (value / maxValue * height);
                    normalizedY = Math.Max(5, Math.Min(height, normalizedY));
                    points.Add(new Point(i * step, normalizedY));
                }

                line.Points = points;
            }
            catch { }
        }

        #endregion

        #region UI Events

        private void ToggleButton_Click(object sender, RoutedEventArgs e)
        {
            if (_protection.IsRunning)
            {
                _protection.Stop();
                StopAnimations();
                Dispatcher.Invoke(() =>
                {
                    if (ScanLine != null) ScanLine.Opacity = 0;
                    UpdateShieldColor(false);
                });
            }
            else
            {
                _protection.Start();
                StartAnimations();
                Dispatcher.Invoke(() =>
                {
                    UpdateShieldColor(true);
                });
            }
            UpdateUI();
        }

        private void ClearLog_Click(object sender, RoutedEventArgs e)
        {
            LogTextBox.Clear();
        }

        #endregion

        #region UI Updates

        private void UpdateUI()
        {
            if (_protection.IsRunning)
            {
                StatusLabel.Text = "Protection Active";
                StatusDescription.Text = "Real-time monitoring is active. Your system is protected.";
                ToggleButton.Content = "Stop Protection";
                ToggleButton.Style = (Style)FindResource("DangerButtonStyle");
                UpdateStatusIndicator(_protection.CurrentStatus);

                StatusBarText.Text = "Protection Active";
                StatusBarIndicator.Fill = (Brush)FindResource("GreenPrimaryBrush");
                LogIndicator.Fill = (Brush)FindResource("GreenPrimaryBrush");

                UpdateShieldColor(true);
            }
            else
            {
                StatusLabel.Text = "Protection Stopped";
                StatusLabel.Foreground = (Brush)FindResource("TextTertiaryBrush");
                StatusDescription.Text = "Real-time monitoring is disabled. Click to start protection.";
                StatusIndicator.Fill = (Brush)FindResource("TextTertiaryBrush");
                ToggleButton.Content = "Start Protection";
                ToggleButton.Style = (Style)FindResource("SuccessButtonStyle");

                StatusBarText.Text = "Protection Disabled";
                StatusBarIndicator.Fill = (Brush)FindResource("TextTertiaryBrush");
                LogIndicator.Fill = (Brush)FindResource("TextTertiaryBrush");

                UpdateShieldColor(false);
            }

            AlertCountLabel.Text = _protection.AlertCount.ToString();
            BlockedCountLabel.Text = _protection.BlockedThreats.ToString();
        }

        public void RefreshUI()
        {
            UpdateUI();
            if (_protection.IsRunning)
            {
                StartAnimations();
            }
        }

        private void UpdateStatusIndicator(ProtectionStatus status)
        {
            Brush statusBrush;
            Color glowColor;

            switch (status)
            {
                case ProtectionStatus.Safe:
                    statusBrush = (Brush)FindResource("SuccessBrush");
                    glowColor = Color.FromArgb(64, 102, 187, 106);
                    break;
                case ProtectionStatus.Warning:
                    statusBrush = (Brush)FindResource("WarningBrush");
                    glowColor = Color.FromArgb(64, 255, 183, 77);
                    break;
                case ProtectionStatus.Critical:
                    statusBrush = (Brush)FindResource("DangerBrush");
                    glowColor = Color.FromArgb(64, 244, 67, 54);
                    break;
                default:
                    statusBrush = (Brush)FindResource("TextTertiaryBrush");
                    glowColor = Color.FromArgb(64, 102, 187, 106);
                    break;
            }

            StatusIndicator.Fill = statusBrush;
            StatusLabel.Foreground = statusBrush;
            StatusBarIndicator.Fill = statusBrush;
            UpdateShieldGlowColor(glowColor);
        }

        private void UpdateShieldGlowColor(Color color)
        {
            try
            {
                var brush = new RadialGradientBrush
                {
                    GradientOrigin = new Point(0.5, 0.5),
                    Center = new Point(0.5, 0.5)
                };
                brush.GradientStops.Add(new GradientStop(color, 0));
                brush.GradientStops.Add(new GradientStop(Colors.Transparent, 1));
                ShieldGlow.Fill = brush;
            }
            catch { }
        }

        private void UpdateShieldColor(bool isActive)
        {
            try
            {
                if (isActive)
                {
                    var brush = new LinearGradientBrush
                    {
                        StartPoint = new Point(0, 0),
                        EndPoint = new Point(1, 1)
                    };
                    brush.GradientStops.Add(new GradientStop(Color.FromRgb(102, 187, 106), 0));
                    brush.GradientStops.Add(new GradientStop(Color.FromRgb(41, 182, 246), 1));
                    ShieldIcon.Fill = brush;
                }
                else
                {
                    ShieldIcon.Fill = (Brush)FindResource("TextTertiaryBrush");
                }
            }
            catch { }
        }

        #endregion

        #region Protection Events

        private void Protection_LogAdded(object? sender, string message)
        {
            Dispatcher.Invoke(() =>
            {
                LogTextBox.AppendText($"[{DateTime.Now:HH:mm:ss}] {message}\n");
                LogTextBox.ScrollToEnd();
                BlinkLogIndicator();
            });
        }

        private async void BlinkLogIndicator()
        {
            try
            {
                var originalBrush = LogIndicator.Fill;
                LogIndicator.Fill = (Brush)FindResource("CyanPrimaryBrush");
                await Task.Delay(200);
                if (!_isDisposed)
                    LogIndicator.Fill = originalBrush;
            }
            catch { }
        }

        private void Protection_StatusChanged(object? sender, ProtectionStatus status)
        {
            Dispatcher.Invoke(() =>
            {
                UpdateStatusIndicator(status);
                AlertCountLabel.Text = _protection.AlertCount.ToString();
            });
        }

        private void Protection_AlertRaised(object? sender, ProtectionAlert alert)
        {
            Dispatcher.Invoke(() =>
            {
                AlertCountLabel.Text = _protection.AlertCount.ToString();
                BlockedCountLabel.Text = _protection.BlockedThreats.ToString();

                if (alert.Status == ProtectionStatus.Critical)
                {
                    FlashShieldRed();

                    MessageBox.Show(
                        $"{alert.Description}\n\n{alert.Details}",
                        "Security Alert",
                        MessageBoxButton.OK,
                        MessageBoxImage.Warning);
                }
            });
        }

        private async void FlashShieldRed()
        {
            try
            {
                var originalBrush = ShieldIcon.Fill;
                for (int i = 0; i < 3; i++)
                {
                    ShieldIcon.Fill = (Brush)FindResource("DangerBrush");
                    await Task.Delay(200);
                    ShieldIcon.Fill = originalBrush;
                    await Task.Delay(200);
                }
            }
            catch { }
        }

        #endregion

        public void Dispose()
        {
            if (_isDisposed) return;
            _isDisposed = true;

            StopAnimations();
            StopStatsUpdater();

            _protection.LogAdded -= Protection_LogAdded;
            _protection.StatusChanged -= Protection_StatusChanged;
            _protection.AlertRaised -= Protection_AlertRaised;
        }
    }
}
