using System;
using System.Collections.ObjectModel;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using SkidrowKiller.Services;

namespace SkidrowKiller.Views
{
    public partial class NetworkProtectionView : Page, IDisposable
    {
        private readonly NetworkProtectionService _networkProtection;
        private readonly ThreatAnalyzer _analyzer;
        private readonly QuarantineService? _quarantine;
        private CancellationTokenSource? _animationCts;
        private CancellationTokenSource? _statsCts;
        private bool _isDisposed;

        public ObservableCollection<BlockedConnectionDisplay> BlockedConnections { get; } = new();

        // Category counters
        private int _warezBlocked;
        private int _crackBlocked;
        private int _torrentBlocked;

        public NetworkProtectionView(NetworkProtectionService networkProtection, ThreatAnalyzer analyzer, QuarantineService? quarantine = null)
        {
            InitializeComponent();
            _networkProtection = networkProtection;
            _analyzer = analyzer;
            _quarantine = quarantine;

            BlockedConnectionsList.ItemsSource = BlockedConnections;

            _networkProtection.LogAdded += NetworkProtection_LogAdded;
            _networkProtection.ConnectionBlocked += NetworkProtection_ConnectionBlocked;
            _networkProtection.StatusChanged += NetworkProtection_StatusChanged;

            Loaded += NetworkProtectionView_Loaded;
            Unloaded += NetworkProtectionView_Unloaded;

            UpdateUI();
        }

        private void NetworkProtectionView_Loaded(object sender, RoutedEventArgs e)
        {
            if (_networkProtection.IsRunning)
            {
                StartAnimations();
            }
            StartStatsUpdater();
        }

        private void NetworkProtectionView_Unloaded(object sender, RoutedEventArgs e)
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
                        if (GlobeGlow != null)
                            GlobeGlow.Opacity = opacity;
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
            while (!token.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(2000, token);

                    await Dispatcher.InvokeAsync(() =>
                    {
                        if (_isDisposed) return;

                        BlockedCountLabel.Text = _networkProtection.BlockedConnections.ToString();
                        DomainsCountLabel.Text = _networkProtection.DomainsInDatabase.ToString();
                        ChecksCountLabel.Text = _networkProtection.TotalChecks.ToString();

                        WarezBlockedLabel.Text = _warezBlocked.ToString();
                        CrackBlockedLabel.Text = _crackBlocked.ToString();
                        TorrentBlockedLabel.Text = _torrentBlocked.ToString();
                        HostsBlockedLabel.Text = _networkProtection.DomainsInDatabase.ToString();

                        if (_networkProtection.IsRunning)
                        {
                            ActivityText.Text = $"Monitoring network traffic • {_networkProtection.TotalChecks} checks";
                        }
                        else
                        {
                            ActivityText.Text = "Web protection disabled";
                        }
                    });
                }
                catch (OperationCanceledException) { break; }
                catch { }
            }
        }

        #endregion

        #region UI Events

        private void ToggleButton_Click(object sender, RoutedEventArgs e)
        {
            if (_networkProtection.IsRunning)
            {
                _networkProtection.Stop();
                StopAnimations();
            }
            else
            {
                _networkProtection.Start();
                StartAnimations();
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
            if (_networkProtection.IsRunning)
            {
                StatusLabel.Text = "Web Protection Active";
                StatusDescription.Text = "Blocking connections to malicious domains and warez sites.";
                ToggleButton.Content = "Stop Protection";
                ToggleButton.Style = (Style)FindResource("DangerButtonStyle");

                var successBrush = (Brush)FindResource("SuccessBrush");
                StatusIndicator.Fill = successBrush;
                StatusLabel.Foreground = successBrush;
                StatusBarIndicator.Fill = successBrush;
                StatusBarText.Text = "Web Protection Active";
                LogIndicator.Fill = (Brush)FindResource("GreenPrimaryBrush");

                HostsStatusLabel.Text = _networkProtection.HostsFileProtection ? "Protected" : "Not Modified";
                HostsStatusLabel.Foreground = _networkProtection.HostsFileProtection
                    ? (Brush)FindResource("GreenPrimaryBrush")
                    : (Brush)FindResource("TextSecondaryBrush");

                UpdateGlobeColor(true);
            }
            else
            {
                StatusLabel.Text = "Web Protection Disabled";
                StatusLabel.Foreground = (Brush)FindResource("TextTertiaryBrush");
                StatusDescription.Text = "Click to start blocking malicious domains and warez sites.";
                StatusIndicator.Fill = (Brush)FindResource("TextTertiaryBrush");
                ToggleButton.Content = "Start Protection";
                ToggleButton.Style = (Style)FindResource("SuccessButtonStyle");

                StatusBarText.Text = "Web Protection Disabled";
                StatusBarIndicator.Fill = (Brush)FindResource("TextTertiaryBrush");
                LogIndicator.Fill = (Brush)FindResource("TextTertiaryBrush");

                HostsStatusLabel.Text = "Not Active";
                HostsStatusLabel.Foreground = (Brush)FindResource("TextSecondaryBrush");

                UpdateGlobeColor(false);
            }

            BlockedCountLabel.Text = _networkProtection.BlockedConnections.ToString();
            DomainsCountLabel.Text = _networkProtection.DomainsInDatabase.ToString();
            ChecksCountLabel.Text = _networkProtection.TotalChecks.ToString();
        }

        public void RefreshUI()
        {
            UpdateUI();
            if (_networkProtection.IsRunning)
            {
                StartAnimations();
            }
        }

        private void UpdateGlobeColor(bool isActive)
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
                    brush.GradientStops.Add(new GradientStop(Color.FromRgb(41, 182, 246), 0));
                    brush.GradientStops.Add(new GradientStop(Color.FromRgb(102, 187, 106), 1));
                    GlobeIconPath.Fill = brush;
                }
                else
                {
                    GlobeIconPath.Fill = (Brush)FindResource("TextTertiaryBrush");
                }
            }
            catch { }
        }

        #endregion

        #region Network Protection Events

        private void NetworkProtection_LogAdded(object? sender, string message)
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

        private void NetworkProtection_ConnectionBlocked(object? sender, NetworkBlockedEvent e)
        {
            Dispatcher.Invoke(() =>
            {
                // Update category counters
                if (e.Category.Contains("Warez"))
                    _warezBlocked++;
                else if (e.Category.Contains("Crack") || e.Category.Contains("Keygen"))
                    _crackBlocked++;
                else if (e.Category.Contains("Torrent"))
                    _torrentBlocked++;

                // Add to list
                BlockedConnections.Insert(0, new BlockedConnectionDisplay
                {
                    Domain = e.Domain,
                    Category = e.Category,
                    ProcessId = e.ProcessId,
                    ProcessName = e.ProcessName,
                    TimeString = e.Timestamp.ToString("HH:mm:ss")
                });

                // Keep only last 50 entries
                while (BlockedConnections.Count > 50)
                {
                    BlockedConnections.RemoveAt(BlockedConnections.Count - 1);
                }

                // Update last block
                LastBlockLabel.Text = $"{e.Domain} ({e.Timestamp:HH:mm})";

                // Flash globe red
                FlashGlobeRed();
            });
        }

        private void NetworkProtection_StatusChanged(object? sender, ProtectionStatus status)
        {
            Dispatcher.Invoke(() =>
            {
                switch (status)
                {
                    case ProtectionStatus.Warning:
                        StatusIndicator.Fill = (Brush)FindResource("WarningBrush");
                        StatusLabel.Foreground = (Brush)FindResource("WarningBrush");
                        break;
                    case ProtectionStatus.Critical:
                        StatusIndicator.Fill = (Brush)FindResource("DangerBrush");
                        StatusLabel.Foreground = (Brush)FindResource("DangerBrush");
                        break;
                    default:
                        if (_networkProtection.IsRunning)
                        {
                            StatusIndicator.Fill = (Brush)FindResource("SuccessBrush");
                            StatusLabel.Foreground = (Brush)FindResource("SuccessBrush");
                        }
                        break;
                }
            });
        }

        private async void FlashGlobeRed()
        {
            try
            {
                var originalBrush = GlobeIconPath.Fill;
                for (int i = 0; i < 2; i++)
                {
                    GlobeIconPath.Fill = (Brush)FindResource("DangerBrush");
                    await Task.Delay(150);
                    GlobeIconPath.Fill = originalBrush;
                    await Task.Delay(150);
                }
            }
            catch { }
        }

        #endregion

        #region Analysis & Deep Scan

        private void BlockedConnectionsList_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
        {
            // Selection changed - buttons visibility handled by binding
        }

        private async void AnalyzeConnection_Click(object sender, RoutedEventArgs e)
        {
            if (sender is not System.Windows.Controls.Button button) return;
            if (button.Tag is not BlockedConnectionDisplay connection) return;

            button.IsEnabled = false;
            button.Content = "Analyzing...";

            try
            {
                RaiseLog($"Starting source analysis for {connection.Domain}...");

                var result = await _networkProtection.AnalyzeSourceAsync(connection.ProcessId, connection.Domain);

                if (result.Success)
                {
                    RaiseLog($"Analysis complete:");
                    RaiseLog($"  Root Cause: {result.RootCause}");
                    RaiseLog($"  Threat Level: {result.ThreatLevel}/10");
                    RaiseLog($"  Recommendation: {result.Recommendation}");

                    // Ask user if they want to deep scan
                    var msgResult = System.Windows.MessageBox.Show(
                        $"Source Analysis Complete\n\n" +
                        $"Process: {result.ProcessName}\n" +
                        $"Path: {result.ProcessPath}\n" +
                        $"Root Cause: {result.RootCause}\n" +
                        $"Threat Level: {result.ThreatLevel}/10\n\n" +
                        $"Recommendation: {result.Recommendation}\n\n" +
                        $"Do you want to perform a Deep Scan to find all related malicious files?",
                        "Source Analysis Complete",
                        System.Windows.MessageBoxButton.YesNo,
                        System.Windows.MessageBoxImage.Warning);

                    if (msgResult == System.Windows.MessageBoxResult.Yes)
                    {
                        await PerformDeepScanAsync(result);
                    }
                }
                else
                {
                    RaiseLog($"Analysis failed: {result.Error}");
                }
            }
            catch (Exception ex)
            {
                RaiseLog($"Error during analysis: {ex.Message}");
            }
            finally
            {
                button.IsEnabled = true;
                button.Content = "Analyze";
            }
        }

        private async void DeepScanSelected_Click(object sender, RoutedEventArgs e)
        {
            if (BlockedConnectionsList.SelectedItem is not BlockedConnectionDisplay connection) return;

            DeepScanButton.IsEnabled = false;
            DeepScanButton.Content = "Scanning...";

            try
            {
                var sourceResult = await _networkProtection.AnalyzeSourceAsync(connection.ProcessId, connection.Domain);
                if (sourceResult.Success)
                {
                    await PerformDeepScanAsync(sourceResult);
                }
            }
            finally
            {
                DeepScanButton.IsEnabled = true;
                DeepScanButton.Content = "Deep Scan Selected";
            }
        }

        private async Task PerformDeepScanAsync(SourceAnalysisResult sourceResult)
        {
            RaiseLog("Starting deep scan...");

            var deepScanResult = await _networkProtection.DeepScanAsync(sourceResult);

            if (deepScanResult.Success)
            {
                if (deepScanResult.MaliciousFiles.Count > 0)
                {
                    var sb = new System.Text.StringBuilder();
                    sb.AppendLine($"Found {deepScanResult.MaliciousFiles.Count} malicious files:\n");

                    foreach (var file in deepScanResult.MaliciousFiles.Take(10))
                    {
                        sb.AppendLine($"  {file.FileName}");
                        sb.AppendLine($"    Threat: {file.ThreatName}");
                        sb.AppendLine($"    Action: {file.RecommendedAction}");
                        sb.AppendLine();
                    }

                    if (deepScanResult.MaliciousFiles.Count > 10)
                    {
                        sb.AppendLine($"  ... and {deepScanResult.MaliciousFiles.Count - 10} more");
                    }

                    sb.AppendLine("\nDo you want to quarantine these files?");

                    var result = System.Windows.MessageBox.Show(
                        sb.ToString(),
                        $"Deep Scan Complete - {deepScanResult.MaliciousFiles.Count} Threats Found",
                        System.Windows.MessageBoxButton.YesNo,
                        System.Windows.MessageBoxImage.Warning);

                    if (result == System.Windows.MessageBoxResult.Yes)
                    {
                        RaiseLog("Quarantining malicious files...");
                        var quarantined = 0;
                        foreach (var file in deepScanResult.MaliciousFiles)
                        {
                            if (_quarantine != null)
                            {
                                var threatInfo = new Models.ThreatInfo
                                {
                                    Name = file.ThreatName,
                                    Path = file.FilePath,
                                    Severity = Models.ThreatSeverity.High
                                };
                                var qResult = _quarantine.QuarantineFile(file.FilePath, threatInfo);
                                if (qResult.Success)
                                {
                                    quarantined++;
                                    RaiseLog($"  Quarantined: {file.FileName}");
                                }
                                else
                                {
                                    RaiseLog($"  Failed to quarantine: {file.FileName} - {qResult.Message}");
                                }
                            }
                            else
                            {
                                RaiseLog($"  Detected: {file.FileName} (quarantine not available)");
                            }
                        }
                        if (quarantined > 0)
                        {
                            RaiseLog($"Successfully quarantined {quarantined} malicious files");
                        }
                    }
                }
                else
                {
                    System.Windows.MessageBox.Show(
                        "Deep scan complete. No additional malicious files found.",
                        "Scan Complete",
                        System.Windows.MessageBoxButton.OK,
                        System.Windows.MessageBoxImage.Information);
                }
            }
        }

        private async void KillSelectedProcess_Click(object sender, RoutedEventArgs e)
        {
            if (BlockedConnectionsList.SelectedItem is not BlockedConnectionDisplay connection) return;

            var result = System.Windows.MessageBox.Show(
                $"Are you sure you want to terminate process '{connection.ProcessName}' (PID: {connection.ProcessId})?\n\n" +
                $"This will forcefully close the application.",
                "Confirm Process Termination",
                System.Windows.MessageBoxButton.YesNo,
                System.Windows.MessageBoxImage.Warning);

            if (result == System.Windows.MessageBoxResult.Yes)
            {
                try
                {
                    var process = System.Diagnostics.Process.GetProcessById(connection.ProcessId);
                    process.Kill(true);
                    RaiseLog($"Terminated process: {connection.ProcessName} (PID: {connection.ProcessId})");
                }
                catch (Exception ex)
                {
                    RaiseLog($"Failed to terminate process: {ex.Message}");
                }
            }

            await Task.CompletedTask;
        }

        private void RaiseLog(string message)
        {
            Dispatcher.Invoke(() =>
            {
                LogTextBox.AppendText($"[{DateTime.Now:HH:mm:ss}] {message}\n");
                LogTextBox.ScrollToEnd();
            });
        }

        #endregion

        public void Dispose()
        {
            if (_isDisposed) return;
            _isDisposed = true;

            StopAnimations();
            StopStatsUpdater();

            _networkProtection.LogAdded -= NetworkProtection_LogAdded;
            _networkProtection.ConnectionBlocked -= NetworkProtection_ConnectionBlocked;
            _networkProtection.StatusChanged -= NetworkProtection_StatusChanged;
        }
    }

    public class BlockedConnectionDisplay
    {
        public string Domain { get; set; } = string.Empty;
        public string Category { get; set; } = string.Empty;
        public int ProcessId { get; set; }
        public string ProcessName { get; set; } = string.Empty;
        public string TimeString { get; set; } = string.Empty;
    }
}
