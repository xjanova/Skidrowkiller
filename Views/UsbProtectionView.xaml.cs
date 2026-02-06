using System;
using System.Threading;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using SkidrowKiller.Services;

namespace SkidrowKiller.Views
{
    public partial class UsbProtectionView : Page
    {
        private readonly UsbScanService _usbService;
        private CancellationTokenSource? _scanCts;
        private int _threatsBlocked;
        private int _threatsFound;
        private int _scannedCount;

        public UsbProtectionView(UsbScanService usbService)
        {
            InitializeComponent();
            _usbService = usbService;

            // Subscribe to events
            _usbService.DeviceConnected += OnDeviceConnected;
            _usbService.DeviceRemoved += OnDeviceRemoved;
            _usbService.ScanStarted += OnScanStarted;
            _usbService.ScanCompleted += OnScanCompleted;
            _usbService.ScanProgress += OnScanProgress;
            _usbService.ThreatFound += OnThreatFound;
            _usbService.LogAdded += OnLogAdded;

            // Initialize UI
            ChkAutoScan.IsChecked = _usbService.AutoScanEnabled;
            ChkBlockAutorun.IsChecked = _usbService.BlockAutorun;

            UpdateStatus();
            RefreshDevicesList();
        }

        private void UpdateStatus()
        {
            Dispatcher.Invoke(() =>
            {
                if (_usbService.IsEnabled)
                {
                    StatusBadge.Background = FindResource("SuccessBrush") as Brush;
                    StatusText.Text = "Active";
                    BtnToggleProtection.Content = "Stop Protection";
                }
                else
                {
                    StatusBadge.Background = FindResource("TextTertiaryBrush") as Brush;
                    StatusText.Text = "Stopped";
                    BtnToggleProtection.Content = "Start Protection";
                }

                TxtDeviceCount.Text = _usbService.ConnectedDevices.Count.ToString();
                TxtScannedCount.Text = _scannedCount.ToString();
                TxtThreatsBlocked.Text = _threatsBlocked.ToString();
                TxtThreatsFound.Text = _threatsFound.ToString();
            });
        }

        private void RefreshDevicesList()
        {
            Dispatcher.Invoke(() =>
            {
                DevicesList.Items.Clear();

                if (_usbService.ConnectedDevices.Count == 0)
                {
                    NoDevicesPanel.Visibility = Visibility.Visible;
                    DevicesList.Visibility = Visibility.Collapsed;
                    return;
                }

                NoDevicesPanel.Visibility = Visibility.Collapsed;
                DevicesList.Visibility = Visibility.Visible;

                foreach (var kvp in _usbService.ConnectedDevices)
                {
                    var device = kvp.Value;
                    DevicesList.Items.Add(CreateDeviceCard(device));
                }
            });
        }

        private Border CreateDeviceCard(UsbDeviceInfo device)
        {
            var card = new Border
            {
                Background = FindResource("BgTertiaryBrush") as Brush,
                CornerRadius = new CornerRadius(8),
                Padding = new Thickness(16),
                Margin = new Thickness(0, 0, 12, 8),
                Width = 220
            };

            var stack = new StackPanel();

            // Drive letter and label
            var header = new StackPanel { Orientation = Orientation.Horizontal };
            header.Children.Add(new TextBlock
            {
                Text = device.DriveLetter,
                FontSize = 18,
                FontWeight = FontWeights.Bold,
                Foreground = FindResource("AccentPrimaryBrush") as Brush
            });
            if (!string.IsNullOrEmpty(device.VolumeLabel))
            {
                header.Children.Add(new TextBlock
                {
                    Text = $" ({device.VolumeLabel})",
                    FontSize = 14,
                    Foreground = FindResource("TextSecondaryBrush") as Brush,
                    VerticalAlignment = VerticalAlignment.Center
                });
            }
            stack.Children.Add(header);

            // Size info
            stack.Children.Add(new TextBlock
            {
                Text = $"{device.FormattedSize} - {device.FileSystem}",
                FontSize = 12,
                Foreground = FindResource("TextSecondaryBrush") as Brush,
                Margin = new Thickness(0, 4, 0, 0)
            });

            // Scan status
            var statusPanel = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 8, 0, 0) };
            var statusDot = new System.Windows.Shapes.Ellipse
            {
                Width = 8,
                Height = 8,
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(0, 0, 6, 0)
            };

            string statusText;
            if (device.LastScanned.HasValue)
            {
                statusDot.Fill = device.ThreatsFound > 0
                    ? FindResource("DangerBrush") as Brush
                    : FindResource("SuccessBrush") as Brush;
                statusText = device.ThreatsFound > 0
                    ? $"{device.ThreatsFound} threats found"
                    : "Clean";
            }
            else
            {
                statusDot.Fill = FindResource("WarningBrush") as Brush;
                statusText = "Not scanned";
            }

            statusPanel.Children.Add(statusDot);
            statusPanel.Children.Add(new TextBlock
            {
                Text = statusText,
                FontSize = 11,
                Foreground = statusDot.Fill
            });
            stack.Children.Add(statusPanel);

            // Scan button
            var scanBtn = new Button
            {
                Content = "Scan Now",
                Style = FindResource("SecondaryButtonStyle") as Style,
                Margin = new Thickness(0, 12, 0, 0),
                Padding = new Thickness(12, 6, 12, 6),
                Tag = device.DriveLetter
            };
            scanBtn.Click += BtnScanDevice_Click;
            stack.Children.Add(scanBtn);

            card.Child = stack;
            return card;
        }

        private void AddLogEntry(string message)
        {
            Dispatcher.Invoke(() =>
            {
                EmptyLogText.Visibility = Visibility.Collapsed;

                var entry = new Border
                {
                    Background = FindResource("BgTertiaryBrush") as Brush,
                    CornerRadius = new CornerRadius(4),
                    Padding = new Thickness(12, 8, 12, 8),
                    Margin = new Thickness(0, 0, 0, 4)
                };

                var stack = new StackPanel { Orientation = Orientation.Horizontal };
                stack.Children.Add(new TextBlock
                {
                    Text = DateTime.Now.ToString("HH:mm:ss"),
                    FontSize = 11,
                    Foreground = FindResource("TextTertiaryBrush") as Brush,
                    Margin = new Thickness(0, 0, 12, 0)
                });
                stack.Children.Add(new TextBlock
                {
                    Text = message,
                    FontSize = 12,
                    Foreground = FindResource("TextSecondaryBrush") as Brush,
                    TextWrapping = TextWrapping.Wrap
                });

                entry.Child = stack;
                LogPanel.Children.Insert(0, entry);

                // Keep only last 100 entries
                while (LogPanel.Children.Count > 101)
                {
                    LogPanel.Children.RemoveAt(LogPanel.Children.Count - 1);
                }
            });
        }

        #region Event Handlers

        private void OnDeviceConnected(object? sender, UsbDeviceEventArgs e)
        {
            AddLogEntry($"USB connected: {e.Device.DriveLetter} ({e.Device.VolumeLabel}) - {e.Device.FormattedSize}");
            RefreshDevicesList();
            UpdateStatus();
        }

        private void OnDeviceRemoved(object? sender, UsbDeviceEventArgs e)
        {
            AddLogEntry($"USB removed: {e.Device.DriveLetter}");
            RefreshDevicesList();
            UpdateStatus();
        }

        private void OnScanStarted(object? sender, UsbScanEventArgs e)
        {
            AddLogEntry($"Scanning {e.Device.DriveLetter}...");
            Dispatcher.Invoke(() =>
            {
                ScanProgressPanel.Visibility = Visibility.Visible;
                TxtScanStatus.Text = $"Scanning {e.Device.DriveLetter}...";
                TxtScanPercent.Text = "0%";
                ScanProgressBar.Value = 0;
                TxtScanFile.Text = "Initializing...";
            });
        }

        private void OnScanProgress(object? sender, UsbScanProgressEventArgs e)
        {
            Dispatcher.Invoke(() =>
            {
                ScanProgressBar.Value = e.ProgressPercent;
                TxtScanPercent.Text = $"{e.ProgressPercent}%";
                TxtScanFile.Text = e.CurrentFile;
                TxtScanStatus.Text = $"Scanning {e.DriveLetter}... ({e.ProcessedFiles}/{e.TotalFiles} files)";
            });
        }

        private void OnScanCompleted(object? sender, UsbScanEventArgs e)
        {
            _scannedCount++;
            Dispatcher.Invoke(() =>
            {
                ScanProgressPanel.Visibility = Visibility.Collapsed;
            });
            if (e.Result.Success)
            {
                AddLogEntry($"Scan complete: {e.Device.DriveLetter} - {e.Result.FilesScanned} files, {e.Result.Threats.Count} threats");
            }
            else
            {
                AddLogEntry($"Scan failed: {e.Device.DriveLetter} - {e.Result.Error}");
            }
            RefreshDevicesList();
            UpdateStatus();
        }

        private void OnThreatFound(object? sender, UsbThreatEventArgs e)
        {
            _threatsFound++;
            AddLogEntry($"Threat detected on {e.DriveLetter}: {e.Threat.Name}");
            UpdateStatus();
        }

        private void OnLogAdded(object? sender, string e)
        {
            if (e.Contains("Autorun blocked") || e.Contains("Autorun deleted"))
            {
                _threatsBlocked++;
                UpdateStatus();
            }
            AddLogEntry(e);
        }

        #endregion

        #region UI Event Handlers

        private void BtnToggleProtection_Click(object sender, RoutedEventArgs e)
        {
            _usbService.IsEnabled = !_usbService.IsEnabled;
            UpdateStatus();
        }

        private async void BtnScanAll_Click(object sender, RoutedEventArgs e)
        {
            if (_usbService.ConnectedDevices.Count == 0)
            {
                MessageBox.Show("No USB devices connected.", "USB Protection", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            BtnScanAll.IsEnabled = false;
            _scanCts = new CancellationTokenSource();

            try
            {
                foreach (var kvp in _usbService.ConnectedDevices)
                {
                    if (_scanCts.Token.IsCancellationRequested) break;
                    await _usbService.ScanDriveAsync(kvp.Key, _scanCts.Token);
                }
            }
            finally
            {
                BtnScanAll.IsEnabled = true;
                _scanCts = null;
            }
        }

        private async void BtnScanDevice_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.Tag is string driveLetter)
            {
                btn.IsEnabled = false;
                btn.Content = "Scanning...";

                try
                {
                    await _usbService.ScanDriveAsync(driveLetter, CancellationToken.None);
                }
                finally
                {
                    btn.IsEnabled = true;
                    btn.Content = "Scan Now";
                }
            }
        }

        private void BtnClearLog_Click(object sender, RoutedEventArgs e)
        {
            LogPanel.Children.Clear();
            LogPanel.Children.Add(EmptyLogText);
            EmptyLogText.Visibility = Visibility.Visible;
        }

        private void ChkAutoScan_Changed(object sender, RoutedEventArgs e)
        {
            if (_usbService != null)
                _usbService.AutoScanEnabled = ChkAutoScan.IsChecked == true;
        }

        private void ChkBlockAutorun_Changed(object sender, RoutedEventArgs e)
        {
            if (_usbService != null)
                _usbService.BlockAutorun = ChkBlockAutorun.IsChecked == true;
        }

        #endregion
    }
}
