using System.ComponentModel;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using SkidrowKiller.Models;
using SkidrowKiller.Services;

namespace SkidrowKiller.Views
{
    public partial class ScanView : Page
    {
        private readonly SafeScanner _scanner;
        private readonly WhitelistManager _whitelist;
        private readonly BackupManager _backup;
        private readonly List<ThreatInfo> _foundThreats = new();
        private readonly List<DriveSelection> _drives = new();
        private double _sectionProgressWidth;
        private double _totalProgressWidth;

        public ScanView(SafeScanner scanner, WhitelistManager whitelist, BackupManager backup)
        {
            InitializeComponent();
            _scanner = scanner;
            _whitelist = whitelist;
            _backup = backup;

            _scanner.LogAdded += Scanner_LogAdded;
            _scanner.ProgressChanged += Scanner_ProgressChanged;
            _scanner.ThreatFound += Scanner_ThreatFound;
            _scanner.ScanCompleted += Scanner_ScanCompleted;
            _scanner.PreScanStatusChanged += Scanner_PreScanStatusChanged;

            // Initialize drives
            LoadDrives();

            // Get the actual width after layout
            Loaded += (s, e) =>
            {
                UpdateProgressBarWidths();
                UpdateScanModeDescription();
            };
            SizeChanged += (s, e) =>
            {
                UpdateProgressBarWidths();
            };
        }

        private void LoadDrives()
        {
            _drives.Clear();
            var drives = DriveInfo.GetDrives()
                .Where(d => d.IsReady && (d.DriveType == DriveType.Fixed || d.DriveType == DriveType.Removable));

            foreach (var drive in drives)
            {
                var driveSelection = new DriveSelection
                {
                    DrivePath = drive.RootDirectory.FullName,
                    DisplayName = $"{drive.Name} ({drive.VolumeLabel}) - {drive.TotalSize / (1024 * 1024 * 1024):F0} GB",
                    IsSelected = drive.Name.StartsWith("C"), // Select C: drive by default
                    IsEnabled = true
                };
                _drives.Add(driveSelection);
            }

            DrivesList.ItemsSource = _drives;
        }

        private void ScanModeRadio_Checked(object sender, RoutedEventArgs e)
        {
            UpdateScanModeDescription();
            UpdateScanModeUI();
        }

        private void UpdateScanModeDescription()
        {
            if (ScanModeDescription == null) return;

            if (QuickScanRadio?.IsChecked == true)
            {
                ScanModeDescription.Text = "⚡ Quick Scan: Scans startup locations, running processes, and common malware hiding spots. Fast and efficient.";
            }
            else if (DeepScanRadio?.IsChecked == true)
            {
                ScanModeDescription.Text = "🔬 Deep Scan: Full system scan of all selected drives, registry, and processes. Thorough but takes longer.";
            }
            else if (CustomScanRadio?.IsChecked == true)
            {
                ScanModeDescription.Text = "⚙️ Custom: Choose exactly what to scan. Configure drives and scan targets below.";
            }
        }

        private void UpdateScanModeUI()
        {
            if (CustomOptionsPanel == null) return;

            // Show/hide custom options
            CustomOptionsPanel.Visibility = CustomScanRadio?.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;

            // Update drive selection based on mode
            if (QuickScanRadio?.IsChecked == true)
            {
                // Quick scan: only system drive
                foreach (var drive in _drives)
                {
                    drive.IsSelected = drive.DrivePath.StartsWith("C");
                    drive.IsEnabled = false;
                }
            }
            else if (DeepScanRadio?.IsChecked == true)
            {
                // Deep scan: all drives selected
                foreach (var drive in _drives)
                {
                    drive.IsSelected = true;
                    drive.IsEnabled = false;
                }
            }
            else
            {
                // Custom: enable all drives for selection
                foreach (var drive in _drives)
                {
                    drive.IsEnabled = true;
                }
            }

            // Refresh drive list
            DrivesList.ItemsSource = null;
            DrivesList.ItemsSource = _drives;
        }

        private ScanMode GetCurrentScanMode()
        {
            if (QuickScanRadio?.IsChecked == true) return ScanMode.Quick;
            if (DeepScanRadio?.IsChecked == true) return ScanMode.Deep;
            return ScanMode.Custom;
        }

        private List<string> GetSelectedDrives()
        {
            return _drives.Where(d => d.IsSelected).Select(d => d.DrivePath).ToList();
        }

        private void UpdateProgressBarWidths()
        {
            // Calculate available width for progress bars
            var container = SectionProgressFill.Parent as Border;
            if (container != null)
            {
                _sectionProgressWidth = container.ActualWidth > 0 ? container.ActualWidth : 400;
                _totalProgressWidth = _sectionProgressWidth;
            }
        }

        private async void StartButton_Click(object sender, RoutedEventArgs e)
        {
            var scanMode = GetCurrentScanMode();
            var selectedDrives = GetSelectedDrives();

            // Validate custom mode
            if (scanMode == ScanMode.Custom)
            {
                if (!ScanFilesCheck.IsChecked == true &&
                    !ScanRegistryCheck.IsChecked == true &&
                    !ScanProcessesCheck.IsChecked == true)
                {
                    MessageBox.Show("Please select at least one scan option.", "Warning",
                        MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                if (!selectedDrives.Any() && ScanFilesCheck.IsChecked == true)
                {
                    MessageBox.Show("Please select at least one drive to scan.", "Warning",
                        MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }
            }

            var modeDescription = scanMode switch
            {
                ScanMode.Quick => "Quick Scan - Common malware locations",
                ScanMode.Deep => "Deep Scan - Full system scan",
                _ => "Custom Scan"
            };

            var result = MessageBox.Show(
                $"Start {modeDescription}?\n\n" +
                $"Mode: {modeDescription}\n" +
                $"Drives: {(scanMode == ScanMode.Quick ? "System Drive" : string.Join(", ", selectedDrives.Select(Path.GetPathRoot)))}\n\n" +
                "• Items with score < 80 will require confirmation\n" +
                "• Backups are created before removal\n" +
                "• You can whitelist false positives\n\n" +
                "Continue?",
                "Start Scan",
                MessageBoxButton.YesNo,
                MessageBoxImage.Question);

            if (result != MessageBoxResult.Yes) return;

            // Reset UI
            _foundThreats.Clear();
            LogTextBox.Clear();
            ScannedCountLabel.Text = "0";
            FoundCountLabel.Text = "0";

            // Reset progress bars
            SectionLabel.Text = "Preparing";
            SectionIndexLabel.Text = "";
            SectionPercentLabel.Text = "0%";
            SectionProgressFill.Width = 0;
            TotalItemsLabel.Text = "";
            TotalPercentLabel.Text = "0%";
            TotalProgressFill.Width = 0;
            PreScanStatusLabel.Visibility = Visibility.Visible;
            PreScanStatusLabel.Text = "Counting items...";

            // Update buttons
            StartButton.IsEnabled = false;
            PauseButton.IsEnabled = true;
            StopButton.IsEnabled = true;
            QuickScanRadio.IsEnabled = false;
            DeepScanRadio.IsEnabled = false;
            CustomScanRadio.IsEnabled = false;
            ScanFilesCheck.IsEnabled = false;
            ScanRegistryCheck.IsEnabled = false;
            ScanProcessesCheck.IsEnabled = false;

            // Disable drive selection
            foreach (var drive in _drives)
            {
                drive.IsEnabled = false;
            }
            DrivesList.ItemsSource = null;
            DrivesList.ItemsSource = _drives;

            StatusLabel.Text = $"Starting {modeDescription}...";

            // Determine scan parameters based on mode
            bool scanFiles, scanRegistry, scanProcesses;
            if (scanMode == ScanMode.Quick)
            {
                scanFiles = true;
                scanRegistry = true;
                scanProcesses = true;
            }
            else if (scanMode == ScanMode.Deep)
            {
                scanFiles = true;
                scanRegistry = true;
                scanProcesses = true;
            }
            else
            {
                scanFiles = ScanFilesCheck.IsChecked == true;
                scanRegistry = ScanRegistryCheck.IsChecked == true;
                scanProcesses = ScanProcessesCheck.IsChecked == true;
            }

            // Start scan with mode and drives
            await _scanner.ScanAsync(scanFiles, scanRegistry, scanProcesses, scanMode, selectedDrives);
        }

        private void PauseButton_Click(object sender, RoutedEventArgs e)
        {
            if (_scanner.IsPaused)
            {
                _scanner.Resume();
                PauseButton.Content = "⏸️ Pause";
                StatusLabel.Text = "Scanning...";
            }
            else
            {
                _scanner.Pause();
                PauseButton.Content = "▶️ Resume";
                StatusLabel.Text = "Paused";
            }
        }

        private void StopButton_Click(object sender, RoutedEventArgs e)
        {
            var result = MessageBox.Show("Stop the scan?", "Confirm",
                MessageBoxButton.YesNo, MessageBoxImage.Question);

            if (result == MessageBoxResult.Yes)
            {
                _scanner.Stop();
                ResetUI();
            }
        }

        private void Scanner_LogAdded(object? sender, string message)
        {
            Dispatcher.Invoke(() =>
            {
                LogTextBox.AppendText($"[{DateTime.Now:HH:mm:ss}] {message}\n");
                LogTextBox.ScrollToEnd();
            });
        }

        private void Scanner_PreScanStatusChanged(object? sender, string status)
        {
            Dispatcher.Invoke(() =>
            {
                PreScanStatusLabel.Text = status;
            });
        }

        private void Scanner_ProgressChanged(object? sender, ProgressEventArgs e)
        {
            Dispatcher.Invoke(() =>
            {
                // Update counters
                ScannedCountLabel.Text = e.ScannedCount.ToString("N0");
                FoundCountLabel.Text = e.FoundCount.ToString();
                CurrentItemLabel.Text = e.CurrentItem;

                // Hide pre-scan status once scanning starts
                PreScanStatusLabel.Visibility = Visibility.Collapsed;
                StatusLabel.Text = "Scanning...";

                // Update section progress
                SectionLabel.Text = e.CurrentSection;
                SectionIndexLabel.Text = $"({e.SectionIndex}/{e.TotalSections})";
                var sectionPercent = Math.Min(e.SectionPercent, 100);
                SectionPercentLabel.Text = $"{sectionPercent:F0}%";

                // Animate section progress bar
                UpdateProgressBarWidths();
                SectionProgressFill.Width = (_sectionProgressWidth * sectionPercent / 100);

                // Update total progress
                TotalItemsLabel.Text = $"{e.ScannedCount:N0} / {e.TotalItems:N0}";
                var totalPercent = Math.Min(e.TotalPercent, 100);
                TotalPercentLabel.Text = $"{totalPercent:F0}%";

                // Animate total progress bar
                TotalProgressFill.Width = (_totalProgressWidth * totalPercent / 100);
            });
        }

        private void Scanner_ThreatFound(object? sender, ThreatInfo threat)
        {
            Dispatcher.Invoke(() =>
            {
                _foundThreats.Add(threat);
                FoundCountLabel.Text = _foundThreats.Count.ToString();
            });
        }

        private void Scanner_ScanCompleted(object? sender, ScanResult result)
        {
            Dispatcher.Invoke(() =>
            {
                ResetUI();

                var message = $"Scan completed!\n\n" +
                             $"Total Scanned: {result.TotalScanned:N0}\n" +
                             $"Threats Found: {result.ThreatsFound}\n" +
                             $"Duration: {result.Duration.TotalSeconds:F1} seconds";

                if (result.ThreatsFound > 0)
                {
                    message += "\n\nGo to 'Threats Found' to review and remove them.";

                    // Ask to process threats
                    var processResult = MessageBox.Show(
                        message + "\n\nDo you want to process the threats now?",
                        "Scan Complete",
                        MessageBoxButton.YesNo,
                        MessageBoxImage.Warning);

                    if (processResult == MessageBoxResult.Yes)
                    {
                        ProcessThreats(result.Threats);
                    }
                }
                else
                {
                    MessageBox.Show(message, "Scan Complete",
                        MessageBoxButton.OK, MessageBoxImage.Information);
                }

                StatusLabel.Text = "Scan completed";
            });
        }

        private async void ProcessThreats(List<ThreatInfo> threats)
        {
            var confirmNeeded = threats.Where(t => t.RequiresConfirmation).ToList();
            var autoRemove = threats.Where(t => !t.RequiresConfirmation).ToList();

            // Auto-remove high confidence threats
            foreach (var threat in autoRemove)
            {
                if (_whitelist.IsWhitelisted(threat.Path)) continue;

                var backed = await _scanner.RemoveThreatAsync(threat, AutoBackupCheck.IsChecked == true);
                if (backed)
                {
                    LogTextBox.AppendText($"[{DateTime.Now:HH:mm:ss}] ✅ Auto-removed: {threat.Path}\n");
                }
            }

            // Confirm uncertain threats
            if (confirmNeeded.Any() && ConfirmDeleteCheck.IsChecked == true)
            {
                foreach (var threat in confirmNeeded)
                {
                    if (_whitelist.IsWhitelisted(threat.Path)) continue;

                    var result = MessageBox.Show(
                        $"Uncertain threat detected (Score: {threat.Score}/100):\n\n" +
                        $"Path: {threat.Path}\n" +
                        $"Patterns: {string.Join(", ", threat.MatchedPatterns)}\n" +
                        $"Severity: {threat.SeverityDisplay}\n\n" +
                        "What do you want to do?",
                        "Confirm Action",
                        MessageBoxButton.YesNoCancel,
                        MessageBoxImage.Question);

                    if (result == MessageBoxResult.Yes)
                    {
                        await _scanner.RemoveThreatAsync(threat, AutoBackupCheck.IsChecked == true);
                        LogTextBox.AppendText($"[{DateTime.Now:HH:mm:ss}] ✅ Removed: {threat.Path}\n");
                    }
                    else if (result == MessageBoxResult.No)
                    {
                        // Add to whitelist
                        _whitelist.AddToWhitelist(threat.Path, "User confirmed as safe");
                        LogTextBox.AppendText($"[{DateTime.Now:HH:mm:ss}] ✅ Whitelisted: {threat.Path}\n");
                    }
                    // Cancel = skip
                }
            }

            LogTextBox.AppendText($"[{DateTime.Now:HH:mm:ss}] ✅ Threat processing completed\n");
            LogTextBox.ScrollToEnd();
        }

        private void ResetUI()
        {
            StartButton.IsEnabled = true;
            PauseButton.IsEnabled = false;
            StopButton.IsEnabled = false;
            PauseButton.Content = "⏸️ Pause";
            QuickScanRadio.IsEnabled = true;
            DeepScanRadio.IsEnabled = true;
            CustomScanRadio.IsEnabled = true;
            ScanFilesCheck.IsEnabled = true;
            ScanRegistryCheck.IsEnabled = true;
            ScanProcessesCheck.IsEnabled = true;
            CurrentItemLabel.Text = "";
            PreScanStatusLabel.Visibility = Visibility.Collapsed;

            // Re-enable drives based on current mode
            UpdateScanModeUI();

            // Set progress to 100% when complete
            SectionLabel.Text = "Complete";
            SectionPercentLabel.Text = "100%";
            UpdateProgressBarWidths();
            SectionProgressFill.Width = _sectionProgressWidth;
            TotalPercentLabel.Text = "100%";
            TotalProgressFill.Width = _totalProgressWidth;
        }
    }

    /// <summary>
    /// Scan mode enumeration
    /// </summary>
    public enum ScanMode
    {
        Quick,  // Fast scan - startup locations, processes, common malware spots
        Deep,   // Full scan - all files on selected drives
        Custom  // User-defined scan targets
    }

    /// <summary>
    /// Drive selection model for UI binding
    /// </summary>
    public class DriveSelection : INotifyPropertyChanged
    {
        private bool _isSelected;
        private bool _isEnabled = true;

        public string DrivePath { get; set; } = string.Empty;
        public string DisplayName { get; set; } = string.Empty;

        public bool IsSelected
        {
            get => _isSelected;
            set
            {
                _isSelected = value;
                PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(IsSelected)));
            }
        }

        public bool IsEnabled
        {
            get => _isEnabled;
            set
            {
                _isEnabled = value;
                PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(IsEnabled)));
            }
        }

        public event PropertyChangedEventHandler? PropertyChanged;
    }
}
