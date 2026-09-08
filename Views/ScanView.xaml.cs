using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Interop;
using System.Windows.Media.Animation;
using System.Windows.Threading;
using Microsoft.Win32;
using SkidrowKiller.Models;
using SkidrowKiller.Services;

namespace SkidrowKiller.Views
{
    public partial class ScanView : Page
    {
        private readonly SafeScanner _scanner;
        private readonly WhitelistManager _whitelist;
        private readonly BackupManager _backup;
        private readonly QuarantineService? _quarantine;
        private readonly ScanReportService _reportService = new();

        // Last finished scan, kept so a report can be produced after the fact.
        private ScanResult? _lastResult;
        private ScanMode _lastScanMode = ScanMode.Quick;
        private List<string> _lastScanPaths = new();

        // Threat-handling policy from Settings -> Threat Actions.
        // 0 = ask every time, 1 = quarantine automatically, 2 = delete automatically, 3 = log only.
        private int _threatActionPolicy;
        private bool _quarantineOnly = true;
        private bool _includeNetworkDrives;
        private readonly List<ThreatInfo> _foundThreats = new();
        private readonly List<DriveSelection> _drives = new();
        private readonly List<string> _customFolders = new();
        private double _sectionProgressWidth;
        private double _totalProgressWidth;
        private DispatcherTimer? _spinTimer;
        private double _currentAngle = 0;

        public ScanView(SafeScanner scanner, WhitelistManager whitelist, BackupManager backup,
            QuarantineService? quarantine = null)
        {
            InitializeComponent();
            _scanner = scanner;
            _whitelist = whitelist;
            _backup = backup;
            _quarantine = quarantine;

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
                InitializeSpinAnimation();
            };
            SizeChanged += (s, e) =>
            {
                UpdateProgressBarWidths();
            };
        }

        private void InitializeSpinAnimation()
        {
            _spinTimer = new DispatcherTimer
            {
                Interval = TimeSpan.FromMilliseconds(16) // ~60fps
            };
            _spinTimer.Tick += (s, e) =>
            {
                _currentAngle = (_currentAngle + 6) % 360;
                SpinningRotation.Angle = _currentAngle;
            };
        }

        private void StartThinkingAnimation()
        {
            ThinkingIndicator.Visibility = Visibility.Visible;
            PreScanStatusLabel.Visibility = Visibility.Visible;
            _spinTimer?.Start();
        }

        private void StopThinkingAnimation()
        {
            ThinkingIndicator.Visibility = Visibility.Collapsed;
            PreScanStatusLabel.Visibility = Visibility.Collapsed;
            _spinTimer?.Stop();
        }

        private void LoadDrives()
        {
            // Remember what the user had ticked so a reload (e.g. after toggling network drives in
            // Settings) does not silently reset their selection.
            var previouslySelected = _drives
                .Where(d => d.IsSelected)
                .Select(d => d.DrivePath)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);

            _drives.Clear();

            var drives = DriveInfo.GetDrives()
                .Where(d => d.IsReady)
                .Where(d => d.DriveType == DriveType.Fixed
                            || d.DriveType == DriveType.Removable
                            // Network drives only appear when the user asked for them; otherwise the
                            // "Scan network drives" setting could never take effect, because the
                            // scanner only ever sees the drives listed here.
                            || (_includeNetworkDrives && d.DriveType == DriveType.Network));

            foreach (var drive in drives)
            {
                string label;
                long sizeGb;
                try
                {
                    label = drive.VolumeLabel;
                    sizeGb = drive.TotalSize / (1024 * 1024 * 1024);
                }
                catch
                {
                    // Network shares can throw on VolumeLabel/TotalSize when the host is unreachable.
                    label = drive.DriveType.ToString();
                    sizeGb = 0;
                }

                var path = drive.RootDirectory.FullName;
                _drives.Add(new DriveSelection
                {
                    DrivePath = path,
                    DisplayName = sizeGb > 0
                        ? $"{drive.Name} ({label}) - {sizeGb:F0} GB"
                        : $"{drive.Name} ({label})",
                    IsSelected = previouslySelected.Count > 0
                        ? previouslySelected.Contains(path)
                        : drive.Name.StartsWith("C"), // Select C: drive by default
                    IsEnabled = true
                });
            }

            DrivesList.ItemsSource = null;
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

            // Update folder hint
            UpdateFolderHint();
        }

        #region Custom Folder Selection

        private void AddCustomFolder_Click(object sender, RoutedEventArgs e)
        {
            var folderPath = ShowFolderBrowserDialog("Select a folder to scan");

            if (!string.IsNullOrEmpty(folderPath))
            {
                // Check if already added
                if (!_customFolders.Contains(folderPath, StringComparer.OrdinalIgnoreCase))
                {
                    _customFolders.Add(folderPath);
                    RefreshCustomFoldersList();
                    UpdateFolderHint();
                }
                else
                {
                    MessageBox.Show("This folder is already in the list.", "Info",
                        MessageBoxButton.OK, MessageBoxImage.Information);
                }
            }
        }

        /// <summary>
        /// Shows a folder browser dialog using Shell32 COM interface
        /// </summary>
        private string? ShowFolderBrowserDialog(string title)
        {
            var openFileDialog = new OpenFileDialog
            {
                Title = title,
                CheckFileExists = false,
                CheckPathExists = true,
                FileName = "Select Folder",
                Filter = "Folders|\n",
                InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.MyComputer)
            };

            // Use OpenFolderDialog if available (Windows 10+)
            try
            {
                var dialog = new OpenFolderDialog
                {
                    Title = title,
                    Multiselect = false
                };

                if (dialog.ShowDialog() == true)
                {
                    return dialog.FolderName;
                }
            }
            catch
            {
                // Fallback: use a workaround with file dialog
                var ofd = new OpenFileDialog
                {
                    Title = title,
                    ValidateNames = false,
                    CheckFileExists = false,
                    CheckPathExists = true,
                    FileName = "Folder Selection"
                };

                if (ofd.ShowDialog() == true)
                {
                    var path = Path.GetDirectoryName(ofd.FileName);
                    if (Directory.Exists(path))
                        return path;
                }
            }

            return null;
        }

        private void RemoveCustomFolder_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button button && button.Tag is string folderPath)
            {
                _customFolders.Remove(folderPath);
                RefreshCustomFoldersList();
                UpdateFolderHint();
            }
        }

        private void ClearCustomFolders_Click(object sender, RoutedEventArgs e)
        {
            if (_customFolders.Count == 0) return;

            var result = MessageBox.Show("Clear all selected folders?", "Confirm",
                MessageBoxButton.YesNo, MessageBoxImage.Question);

            if (result == MessageBoxResult.Yes)
            {
                _customFolders.Clear();
                RefreshCustomFoldersList();
                UpdateFolderHint();
            }
        }

        private void RefreshCustomFoldersList()
        {
            CustomFoldersList.ItemsSource = null;
            CustomFoldersList.ItemsSource = _customFolders.ToList();
        }

        private void UpdateFolderHint()
        {
            if (FolderHintText == null) return;

            if (_customFolders.Count == 0)
            {
                FolderHintText.Text = "💡 No folders added - will scan selected drives";
            }
            else
            {
                FolderHintText.Text = $"✅ {_customFolders.Count} folder(s) selected - will scan these instead of drives";
            }
        }

        private List<string> GetCustomFolders()
        {
            return _customFolders.ToList();
        }

        #endregion

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
            var customFolders = GetCustomFolders();

            // Validate custom mode
            if (scanMode == ScanMode.Custom)
            {
                if (ScanFilesCheck.IsChecked != true &&
                    ScanRegistryCheck.IsChecked != true &&
                    ScanProcessesCheck.IsChecked != true)
                {
                    MessageBox.Show("Please select at least one scan option.", "Warning",
                        MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                // For file scan, need either drives or custom folders
                if (ScanFilesCheck.IsChecked == true && !selectedDrives.Any() && !customFolders.Any())
                {
                    MessageBox.Show("Please select at least one drive or add specific folders to scan.", "Warning",
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

            // Build target description
            string targetDescription;
            if (scanMode == ScanMode.Quick)
            {
                targetDescription = "System Drive";
            }
            else if (customFolders.Any())
            {
                targetDescription = $"{customFolders.Count} specific folder(s)";
            }
            else
            {
                targetDescription = string.Join(", ", selectedDrives.Select(Path.GetPathRoot));
            }

            var result = MessageBox.Show(
                $"Start {modeDescription}?\n\n" +
                $"Mode: {modeDescription}\n" +
                $"Target: {targetDescription}\n\n" +
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

            // Reset progress bars and show thinking animation
            SectionLabel.Text = "Preparing";
            SectionIndexLabel.Text = "";
            SectionPercentLabel.Text = "0%";
            SectionProgressFill.Width = 0;
            TotalItemsLabel.Text = "";
            TotalPercentLabel.Text = "0%";
            TotalProgressFill.Width = 0;
            PreScanStatusLabel.Text = "Analyzing targets...";
            StartThinkingAnimation();

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

            // Auto-scroll to log section so user can see scan progress immediately
            LogTextBox.BringIntoView();

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

            // Start scan with mode, drives, and custom folders
            _lastScanMode = scanMode;
            _lastScanPaths = (customFolders?.Count > 0 ? customFolders : selectedDrives) ?? new List<string>();

            await _scanner.ScanAsync(scanFiles, scanRegistry, scanProcesses, scanMode, selectedDrives, customFolders);
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
                // Keep animation running during pre-scan
                if (!string.IsNullOrEmpty(status) && ThinkingIndicator.Visibility != Visibility.Visible)
                {
                    StartThinkingAnimation();
                }
            });
        }

        private void Scanner_ProgressChanged(object? sender, ProgressEventArgs e)
        {
            Dispatcher.Invoke(() =>
            {
                // Stop thinking animation once actual scanning starts
                StopThinkingAnimation();

                // Update counters
                ScannedCountLabel.Text = e.ScannedCount.ToString("N0");
                FoundCountLabel.Text = e.FoundCount.ToString();
                CurrentItemLabel.Text = e.CurrentItem;

                // Update section progress
                SectionLabel.Text = e.CurrentSection;
                SectionIndexLabel.Text = $"({e.SectionIndex}/{e.TotalSections})";
                var sectionPercent = Math.Min(e.SectionPercent, 100);
                SectionPercentLabel.Text = $"{sectionPercent:F0}%";

                // Animate section progress bar
                UpdateProgressBarWidths();
                SectionProgressFill.Width = (_sectionProgressWidth * sectionPercent / 100);

                // Update total items info
                TotalItemsLabel.Text = $"({e.ScannedCount:N0}/{e.TotalItems:N0})";
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
            _lastResult = result;

            Dispatcher.Invoke(() =>
            {
                ResetUI();
                ReportButton.IsEnabled = true;

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

        /// <summary>
        /// Seed this view from the user's saved settings. Before this existed, the Scanning and
        /// Threat Actions sections of the Settings screen were stored but never consulted.
        /// </summary>
        public void ApplyUserSettings(UserSettings settings)
        {
            if (!Dispatcher.CheckAccess())
            {
                Dispatcher.Invoke(() => ApplyUserSettings(settings));
                return;
            }

            _threatActionPolicy = settings.ThreatAction;
            _quarantineOnly = settings.QuarantineOnly;

            if (_includeNetworkDrives != settings.ScanNetworkDrives)
            {
                _includeNetworkDrives = settings.ScanNetworkDrives;
                if (!_scanner.IsScanning) LoadDrives();
            }

            // Don't yank the targets out from under a scan that is already running.
            if (!_scanner.IsScanning)
            {
                ScanFilesCheck.IsChecked = settings.ScanFiles;
                ScanRegistryCheck.IsChecked = settings.ScanRegistry;
                ScanProcessesCheck.IsChecked = settings.ScanProcesses;
            }

            AutoBackupCheck.IsChecked = settings.BackupBeforeDelete;
            ConfirmDeleteCheck.IsChecked = settings.ThreatAction == 0;
        }

        /// <summary>
        /// Dispose of one threat according to the configured policy: quarantine (reversible) when
        /// "Quarantine only" is set, otherwise a backed-up removal.
        /// </summary>
        private async Task<bool> ApplyThreatActionAsync(ThreatInfo threat)
        {
            var backup = AutoBackupCheck.IsChecked == true;

            // Only file-backed threats can be quarantined. Registry values, processes and injected
            // DLLs have nothing to move aside, so they always go through the normal removal path
            // (which still takes a backup first).
            var quarantinable = threat.Type is ThreatType.File or ThreatType.Directory;

            if (_quarantineOnly && quarantinable && _quarantine != null)
            {
                var result = threat.Type == ThreatType.Directory
                    ? _quarantine.QuarantineDirectory(threat.Path, threat)
                    : _quarantine.QuarantineFile(threat.Path, threat);

                if (result.Success)
                {
                    LogTextBox.AppendText($"[{DateTime.Now:HH:mm:ss}] 🔒 Quarantined: {threat.Path}\n");
                    return true;
                }

                LogTextBox.AppendText($"[{DateTime.Now:HH:mm:ss}] ⚠️ Quarantine failed ({result.Message}): {threat.Path}\n");
                return false;
            }

            return await _scanner.RemoveThreatAsync(threat, backup);
        }

        private async void ProcessThreats(List<ThreatInfo> threats)
        {
            // "Ignore (log only)" means exactly that - touch nothing.
            if (_threatActionPolicy == 3)
            {
                foreach (var threat in threats)
                    LogTextBox.AppendText($"[{DateTime.Now:HH:mm:ss}] ℹ️ Logged only (per settings): {threat.Path}\n");

                LogTextBox.AppendText($"[{DateTime.Now:HH:mm:ss}] ✅ Threat processing completed (log-only mode)\n");
                LogTextBox.ScrollToEnd();
                return;
            }

            // "Quarantine automatically" / "Delete automatically" skip the per-threat prompt entirely.
            if (_threatActionPolicy == 1 || _threatActionPolicy == 2)
            {
                var deleteOutright = _threatActionPolicy == 2 && !_quarantineOnly;

                foreach (var threat in threats)
                {
                    if (_whitelist.IsWhitelisted(threat.Path)) continue;

                    var ok = deleteOutright
                        ? await _scanner.RemoveThreatAsync(threat, AutoBackupCheck.IsChecked == true)
                        : await ApplyThreatActionAsync(threat);

                    if (ok && deleteOutright)
                        LogTextBox.AppendText($"[{DateTime.Now:HH:mm:ss}] ✅ Removed: {threat.Path}\n");
                }

                LogTextBox.AppendText($"[{DateTime.Now:HH:mm:ss}] ✅ Threat processing completed\n");
                LogTextBox.ScrollToEnd();
                return;
            }

            var confirmNeeded = threats.Where(t => t.RequiresConfirmation).ToList();
            var autoRemove = threats.Where(t => !t.RequiresConfirmation).ToList();

            // Auto-remove high confidence threats
            foreach (var threat in autoRemove)
            {
                if (_whitelist.IsWhitelisted(threat.Path)) continue;

                if (await ApplyThreatActionAsync(threat) && !_quarantineOnly)
                {
                    LogTextBox.AppendText($"[{DateTime.Now:HH:mm:ss}] ✅ Auto-removed: {threat.Path}\n");
                }
            }

            // Confirm uncertain threats
            if (confirmNeeded.Any() && ConfirmDeleteCheck.IsChecked == true)
            {
                bool removeAll = false;
                bool skipAll = false;

                for (int i = 0; i < confirmNeeded.Count; i++)
                {
                    var threat = confirmNeeded[i];
                    if (_whitelist.IsWhitelisted(threat.Path)) continue;

                    // Handle bulk actions
                    if (removeAll)
                    {
                        if (await ApplyThreatActionAsync(threat) && !_quarantineOnly)
                            LogTextBox.AppendText($"[{DateTime.Now:HH:mm:ss}] ✅ Removed: {threat.Path}\n");
                        continue;
                    }
                    if (skipAll)
                    {
                        LogTextBox.AppendText($"[{DateTime.Now:HH:mm:ss}] ⏭️ Skipped: {threat.Path}\n");
                        continue;
                    }

                    // Show confirmation dialog (check if app is still running)
                    if (Application.Current == null || Application.Current.MainWindow == null)
                    {
                        // Application is shutting down, stop processing
                        return;
                    }

                    var dialog = new ThreatConfirmDialog(threat, i, confirmNeeded.Count)
                    {
                        Owner = Window.GetWindow(this)
                    };

                    if (dialog.ShowDialog() == true)
                    {
                        switch (dialog.SelectedAction)
                        {
                            case ThreatAction.Remove:
                                if (await ApplyThreatActionAsync(threat) && !_quarantineOnly)
                                    LogTextBox.AppendText($"[{DateTime.Now:HH:mm:ss}] ✅ Removed: {threat.Path}\n");
                                break;

                            case ThreatAction.RemoveAll:
                                removeAll = true;
                                if (await ApplyThreatActionAsync(threat) && !_quarantineOnly)
                                    LogTextBox.AppendText($"[{DateTime.Now:HH:mm:ss}] ✅ Removed: {threat.Path}\n");
                                break;

                            case ThreatAction.Skip:
                                LogTextBox.AppendText($"[{DateTime.Now:HH:mm:ss}] ⏭️ Skipped: {threat.Path}\n");
                                break;

                            case ThreatAction.SkipAll:
                                skipAll = true;
                                LogTextBox.AppendText($"[{DateTime.Now:HH:mm:ss}] ⏭️ Skipped: {threat.Path}\n");
                                break;

                            case ThreatAction.Whitelist:
                                _whitelist.AddToWhitelist(threat.Path, "User confirmed as safe");
                                LogTextBox.AppendText($"[{DateTime.Now:HH:mm:ss}] ✅ Whitelisted: {threat.Path}\n");
                                break;
                        }
                    }
                }
            }

            LogTextBox.AppendText($"[{DateTime.Now:HH:mm:ss}] ✅ Threat processing completed\n");
            LogTextBox.ScrollToEnd();
        }

        /// <summary>
        /// Write a report for the last scan. ScanReportService could already render HTML/TXT/CSV/JSON
        /// but nothing in the app ever called it, so the feature was unreachable.
        /// </summary>
        private async void ReportButton_Click(object sender, RoutedEventArgs e)
        {
            if (_lastResult == null)
            {
                MessageBox.Show("Run a scan first - there is nothing to report on yet.",
                    "No Scan Data", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            ReportButton.IsEnabled = false;
            try
            {
                var data = new ScanReportData
                {
                    ScanDate = DateTime.Now - _lastResult.Duration,
                    ScanType = _lastScanMode switch
                    {
                        ScanMode.Quick => "Quick Scan",
                        ScanMode.Deep => "Deep Scan",
                        _ => "Custom Scan"
                    },
                    Duration = _lastResult.Duration,
                    ItemsScanned = (int)Math.Min(_lastResult.TotalScanned, int.MaxValue),
                    ThreatsRemoved = _lastResult.ThreatsRemoved,
                    ThreatsQuarantined = _quarantineOnly ? _lastResult.ThreatsRemoved : 0,
                    Threats = _lastResult.Threats,
                    ScannedPaths = _lastScanPaths
                };

                var path = await _reportService.GenerateReportAsync(data, ReportFormat.Html);

                LogTextBox.AppendText($"[{DateTime.Now:HH:mm:ss}] 📄 Report saved: {path}\n");
                LogTextBox.ScrollToEnd();

                if (MessageBox.Show($"Report saved to:\n{path}\n\nOpen it now?", "Report Ready",
                        MessageBoxButton.YesNo, MessageBoxImage.Information) == MessageBoxResult.Yes)
                {
                    System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                    {
                        FileName = path,
                        UseShellExecute = true
                    });
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Could not generate the report: {ex.Message}", "Report Failed",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                ReportButton.IsEnabled = true;
            }
        }

        private void ResetUI()
        {
            // Stop any running animations
            StopThinkingAnimation();

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
