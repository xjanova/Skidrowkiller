using System;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Microsoft.Win32;
using SkidrowKiller.Services;
using System.Linq;

namespace SkidrowKiller.Views
{
    public partial class RansomwareProtectionView : Page
    {
        private readonly RansomwareProtectionService _ransomwareService;
        private int _alertCount;
        private int _honeypotCount;

        public RansomwareProtectionView(RansomwareProtectionService ransomwareService)
        {
            InitializeComponent();
            _ransomwareService = ransomwareService;

            // Subscribe to events
            _ransomwareService.AlertRaised += OnAlertRaised;
            _ransomwareService.LogAdded += OnLogAdded;
            _ransomwareService.StatusChanged += OnStatusChanged;

            // Initialize UI
            UpdateStatus();
            RefreshFoldersList();
            CountHoneypots();
        }

        private void UpdateStatus()
        {
            Dispatcher.Invoke(() =>
            {
                if (_ransomwareService.IsEnabled)
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

                TxtFolderCount.Text = _ransomwareService.ProtectedFolders.Count.ToString();
                TxtHoneypotCount.Text = _honeypotCount.ToString();
                TxtAlertCount.Text = _alertCount.ToString();
            });
        }

        private void CountHoneypots()
        {
            _honeypotCount = 0;
            foreach (var folder in _ransomwareService.ProtectedFolders)
            {
                var honeypotPath = Path.Combine(folder, ".~important_backup.docx");
                if (File.Exists(honeypotPath))
                {
                    _honeypotCount++;
                }
            }

            // Also count honeypots in the honeypot folder
            var appData = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "SkidrowKiller", "Honeypots"
            );
            if (Directory.Exists(appData))
            {
                _honeypotCount += Directory.GetFiles(appData).Length;
            }
        }

        private void RefreshFoldersList()
        {
            Dispatcher.Invoke(() =>
            {
                FoldersList.Items.Clear();

                foreach (var folder in _ransomwareService.ProtectedFolders)
                {
                    FoldersList.Items.Add(CreateFolderCard(folder));
                }

                UpdateStatus();
            });
        }

        private Border CreateFolderCard(string folderPath)
        {
            var card = new Border
            {
                Background = FindResource("BgTertiaryBrush") as Brush,
                CornerRadius = new CornerRadius(6),
                Padding = new Thickness(12, 8, 12, 8),
                Margin = new Thickness(0, 0, 8, 8)
            };

            var grid = new Grid();
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

            var stack = new StackPanel();

            // Folder name
            var folderName = Path.GetFileName(folderPath);
            if (string.IsNullOrEmpty(folderName)) folderName = folderPath;

            stack.Children.Add(new TextBlock
            {
                Text = folderName,
                FontSize = 13,
                FontWeight = FontWeights.SemiBold,
                Foreground = FindResource("TextPrimaryBrush") as Brush
            });

            // Full path
            stack.Children.Add(new TextBlock
            {
                Text = folderPath,
                FontSize = 10,
                Foreground = FindResource("TextTertiaryBrush") as Brush,
                TextTrimming = TextTrimming.CharacterEllipsis,
                MaxWidth = 200
            });

            Grid.SetColumn(stack, 0);
            grid.Children.Add(stack);

            // Remove button
            var removeBtn = new Button
            {
                Content = "X",
                Style = FindResource("SecondaryButtonStyle") as Style,
                Padding = new Thickness(8, 4, 8, 4),
                FontSize = 10,
                Tag = folderPath,
                VerticalAlignment = VerticalAlignment.Center
            };
            removeBtn.Click += BtnRemoveFolder_Click;

            Grid.SetColumn(removeBtn, 1);
            grid.Children.Add(removeBtn);

            card.Child = grid;
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
                    FontSize = 10,
                    Foreground = FindResource("TextTertiaryBrush") as Brush,
                    Margin = new Thickness(0, 0, 8, 0)
                });
                stack.Children.Add(new TextBlock
                {
                    Text = message,
                    FontSize = 11,
                    Foreground = FindResource("TextSecondaryBrush") as Brush,
                    TextWrapping = TextWrapping.Wrap
                });

                entry.Child = stack;
                LogPanel.Children.Insert(0, entry);

                // Keep only last 50 entries
                while (LogPanel.Children.Count > 51)
                {
                    LogPanel.Children.RemoveAt(LogPanel.Children.Count - 1);
                }
            });
        }

        private void AddAlertEntry(RansomwareAlertEventArgs alert)
        {
            Dispatcher.Invoke(() =>
            {
                EmptyAlertsText.Visibility = Visibility.Collapsed;
                _alertCount++;
                UpdateStatus();

                var severityColor = alert.Severity switch
                {
                    AlertSeverity.Critical => FindResource("DangerBrush") as Brush,
                    AlertSeverity.High => FindResource("WarningBrush") as Brush,
                    AlertSeverity.Medium => FindResource("WarningBrush") as Brush,
                    _ => FindResource("TextSecondaryBrush") as Brush
                };

                var entry = new Border
                {
                    Background = FindResource("BgTertiaryBrush") as Brush,
                    BorderBrush = severityColor,
                    BorderThickness = new Thickness(2, 0, 0, 0),
                    Padding = new Thickness(12, 8, 12, 8),
                    Margin = new Thickness(0, 0, 0, 8)
                };

                var stack = new StackPanel();

                // Header with severity
                var header = new StackPanel { Orientation = Orientation.Horizontal };
                header.Children.Add(new TextBlock
                {
                    Text = $"[{alert.Severity}]",
                    FontSize = 11,
                    FontWeight = FontWeights.Bold,
                    Foreground = severityColor,
                    Margin = new Thickness(0, 0, 8, 0)
                });
                header.Children.Add(new TextBlock
                {
                    Text = alert.AlertType.ToString(),
                    FontSize = 11,
                    FontWeight = FontWeights.SemiBold,
                    Foreground = FindResource("TextPrimaryBrush") as Brush
                });
                stack.Children.Add(header);

                // Description
                stack.Children.Add(new TextBlock
                {
                    Text = alert.Description,
                    FontSize = 11,
                    Foreground = FindResource("TextSecondaryBrush") as Brush,
                    TextWrapping = TextWrapping.Wrap,
                    Margin = new Thickness(0, 4, 0, 0)
                });

                // File path if available
                if (!string.IsNullOrEmpty(alert.FilePath))
                {
                    stack.Children.Add(new TextBlock
                    {
                        Text = alert.FilePath,
                        FontSize = 10,
                        Foreground = FindResource("TextTertiaryBrush") as Brush,
                        TextTrimming = TextTrimming.CharacterEllipsis,
                        Margin = new Thickness(0, 2, 0, 0)
                    });
                }

                // Timestamp
                stack.Children.Add(new TextBlock
                {
                    Text = alert.Timestamp.ToString("HH:mm:ss"),
                    FontSize = 9,
                    Foreground = FindResource("TextTertiaryBrush") as Brush,
                    Margin = new Thickness(0, 4, 0, 0)
                });

                entry.Child = stack;
                AlertsPanel.Children.Insert(0, entry);

                // Keep only last 20 alerts
                while (AlertsPanel.Children.Count > 21)
                {
                    AlertsPanel.Children.RemoveAt(AlertsPanel.Children.Count - 1);
                }
            });
        }

        #region Event Handlers

        private void OnAlertRaised(object? sender, RansomwareAlertEventArgs e)
        {
            AddAlertEntry(e);
        }

        private void OnLogAdded(object? sender, string e)
        {
            AddLogEntry(e);
        }

        private void OnStatusChanged(object? sender, bool isEnabled)
        {
            UpdateStatus();
        }

        #endregion

        #region UI Event Handlers

        private void BtnToggleProtection_Click(object sender, RoutedEventArgs e)
        {
            if (_ransomwareService.IsEnabled)
            {
                _ransomwareService.Stop();
            }
            else
            {
                _ransomwareService.Start();
            }
            UpdateStatus();
        }

        private void BtnAddFolder_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var dialog = new OpenFolderDialog
                {
                    Title = "Select a folder to protect from ransomware",
                    Multiselect = false
                };

                if (dialog.ShowDialog() == true)
                {
                    _ransomwareService.AddProtectedFolder(dialog.FolderName);
                    RefreshFoldersList();
                    CountHoneypots();
                }
            }
            catch
            {
                // Fallback for older Windows versions
                var ofd = new OpenFileDialog
                {
                    Title = "Select a folder to protect",
                    ValidateNames = false,
                    CheckFileExists = false,
                    CheckPathExists = true,
                    FileName = "Select Folder"
                };

                if (ofd.ShowDialog() == true)
                {
                    var path = Path.GetDirectoryName(ofd.FileName);
                    if (!string.IsNullOrEmpty(path) && Directory.Exists(path))
                    {
                        _ransomwareService.AddProtectedFolder(path);
                        RefreshFoldersList();
                        CountHoneypots();
                    }
                }
            }
        }

        private void BtnRemoveFolder_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.Tag is string folderPath)
            {
                var result = MessageBox.Show(
                    $"Remove protection from:\n{folderPath}?",
                    "Remove Protection",
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Question);

                if (result == MessageBoxResult.Yes)
                {
                    _ransomwareService.RemoveProtectedFolder(folderPath);
                    RefreshFoldersList();
                    CountHoneypots();
                }
            }
        }

        private void BtnRefreshSnapshots_Click(object sender, RoutedEventArgs e)
        {
            // Restart the service to refresh snapshots
            if (_ransomwareService.IsEnabled)
            {
                _ransomwareService.Stop();
                _ransomwareService.Start();
                AddLogEntry("File snapshots refreshed");
            }
            else
            {
                MessageBox.Show("Protection must be enabled to refresh snapshots.",
                    "Ransomware Protection", MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }

        private void BtnClearLog_Click(object sender, RoutedEventArgs e)
        {
            LogPanel.Children.Clear();
            LogPanel.Children.Add(EmptyLogText);
            EmptyLogText.Visibility = Visibility.Visible;
        }

        #endregion
    }
}
