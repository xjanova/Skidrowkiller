using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using SkidrowKiller.Services;

namespace SkidrowKiller.Views
{
    public partial class BrowserProtectionView : Page
    {
        private readonly BrowserProtectionService _browserProtection;
        private CancellationTokenSource? _cts;
        private List<BrowserScanResult>? _lastResults;

        public BrowserProtectionView(BrowserProtectionService browserProtection)
        {
            InitializeComponent();
            _browserProtection = browserProtection;

            _browserProtection.Start();
            RefreshBrowserList();
        }

        public void RefreshBrowserList()
        {
            BrowsersList.ItemsSource = _browserProtection.DetectedBrowsers;
        }

        private async void BtnScan_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                BtnScan.IsEnabled = false;
                BtnRemoveThreats.IsEnabled = false;
                EmptyState.Visibility = Visibility.Collapsed;
                ResultsScroll.Visibility = Visibility.Collapsed;
                ProgressPanel.Visibility = Visibility.Visible;

                _cts = new CancellationTokenSource();
                _lastResults = await _browserProtection.ScanAllBrowsersAsync(_cts.Token);

                DisplayResults(_lastResults);
            }
            catch (OperationCanceledException)
            {
                // Scan cancelled
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error scanning browsers: {ex.Message}", "Error",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                BtnScan.IsEnabled = true;
                ProgressPanel.Visibility = Visibility.Collapsed;
            }
        }

        private void DisplayResults(List<BrowserScanResult> results)
        {
            ResultsPanel.Children.Clear();

            int totalExtensions = 0;
            int maliciousExtensions = 0;
            int hijackedSettings = 0;

            foreach (var result in results)
            {
                totalExtensions += result.ExtensionsScanned;
                maliciousExtensions += result.MaliciousExtensions.Count;
                hijackedSettings += result.HijackedSettings.Count;

                // Browser header
                var browserHeader = new Border
                {
                    Background = (Brush)FindResource("BgTertiaryBrush"),
                    CornerRadius = new CornerRadius(4),
                    Padding = new Thickness(12, 8, 12, 8),
                    Margin = new Thickness(0, 0, 0, 8)
                };

                var headerPanel = new StackPanel { Orientation = Orientation.Horizontal };
                headerPanel.Children.Add(new TextBlock
                {
                    Text = result.Browser.Name,
                    FontWeight = FontWeights.SemiBold,
                    Foreground = (Brush)FindResource("TextPrimaryBrush"),
                    VerticalAlignment = VerticalAlignment.Center
                });
                headerPanel.Children.Add(new TextBlock
                {
                    Text = $" - {result.ExtensionsScanned} extensions scanned",
                    Foreground = (Brush)FindResource("TextSecondaryBrush"),
                    VerticalAlignment = VerticalAlignment.Center,
                    Margin = new Thickness(8, 0, 0, 0)
                });
                browserHeader.Child = headerPanel;
                ResultsPanel.Children.Add(browserHeader);

                // Malicious extensions
                foreach (var ext in result.MaliciousExtensions)
                {
                    var extItem = CreateThreatItem(
                        $"Malicious Extension: {ext.Name}",
                        ext.Description,
                        ext.Path,
                        true);
                    ResultsPanel.Children.Add(extItem);
                }

                // Hijacked settings
                foreach (var setting in result.HijackedSettings)
                {
                    var settingItem = CreateThreatItem(
                        $"Hijacked {setting.Type}",
                        setting.Description,
                        setting.CurrentValue,
                        false);
                    ResultsPanel.Children.Add(settingItem);
                }

                // If no issues
                if (result.MaliciousExtensions.Count == 0 && result.HijackedSettings.Count == 0)
                {
                    var safeItem = new Border
                    {
                        Background = (Brush)FindResource("BgCardBrush"),
                        BorderBrush = (Brush)FindResource("SuccessBrush"),
                        BorderThickness = new Thickness(1),
                        CornerRadius = new CornerRadius(4),
                        Padding = new Thickness(12),
                        Margin = new Thickness(0, 0, 0, 8)
                    };
                    safeItem.Child = new TextBlock
                    {
                        Text = "No threats detected in this browser",
                        Foreground = (Brush)FindResource("SuccessBrush")
                    };
                    ResultsPanel.Children.Add(safeItem);
                }
            }

            ResultsCount.Text = $"{totalExtensions} extensions, {maliciousExtensions} threats, {hijackedSettings} hijacked settings";
            BtnRemoveThreats.IsEnabled = maliciousExtensions > 0;
            ResultsScroll.Visibility = Visibility.Visible;

            if (results.Count == 0)
            {
                EmptyState.Visibility = Visibility.Visible;
                ResultsScroll.Visibility = Visibility.Collapsed;
            }
        }

        private Border CreateThreatItem(string title, string description, string path, bool isMalicious)
        {
            var item = new Border
            {
                Background = (Brush)FindResource("BgCardBrush"),
                BorderBrush = isMalicious
                    ? (Brush)FindResource("DangerBrush")
                    : (Brush)FindResource("WarningBrush"),
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(4),
                Padding = new Thickness(12),
                Margin = new Thickness(0, 0, 0, 8)
            };

            var panel = new StackPanel();
            panel.Children.Add(new TextBlock
            {
                Text = title,
                FontWeight = FontWeights.SemiBold,
                Foreground = isMalicious
                    ? (Brush)FindResource("DangerBrush")
                    : (Brush)FindResource("WarningBrush")
            });

            if (!string.IsNullOrEmpty(description))
            {
                panel.Children.Add(new TextBlock
                {
                    Text = description,
                    Foreground = (Brush)FindResource("TextSecondaryBrush"),
                    TextWrapping = TextWrapping.Wrap,
                    Margin = new Thickness(0, 4, 0, 0)
                });
            }

            panel.Children.Add(new TextBlock
            {
                Text = path,
                Foreground = (Brush)FindResource("TextTertiaryBrush"),
                FontSize = 11,
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 4, 0, 0)
            });

            item.Child = panel;
            return item;
        }

        private async void BtnRemoveThreats_Click(object sender, RoutedEventArgs e)
        {
            if (_lastResults == null) return;

            var result = MessageBox.Show(
                "Are you sure you want to remove all detected malicious extensions? This cannot be undone.",
                "Confirm Removal",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning);

            if (result != MessageBoxResult.Yes) return;

            int removed = 0;
            int failed = 0;

            foreach (var browserResult in _lastResults)
            {
                foreach (var ext in browserResult.MaliciousExtensions.ToList())
                {
                    var success = await _browserProtection.RemoveExtensionAsync(browserResult.Browser, ext);
                    if (success)
                    {
                        removed++;
                        browserResult.MaliciousExtensions.Remove(ext);
                    }
                    else
                    {
                        failed++;
                    }
                }
            }

            MessageBox.Show(
                $"Removed {removed} malicious extension(s).\n{(failed > 0 ? $"Failed to remove {failed} extension(s)." : "")}",
                "Removal Complete",
                MessageBoxButton.OK,
                MessageBoxImage.Information);

            // Refresh display
            DisplayResults(_lastResults);
        }
    }
}
