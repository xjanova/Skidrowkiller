using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using SkidrowKiller.Services;

namespace SkidrowKiller.Views
{
    public partial class ThreatIntelligenceView : Page
    {
        private readonly ThreatIntelligenceService _threatIntel;
        private readonly LicenseService? _licenseService;
        private CancellationTokenSource? _cts;
        private LicenseTier _currentTier = LicenseTier.Free;
        private bool _isTrial = false;

        public ThreatIntelligenceView(ThreatIntelligenceService threatIntel, LicenseService? licenseService = null)
        {
            InitializeComponent();

            _threatIntel = threatIntel;
            _licenseService = licenseService;

            // Subscribe to events
            _threatIntel.ProgressChanged += ThreatIntel_ProgressChanged;
            _threatIntel.UpdateCompleted += ThreatIntel_UpdateCompleted;

            // Determine current tier from license
            DetermineCurrentTier();

            // Load initial data
            RefreshUI();
        }

        private void DetermineCurrentTier()
        {
            if (_licenseService == null)
            {
                _currentTier = LicenseTier.Free;
                _isTrial = false;
                return;
            }

            // Use centralized GetCurrentTier() - Trial now returns Enterprise tier
            _currentTier = _licenseService.GetCurrentTier();
            _isTrial = _licenseService.IsTrial;
        }

        private void RefreshUI()
        {
            // Re-check tier in case license changed
            DetermineCurrentTier();

            // Update stats
            var stats = _threatIntel.Stats;
            TxtTotalHashes.Text = stats.TotalHashes.ToString("N0");
            TxtTotalUrls.Text = stats.TotalUrls.ToString("N0");
            TxtTotalIPs.Text = stats.TotalIPs.ToString("N0");
            TxtTotalYara.Text = stats.TotalYaraRules.ToString("N0");

            // Update tier info - show (TRIAL) if on trial
            var tierName = _currentTier switch
            {
                LicenseTier.Free => "Free",
                LicenseTier.Pro => "Pro",
                LicenseTier.Enterprise => "Enterprise",
                _ => "Free"
            };

            // Append (TRIAL) if user is on trial
            TxtCurrentTier.Text = _isTrial ? $"{tierName} (TRIAL)" : tierName;

            var allFeeds = _threatIntel.GetFeeds();
            var availableFeeds = _threatIntel.GetFeedsForTier(_currentTier);
            TxtAvailableFeeds.Text = $"{availableFeeds.Count} of {allFeeds.Count} feeds available";

            // Hide upgrade button for enterprise (unless it's trial - they can still purchase)
            // For trial users, show different message
            if (_isTrial)
            {
                BtnUpgrade.Visibility = Visibility.Visible;
                BtnUpgrade.Content = "Purchase License";
            }
            else
            {
                BtnUpgrade.Visibility = _currentTier == LicenseTier.Enterprise
                    ? Visibility.Collapsed
                    : Visibility.Visible;
            }

            // Update last update time
            if (_threatIntel.LastUpdate != DateTime.MinValue)
            {
                TxtLastUpdate.Text = $"Last update: {_threatIntel.LastUpdate:g}";
            }

            // Update feed list
            RefreshFeedList();
        }

        private void RefreshFeedList()
        {
            var feeds = _threatIntel.GetFeeds();
            var feedViewModels = feeds.Select(f => new FeedViewModel(f, _currentTier)).ToList();
            FeedsList.ItemsSource = feedViewModels;
        }

        private void ThreatIntel_ProgressChanged(object? sender, ThreatIntelProgressEventArgs e)
        {
            Dispatcher.Invoke(() =>
            {
                MainProgressBar.Value = e.PercentComplete;
                TxtProgressPercent.Text = $"{e.PercentComplete}%";
                TxtProgressStatus.Text = e.Status;
                TxtCurrentFeed.Text = e.CurrentFeed;
                TxtFeedCount.Text = $"({e.FeedsCompleted}/{e.TotalFeeds})";
            });
        }

        private void ThreatIntel_UpdateCompleted(object? sender, ThreatIntelCompleteEventArgs e)
        {
            Dispatcher.Invoke(() =>
            {
                ProgressPanel.Visibility = Visibility.Collapsed;
                BtnUpdateAll.IsEnabled = true;
                BtnRefresh.IsEnabled = true;

                RefreshUI();

                var result = e.Result;
                var message = $"Update Complete!\n\n" +
                              $"Feeds updated: {result.FeedsUpdated}\n" +
                              $"New hashes: {result.NewHashes:N0}\n" +
                              $"New URLs: {result.NewUrls:N0}\n" +
                              $"New IPs: {result.NewIPs:N0}\n" +
                              $"New YARA rules: {result.NewYaraRules:N0}\n" +
                              $"Duration: {result.Duration.TotalSeconds:F1}s";

                if (result.Errors.Any())
                {
                    message += $"\n\nErrors ({result.FeedsFailed}):\n" +
                               string.Join("\n", result.Errors.Take(5));
                }

                MessageBox.Show(message, "Threat Intelligence Update",
                    MessageBoxButton.OK,
                    result.Success ? MessageBoxImage.Information : MessageBoxImage.Warning);
            });
        }

        private async void BtnUpdateAll_Click(object sender, RoutedEventArgs e)
        {
            if (_threatIntel.IsUpdating) return;

            BtnUpdateAll.IsEnabled = false;
            BtnRefresh.IsEnabled = false;
            ProgressPanel.Visibility = Visibility.Visible;
            MainProgressBar.Value = 0;
            TxtProgressPercent.Text = "0%";
            TxtProgressStatus.Text = "Initializing...";

            try
            {
                _cts = new CancellationTokenSource();
                await _threatIntel.UpdateAllAsync(_currentTier, _cts.Token);
            }
            catch (OperationCanceledException)
            {
                MessageBox.Show("Update cancelled.", "Cancelled",
                    MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Update failed: {ex.Message}", "Error",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                ProgressPanel.Visibility = Visibility.Collapsed;
                BtnUpdateAll.IsEnabled = true;
                BtnRefresh.IsEnabled = true;
            }
        }

        private void BtnCancel_Click(object sender, RoutedEventArgs e)
        {
            _cts?.Cancel();
        }

        private void BtnRefresh_Click(object sender, RoutedEventArgs e)
        {
            RefreshUI();
        }

        private void BtnUpgrade_Click(object sender, RoutedEventArgs e)
        {
            // Open purchase URL
            var url = _licenseService?.GetPurchaseUrl() ?? "https://xman4289.com/products/skidrow-killer";
            try
            {
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                {
                    FileName = url,
                    UseShellExecute = true
                });
            }
            catch
            {
                MessageBox.Show($"Please visit: {url}", "Upgrade",
                    MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }
    }

    public class FeedViewModel
    {
        private readonly ThreatFeed _feed;
        private readonly LicenseTier _currentTier;

        public FeedViewModel(ThreatFeed feed, LicenseTier currentTier)
        {
            _feed = feed;
            _currentTier = currentTier;
        }

        public string Name => _feed.Name;
        public string TierDisplay => _feed.TierDisplay;
        public string CategoryDisplay => _feed.CategoryDisplay;

        public bool IsAvailable => _feed.RequiredTier <= _currentTier;

        public string StatusText => IsAvailable
            ? (_feed.LastUpdate == DateTime.MinValue ? "Not updated" : _feed.LastUpdate.ToString("g"))
            : "Locked";

        public Brush StatusColor => IsAvailable
            ? (_feed.LastUpdate == DateTime.MinValue
                ? (Brush)Application.Current.FindResource("TextTertiaryBrush")
                : (Brush)Application.Current.FindResource("SuccessBrush"))
            : (Brush)Application.Current.FindResource("TextTertiaryBrush");

        public Brush TierColor => _feed.RequiredTier switch
        {
            LicenseTier.Free => (Brush)Application.Current.FindResource("SuccessBrush"),
            LicenseTier.Pro => (Brush)Application.Current.FindResource("AccentPrimaryBrush"),
            LicenseTier.Enterprise => (Brush)Application.Current.FindResource("WarningBrush"),
            _ => (Brush)Application.Current.FindResource("TextTertiaryBrush")
        };

        public string ItemCountText => _feed.LastItemCount > 0
            ? $"{_feed.LastItemCount:N0} items"
            : "-";
    }
}
