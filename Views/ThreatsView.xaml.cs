using System.Windows;
using System.Windows.Controls;
using SkidrowKiller.Models;
using SkidrowKiller.Services;

namespace SkidrowKiller.Views
{
    public partial class ThreatsView : Page
    {
        private readonly SafeScanner _scanner;
        private readonly WhitelistManager _whitelist;
        private readonly BackupManager _backup;
        private readonly QuarantineService _quarantine;
        private List<ThreatInfo> _threats = new();

        public ThreatsView(SafeScanner scanner, WhitelistManager whitelist, BackupManager backup, QuarantineService quarantine)
        {
            InitializeComponent();
            _scanner = scanner;
            _whitelist = whitelist;
            _backup = backup;
            _quarantine = quarantine;

            _scanner.ThreatFound += Scanner_ThreatFound;
        }

        private void Scanner_ThreatFound(object? sender, ThreatInfo threat)
        {
            Dispatcher.Invoke(() =>
            {
                _threats.Add(threat);
                RefreshThreats();

                // Auto-scroll to bottom to show newest threat
                ThreatsScrollViewer.ScrollToEnd();
            });
        }

        public void RefreshThreats()
        {
            ThreatsListBox.ItemsSource = null;
            ThreatsListBox.ItemsSource = _threats;
            ThreatCountLabel.Text = $"{_threats.Count} threats found";

            EmptyState.Visibility = _threats.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
            ThreatsListBox.Visibility = _threats.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
        }

        private void RefreshButton_Click(object sender, RoutedEventArgs e)
        {
            RefreshThreats();
        }

        private async void RemoveButton_Click(object sender, RoutedEventArgs e)
        {
            if (sender is not Button button || button.Tag is not ThreatInfo threat) return;

            var result = MessageBox.Show(
                $"Remove this threat?\n\n{threat.Path}\n\nA backup will be created first.",
                "Confirm Removal",
                MessageBoxButton.YesNo,
                MessageBoxImage.Question);

            if (result != MessageBoxResult.Yes) return;

            var removed = await _scanner.RemoveThreatAsync(threat, backup: true);
            if (removed)
            {
                _threats.Remove(threat);
                RefreshThreats();
                MessageBox.Show("Threat removed successfully!", "Success",
                    MessageBoxButton.OK, MessageBoxImage.Information);
            }
            else
            {
                MessageBox.Show("Failed to remove threat.", "Error",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void WhitelistButton_Click(object sender, RoutedEventArgs e)
        {
            if (sender is not Button button || button.Tag is not ThreatInfo threat) return;

            _whitelist.AddToWhitelist(threat.Path, "User confirmed as safe");
            _threats.Remove(threat);
            RefreshThreats();

            MessageBox.Show($"Added to whitelist:\n{threat.Path}", "Whitelisted",
                MessageBoxButton.OK, MessageBoxImage.Information);
        }

        private void QuarantineButton_Click(object sender, RoutedEventArgs e)
        {
            if (sender is not Button button || button.Tag is not ThreatInfo threat) return;

            var result = MessageBox.Show(
                $"Quarantine this threat?\n\n{threat.Path}\n\nThe file will be encrypted and isolated.",
                "Confirm Quarantine",
                MessageBoxButton.YesNo,
                MessageBoxImage.Question);

            if (result != MessageBoxResult.Yes) return;

            var quarantineResult = _quarantine.QuarantineFile(threat.Path, threat);
            if (quarantineResult.Success)
            {
                _threats.Remove(threat);
                RefreshThreats();
                MessageBox.Show(quarantineResult.Message, "Quarantined",
                    MessageBoxButton.OK, MessageBoxImage.Information);
            }
            else
            {
                MessageBox.Show($"Failed to quarantine: {quarantineResult.Message}", "Error",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private async void RemoveAllButton_Click(object sender, RoutedEventArgs e)
        {
            if (!_threats.Any())
            {
                MessageBox.Show("No threats to remove.", "No Threats",
                    MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            var result = MessageBox.Show(
                $"Remove all {_threats.Count} threats?\n\nBackups will be created first.",
                "Confirm Removal",
                MessageBoxButton.YesNo,
                MessageBoxImage.Question);

            if (result != MessageBoxResult.Yes) return;

            var toRemove = _threats.ToList();
            var removed = 0;
            foreach (var threat in toRemove)
            {
                if (await _scanner.RemoveThreatAsync(threat, backup: true))
                {
                    _threats.Remove(threat);
                    removed++;
                }
            }

            RefreshThreats();
            MessageBox.Show($"Removed {removed} of {toRemove.Count} threats.", "Complete",
                MessageBoxButton.OK, MessageBoxImage.Information);
        }

        private void WhitelistAllButton_Click(object sender, RoutedEventArgs e)
        {
            if (!_threats.Any())
            {
                MessageBox.Show("No threats to whitelist.", "No Threats",
                    MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            var result = MessageBox.Show(
                $"Whitelist all {_threats.Count} threats?\n\nThey will be marked as safe.",
                "Confirm Whitelist",
                MessageBoxButton.YesNo,
                MessageBoxImage.Question);

            if (result != MessageBoxResult.Yes) return;

            var count = _threats.Count;
            foreach (var threat in _threats.ToList())
            {
                _whitelist.AddToWhitelist(threat.Path, "User confirmed as safe");
                _threats.Remove(threat);
            }

            RefreshThreats();
            MessageBox.Show($"Added {count} items to whitelist.", "Whitelisted",
                MessageBoxButton.OK, MessageBoxImage.Information);
        }

        private void QuarantineAllButton_Click(object sender, RoutedEventArgs e)
        {
            if (!_threats.Any())
            {
                MessageBox.Show("No threats to quarantine.", "No Threats",
                    MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            var result = MessageBox.Show(
                $"Quarantine all {_threats.Count} threats?\n\nFiles will be encrypted and isolated.",
                "Confirm Quarantine",
                MessageBoxButton.YesNo,
                MessageBoxImage.Question);

            if (result != MessageBoxResult.Yes) return;

            var toQuarantine = _threats.ToList();
            var quarantined = 0;
            foreach (var threat in toQuarantine)
            {
                var qResult = _quarantine.QuarantineFile(threat.Path, threat);
                if (qResult.Success)
                {
                    _threats.Remove(threat);
                    quarantined++;
                }
            }

            RefreshThreats();
            MessageBox.Show($"Quarantined {quarantined} of {toQuarantine.Count} threats.", "Complete",
                MessageBoxButton.OK, MessageBoxImage.Information);
        }
    }
}
