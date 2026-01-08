using System.Windows;
using System.Windows.Controls;
using SkidrowKiller.Services;
using Serilog;

namespace SkidrowKiller.Views
{
    public partial class QuarantineView : Page
    {
        private readonly QuarantineService _quarantine;
        private readonly ILogger _logger;

        public QuarantineView(QuarantineService quarantine)
        {
            InitializeComponent();
            _quarantine = quarantine;
            _logger = LoggingService.ForContext<QuarantineView>();

            _quarantine.ItemQuarantined += Quarantine_ItemChanged;
            _quarantine.ItemRestored += Quarantine_ItemChanged;

            RefreshQuarantine();
        }

        private void Quarantine_ItemChanged(object? sender, QuarantineEntry entry)
        {
            Dispatcher.Invoke(RefreshQuarantine);
        }

        public void RefreshQuarantine()
        {
            var entries = _quarantine.GetAllEntries();
            QuarantineListBox.ItemsSource = null;
            QuarantineListBox.ItemsSource = entries;

            QuarantinedCountLabel.Text = entries.Count.ToString();
            ItemCountLabel.Text = $"{entries.Count} items in quarantine";

            // Calculate total size
            var totalSize = _quarantine.GetTotalQuarantineSize();
            TotalSizeLabel.Text = FormatSize(totalSize);

            // Find oldest item
            if (entries.Count > 0)
            {
                var oldest = entries.OrderBy(e => e.QuarantinedAt).First();
                OldestItemLabel.Text = oldest.QuarantinedAt.ToString("dd/MM/yyyy");
            }
            else
            {
                OldestItemLabel.Text = "-";
            }

            // Update visibility
            EmptyState.Visibility = entries.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
            QuarantineListBox.Visibility = entries.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
        }

        private static string FormatSize(long bytes)
        {
            if (bytes < 1024) return $"{bytes} B";
            if (bytes < 1024 * 1024) return $"{bytes / 1024.0:F1} KB";
            if (bytes < 1024 * 1024 * 1024) return $"{bytes / (1024.0 * 1024):F1} MB";
            return $"{bytes / (1024.0 * 1024 * 1024):F2} GB";
        }

        private void RefreshButton_Click(object sender, RoutedEventArgs e)
        {
            RefreshQuarantine();
        }

        private void RestoreButton_Click(object sender, RoutedEventArgs e)
        {
            if (sender is not Button button || button.Tag is not QuarantineEntry entry) return;

            var result = MessageBox.Show(
                $"Restore this item to its original location?\n\n" +
                $"File: {entry.FileName}\n" +
                $"Path: {entry.OriginalPath}\n" +
                $"Threat: {entry.ThreatName}\n\n" +
                "WARNING: Only restore if you're certain this is a false positive!",
                "Confirm Restore",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning);

            if (result != MessageBoxResult.Yes) return;

            var restoreResult = _quarantine.RestoreItem(entry.Id);
            if (restoreResult.Success)
            {
                RefreshQuarantine();
                MessageBox.Show(restoreResult.Message, "Restored",
                    MessageBoxButton.OK, MessageBoxImage.Information);
            }
            else
            {
                MessageBox.Show($"Failed to restore: {restoreResult.Message}", "Error",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void DeleteButton_Click(object sender, RoutedEventArgs e)
        {
            if (sender is not Button button || button.Tag is not QuarantineEntry entry) return;

            var result = MessageBox.Show(
                $"Permanently delete this item?\n\n" +
                $"File: {entry.FileName}\n" +
                $"Original Path: {entry.OriginalPath}\n\n" +
                "This action cannot be undone!",
                "Confirm Delete",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning);

            if (result != MessageBoxResult.Yes) return;

            var deleteResult = _quarantine.DeletePermanently(entry.Id);
            if (deleteResult.Success)
            {
                RefreshQuarantine();
                MessageBox.Show(deleteResult.Message, "Deleted",
                    MessageBoxButton.OK, MessageBoxImage.Information);
            }
            else
            {
                MessageBox.Show($"Failed to delete: {deleteResult.Message}", "Error",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void DeleteAllButton_Click(object sender, RoutedEventArgs e)
        {
            var entries = _quarantine.GetAllEntries();
            if (entries.Count == 0)
            {
                MessageBox.Show("No items to delete.", "Quarantine Empty",
                    MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            var result = MessageBox.Show(
                $"Permanently delete ALL {entries.Count} quarantined items?\n\n" +
                "This action cannot be undone!",
                "Confirm Delete All",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning);

            if (result != MessageBoxResult.Yes) return;

            var deleted = 0;
            foreach (var entry in entries.ToList())
            {
                var deleteResult = _quarantine.DeletePermanently(entry.Id);
                if (deleteResult.Success) deleted++;
            }

            RefreshQuarantine();
            MessageBox.Show($"Deleted {deleted} items.", "Complete",
                MessageBoxButton.OK, MessageBoxImage.Information);
        }
    }
}
