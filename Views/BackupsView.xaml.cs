using System.Globalization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using SkidrowKiller.Services;

namespace SkidrowKiller.Views
{
    public partial class BackupsView : Page
    {
        private readonly BackupManager _backup;

        public BackupsView(BackupManager backup)
        {
            InitializeComponent();
            _backup = backup;
            RefreshBackups();
        }

        public void RefreshBackups()
        {
            var items = _backup.GetBackups();
            BackupsListBox.ItemsSource = null;
            BackupsListBox.ItemsSource = items;

            BackupCountLabel.Text = items.Count.ToString();
            BackupSizeLabel.Text = FormatFileSize(_backup.GetTotalBackupSize());

            EmptyState.Visibility = items.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
            BackupsListBox.Visibility = items.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
        }

        private void RefreshButton_Click(object sender, RoutedEventArgs e)
        {
            RefreshBackups();
        }

        private void RestoreButton_Click(object sender, RoutedEventArgs e)
        {
            if (sender is not Button button || button.Tag is not string id) return;

            var result = MessageBox.Show(
                "Restore this item to its original location?\n\nThis will overwrite any existing file.",
                "Confirm Restore",
                MessageBoxButton.YesNo,
                MessageBoxImage.Question);

            if (result != MessageBoxResult.Yes) return;

            if (_backup.Restore(id))
            {
                RefreshBackups();
                MessageBox.Show("Item restored successfully!", "Success",
                    MessageBoxButton.OK, MessageBoxImage.Information);
            }
            else
            {
                MessageBox.Show("Failed to restore item.", "Error",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void DeleteButton_Click(object sender, RoutedEventArgs e)
        {
            if (sender is not Button button || button.Tag is not string id) return;

            var result = MessageBox.Show(
                "Delete this backup?\n\nThis cannot be undone.",
                "Confirm Delete",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning);

            if (result == MessageBoxResult.Yes)
            {
                _backup.DeleteBackup(id);
                RefreshBackups();
            }
        }

        private void CleanButton_Click(object sender, RoutedEventArgs e)
        {
            var result = MessageBox.Show(
                "Clean all backups older than 7 days?",
                "Clean Old Backups",
                MessageBoxButton.YesNo,
                MessageBoxImage.Question);

            if (result == MessageBoxResult.Yes)
            {
                _backup.CleanOldBackups(7);
                RefreshBackups();
                MessageBox.Show("Old backups cleaned!", "Complete",
                    MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }

        private string FormatFileSize(long bytes)
        {
            string[] sizes = { "B", "KB", "MB", "GB", "TB" };
            double len = bytes;
            int order = 0;
            while (len >= 1024 && order < sizes.Length - 1)
            {
                order++;
                len /= 1024;
            }
            return $"{len:0.##} {sizes[order]}";
        }
    }

    public class FileSizeConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is not long bytes) return "0 B";

            string[] sizes = { "B", "KB", "MB", "GB", "TB" };
            double len = bytes;
            int order = 0;
            while (len >= 1024 && order < sizes.Length - 1)
            {
                order++;
                len /= 1024;
            }
            return $"{len:0.##} {sizes[order]}";
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }
}
