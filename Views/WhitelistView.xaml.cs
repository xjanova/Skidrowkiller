using System.Windows;
using System.Windows.Controls;
using Microsoft.Win32;
using SkidrowKiller.Services;

namespace SkidrowKiller.Views
{
    public partial class WhitelistView : Page
    {
        private readonly WhitelistManager _whitelist;

        public WhitelistView(WhitelistManager whitelist)
        {
            InitializeComponent();
            _whitelist = whitelist;
            RefreshWhitelist();
        }

        public void RefreshWhitelist()
        {
            var items = _whitelist.GetWhitelist();
            WhitelistListBox.ItemsSource = null;
            WhitelistListBox.ItemsSource = items;
            CountLabel.Text = $"{items.Count} items in whitelist";

            EmptyState.Visibility = items.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
            WhitelistListBox.Visibility = items.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
        }

        private void BrowseButton_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new OpenFileDialog
            {
                Title = "Select file to whitelist",
                Filter = "All files (*.*)|*.*"
            };

            if (dialog.ShowDialog() == true)
            {
                PathTextBox.Text = dialog.FileName;
            }
        }

        private void AddButton_Click(object sender, RoutedEventArgs e)
        {
            var path = PathTextBox.Text.Trim();
            var reason = ReasonTextBox.Text.Trim();

            if (string.IsNullOrEmpty(path))
            {
                MessageBox.Show("Please enter a path.", "Validation Error",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            // Check if it's a pattern (contains *)
            var isPattern = path.Contains("*");

            _whitelist.AddToWhitelist(path, reason, isPattern);

            PathTextBox.Clear();
            ReasonTextBox.Text = "User added";
            RefreshWhitelist();

            MessageBox.Show($"Added to whitelist:\n{path}", "Success",
                MessageBoxButton.OK, MessageBoxImage.Information);
        }

        private void RemoveButton_Click(object sender, RoutedEventArgs e)
        {
            if (sender is not Button button || button.Tag is not string id) return;

            var result = MessageBox.Show(
                "Remove this item from the whitelist?",
                "Confirm",
                MessageBoxButton.YesNo,
                MessageBoxImage.Question);

            if (result == MessageBoxResult.Yes)
            {
                _whitelist.RemoveFromWhitelist(id);
                RefreshWhitelist();
            }
        }
    }
}
