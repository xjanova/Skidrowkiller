using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using SkidrowKiller.Services;

namespace SkidrowKiller.Views
{
    public partial class SystemCleanupView : Page
    {
        private readonly SystemCleanupService _cleanupService;
        private readonly ObservableCollection<CleanupCategoryViewModel> _categories;
        private CancellationTokenSource? _cts;
        private CleanupAnalysisResult? _lastAnalysis;

        public SystemCleanupView()
        {
            InitializeComponent();

            _cleanupService = new SystemCleanupService();
            _cleanupService.ProgressChanged += CleanupService_ProgressChanged;

            // Initialize categories
            _categories = new ObservableCollection<CleanupCategoryViewModel>(
                SystemCleanupService.CleanupCategories.Select(c => new CleanupCategoryViewModel(c)));

            CategoriesList.ItemsSource = _categories;
        }

        private void CleanupService_ProgressChanged(object? sender, CleanupProgressEventArgs e)
        {
            Dispatcher.Invoke(() =>
            {
                ProgressStatus.Text = e.Status;
                ProgressBar.Value = e.PercentComplete;
            });
        }

        private void BtnSelectAll_Click(object sender, RoutedEventArgs e)
        {
            foreach (var cat in _categories)
            {
                cat.IsSelected = true;
            }
        }

        private void BtnSelectNone_Click(object sender, RoutedEventArgs e)
        {
            foreach (var cat in _categories)
            {
                cat.IsSelected = false;
            }
        }

        private async void BtnAnalyze_Click(object sender, RoutedEventArgs e)
        {
            var selectedIds = _categories.Where(c => c.IsSelected).Select(c => c.Id).ToList();

            if (!selectedIds.Any())
            {
                MessageBox.Show("Please select at least one category to analyze.",
                    "No Selection", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            try
            {
                BtnAnalyze.IsEnabled = false;
                BtnClean.IsEnabled = false;
                ProgressPanel.Visibility = Visibility.Visible;
                ProgressBar.IsIndeterminate = true;

                // Reset size displays
                foreach (var cat in _categories)
                {
                    cat.SizeText = "";
                }

                _cts = new CancellationTokenSource();
                _lastAnalysis = await _cleanupService.AnalyzeAsync(selectedIds, _cts.Token);

                // Update category sizes
                foreach (var result in _lastAnalysis.Categories)
                {
                    var cat = _categories.FirstOrDefault(c => c.Id == result.Category.Id);
                    if (cat != null)
                    {
                        cat.SizeText = SystemCleanupService.FormatSize(result.TotalSize);
                    }
                }

                // Update summary
                SummaryText.Text = $"Found {_lastAnalysis.TotalFiles:N0} files to clean";
                TotalSizeText.Text = $"Total: {SystemCleanupService.FormatSize(_lastAnalysis.TotalSize)}";
                BtnClean.IsEnabled = _lastAnalysis.TotalSize > 0;
            }
            catch (OperationCanceledException)
            {
                // Analysis cancelled
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error analyzing: {ex.Message}", "Error",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                BtnAnalyze.IsEnabled = true;
                ProgressPanel.Visibility = Visibility.Collapsed;
                ProgressBar.IsIndeterminate = false;
            }
        }

        private async void BtnClean_Click(object sender, RoutedEventArgs e)
        {
            var selectedIds = _categories.Where(c => c.IsSelected).Select(c => c.Id).ToList();

            if (!selectedIds.Any())
            {
                MessageBox.Show("Please select at least one category to clean.",
                    "No Selection", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            var confirmResult = MessageBox.Show(
                "Are you sure you want to delete the selected items? This cannot be undone.",
                "Confirm Cleanup",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning);

            if (confirmResult != MessageBoxResult.Yes) return;

            try
            {
                BtnAnalyze.IsEnabled = false;
                BtnClean.IsEnabled = false;
                ProgressPanel.Visibility = Visibility.Visible;
                ProgressBar.IsIndeterminate = false;
                ProgressBar.Value = 0;

                _cts = new CancellationTokenSource();
                var result = await _cleanupService.CleanAsync(selectedIds, _cts.Token);

                // Reset size displays
                foreach (var cat in _categories)
                {
                    if (selectedIds.Contains(cat.Id))
                    {
                        cat.SizeText = "";
                    }
                }

                // Show results
                MessageBox.Show(
                    $"Cleanup Complete!\n\n" +
                    $"Files deleted: {result.FilesDeleted:N0}\n" +
                    $"Space freed: {SystemCleanupService.FormatSize(result.SpaceFreed)}\n" +
                    (result.FilesFailed > 0 ? $"Failed to delete: {result.FilesFailed:N0} files" : ""),
                    "Cleanup Complete",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);

                SummaryText.Text = "Cleanup complete";
                TotalSizeText.Text = $"Freed: {SystemCleanupService.FormatSize(result.SpaceFreed)}";
                _lastAnalysis = null;
            }
            catch (OperationCanceledException)
            {
                // Cleanup cancelled
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error during cleanup: {ex.Message}", "Error",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                BtnAnalyze.IsEnabled = true;
                BtnClean.IsEnabled = false;
                ProgressPanel.Visibility = Visibility.Collapsed;
            }
        }
    }

    public class CleanupCategoryViewModel : INotifyPropertyChanged
    {
        private bool _isSelected;
        private string _sizeText = "";

        public string Id { get; }
        public string Name { get; }
        public string Description { get; }

        public bool IsSelected
        {
            get => _isSelected;
            set
            {
                _isSelected = value;
                OnPropertyChanged(nameof(IsSelected));
            }
        }

        public string SizeText
        {
            get => _sizeText;
            set
            {
                _sizeText = value;
                OnPropertyChanged(nameof(SizeText));
            }
        }

        public CleanupCategoryViewModel(CleanupCategory category)
        {
            Id = category.Id;
            Name = category.Name;
            Description = category.Description;
            IsSelected = category.IsSelected;
        }

        public event PropertyChangedEventHandler? PropertyChanged;

        protected virtual void OnPropertyChanged(string propertyName)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }
}
