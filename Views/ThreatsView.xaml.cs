using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
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

        // Sorting and Pagination state
        private string _sortField = "Severity";
        private bool _sortAscending = false;
        private int _pageSize = 20;
        private int _currentPage = 1;
        private int _totalPages = 1;
        private bool _isInitialized = false;

        public ThreatsView(SafeScanner scanner, WhitelistManager whitelist, BackupManager backup, QuarantineService quarantine)
        {
            InitializeComponent();
            _scanner = scanner;
            _whitelist = whitelist;
            _backup = backup;
            _quarantine = quarantine;

            _scanner.ThreatFound += Scanner_ThreatFound;
            _isInitialized = true;

            // Handle mouse wheel scrolling for the entire content area
            ThreatsListBox.PreviewMouseWheel += OnPreviewMouseWheel;
        }

        private void OnPreviewMouseWheel(object sender, MouseWheelEventArgs e)
        {
            // Bubble scroll event to parent ScrollViewer
            ThreatsScrollViewer.ScrollToVerticalOffset(ThreatsScrollViewer.VerticalOffset - e.Delta / 3.0);
            e.Handled = true;
        }

        private void Scanner_ThreatFound(object? sender, ThreatInfo threat)
        {
            Dispatcher.Invoke(() =>
            {
                _threats.Add(threat);
                RefreshThreats();

                // Auto-scroll to bottom to show newest threat
                ScrollToEnd();
            });
        }

        private void ScrollToEnd()
        {
            ThreatsScrollViewer.ScrollToEnd();
        }

        private void ScrollToTop()
        {
            ThreatsScrollViewer.ScrollToTop();
        }

        public void RefreshThreats()
        {
            // Apply sorting
            var sortedThreats = ApplySorting(_threats);

            // Apply pagination
            var totalCount = sortedThreats.Count;
            var pagedThreats = ApplyPagination(sortedThreats);

            ThreatsListBox.ItemsSource = null;
            ThreatsListBox.ItemsSource = pagedThreats;
            ThreatCountLabel.Text = $"{totalCount} threats found";

            EmptyState.Visibility = totalCount == 0 ? Visibility.Visible : Visibility.Collapsed;
            ThreatsScrollViewer.Visibility = totalCount > 0 ? Visibility.Visible : Visibility.Collapsed;

            // Update pagination UI
            UpdatePaginationUI(totalCount);
        }

        private List<ThreatInfo> ApplySorting(List<ThreatInfo> threats)
        {
            IEnumerable<ThreatInfo> sorted = _sortField switch
            {
                "Severity" => _sortAscending
                    ? threats.OrderBy(t => t.Severity).ThenBy(t => t.Score)
                    : threats.OrderByDescending(t => t.Severity).ThenByDescending(t => t.Score),
                "Name" => _sortAscending
                    ? threats.OrderBy(t => t.Name)
                    : threats.OrderByDescending(t => t.Name),
                "Date Found" => _sortAscending
                    ? threats.OrderBy(t => t.DetectedAt)
                    : threats.OrderByDescending(t => t.DetectedAt),
                "Category" => _sortAscending
                    ? threats.OrderBy(t => t.Category).ThenByDescending(t => t.Severity)
                    : threats.OrderByDescending(t => t.Category).ThenByDescending(t => t.Severity),
                "Score" => _sortAscending
                    ? threats.OrderBy(t => t.Score)
                    : threats.OrderByDescending(t => t.Score),
                _ => threats.OrderByDescending(t => t.Severity).ThenByDescending(t => t.Score)
            };

            return sorted.ToList();
        }

        private List<ThreatInfo> ApplyPagination(List<ThreatInfo> threats)
        {
            if (_pageSize <= 0) // "All" selected
            {
                _totalPages = 1;
                _currentPage = 1;
                return threats;
            }

            _totalPages = Math.Max(1, (int)Math.Ceiling((double)threats.Count / _pageSize));
            _currentPage = Math.Clamp(_currentPage, 1, _totalPages);

            return threats
                .Skip((_currentPage - 1) * _pageSize)
                .Take(_pageSize)
                .ToList();
        }

        private void UpdatePaginationUI(int totalCount)
        {
            if (_pageSize <= 0 || totalCount <= _pageSize)
            {
                // Hide pagination when showing all or when items fit in one page
                PaginationPanel.Visibility = Visibility.Collapsed;
                return;
            }

            PaginationPanel.Visibility = Visibility.Visible;

            // Update page info text
            var startItem = (_currentPage - 1) * _pageSize + 1;
            var endItem = Math.Min(_currentPage * _pageSize, totalCount);
            PageInfoText.Text = $"Showing {startItem}-{endItem} of {totalCount}";

            // Update current page text
            CurrentPageText.Text = $"Page {_currentPage} of {_totalPages}";

            // Enable/disable navigation buttons
            FirstPageButton.IsEnabled = _currentPage > 1;
            PrevPageButton.IsEnabled = _currentPage > 1;
            NextPageButton.IsEnabled = _currentPage < _totalPages;
            LastPageButton.IsEnabled = _currentPage < _totalPages;
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

        #region Sorting Event Handlers

        private void SortByComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (!_isInitialized) return;
            if (SortByComboBox.SelectedItem is ComboBoxItem selectedItem)
            {
                _sortField = selectedItem.Content?.ToString() ?? "Severity";
                _currentPage = 1; // Reset to first page when sort changes
                RefreshThreats();
                ScrollToTop();
            }
        }

        private void SortOrderButton_Click(object sender, RoutedEventArgs e)
        {
            _sortAscending = !_sortAscending;
            SortOrderButton.Content = _sortAscending ? "▲" : "▼";
            SortOrderButton.ToolTip = _sortAscending ? "Ascending (click to change)" : "Descending (click to change)";
            RefreshThreats();
            ScrollToTop();
        }

        #endregion

        #region Pagination Event Handlers

        private void PageSizeComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (!_isInitialized) return;
            if (PageSizeComboBox.SelectedItem is ComboBoxItem selectedItem)
            {
                var content = selectedItem.Content?.ToString();
                if (content == "All")
                {
                    _pageSize = 0; // 0 means show all
                }
                else if (int.TryParse(content, out var size))
                {
                    _pageSize = size;
                }
                _currentPage = 1; // Reset to first page when page size changes
                RefreshThreats();
                ScrollToTop();
            }
        }

        private void FirstPageButton_Click(object sender, RoutedEventArgs e)
        {
            if (_currentPage > 1)
            {
                _currentPage = 1;
                RefreshThreats();
                ScrollToTop();
            }
        }

        private void PrevPageButton_Click(object sender, RoutedEventArgs e)
        {
            if (_currentPage > 1)
            {
                _currentPage--;
                RefreshThreats();
                ScrollToTop();
            }
        }

        private void NextPageButton_Click(object sender, RoutedEventArgs e)
        {
            if (_currentPage < _totalPages)
            {
                _currentPage++;
                RefreshThreats();
                ScrollToTop();
            }
        }

        private void LastPageButton_Click(object sender, RoutedEventArgs e)
        {
            if (_currentPage < _totalPages)
            {
                _currentPage = _totalPages;
                RefreshThreats();
                ScrollToTop();
            }
        }

        private void GoToPageTextBox_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Enter)
            {
                if (int.TryParse(GoToPageTextBox.Text, out var pageNum))
                {
                    pageNum = Math.Clamp(pageNum, 1, _totalPages);
                    if (pageNum != _currentPage)
                    {
                        _currentPage = pageNum;
                        RefreshThreats();
                        ScrollToTop();
                    }
                }
                GoToPageTextBox.Clear();
            }
        }

        #endregion
    }
}
