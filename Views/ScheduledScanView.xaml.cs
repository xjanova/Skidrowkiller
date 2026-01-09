using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using SkidrowKiller.Services;

namespace SkidrowKiller.Views
{
    public partial class ScheduledScanView : Page
    {
        private readonly ScheduledScanService _scheduledScanService;

        public ScheduledScanView(ScheduledScanService scheduledScanService)
        {
            InitializeComponent();
            _scheduledScanService = scheduledScanService;

            // Subscribe to events
            _scheduledScanService.ScanStarted += OnScanStarted;
            _scheduledScanService.ScanCompleted += OnScanCompleted;
            _scheduledScanService.LogAdded += OnLogAdded;

            UpdateStatus();
            RefreshSchedulesList();
        }

        private void UpdateStatus()
        {
            Dispatcher.Invoke(() =>
            {
                if (_scheduledScanService.IsRunning)
                {
                    StatusBadge.Background = FindResource("SuccessBrush") as Brush;
                    StatusText.Text = "Running";
                    BtnToggleService.Content = "Stop Service";
                }
                else
                {
                    StatusBadge.Background = FindResource("TextTertiaryBrush") as Brush;
                    StatusText.Text = "Stopped";
                    BtnToggleService.Content = "Start Service";
                }

                // Update stats
                TxtTotalSchedules.Text = _scheduledScanService.Schedules.Count.ToString();
                TxtActiveSchedules.Text = _scheduledScanService.Schedules.Count(s => s.IsEnabled).ToString();

                // Update next scan info
                var nextSchedule = _scheduledScanService.NextSchedule;
                if (nextSchedule != null)
                {
                    var nextRun = _scheduledScanService.GetNextRunTime(nextSchedule, DateTime.Now);
                    TxtNextScanName.Text = nextSchedule.Name;
                    TxtNextScanTime.Text = nextRun.HasValue
                        ? nextRun.Value.ToString("dddd, MMM d 'at' h:mm tt")
                        : "Not scheduled";
                }
                else
                {
                    TxtNextScanName.Text = "No scheduled scans";
                    TxtNextScanTime.Text = "Enable a schedule to automate scans";
                }
            });
        }

        private void RefreshSchedulesList()
        {
            Dispatcher.Invoke(() =>
            {
                SchedulesPanel.Children.Clear();

                if (_scheduledScanService.Schedules.Count == 0)
                {
                    EmptyState.Visibility = Visibility.Visible;
                    SchedulesScroll.Visibility = Visibility.Collapsed;
                    return;
                }

                EmptyState.Visibility = Visibility.Collapsed;
                SchedulesScroll.Visibility = Visibility.Visible;

                foreach (var schedule in _scheduledScanService.Schedules)
                {
                    SchedulesPanel.Children.Add(CreateScheduleCard(schedule));
                }

                UpdateStatus();
            });
        }

        private Border CreateScheduleCard(ScanSchedule schedule)
        {
            var card = new Border
            {
                Background = FindResource("BgTertiaryBrush") as Brush,
                CornerRadius = new CornerRadius(8),
                Padding = new Thickness(16),
                Margin = new Thickness(0, 0, 0, 8)
            };

            var grid = new Grid();
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

            // Toggle Switch
            var togglePanel = new StackPanel { VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 16, 0) };
            var toggleCheck = new CheckBox
            {
                IsChecked = schedule.IsEnabled,
                Tag = schedule.Id
            };
            toggleCheck.Checked += (s, e) => ToggleSchedule(schedule.Id, true);
            toggleCheck.Unchecked += (s, e) => ToggleSchedule(schedule.Id, false);
            togglePanel.Children.Add(toggleCheck);
            Grid.SetColumn(togglePanel, 0);
            grid.Children.Add(togglePanel);

            // Schedule Info
            var infoStack = new StackPanel();

            // Name and type
            var headerStack = new StackPanel { Orientation = Orientation.Horizontal };
            headerStack.Children.Add(new TextBlock
            {
                Text = schedule.Name,
                FontSize = 15,
                FontWeight = FontWeights.SemiBold,
                Foreground = FindResource("TextPrimaryBrush") as Brush
            });
            headerStack.Children.Add(new Border
            {
                Background = GetScanTypeBrush(schedule.ScanType),
                CornerRadius = new CornerRadius(4),
                Padding = new Thickness(6, 2, 6, 2),
                Margin = new Thickness(8, 0, 0, 0),
                Child = new TextBlock
                {
                    Text = schedule.ScanType.ToString(),
                    FontSize = 10,
                    Foreground = Brushes.White
                }
            });
            infoStack.Children.Add(headerStack);

            // Frequency description
            infoStack.Children.Add(new TextBlock
            {
                Text = GetFrequencyDescription(schedule),
                FontSize = 12,
                Foreground = FindResource("TextSecondaryBrush") as Brush,
                Margin = new Thickness(0, 4, 0, 0)
            });

            // Last run info
            var lastRunText = schedule.LastRun == DateTime.MinValue
                ? "Never run"
                : $"Last run: {schedule.LastRun:MMM d, yyyy 'at' h:mm tt}";
            infoStack.Children.Add(new TextBlock
            {
                Text = lastRunText,
                FontSize = 11,
                Foreground = FindResource("TextTertiaryBrush") as Brush,
                Margin = new Thickness(0, 2, 0, 0)
            });

            // Result
            if (!string.IsNullOrEmpty(schedule.LastResult))
            {
                infoStack.Children.Add(new TextBlock
                {
                    Text = schedule.LastResult,
                    FontSize = 11,
                    Foreground = schedule.LastResult.StartsWith("Error")
                        ? FindResource("DangerBrush") as Brush
                        : FindResource("TextTertiaryBrush") as Brush,
                    Margin = new Thickness(0, 2, 0, 0)
                });
            }

            Grid.SetColumn(infoStack, 1);
            grid.Children.Add(infoStack);

            // Actions
            var actionsStack = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center };

            var editBtn = new Button
            {
                Content = "Edit",
                Style = FindResource("SecondaryButtonStyle") as Style,
                Padding = new Thickness(12, 6, 12, 6),
                Tag = schedule.Id,
                Margin = new Thickness(0, 0, 8, 0)
            };
            editBtn.Click += BtnEditSchedule_Click;
            actionsStack.Children.Add(editBtn);

            var deleteBtn = new Button
            {
                Content = "Delete",
                Style = FindResource("SecondaryButtonStyle") as Style,
                Padding = new Thickness(12, 6, 12, 6),
                Tag = schedule.Id
            };
            deleteBtn.Click += BtnDeleteSchedule_Click;
            actionsStack.Children.Add(deleteBtn);

            Grid.SetColumn(actionsStack, 2);
            grid.Children.Add(actionsStack);

            card.Child = grid;
            return card;
        }

        private Brush GetScanTypeBrush(ScheduledScanType scanType)
        {
            return scanType switch
            {
                ScheduledScanType.Quick => FindResource("SuccessBrush") as Brush ?? Brushes.Green,
                ScheduledScanType.Full => FindResource("AccentPrimaryBrush") as Brush ?? Brushes.Blue,
                ScheduledScanType.Custom => FindResource("WarningBrush") as Brush ?? Brushes.Orange,
                _ => Brushes.Gray
            };
        }

        private string GetFrequencyDescription(ScanSchedule schedule)
        {
            var time = $"{schedule.Hour:D2}:{schedule.Minute:D2}";

            return schedule.Frequency switch
            {
                ScanFrequency.Daily => $"Every day at {time}",
                ScanFrequency.Weekly => $"Every {string.Join(", ", schedule.DaysOfWeek.Select(d => d.ToString().Substring(0, 3)))} at {time}",
                ScanFrequency.Monthly => $"Day {schedule.DayOfMonth} of each month at {time}",
                ScanFrequency.Once => schedule.ScheduledDate.HasValue
                    ? $"Once on {schedule.ScheduledDate.Value:MMM d, yyyy} at {time}"
                    : $"Once at {time}",
                _ => $"At {time}"
            };
        }

        private void ToggleSchedule(string scheduleId, bool enabled)
        {
            _scheduledScanService.EnableSchedule(scheduleId, enabled);
            UpdateStatus();
        }

        #region Event Handlers

        private void OnScanStarted(object? sender, ScheduledScanEventArgs e)
        {
            Dispatcher.Invoke(() =>
            {
                MessageBox.Show($"Scheduled scan started: {e.Schedule.Name}",
                    "Scheduled Scan", MessageBoxButton.OK, MessageBoxImage.Information);
            });
        }

        private void OnScanCompleted(object? sender, ScheduledScanEventArgs e)
        {
            RefreshSchedulesList();
        }

        private void OnLogAdded(object? sender, string e)
        {
            // Could add logging UI here if needed
        }

        #endregion

        #region UI Event Handlers

        private void BtnToggleService_Click(object sender, RoutedEventArgs e)
        {
            if (_scheduledScanService.IsRunning)
            {
                _scheduledScanService.Stop();
            }
            else
            {
                _scheduledScanService.Start();
            }
            UpdateStatus();
        }

        private void BtnAddSchedule_Click(object sender, RoutedEventArgs e)
        {
            ShowScheduleDialog(null);
        }

        private void BtnEditSchedule_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.Tag is string scheduleId)
            {
                var schedule = _scheduledScanService.Schedules.FirstOrDefault(s => s.Id == scheduleId);
                if (schedule != null)
                {
                    ShowScheduleDialog(schedule);
                }
            }
        }

        private void BtnDeleteSchedule_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.Tag is string scheduleId)
            {
                var result = MessageBox.Show("Delete this schedule?", "Confirm Delete",
                    MessageBoxButton.YesNo, MessageBoxImage.Question);
                if (result == MessageBoxResult.Yes)
                {
                    _scheduledScanService.RemoveSchedule(scheduleId);
                    RefreshSchedulesList();
                }
            }
        }

        private void ShowScheduleDialog(ScanSchedule? existingSchedule)
        {
            var dialog = new ScheduleEditDialog(existingSchedule);
            dialog.Owner = Window.GetWindow(this);

            if (dialog.ShowDialog() == true)
            {
                if (existingSchedule == null)
                {
                    _scheduledScanService.AddSchedule(dialog.Schedule);
                }
                else
                {
                    dialog.Schedule.Id = existingSchedule.Id;
                    _scheduledScanService.UpdateSchedule(dialog.Schedule);
                }
                RefreshSchedulesList();
            }
        }

        #endregion
    }

    /// <summary>
    /// Simple dialog for editing schedules
    /// </summary>
    public class ScheduleEditDialog : Window
    {
        public ScanSchedule Schedule { get; private set; }

        private TextBox _nameBox;
        private ComboBox _frequencyBox;
        private ComboBox _scanTypeBox;
        private TextBox _hourBox;
        private TextBox _minuteBox;

        public ScheduleEditDialog(ScanSchedule? existingSchedule)
        {
            Schedule = existingSchedule ?? new ScanSchedule();

            Title = existingSchedule == null ? "New Schedule" : "Edit Schedule";
            Width = 400;
            Height = 350;
            WindowStartupLocation = WindowStartupLocation.CenterOwner;
            Background = new SolidColorBrush(Color.FromRgb(13, 17, 23));

            var grid = new Grid { Margin = new Thickness(20) };
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            grid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

            // Name
            var nameLabel = new TextBlock { Text = "Schedule Name:", Foreground = Brushes.White, Margin = new Thickness(0, 0, 0, 4) };
            Grid.SetRow(nameLabel, 0);
            grid.Children.Add(nameLabel);

            _nameBox = new TextBox { Text = Schedule.Name, Padding = new Thickness(8), Margin = new Thickness(0, 0, 0, 12) };
            Grid.SetRow(_nameBox, 1);
            grid.Children.Add(_nameBox);

            // Frequency and Scan Type Row
            var optionsPanel = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 0, 12) };

            var freqStack = new StackPanel { Margin = new Thickness(0, 0, 20, 0) };
            freqStack.Children.Add(new TextBlock { Text = "Frequency:", Foreground = Brushes.White, Margin = new Thickness(0, 0, 0, 4) });
            _frequencyBox = new ComboBox { Width = 120, Padding = new Thickness(8) };
            _frequencyBox.Items.Add("Daily");
            _frequencyBox.Items.Add("Weekly");
            _frequencyBox.Items.Add("Monthly");
            _frequencyBox.SelectedIndex = (int)Schedule.Frequency;
            freqStack.Children.Add(_frequencyBox);
            optionsPanel.Children.Add(freqStack);

            var typeStack = new StackPanel();
            typeStack.Children.Add(new TextBlock { Text = "Scan Type:", Foreground = Brushes.White, Margin = new Thickness(0, 0, 0, 4) });
            _scanTypeBox = new ComboBox { Width = 120, Padding = new Thickness(8) };
            _scanTypeBox.Items.Add("Quick");
            _scanTypeBox.Items.Add("Full");
            _scanTypeBox.Items.Add("Custom");
            _scanTypeBox.SelectedIndex = (int)Schedule.ScanType;
            typeStack.Children.Add(_scanTypeBox);
            optionsPanel.Children.Add(typeStack);

            Grid.SetRow(optionsPanel, 2);
            grid.Children.Add(optionsPanel);

            // Time
            var timePanel = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 0, 12) };
            timePanel.Children.Add(new TextBlock { Text = "Time:", Foreground = Brushes.White, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 8, 0) });
            _hourBox = new TextBox { Text = Schedule.Hour.ToString("D2"), Width = 50, Padding = new Thickness(8), TextAlignment = TextAlignment.Center };
            timePanel.Children.Add(_hourBox);
            timePanel.Children.Add(new TextBlock { Text = ":", Foreground = Brushes.White, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(4, 0, 4, 0) });
            _minuteBox = new TextBox { Text = Schedule.Minute.ToString("D2"), Width = 50, Padding = new Thickness(8), TextAlignment = TextAlignment.Center };
            timePanel.Children.Add(_minuteBox);

            Grid.SetRow(timePanel, 3);
            grid.Children.Add(timePanel);

            // Buttons
            var buttonPanel = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };
            var cancelBtn = new Button { Content = "Cancel", Padding = new Thickness(20, 8, 20, 8), Margin = new Thickness(0, 0, 8, 0) };
            cancelBtn.Click += (s, e) => DialogResult = false;
            buttonPanel.Children.Add(cancelBtn);

            var saveBtn = new Button { Content = "Save", Padding = new Thickness(20, 8, 20, 8), Background = new SolidColorBrush(Color.FromRgb(41, 182, 246)) };
            saveBtn.Click += (s, e) =>
            {
                Schedule.Name = _nameBox.Text;
                Schedule.Frequency = (ScanFrequency)_frequencyBox.SelectedIndex;
                Schedule.ScanType = (ScheduledScanType)_scanTypeBox.SelectedIndex;
                if (int.TryParse(_hourBox.Text, out int hour)) Schedule.Hour = Math.Clamp(hour, 0, 23);
                if (int.TryParse(_minuteBox.Text, out int minute)) Schedule.Minute = Math.Clamp(minute, 0, 59);
                Schedule.IsEnabled = true;
                DialogResult = true;
            };
            buttonPanel.Children.Add(saveBtn);

            Grid.SetRow(buttonPanel, 5);
            grid.Children.Add(buttonPanel);

            Content = grid;
        }
    }
}
