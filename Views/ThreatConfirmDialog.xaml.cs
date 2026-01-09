using System.Windows;
using System.Windows.Media;
using SkidrowKiller.Models;

namespace SkidrowKiller.Views
{
    public enum ThreatAction
    {
        Remove,
        RemoveAll,
        Skip,
        SkipAll,
        Whitelist
    }

    public partial class ThreatConfirmDialog : Window
    {
        public ThreatAction SelectedAction { get; private set; } = ThreatAction.Skip;

        private readonly ThreatInfo _threat;
        private readonly int _currentIndex;
        private readonly int _totalCount;

        public ThreatConfirmDialog(ThreatInfo threat, int currentIndex, int totalCount)
        {
            InitializeComponent();
            _threat = threat;
            _currentIndex = currentIndex;
            _totalCount = totalCount;

            DisplayThreatInfo();
        }

        private void DisplayThreatInfo()
        {
            // Update count label
            CountLabel.Text = $"({_currentIndex + 1} of {_totalCount})";

            // Update score
            ScoreLabel.Text = _threat.Score.ToString();
            ScoreLabel.Foreground = GetScoreBrush(_threat.Score);

            // Update path
            PathLabel.Text = _threat.Path;
            PathLabel.ToolTip = _threat.Path;

            // Update patterns
            PatternsLabel.Text = string.Join(", ", _threat.MatchedPatterns);

            // Update severity
            SeverityLabel.Text = GetSeverityText(_threat.Score);
            SeverityLabel.Foreground = GetScoreBrush(_threat.Score);
        }

        private string GetSeverityText(int score)
        {
            return score switch
            {
                >= 80 => "High",
                >= 60 => "Medium",
                >= 40 => "Low",
                _ => "Very Low"
            };
        }

        private Brush GetScoreBrush(int score)
        {
            return score switch
            {
                >= 80 => (Brush)FindResource("DangerBrush"),
                >= 60 => (Brush)FindResource("WarningBrush"),
                _ => (Brush)FindResource("InfoBrush")
            };
        }

        private void Remove_Click(object sender, RoutedEventArgs e)
        {
            SelectedAction = ThreatAction.Remove;
            DialogResult = true;
            Close();
        }

        private void RemoveAll_Click(object sender, RoutedEventArgs e)
        {
            SelectedAction = ThreatAction.RemoveAll;
            DialogResult = true;
            Close();
        }

        private void Skip_Click(object sender, RoutedEventArgs e)
        {
            SelectedAction = ThreatAction.Skip;
            DialogResult = true;
            Close();
        }

        private void SkipAll_Click(object sender, RoutedEventArgs e)
        {
            SelectedAction = ThreatAction.SkipAll;
            DialogResult = true;
            Close();
        }

        private void Whitelist_Click(object sender, RoutedEventArgs e)
        {
            SelectedAction = ThreatAction.Whitelist;
            DialogResult = true;
            Close();
        }
    }
}
