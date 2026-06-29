using System;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using SkidrowKiller.Services;

namespace SkidrowKiller.Views
{
    public partial class HomeView : Page
    {
        private readonly SettingsDatabase _db;
        private readonly QuarantineService _quarantine;
        private readonly ThreatIntelligenceService _intel;
        private readonly ProtectionService _protection;
        private readonly SelfTestService _selfTest;

        public event EventHandler? QuickScanRequested;
        public event EventHandler? UpdateIntelRequested;

        public HomeView(SettingsDatabase db, QuarantineService quarantine, ThreatIntelligenceService intel,
            ProtectionService protection, SelfTestService selfTest)
        {
            InitializeComponent();
            _db = db;
            _quarantine = quarantine;
            _intel = intel;
            _protection = protection;
            _selfTest = selfTest;
            RefreshStats();
        }

        public void RefreshStats()
        {
            try
            {
                var stats = _db.GetStatistics();
                TxtScans.Text = stats.TotalScans.ToString("N0");
                TxtThreats.Text = stats.TotalThreats.ToString("N0");
                TxtLastScan.Text = stats.LastScanDate.HasValue
                    ? $"Last scan: {stats.LastScanDate.Value:g}"
                    : "Last scan: never";
            }
            catch { }

            try { TxtQuarantine.Text = _quarantine.GetAllEntries().Count.ToString("N0"); } catch { }

            try
            {
                var s = _intel.Stats;
                TxtIocs.Text = (s.TotalHashes + s.TotalUrls + s.TotalIPs + s.TotalYaraRules).ToString("N0");
            }
            catch { }

            try
            {
                var on = _protection.IsRunning;
                StatusDot.Fill = (System.Windows.Media.Brush)FindResource(on ? "SuccessBrush" : "WarningBrush");
                TxtProtectionStatus.Text = on ? "Protected" : "Partial Protection";
                TxtProtectionStatus.Foreground = (System.Windows.Media.Brush)FindResource(on ? "SuccessBrush" : "WarningBrush");
                TxtProtectionDetail.Text = on
                    ? "Real-time protection and the multi-layer engine are active."
                    : "Real-time protection is off — turn it on in Monitor for full coverage.";
            }
            catch { }
        }

        private async void BtnSelfTest_Click(object sender, RoutedEventArgs e)
        {
            BtnSelfTest.IsEnabled = false;
            TxtSelfTestSummary.Text = "Running self-test...";
            try
            {
                var results = await _selfTest.RunAsync();
                SelfTestList.ItemsSource = results;
                var passed = results.Count(r => r.Passed);
                TxtSelfTestSummary.Text = $"{passed}/{results.Count} checks passed";
            }
            catch (Exception ex)
            {
                TxtSelfTestSummary.Text = $"Self-test error: {ex.Message}";
            }
            finally
            {
                BtnSelfTest.IsEnabled = true;
            }
        }

        private void BtnQuickScan_Click(object sender, RoutedEventArgs e)
            => QuickScanRequested?.Invoke(this, EventArgs.Empty);

        private void BtnUpdateIntel_Click(object sender, RoutedEventArgs e)
            => UpdateIntelRequested?.Invoke(this, EventArgs.Empty);
    }
}
