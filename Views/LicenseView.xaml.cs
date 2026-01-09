using System;
using System.Diagnostics;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using SkidrowKiller.Services;

namespace SkidrowKiller.Views
{
    public partial class LicenseView : Page
    {
        private readonly LicenseService _licenseService;

        public LicenseView(LicenseService licenseService)
        {
            InitializeComponent();
            _licenseService = licenseService;

            _licenseService.LicenseStatusChanged += LicenseService_StatusChanged;

            // Display Device ID
            DeviceIdTextBlock.Text = _licenseService.GetDeviceId();

            UpdateUI();
        }

        private void LicenseService_StatusChanged(object? sender, LicenseStatus status)
        {
            Dispatcher.Invoke(() => UpdateUI());
        }

        private void UpdateUI()
        {
            var license = _licenseService.CurrentLicense;

            if (license == null || !license.IsValid)
            {
                // Not activated
                ShowNotActivatedState();
            }
            else if (license.IsTrial)
            {
                // Trial mode
                ShowTrialState(license);
            }
            else
            {
                // Licensed
                ShowLicensedState(license);
            }
        }

        private void ShowNotActivatedState()
        {
            LicenseStatusLabel.Text = "Not Activated";
            LicenseStatusLabel.Foreground = (Brush)FindResource("TextTertiaryBrush");
            LicenseDetailLabel.Text = "Please enter your license key to activate";

            StatusIcon.Data = Geometry.Parse("M12,2A10,10 0 0,0 2,12A10,10 0 0,0 12,22A10,10 0 0,0 22,12A10,10 0 0,0 12,2M12,20A8,8 0 0,1 4,12A8,8 0 0,1 12,4A8,8 0 0,1 20,12A8,8 0 0,1 12,20M12,6A6,6 0 0,0 6,12A6,6 0 0,0 12,18A6,6 0 0,0 18,12A6,6 0 0,0 12,6");
            StatusIcon.Fill = (Brush)FindResource("TextTertiaryBrush");

            UpdateStatusGlow(Colors.Gray);

            LicenseInfoPanel.Visibility = Visibility.Collapsed;
            DaysBadge.Visibility = Visibility.Collapsed;
            ActivationPanel.Visibility = Visibility.Visible;
            LicensedPanel.Visibility = Visibility.Collapsed;
            StartTrialButton.IsEnabled = true;
        }

        private void ShowTrialState(LicenseInfo license)
        {
            LicenseStatusLabel.Text = "Trial Version";
            LicenseStatusLabel.Foreground = (Brush)FindResource("WarningBrush");
            LicenseDetailLabel.Text = "Limited features. Upgrade to Pro for full access.";

            StatusIcon.Data = Geometry.Parse("M12,20A8,8 0 0,0 20,12A8,8 0 0,0 12,4A8,8 0 0,0 4,12A8,8 0 0,0 12,20M12,2A10,10 0 0,1 22,12A10,10 0 0,1 12,22C6.47,22 2,17.5 2,12A10,10 0 0,1 12,2M12.5,7V12.25L17,14.92L16.25,16.15L11,13V7H12.5Z");
            StatusIcon.Fill = (Brush)FindResource("WarningBrush");

            UpdateStatusGlow(Color.FromRgb(255, 183, 77));

            LicenseInfoPanel.Visibility = Visibility.Collapsed;

            DaysBadge.Visibility = Visibility.Visible;
            DaysBadge.Background = new SolidColorBrush(Color.FromArgb(32, 255, 183, 77));
            DaysCountLabel.Text = license.DaysRemaining.ToString();
            DaysCountLabel.Foreground = (Brush)FindResource("WarningBrush");

            ActivationPanel.Visibility = Visibility.Visible;
            LicensedPanel.Visibility = Visibility.Collapsed;
            StartTrialButton.IsEnabled = false;
            StartTrialButton.Content = "Trial Active";
        }

        private void ShowLicensedState(LicenseInfo license)
        {
            LicenseStatusLabel.Text = "License Active";
            LicenseStatusLabel.Foreground = (Brush)FindResource("GreenPrimaryBrush");
            LicenseDetailLabel.Text = license.ProductName ?? "Skidrow Killer Pro";

            StatusIcon.Data = Geometry.Parse("M12,1L3,5V11C3,16.55 6.84,21.74 12,23C17.16,21.74 21,16.55 21,11V5L12,1M10,17L6,13L7.41,11.59L10,14.17L16.59,7.58L18,9L10,17Z");
            StatusIcon.Fill = (Brush)FindResource("GreenPrimaryBrush");

            UpdateStatusGlow(Color.FromRgb(102, 187, 106));

            // Show license details
            LicenseInfoPanel.Visibility = Visibility.Visible;
            EmailLabel.Text = license.Email ?? "-";
            ExpiresLabel.Text = license.ExpiresAt?.ToString("yyyy-MM-dd") ?? "Never";
            DevicesLabel.Text = $"{license.CurrentDevices}/{license.MaxDevices}";

            // Days badge
            DaysBadge.Visibility = Visibility.Visible;
            DaysBadge.Background = new SolidColorBrush(Color.FromArgb(32, 102, 187, 106));

            if (license.ExpiresAt == null || license.ExpiresAt > DateTime.Now.AddYears(10))
            {
                DaysCountLabel.Text = "∞";
            }
            else
            {
                DaysCountLabel.Text = license.DaysRemaining.ToString();
            }
            DaysCountLabel.Foreground = (Brush)FindResource("GreenPrimaryBrush");

            ActivationPanel.Visibility = Visibility.Collapsed;
            LicensedPanel.Visibility = Visibility.Visible;
            StartTrialButton.IsEnabled = false;
            StartTrialButton.Content = "License Active";
        }

        private void UpdateStatusGlow(Color color)
        {
            var brush = new RadialGradientBrush
            {
                GradientOrigin = new Point(0.5, 0.5),
                Center = new Point(0.5, 0.5)
            };
            brush.GradientStops.Add(new GradientStop(Color.FromArgb(64, color.R, color.G, color.B), 0));
            brush.GradientStops.Add(new GradientStop(Colors.Transparent, 1));
            StatusGlow.Fill = brush;
        }

        private async void ActivateButton_Click(object sender, RoutedEventArgs e)
        {
            var licenseKey = LicenseKeyTextBox.Text.Trim();

            if (string.IsNullOrEmpty(licenseKey))
            {
                ShowActivationMessage("Please enter a license key", false);
                return;
            }

            ActivateButton.IsEnabled = false;
            ActivateButton.Content = "Activating...";
            ActivationMessage.Text = "";

            try
            {
                var result = await _licenseService.ActivateLicenseAsync(licenseKey);

                if (result.Success)
                {
                    ShowActivationMessage(result.Message, true);
                    LicenseKeyTextBox.Clear();
                    UpdateUI();
                }
                else
                {
                    ShowActivationMessage(result.Message, false);
                }
            }
            catch (Exception ex)
            {
                ShowActivationMessage($"Error: {ex.Message}", false);
            }
            finally
            {
                ActivateButton.IsEnabled = true;
                ActivateButton.Content = "Activate";
            }
        }

        private async void ValidateButton_Click(object sender, RoutedEventArgs e)
        {
            ValidateButton.IsEnabled = false;
            ValidateButton.Content = "Validating...";

            try
            {
                var result = await _licenseService.ValidateLicenseAsync();
                ShowLicensedMessage(result.Message, result.Success);
                UpdateUI();
            }
            catch (Exception ex)
            {
                ShowLicensedMessage($"Error: {ex.Message}", false);
            }
            finally
            {
                ValidateButton.IsEnabled = true;
                ValidateButton.Content = "Validate License";
            }
        }

        private async void DeactivateButton_Click(object sender, RoutedEventArgs e)
        {
            var result = MessageBox.Show(
                "Are you sure you want to deactivate this license?\n\nYou can reactivate it later on this or another device.",
                "Deactivate License",
                MessageBoxButton.YesNo,
                MessageBoxImage.Question);

            if (result != MessageBoxResult.Yes) return;

            DeactivateButton.IsEnabled = false;
            DeactivateButton.Content = "Deactivating...";

            try
            {
                var deactivateResult = await _licenseService.DeactivateLicenseAsync();
                ShowLicensedMessage(deactivateResult.Message, deactivateResult.Success);
                UpdateUI();
            }
            catch (Exception ex)
            {
                ShowLicensedMessage($"Error: {ex.Message}", false);
            }
            finally
            {
                DeactivateButton.IsEnabled = true;
                DeactivateButton.Content = "Deactivate";
            }
        }

        private async void StartTrialButton_Click(object sender, RoutedEventArgs e)
        {
            StartTrialButton.IsEnabled = false;
            StartTrialButton.Content = "Starting...";

            try
            {
                var result = await _licenseService.StartDemoAsync();

                if (result.Success)
                {
                    ShowActivationMessage(result.Message, true);
                    UpdateUI();
                }
                else
                {
                    ShowActivationMessage(result.Message, false);
                }
            }
            catch (Exception ex)
            {
                ShowActivationMessage($"Error: {ex.Message}", false);
            }
            finally
            {
                StartTrialButton.IsEnabled = true;
                StartTrialButton.Content = "Start 7-Day Trial";
            }
        }

        private void PurchaseLink_Click(object sender, MouseButtonEventArgs e)
        {
            OpenPurchasePage();
        }

        private void OpenPurchasePage()
        {
            try
            {
                var purchaseUrl = _licenseService.GetPurchaseUrl();
                Process.Start(new ProcessStartInfo
                {
                    FileName = purchaseUrl,
                    UseShellExecute = true
                });
            }
            catch { }
        }

        private void BuyLicense_Click(object sender, RoutedEventArgs e)
        {
            OpenPurchasePage();
        }

        private void CopyDeviceId_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                Clipboard.SetText(DeviceIdTextBlock.Text);
                CopyDeviceIdButton.Content = "Copied!";

                // Reset button text after 2 seconds
                var timer = new System.Windows.Threading.DispatcherTimer
                {
                    Interval = TimeSpan.FromSeconds(2)
                };
                timer.Tick += (s, args) =>
                {
                    timer.Stop();
                    CopyDeviceIdButton.Content = "Copy";
                };
                timer.Start();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to copy: {ex.Message}", "Error",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void ShowActivationMessage(string message, bool success)
        {
            ActivationMessage.Text = message;
            ActivationMessage.Foreground = success
                ? (Brush)FindResource("GreenPrimaryBrush")
                : (Brush)FindResource("DangerBrush");
        }

        private void ShowLicensedMessage(string message, bool success)
        {
            LicensedMessage.Text = message;
            LicensedMessage.Foreground = success
                ? (Brush)FindResource("GreenPrimaryBrush")
                : (Brush)FindResource("DangerBrush");
        }

        public void RefreshLicense()
        {
            UpdateUI();
        }

    }
}
