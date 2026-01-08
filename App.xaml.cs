using System;
using System.Windows;
using System.Windows.Threading;
using SkidrowKiller.Services;
using Serilog;

namespace SkidrowKiller
{
    public partial class App : Application
    {
        private UpdateService? _updateService;

        protected override void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);

            // Handle WPF dispatcher unhandled exceptions
            DispatcherUnhandledException += App_DispatcherUnhandledException;

            // Initialize update service and check for updates
            _updateService = new UpdateService();
            CheckForUpdatesAsync();

            var mainWindow = new MainWindow();
            mainWindow.Show();

            Log.Information("Main window initialized");
        }

        private async void CheckForUpdatesAsync()
        {
            try
            {
                var updateInfo = await _updateService!.CheckForUpdatesAsync();
                if (updateInfo != null)
                {
                    var result = MessageBox.Show(
                        $"A new version of Skidrow Killer is available!\n\n" +
                        $"Current version: {updateInfo.CurrentVersion}\n" +
                        $"Latest version: {updateInfo.LatestVersion}\n\n" +
                        $"Would you like to visit the download page?",
                        "Update Available",
                        MessageBoxButton.YesNo,
                        MessageBoxImage.Information);

                    if (result == MessageBoxResult.Yes && !string.IsNullOrEmpty(updateInfo.ReleaseUrl))
                    {
                        try
                        {
                            var psi = new System.Diagnostics.ProcessStartInfo
                            {
                                FileName = updateInfo.ReleaseUrl,
                                UseShellExecute = true
                            };
                            System.Diagnostics.Process.Start(psi);
                        }
                        catch (Exception ex)
                        {
                            Log.Error(ex, "Failed to open update URL");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Log.Warning(ex, "Update check failed");
            }
        }

        private void App_DispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
        {
            Log.Error(e.Exception, "Unhandled WPF dispatcher exception");

            // Show error message to user
            MessageBox.Show(
                $"An unexpected error occurred:\n\n{e.Exception.Message}\n\n" +
                "The application will try to continue, but some features may not work correctly.",
                "Error",
                MessageBoxButton.OK,
                MessageBoxImage.Error);

            // Mark as handled to prevent application crash
            e.Handled = true;
        }

        protected override void OnExit(ExitEventArgs e)
        {
            Log.Information("Application exiting with code {ExitCode}", e.ApplicationExitCode);
            _updateService?.Dispose();
            base.OnExit(e);
        }
    }
}
