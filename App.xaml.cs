using System;
using System.Linq;
using System.Windows;
using System.Windows.Threading;
using SkidrowKiller.Services;
using Serilog;

namespace SkidrowKiller
{
    public partial class App : Application
    {
        private UpdateService? _updateService;

        /// <summary>
        /// Command line the process was started with. WPF's StartupEventArgs is empty here because
        /// Program.Main owns the entry point, so the args are handed over explicitly.
        /// </summary>
        public static string[] StartupArgs { get; set; } = Array.Empty<string>();

        /// <summary>True when launched with --minimized (the Run key adds it for "Start minimized").</summary>
        public static bool StartMinimizedRequested =>
            StartupArgs.Any(a => a.Equals("--minimized", StringComparison.OrdinalIgnoreCase)
                              || a.Equals("/minimized", StringComparison.OrdinalIgnoreCase));

        protected override void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);

            // Handle WPF dispatcher unhandled exceptions
            DispatcherUnhandledException += App_DispatcherUnhandledException;

            // The update service is created here but the check is NOT fired blindly any more - it is
            // started by MainWindow once the user's "Check for updates on startup" setting is known.
            _updateService = new UpdateService();

            var mainWindow = new MainWindow();

            if (StartMinimizedRequested)
            {
                mainWindow.WindowState = WindowState.Minimized;
                Log.Information("Starting minimized (--minimized)");
            }

            mainWindow.Show();

            Log.Information("Main window initialized");
        }

        /// <summary>
        /// Run the startup update check. Called by MainWindow only when both
        /// Updates:CheckForUpdatesOnStartup and the user's "Check for updates" setting allow it.
        /// </summary>
        public void RunStartupUpdateCheck() => CheckForUpdatesAsync();

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
