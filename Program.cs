using System;
using System.IO;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Threading;
using SkidrowKiller.Services;
using Serilog;

namespace SkidrowKiller
{
    public class Program
    {
        private static Mutex? _mutex;
        private const string MutexName = "SkidrowKiller_SingleInstance_Mutex";

        [STAThread]
        public static void Main(string[] args)
        {
            // Single instance check
            _mutex = new Mutex(true, MutexName, out bool createdNew);
            if (!createdNew)
            {
                MessageBox.Show(
                    "Skidrow Killer is already running.",
                    "Already Running",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
                return;
            }

            try
            {
                // Initialize logging first
                LoggingService.Initialize();
                Log.Information("Application starting...");

                // Set up global exception handlers
                SetupExceptionHandlers();

                // Check for admin privileges
                if (!IsRunningAsAdmin())
                {
                    Log.Warning("Application launched without administrator privileges");
                    MessageBox.Show(
                        "Skidrow Killer requires administrator privileges to scan and remove threats.\n\n" +
                        "Please right-click and select 'Run as administrator'.",
                        "Administrator Required",
                        MessageBoxButton.OK,
                        MessageBoxImage.Warning);
                    return;
                }

                Log.Information("Running with administrator privileges");
                Log.Information("Version: {Version}, Environment: {Environment}",
                    UpdateService.GetCurrentVersion(),
                    AppConfiguration.Settings.Application.Environment);

                var app = new App();
                app.InitializeComponent();
                app.Run();
            }
            catch (Exception ex)
            {
                Log.Fatal(ex, "Application crashed during startup");
                HandleFatalException(ex);
            }
            finally
            {
                Log.Information("Application shutting down");
                LoggingService.Shutdown();
                _mutex?.ReleaseMutex();
                _mutex?.Dispose();
            }
        }

        private static void SetupExceptionHandlers()
        {
            // Handle exceptions from the current AppDomain
            AppDomain.CurrentDomain.UnhandledException += (sender, e) =>
            {
                var exception = e.ExceptionObject as Exception;
                Log.Fatal(exception, "Unhandled AppDomain exception. IsTerminating: {IsTerminating}", e.IsTerminating);

                if (e.IsTerminating)
                {
                    HandleFatalException(exception);
                }
            };

            // Handle exceptions from background tasks
            TaskScheduler.UnobservedTaskException += (sender, e) =>
            {
                Log.Error(e.Exception, "Unobserved task exception");
                e.SetObserved(); // Prevent the process from terminating
            };
        }

        private static void HandleFatalException(Exception? ex)
        {
            var message = "A fatal error has occurred and the application must close.\n\n";

            if (ex != null)
            {
                message += $"Error: {ex.Message}\n\n";

                // Write crash report
                try
                {
                    var crashReportPath = Path.Combine(
                        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                        "SkidrowKiller",
                        "crash_report.txt");

                    var directory = Path.GetDirectoryName(crashReportPath);
                    if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
                    {
                        Directory.CreateDirectory(directory);
                    }

                    var crashReport = $"""
                        Skidrow Killer Crash Report
                        ============================
                        Time: {DateTime.Now:yyyy-MM-dd HH:mm:ss}
                        Version: {UpdateService.GetCurrentVersion()}
                        OS: {Environment.OSVersion}
                        .NET Runtime: {Environment.Version}

                        Exception Type: {ex.GetType().FullName}
                        Message: {ex.Message}

                        Stack Trace:
                        {ex.StackTrace}

                        Inner Exception:
                        {ex.InnerException?.ToString() ?? "None"}
                        """;

                    File.WriteAllText(crashReportPath, crashReport);
                    message += $"A crash report has been saved to:\n{crashReportPath}";
                }
                catch
                {
                    // Ignore errors writing crash report
                }
            }

            MessageBox.Show(message, "Fatal Error", MessageBoxButton.OK, MessageBoxImage.Error);
        }

        private static bool IsRunningAsAdmin()
        {
            try
            {
                using var identity = WindowsIdentity.GetCurrent();
                var principal = new WindowsPrincipal(identity);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Failed to check administrator privileges");
                return false;
            }
        }
    }
}
