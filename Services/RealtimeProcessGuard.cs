using System;
using System.Management;
using SkidrowKiller.Models;
using Serilog;

namespace SkidrowKiller.Services
{
    /// <summary>
    /// Real-time process-start guard. Subscribes to the kernel <c>Win32_ProcessStartTrace</c> WMI event so
    /// EVERY process is seen the instant it starts — including fast "droppers" that spawn, inject, and exit
    /// in well under a second (which the 2-second polling monitors miss entirely). For each new process we
    /// grab its command line (best-effort) and run it through the shared LOLBin / anti-recovery evaluator.
    /// </summary>
    public class RealtimeProcessGuard : IDisposable
    {
        private readonly ThreatAnalyzer _analyzer;
        private readonly WhitelistManager? _whitelist;
        private readonly ILogger _logger;
        private ManagementEventWatcher? _watcher;
        private bool _disposed;

        public event EventHandler<ThreatInfo>? ThreatDetected;
        public event EventHandler<string>? LogAdded;
        public bool IsRunning { get; private set; }

        public RealtimeProcessGuard(ThreatAnalyzer analyzer, WhitelistManager? whitelist = null)
        {
            _analyzer = analyzer;
            _whitelist = whitelist;
            _logger = LoggingService.ForContext<RealtimeProcessGuard>();
        }

        public void Start()
        {
            if (IsRunning) return;
            try
            {
                _watcher = new ManagementEventWatcher(new WqlEventQuery("SELECT * FROM Win32_ProcessStartTrace"));
                _watcher.EventArrived += OnProcessStarted;
                _watcher.Start();
                IsRunning = true;
                _logger.Information("Real-time process guard started (Win32_ProcessStartTrace)");
                LogAdded?.Invoke(this, "🛰️ Real-time process guard active");
            }
            catch (Exception ex)
            {
                // Locked-down / non-admin machines may deny the trace — degrade quietly to the pollers.
                _logger.Warning(ex, "Real-time process guard could not start (needs admin / WMI). Falling back to polling.");
                IsRunning = false;
            }
        }

        public void Stop()
        {
            try
            {
                if (_watcher != null)
                {
                    _watcher.EventArrived -= OnProcessStarted;
                    _watcher.Stop();
                    _watcher.Dispose();
                    _watcher = null;
                }
            }
            catch { }
            IsRunning = false;
        }

        private void OnProcessStarted(object sender, EventArrivedEventArgs e)
        {
            try
            {
                var name = e.NewEvent.Properties["ProcessName"]?.Value as string ?? "";
                var pid = Convert.ToInt32(e.NewEvent.Properties["ProcessID"]?.Value ?? 0);
                if (pid <= 0) return;

                // Self-exclusion: never analyze our own spawned children.
                if (name.Contains("skidrow", StringComparison.OrdinalIgnoreCase)) return;

                var (cmd, exe) = TryGetProcessDetails(pid);

                if (!string.IsNullOrEmpty(exe) && _whitelist?.IsWhitelisted(exe) == true) return;

                var threat = SystemInspectionScanner.EvaluateProcessCommandLine(pid, name, exe, cmd);
                if (threat != null)
                {
                    _logger.Warning("Real-time guard flagged process {Name} (PID {Pid}): {Desc}", name, pid, threat.Description);
                    LogAdded?.Invoke(this, $"🔴 [REALTIME] {threat.SeverityDisplay}: {name} — {threat.Description}");
                    ThreatDetected?.Invoke(this, threat);
                }
            }
            catch (Exception ex)
            {
                _logger.Debug(ex, "Process-start event handling failed");
            }
        }

        /// <summary>Best-effort fetch of a just-started process's command line + path (it may already be gone).</summary>
        private static (string Cmd, string Exe) TryGetProcessDetails(int pid)
        {
            try
            {
                using var searcher = new ManagementObjectSearcher(
                    $"SELECT CommandLine, ExecutablePath FROM Win32_Process WHERE ProcessId = {pid}");
                foreach (ManagementObject mo in searcher.Get())
                {
                    var cmd = mo["CommandLine"] as string ?? "";
                    var exe = mo["ExecutablePath"] as string ?? "";
                    mo.Dispose();
                    return (cmd, exe);
                }
            }
            catch { }
            return ("", "");
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            Stop();
            GC.SuppressFinalize(this);
        }
    }
}
