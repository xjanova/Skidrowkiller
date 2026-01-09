using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using SkidrowKiller.Views;

namespace SkidrowKiller.Services
{
    /// <summary>
    /// Scheduled Scan Service - Automatically runs scans at specified times.
    /// Supports daily, weekly, and custom schedules.
    /// </summary>
    public class ScheduledScanService : IDisposable
    {
        private readonly SafeScanner _scanner;
        private readonly string _configPath;
        private CancellationTokenSource? _cts;
        private List<ScanSchedule> _schedules = new();
        private bool _isDisposed;
        private DateTime _lastCheckTime = DateTime.MinValue;

        public event EventHandler<ScheduledScanEventArgs>? ScanStarted;
        public event EventHandler<ScheduledScanEventArgs>? ScanCompleted;
        public event EventHandler<string>? LogAdded;

        public bool IsRunning => _cts != null;
        public IReadOnlyList<ScanSchedule> Schedules => _schedules.AsReadOnly();
        public ScanSchedule? NextSchedule => GetNextSchedule();

        public ScheduledScanService(SafeScanner scanner)
        {
            _scanner = scanner;
            _configPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "SkidrowKiller",
                "schedules.json"
            );
            LoadSchedules();
        }

        public void Start()
        {
            if (_cts != null) return;

            _cts = new CancellationTokenSource();
            Task.Run(() => SchedulerLoop(_cts.Token));
            RaiseLog("Scheduled scan service started");
        }

        public void Stop()
        {
            _cts?.Cancel();
            _cts?.Dispose();
            _cts = null;
            RaiseLog("Scheduled scan service stopped");
        }

        private async Task SchedulerLoop(CancellationToken token)
        {
            while (!token.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(30000, token); // Check every 30 seconds

                    var now = DateTime.Now;

                    // Avoid checking too frequently
                    if ((now - _lastCheckTime).TotalSeconds < 55) continue;
                    _lastCheckTime = now;

                    foreach (var schedule in _schedules.Where(s => s.IsEnabled))
                    {
                        if (ShouldRunNow(schedule, now))
                        {
                            await RunScheduledScan(schedule, token);
                            schedule.LastRun = now;
                            SaveSchedules();
                        }
                    }
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    RaiseLog($"Scheduler error: {ex.Message}");
                }
            }
        }

        private bool ShouldRunNow(ScanSchedule schedule, DateTime now)
        {
            // Check if already ran today/this hour
            if (schedule.LastRun.Date == now.Date &&
                schedule.LastRun.Hour == now.Hour &&
                schedule.LastRun.Minute == now.Minute)
            {
                return false;
            }

            // Check time match (within 1 minute window)
            if (now.Hour != schedule.Hour || now.Minute != schedule.Minute)
            {
                return false;
            }

            switch (schedule.Frequency)
            {
                case ScanFrequency.Daily:
                    return true;

                case ScanFrequency.Weekly:
                    return schedule.DaysOfWeek.Contains(now.DayOfWeek);

                case ScanFrequency.Monthly:
                    return now.Day == schedule.DayOfMonth;

                case ScanFrequency.Once:
                    if (schedule.ScheduledDate?.Date == now.Date)
                    {
                        schedule.IsEnabled = false; // Disable after running
                        return true;
                    }
                    return false;

                default:
                    return false;
            }
        }

        private async Task RunScheduledScan(ScanSchedule schedule, CancellationToken token)
        {
            RaiseLog($"📅 Starting scheduled scan: {schedule.Name}");
            ScanStarted?.Invoke(this, new ScheduledScanEventArgs(schedule));

            try
            {
                var scanMode = schedule.ScanType switch
                {
                    ScheduledScanType.Quick => Views.ScanMode.Quick,
                    ScheduledScanType.Full => Views.ScanMode.Deep,
                    ScheduledScanType.Custom => Views.ScanMode.Custom,
                    _ => Views.ScanMode.Quick
                };

                var customFolders = schedule.ScanType == ScheduledScanType.Custom && schedule.CustomPaths.Count > 0
                    ? schedule.CustomPaths
                    : null;

                // Run the scan
                var result = await _scanner.ScanAsync(
                    scanFiles: true,
                    scanRegistry: true,
                    scanProcesses: true,
                    scanMode: scanMode,
                    customFolders: customFolders
                );

                schedule.LastRun = DateTime.Now;
                schedule.LastResult = $"Completed: {result.ThreatsFound} threats found";

                RaiseLog($"📅 Scheduled scan completed: {schedule.Name}");
                ScanCompleted?.Invoke(this, new ScheduledScanEventArgs(schedule));
            }
            catch (OperationCanceledException)
            {
                schedule.LastResult = "Cancelled";
                RaiseLog($"📅 Scheduled scan cancelled: {schedule.Name}");
            }
            catch (Exception ex)
            {
                schedule.LastResult = $"Error: {ex.Message}";
                RaiseLog($"📅 Scheduled scan failed: {schedule.Name} - {ex.Message}");
            }

            SaveSchedules();
        }

        #region Schedule Management

        public void AddSchedule(ScanSchedule schedule)
        {
            schedule.Id = Guid.NewGuid().ToString();
            _schedules.Add(schedule);
            SaveSchedules();
            RaiseLog($"Schedule added: {schedule.Name}");
        }

        public void UpdateSchedule(ScanSchedule schedule)
        {
            var existing = _schedules.FirstOrDefault(s => s.Id == schedule.Id);
            if (existing != null)
            {
                var index = _schedules.IndexOf(existing);
                _schedules[index] = schedule;
                SaveSchedules();
                RaiseLog($"Schedule updated: {schedule.Name}");
            }
        }

        public void RemoveSchedule(string scheduleId)
        {
            var schedule = _schedules.FirstOrDefault(s => s.Id == scheduleId);
            if (schedule != null)
            {
                _schedules.Remove(schedule);
                SaveSchedules();
                RaiseLog($"Schedule removed: {schedule.Name}");
            }
        }

        public void EnableSchedule(string scheduleId, bool enabled)
        {
            var schedule = _schedules.FirstOrDefault(s => s.Id == scheduleId);
            if (schedule != null)
            {
                schedule.IsEnabled = enabled;
                SaveSchedules();
            }
        }

        public ScanSchedule? GetNextSchedule()
        {
            var now = DateTime.Now;
            return _schedules
                .Where(s => s.IsEnabled)
                .Select(s => new { Schedule = s, NextRun = GetNextRunTime(s, now) })
                .Where(x => x.NextRun.HasValue)
                .OrderBy(x => x.NextRun)
                .Select(x => x.Schedule)
                .FirstOrDefault();
        }

        public DateTime? GetNextRunTime(ScanSchedule schedule, DateTime from)
        {
            if (!schedule.IsEnabled) return null;

            var today = from.Date.AddHours(schedule.Hour).AddMinutes(schedule.Minute);

            switch (schedule.Frequency)
            {
                case ScanFrequency.Daily:
                    return from > today ? today.AddDays(1) : today;

                case ScanFrequency.Weekly:
                    for (int i = 0; i < 7; i++)
                    {
                        var date = from.Date.AddDays(i);
                        var time = date.AddHours(schedule.Hour).AddMinutes(schedule.Minute);
                        if (schedule.DaysOfWeek.Contains(date.DayOfWeek) && time > from)
                        {
                            return time;
                        }
                    }
                    break;

                case ScanFrequency.Monthly:
                    var thisMonth = new DateTime(from.Year, from.Month,
                        Math.Min(schedule.DayOfMonth, DateTime.DaysInMonth(from.Year, from.Month)),
                        schedule.Hour, schedule.Minute, 0);
                    if (thisMonth > from) return thisMonth;
                    var nextMonth = from.AddMonths(1);
                    return new DateTime(nextMonth.Year, nextMonth.Month,
                        Math.Min(schedule.DayOfMonth, DateTime.DaysInMonth(nextMonth.Year, nextMonth.Month)),
                        schedule.Hour, schedule.Minute, 0);

                case ScanFrequency.Once:
                    if (schedule.ScheduledDate.HasValue)
                    {
                        var time = schedule.ScheduledDate.Value.Date
                            .AddHours(schedule.Hour).AddMinutes(schedule.Minute);
                        return time > from ? time : null;
                    }
                    break;
            }

            return null;
        }

        #endregion

        #region Persistence

        private void LoadSchedules()
        {
            try
            {
                if (File.Exists(_configPath))
                {
                    var json = File.ReadAllText(_configPath);
                    _schedules = JsonSerializer.Deserialize<List<ScanSchedule>>(json) ?? new();
                }
            }
            catch
            {
                _schedules = new();
            }

            // Add default schedule if none exist
            if (_schedules.Count == 0)
            {
                _schedules.Add(new ScanSchedule
                {
                    Id = Guid.NewGuid().ToString(),
                    Name = "Daily Quick Scan",
                    Frequency = ScanFrequency.Daily,
                    ScanType = ScheduledScanType.Quick,
                    Hour = 12,
                    Minute = 0,
                    IsEnabled = false // Disabled by default
                });
                SaveSchedules();
            }
        }

        private void SaveSchedules()
        {
            try
            {
                var dir = Path.GetDirectoryName(_configPath);
                if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
                {
                    Directory.CreateDirectory(dir);
                }

                var json = JsonSerializer.Serialize(_schedules, new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(_configPath, json);
            }
            catch { }
        }

        #endregion

        private void RaiseLog(string message)
        {
            LogAdded?.Invoke(this, message);
        }

        public void Dispose()
        {
            if (_isDisposed) return;
            _isDisposed = true;
            Stop();
        }
    }

    public class ScanSchedule
    {
        public string Id { get; set; } = string.Empty;
        public string Name { get; set; } = "New Schedule";
        public bool IsEnabled { get; set; } = true;
        public ScanFrequency Frequency { get; set; } = ScanFrequency.Daily;
        public ScheduledScanType ScanType { get; set; } = ScheduledScanType.Quick;
        public int Hour { get; set; } = 12;
        public int Minute { get; set; } = 0;
        public List<DayOfWeek> DaysOfWeek { get; set; } = new();
        public int DayOfMonth { get; set; } = 1;
        public DateTime? ScheduledDate { get; set; }
        public List<string> CustomPaths { get; set; } = new();
        public DateTime LastRun { get; set; } = DateTime.MinValue;
        public string LastResult { get; set; } = "Never run";
    }

    public enum ScanFrequency
    {
        Daily,
        Weekly,
        Monthly,
        Once
    }

    public enum ScheduledScanType
    {
        Quick,
        Full,
        Custom
    }

    public class ScheduledScanEventArgs : EventArgs
    {
        public ScanSchedule Schedule { get; }

        public ScheduledScanEventArgs(ScanSchedule schedule)
        {
            Schedule = schedule;
        }
    }
}
