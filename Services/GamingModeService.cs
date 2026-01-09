using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32;

namespace SkidrowKiller.Services
{
    /// <summary>
    /// Gaming Mode - Reduces CPU/Memory usage and disables notifications when gaming or running fullscreen apps.
    /// Auto-detects games and fullscreen applications.
    /// </summary>
    public class GamingModeService : IDisposable
    {
        private readonly ProtectionService _protection;
        private CancellationTokenSource? _cts;
        private bool _isGamingMode;
        private bool _wasProtectionRunning;
        private string? _currentGame;
        private DateTime _gamingStartTime;
        private bool _autoDetectEnabled = true;
        private bool _isDisposed;

        // Known game processes and platforms
        private static readonly HashSet<string> KnownGamePlatforms = new(StringComparer.OrdinalIgnoreCase)
        {
            "steam", "steamwebhelper", "epicgameslauncher", "easyanticheat",
            "battlenet", "origin", "eadesktop", "ubisoft", "uplay",
            "goggalaxy", "riotclientservices", "valorant-win64-shipping",
            "gog", "bethesda", "rockstargames", "playnite"
        };

        private static readonly HashSet<string> KnownGameProcesses = new(StringComparer.OrdinalIgnoreCase)
        {
            // Popular Games
            "csgo", "cs2", "dota2", "valorant", "leagueoflegends",
            "fortnite", "apex_legends", "pubg", "overwatch", "minecraft",
            "gta5", "gtav", "rdr2", "cyberpunk2077", "eldenring",
            "baldursgate3", "starfield", "diablo4", "wow", "ffxiv",
            "lostark", "newworld", "destiny2", "warframe", "pathofexile",
            "rocketleague", "fifa", "nba2k", "callofduty", "cod",
            "battlefield", "rainbowsix", "r6", "deadbydaylight", "rust",
            "ark", "terraria", "stardewvalley", "hogwartslegacy",
            // Emulators
            "retroarch", "dolphin", "pcsx2", "rpcs3", "yuzu", "ryujinx", "cemu"
        };

        private static readonly string[] GameFolderKeywords = {
            "games", "steam", "steamapps", "epic games", "riot games",
            "origin", "ubisoft", "gog galaxy", "battlenet"
        };

        public event EventHandler<GamingModeEventArgs>? GamingModeChanged;
        public event EventHandler<string>? LogAdded;

        public bool IsGamingMode => _isGamingMode;
        public bool AutoDetectEnabled
        {
            get => _autoDetectEnabled;
            set => _autoDetectEnabled = value;
        }
        public string? CurrentGame => _currentGame;
        public TimeSpan GamingDuration => _isGamingMode ? DateTime.Now - _gamingStartTime : TimeSpan.Zero;

        // Settings
        public bool PauseProtection { get; set; } = false; // Don't pause by default, just reduce intensity
        public bool SuppressNotifications { get; set; } = true;
        public bool ReduceScanIntensity { get; set; } = true;
        public int ReducedScanIntervalMs { get; set; } = 10000; // 10 seconds instead of 2

        public GamingModeService(ProtectionService protection)
        {
            _protection = protection;
        }

        public void Start()
        {
            if (_cts != null) return;

            _cts = new CancellationTokenSource();
            Task.Run(() => MonitorLoop(_cts.Token));
            RaiseLog("Gaming Mode monitor started");
        }

        public void Stop()
        {
            _cts?.Cancel();
            _cts?.Dispose();
            _cts = null;

            if (_isGamingMode)
            {
                ExitGamingMode("Service stopped");
            }
        }

        private async Task MonitorLoop(CancellationToken token)
        {
            while (!token.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(5000, token); // Check every 5 seconds

                    if (!_autoDetectEnabled) continue;

                    var (isGaming, gameName) = DetectGamingActivity();

                    if (isGaming && !_isGamingMode)
                    {
                        EnterGamingMode(gameName);
                    }
                    else if (!isGaming && _isGamingMode)
                    {
                        ExitGamingMode("Game closed");
                    }
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    RaiseLog($"Gaming mode error: {ex.Message}");
                }
            }
        }

        private (bool isGaming, string? gameName) DetectGamingActivity()
        {
            try
            {
                // Check for fullscreen application
                if (IsFullscreenAppRunning())
                {
                    var foregroundApp = GetForegroundProcessName();
                    if (!string.IsNullOrEmpty(foregroundApp) && !IsSystemProcess(foregroundApp))
                    {
                        return (true, foregroundApp);
                    }
                }

                // Check for known game processes
                var processes = Process.GetProcesses();
                foreach (var proc in processes)
                {
                    try
                    {
                        var name = proc.ProcessName.ToLower();

                        // Check known games
                        if (KnownGameProcesses.Contains(name))
                        {
                            return (true, proc.ProcessName);
                        }

                        // Check if launched from game folder
                        try
                        {
                            var path = proc.MainModule?.FileName?.ToLower() ?? "";
                            if (GameFolderKeywords.Any(k => path.Contains(k)))
                            {
                                // Additional check: high memory or GPU usage
                                if (proc.WorkingSet64 > 500 * 1024 * 1024) // > 500MB RAM
                                {
                                    return (true, proc.ProcessName);
                                }
                            }
                        }
                        catch { }
                    }
                    catch { }
                    finally
                    {
                        proc.Dispose();
                    }
                }
            }
            catch { }

            return (false, null);
        }

        public void EnterGamingMode(string? gameName = null)
        {
            if (_isGamingMode) return;

            _isGamingMode = true;
            _currentGame = gameName ?? "Unknown";
            _gamingStartTime = DateTime.Now;
            _wasProtectionRunning = _protection.IsRunning;

            // Apply gaming mode settings
            if (PauseProtection && _protection.IsRunning)
            {
                _protection.Stop();
                RaiseLog($"Protection paused for gaming: {_currentGame}");
            }

            RaiseLog($"🎮 Gaming Mode ACTIVATED - {_currentGame}");
            GamingModeChanged?.Invoke(this, new GamingModeEventArgs(true, _currentGame));
        }

        public void ExitGamingMode(string reason = "Manual")
        {
            if (!_isGamingMode) return;

            var duration = GamingDuration;
            _isGamingMode = false;

            // Restore protection if it was running
            if (PauseProtection && _wasProtectionRunning && !_protection.IsRunning)
            {
                _protection.Start();
                RaiseLog("Protection resumed after gaming");
            }

            RaiseLog($"🎮 Gaming Mode DEACTIVATED - Duration: {duration:hh\\:mm\\:ss} - Reason: {reason}");
            GamingModeChanged?.Invoke(this, new GamingModeEventArgs(false, _currentGame));

            _currentGame = null;
        }

        public void ToggleGamingMode()
        {
            if (_isGamingMode)
                ExitGamingMode("Manual toggle");
            else
                EnterGamingMode("Manual activation");
        }

        #region Fullscreen Detection

        [DllImport("user32.dll")]
        private static extern IntPtr GetForegroundWindow();

        [DllImport("user32.dll")]
        private static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);

        [DllImport("user32.dll")]
        private static extern int GetWindowThreadProcessId(IntPtr hWnd, out int lpdwProcessId);

        [StructLayout(LayoutKind.Sequential)]
        private struct RECT
        {
            public int Left, Top, Right, Bottom;
        }

        private bool IsFullscreenAppRunning()
        {
            try
            {
                var hwnd = GetForegroundWindow();
                if (hwnd == IntPtr.Zero) return false;

                GetWindowRect(hwnd, out RECT rect);
                var screen = System.Windows.SystemParameters.PrimaryScreenWidth;
                var screenH = System.Windows.SystemParameters.PrimaryScreenHeight;

                // Check if window covers entire screen
                return rect.Left <= 0 && rect.Top <= 0 &&
                       rect.Right >= screen && rect.Bottom >= screenH;
            }
            catch
            {
                return false;
            }
        }

        private string? GetForegroundProcessName()
        {
            try
            {
                var hwnd = GetForegroundWindow();
                if (hwnd == IntPtr.Zero) return null;

                GetWindowThreadProcessId(hwnd, out int pid);
                using var proc = Process.GetProcessById(pid);
                return proc.ProcessName;
            }
            catch
            {
                return null;
            }
        }

        private bool IsSystemProcess(string name)
        {
            var systemProcs = new[] { "explorer", "dwm", "shellexperiencehost", "searchui", "startmenuexperiencehost" };
            return systemProcs.Contains(name.ToLower());
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

    public class GamingModeEventArgs : EventArgs
    {
        public bool IsEnabled { get; }
        public string? GameName { get; }

        public GamingModeEventArgs(bool isEnabled, string? gameName)
        {
            IsEnabled = isEnabled;
            GameName = gameName;
        }
    }
}
