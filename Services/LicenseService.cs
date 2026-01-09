using System;
using System.IO;
using System.Management;
using System.Net.Http;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using Serilog;

namespace SkidrowKiller.Services
{
    /// <summary>
    /// License service for XMAN Studio integration.
    /// API Base: https://xmanstudio.com/api/v1/license
    /// </summary>
    public class LicenseService
    {
        private const string API_BASE_URL = "https://xman4289.com/api/v1/license";
        private const string PRODUCT_ID = "skidrow-killer";
        private const string LICENSE_FILE = "license.dat";
        private const string CONNECTIVITY_FILE = "connectivity.dat";
        private const int OFFLINE_GRACE_PERIOD_HOURS = 24; // 1 day offline grace period
        private const int MAX_ACTIVATIONS = 3; // Max devices per license
        private const int TRIAL_DAYS = 7; // Trial period in days

        private readonly HttpClient _httpClient;
        private readonly ILogger _logger;
        private readonly string _licenseFilePath;
        private readonly string _connectivityFilePath;
        private readonly System.Timers.Timer _connectivityTimer;

        private LicenseInfo? _currentLicense;
        private DateTime _lastSuccessfulConnection;
        private bool _isOfflineDowngraded;

        public event EventHandler<LicenseStatus>? LicenseStatusChanged;

        public LicenseInfo? CurrentLicense => _currentLicense;
        public bool IsLicensed => _currentLicense?.IsValid ?? false;
        public bool IsTrial => _currentLicense?.IsTrial ?? true;
        public bool IsOfflineDowngraded => _isOfflineDowngraded;
        public int DaysRemaining => _currentLicense?.DaysRemaining ?? 0;
        public DateTime LastConnectionTime => _lastSuccessfulConnection;

        public LicenseService()
        {
            _httpClient = new HttpClient
            {
                Timeout = TimeSpan.FromSeconds(30)
            };
            _httpClient.DefaultRequestHeaders.Add("User-Agent", $"SkidrowKiller/{UpdateService.GetCurrentVersion()}");
            _httpClient.DefaultRequestHeaders.Add("X-Product-ID", PRODUCT_ID);

            _logger = LoggingService.ForContext<LicenseService>();

            var appData = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "SkidrowKiller"
            );
            Directory.CreateDirectory(appData);
            _licenseFilePath = Path.Combine(appData, LICENSE_FILE);
            _connectivityFilePath = Path.Combine(appData, CONNECTIVITY_FILE);

            // Load saved data
            LoadLocalLicense();
            LoadConnectivityData();

            // Setup connectivity check timer (every 30 minutes)
            _connectivityTimer = new System.Timers.Timer(30 * 60 * 1000); // 30 minutes
            _connectivityTimer.Elapsed += async (s, e) => await CheckConnectivityAsync();
            _connectivityTimer.AutoReset = true;
            _connectivityTimer.Start();

            // Initial connectivity check
            _ = CheckConnectivityAsync();
        }

        #region License Activation

        /// <summary>
        /// Activate a license key with the server
        /// </summary>
        public async Task<LicenseResult> ActivateLicenseAsync(string licenseKey)
        {
            try
            {
                _logger.Information("Activating license: {Key}", MaskLicenseKey(licenseKey));

                var machineId = GetMachineId();
                var request = new LicenseActivationRequest
                {
                    LicenseKey = licenseKey.Trim().ToUpper(),
                    MachineId = machineId,
                    ProductId = PRODUCT_ID,
                    MachineName = Environment.MachineName,
                    OsVersion = Environment.OSVersion.ToString(),
                    AppVersion = UpdateService.GetCurrentVersion()
                };

                var response = await _httpClient.PostAsJsonAsync($"{API_BASE_URL}/activate", request);
                var result = await response.Content.ReadFromJsonAsync<LicenseApiResponse>();

                if (result == null)
                {
                    return new LicenseResult { Success = false, Message = "Invalid server response" };
                }

                if (result.Success && result.Data != null)
                {
                    _currentLicense = new LicenseInfo
                    {
                        LicenseKey = licenseKey,
                        MachineId = machineId,
                        Email = result.Data.Email,
                        CustomerName = result.Data.CustomerName,
                        ProductName = result.Data.ProductName,
                        ExpiresAt = result.Data.ExpiresAt,
                        ActivatedAt = DateTime.Now,
                        MaxDevices = result.Data.MaxDevices,
                        CurrentDevices = result.Data.CurrentDevices,
                        Features = result.Data.Features,
                        IsTrial = false,
                        IsValid = true
                    };

                    SaveLocalLicense();
                    LicenseStatusChanged?.Invoke(this, LicenseStatus.Active);

                    _logger.Information("License activated successfully for {Email}", result.Data.Email);
                    return new LicenseResult
                    {
                        Success = true,
                        Message = "License activated successfully!",
                        License = _currentLicense
                    };
                }

                _logger.Warning("License activation failed: {Message}", result.Message);
                return new LicenseResult { Success = false, Message = result.Message ?? "Activation failed" };
            }
            catch (HttpRequestException ex)
            {
                _logger.Error(ex, "Network error during license activation");
                return new LicenseResult { Success = false, Message = "Network error. Please check your connection." };
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Error during license activation");
                return new LicenseResult { Success = false, Message = $"Error: {ex.Message}" };
            }
        }

        /// <summary>
        /// Validate current license with server
        /// </summary>
        public async Task<LicenseResult> ValidateLicenseAsync()
        {
            if (_currentLicense == null || string.IsNullOrEmpty(_currentLicense.LicenseKey))
            {
                return new LicenseResult { Success = false, Message = "No license to validate" };
            }

            try
            {
                _logger.Information("Validating license...");

                var request = new LicenseValidationRequest
                {
                    LicenseKey = _currentLicense.LicenseKey,
                    MachineId = GetMachineId(),
                    ProductId = PRODUCT_ID
                };

                var response = await _httpClient.PostAsJsonAsync($"{API_BASE_URL}/validate", request);
                var result = await response.Content.ReadFromJsonAsync<LicenseApiResponse>();

                if (result?.Success == true && result.Data != null)
                {
                    _currentLicense.ExpiresAt = result.Data.ExpiresAt;
                    _currentLicense.IsValid = true;
                    _currentLicense.Features = result.Data.Features;
                    SaveLocalLicense();

                    LicenseStatusChanged?.Invoke(this, LicenseStatus.Active);
                    return new LicenseResult { Success = true, Message = "License is valid", License = _currentLicense };
                }

                // License invalid or expired
                _currentLicense.IsValid = false;
                SaveLocalLicense();
                LicenseStatusChanged?.Invoke(this, LicenseStatus.Invalid);

                return new LicenseResult { Success = false, Message = result?.Message ?? "License validation failed" };
            }
            catch (HttpRequestException)
            {
                // Offline mode - use cached license if not expired
                if (_currentLicense.ExpiresAt > DateTime.Now)
                {
                    _logger.Warning("Offline mode - using cached license");
                    return new LicenseResult { Success = true, Message = "Offline mode - using cached license", License = _currentLicense };
                }

                return new LicenseResult { Success = false, Message = "Cannot validate license offline" };
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Error validating license");
                return new LicenseResult { Success = false, Message = $"Error: {ex.Message}" };
            }
        }

        /// <summary>
        /// Deactivate license from this machine
        /// </summary>
        public async Task<LicenseResult> DeactivateLicenseAsync()
        {
            if (_currentLicense == null || string.IsNullOrEmpty(_currentLicense.LicenseKey))
            {
                return new LicenseResult { Success = false, Message = "No license to deactivate" };
            }

            try
            {
                _logger.Information("Deactivating license...");

                var request = new LicenseDeactivationRequest
                {
                    LicenseKey = _currentLicense.LicenseKey,
                    MachineId = GetMachineId(),
                    ProductId = PRODUCT_ID
                };

                var response = await _httpClient.PostAsJsonAsync($"{API_BASE_URL}/deactivate", request);
                var result = await response.Content.ReadFromJsonAsync<LicenseApiResponse>();

                // Clear local license regardless of server response
                _currentLicense = null;
                DeleteLocalLicense();
                LicenseStatusChanged?.Invoke(this, LicenseStatus.NotActivated);

                if (result?.Success == true)
                {
                    _logger.Information("License deactivated successfully");
                    return new LicenseResult { Success = true, Message = "License deactivated successfully" };
                }

                return new LicenseResult { Success = true, Message = "Local license removed" };
            }
            catch (Exception ex)
            {
                // Still remove local license
                _currentLicense = null;
                DeleteLocalLicense();
                LicenseStatusChanged?.Invoke(this, LicenseStatus.NotActivated);

                _logger.Error(ex, "Error deactivating license (local removed)");
                return new LicenseResult { Success = true, Message = "Local license removed" };
            }
        }

        /// <summary>
        /// Get license status from server
        /// </summary>
        public async Task<LicenseStatusResponse?> GetLicenseStatusAsync(string licenseKey)
        {
            try
            {
                var response = await _httpClient.GetFromJsonAsync<LicenseApiResponse>($"{API_BASE_URL}/status/{licenseKey}");
                return response?.Data;
            }
            catch
            {
                return null;
            }
        }

        #endregion

        #region Device Registration

        /// <summary>
        /// Register device with server (called on startup)
        /// Reports device info for analytics and license preparation
        /// </summary>
        public async Task<bool> RegisterDeviceAsync()
        {
            try
            {
                _logger.Information("Registering device with license server...");

                var request = new DeviceRegistrationRequest
                {
                    DeviceId = GetDeviceId(),
                    MachineId = GetMachineId(),
                    MachineName = Environment.MachineName,
                    OsVersion = Environment.OSVersion.ToString(),
                    AppVersion = UpdateService.GetCurrentVersion(),
                    ProductId = PRODUCT_ID
                };

                var response = await _httpClient.PostAsJsonAsync($"{API_BASE_URL}/device/register", request);

                if (response.IsSuccessStatusCode)
                {
                    _lastSuccessfulConnection = DateTime.Now;
                    SaveConnectivityData();
                    _logger.Information("Device registered successfully");
                    return true;
                }

                _logger.Warning("Device registration returned status: {Status}", response.StatusCode);
                return false;
            }
            catch (Exception ex)
            {
                _logger.Warning(ex, "Device registration failed (server may be offline)");
                return false;
            }
        }

        /// <summary>
        /// Get purchase URL with pre-filled device ID
        /// </summary>
        public string GetPurchaseUrl()
        {
            var deviceId = GetDeviceId();
            return $"https://xman4289.com/products/skidrow-killer?device_id={Uri.EscapeDataString(deviceId)}";
        }

        #endregion

        #region Demo/Trial

        /// <summary>
        /// Start demo mode (7 days trial)
        /// </summary>
        public async Task<LicenseResult> StartDemoAsync()
        {
            try
            {
                _logger.Information("Starting demo mode...");

                var request = new DemoRequest
                {
                    MachineId = GetMachineId(),
                    ProductId = PRODUCT_ID,
                    MachineName = Environment.MachineName
                };

                var response = await _httpClient.PostAsJsonAsync($"{API_BASE_URL}/demo", request);
                var result = await response.Content.ReadFromJsonAsync<LicenseApiResponse>();

                if (result?.Success == true && result.Data != null)
                {
                    _currentLicense = new LicenseInfo
                    {
                        LicenseKey = "DEMO",
                        MachineId = GetMachineId(),
                        ExpiresAt = result.Data.ExpiresAt ?? DateTime.Now.AddDays(7),
                        ActivatedAt = DateTime.Now,
                        IsTrial = true,
                        IsValid = true,
                        Features = new[] { "basic_scan", "real_time_protection" }
                    };

                    SaveLocalLicense();
                    LicenseStatusChanged?.Invoke(this, LicenseStatus.Trial);

                    return new LicenseResult { Success = true, Message = "Demo started!", License = _currentLicense };
                }

                return new LicenseResult { Success = false, Message = result?.Message ?? "Could not start demo" };
            }
            catch (Exception ex)
            {
                // Offline demo - 7 days from first run
                _currentLicense = new LicenseInfo
                {
                    LicenseKey = "DEMO-OFFLINE",
                    MachineId = GetMachineId(),
                    ExpiresAt = DateTime.Now.AddDays(7),
                    ActivatedAt = DateTime.Now,
                    IsTrial = true,
                    IsValid = true,
                    Features = new[] { "basic_scan" }
                };

                SaveLocalLicense();
                LicenseStatusChanged?.Invoke(this, LicenseStatus.Trial);

                _logger.Warning(ex, "Started offline demo mode");
                return new LicenseResult { Success = true, Message = "Demo started (offline mode)", License = _currentLicense };
            }
        }

        /// <summary>
        /// Check if demo is still valid
        /// </summary>
        public async Task<bool> CheckDemoAsync()
        {
            if (_currentLicense?.IsTrial != true) return false;

            try
            {
                var request = new DemoCheckRequest
                {
                    MachineId = GetMachineId(),
                    ProductId = PRODUCT_ID
                };

                var response = await _httpClient.PostAsJsonAsync($"{API_BASE_URL}/demo/check", request);
                var result = await response.Content.ReadFromJsonAsync<LicenseApiResponse>();

                return result?.Success == true;
            }
            catch
            {
                // Offline - check local expiry
                return _currentLicense.ExpiresAt > DateTime.Now;
            }
        }

        #endregion

        #region Connectivity Check & Auto-Downgrade

        /// <summary>
        /// Check connectivity with license server and handle offline grace period
        /// </summary>
        public async Task<bool> CheckConnectivityAsync()
        {
            try
            {
                // Simple ping to server
                var response = await _httpClient.GetAsync($"{API_BASE_URL}/ping");

                if (response.IsSuccessStatusCode)
                {
                    // Connection successful
                    _lastSuccessfulConnection = DateTime.Now;
                    SaveConnectivityData();

                    // If was downgraded, try to restore
                    if (_isOfflineDowngraded && _currentLicense != null && !_currentLicense.IsTrial)
                    {
                        _isOfflineDowngraded = false;
                        var validateResult = await ValidateLicenseAsync();
                        if (validateResult.Success)
                        {
                            _logger.Information("License restored after reconnection");
                            LicenseStatusChanged?.Invoke(this, LicenseStatus.Active);
                        }
                    }

                    return true;
                }
            }
            catch (Exception ex)
            {
                _logger.Warning(ex, "Connectivity check failed");
            }

            // Connection failed - check grace period
            CheckOfflineGracePeriod();
            return false;
        }

        /// <summary>
        /// Check if offline grace period has expired and downgrade if necessary
        /// </summary>
        private void CheckOfflineGracePeriod()
        {
            if (_currentLicense == null || _currentLicense.IsTrial)
            {
                return; // Already trial or no license
            }

            var hoursSinceLastConnection = (DateTime.Now - _lastSuccessfulConnection).TotalHours;

            if (hoursSinceLastConnection > OFFLINE_GRACE_PERIOD_HOURS)
            {
                // Grace period expired - downgrade to trial
                DowngradeToTrial();
            }
            else
            {
                var hoursRemaining = OFFLINE_GRACE_PERIOD_HOURS - hoursSinceLastConnection;
                _logger.Warning("Offline mode. {Hours:F1} hours remaining before trial downgrade", hoursRemaining);
            }
        }

        /// <summary>
        /// Downgrade current license to trial mode
        /// </summary>
        private void DowngradeToTrial()
        {
            if (_isOfflineDowngraded) return; // Already downgraded

            _logger.Warning("License downgraded to trial due to extended offline period");

            _isOfflineDowngraded = true;

            // Store original license info for restoration
            var originalLicense = _currentLicense;

            // Create trial license
            _currentLicense = new LicenseInfo
            {
                LicenseKey = $"OFFLINE-TRIAL-{originalLicense?.LicenseKey?[..8] ?? "XXXX"}",
                MachineId = GetMachineId(),
                ExpiresAt = DateTime.Now.AddDays(TRIAL_DAYS),
                ActivatedAt = DateTime.Now,
                IsTrial = true,
                IsValid = true,
                Features = new[] { "basic_scan", "real_time_protection" }, // Limited features
                Email = originalLicense?.Email,
                CustomerName = originalLicense?.CustomerName
            };

            SaveLocalLicense();
            LicenseStatusChanged?.Invoke(this, LicenseStatus.Trial);
        }

        /// <summary>
        /// Load connectivity data from file
        /// </summary>
        private void LoadConnectivityData()
        {
            try
            {
                if (File.Exists(_connectivityFilePath))
                {
                    var data = File.ReadAllText(_connectivityFilePath);
                    var parts = data.Split('|');

                    if (parts.Length >= 2)
                    {
                        _lastSuccessfulConnection = DateTime.Parse(parts[0]);
                        _isOfflineDowngraded = bool.Parse(parts[1]);
                    }
                }
                else
                {
                    _lastSuccessfulConnection = DateTime.Now;
                    _isOfflineDowngraded = false;
                }
            }
            catch
            {
                _lastSuccessfulConnection = DateTime.Now;
                _isOfflineDowngraded = false;
            }
        }

        /// <summary>
        /// Save connectivity data to file
        /// </summary>
        private void SaveConnectivityData()
        {
            try
            {
                var data = $"{_lastSuccessfulConnection:O}|{_isOfflineDowngraded}";
                File.WriteAllText(_connectivityFilePath, data);
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Failed to save connectivity data");
            }
        }

        /// <summary>
        /// Get hours remaining in offline grace period
        /// </summary>
        public double GetOfflineGraceHoursRemaining()
        {
            var hoursSince = (DateTime.Now - _lastSuccessfulConnection).TotalHours;
            return Math.Max(0, OFFLINE_GRACE_PERIOD_HOURS - hoursSince);
        }

        /// <summary>
        /// Force restore license (when back online)
        /// </summary>
        public async Task<bool> TryRestoreLicenseAsync()
        {
            if (!_isOfflineDowngraded) return true;

            var connected = await CheckConnectivityAsync();
            return connected && !_isOfflineDowngraded;
        }

        #endregion

        #region Local License Storage

        private void LoadLocalLicense()
        {
            try
            {
                if (!File.Exists(_licenseFilePath)) return;

                var encryptedData = File.ReadAllBytes(_licenseFilePath);
                var decryptedJson = DecryptData(encryptedData);
                _currentLicense = JsonSerializer.Deserialize<LicenseInfo>(decryptedJson);

                if (_currentLicense != null)
                {
                    // Check if expired
                    if (_currentLicense.ExpiresAt < DateTime.Now)
                    {
                        _currentLicense.IsValid = false;
                        _logger.Warning("Loaded license is expired");
                    }
                    else
                    {
                        _logger.Information("License loaded from cache");
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Failed to load local license");
                _currentLicense = null;
            }
        }

        private void SaveLocalLicense()
        {
            if (_currentLicense == null) return;

            try
            {
                var json = JsonSerializer.Serialize(_currentLicense);
                var encryptedData = EncryptData(json);
                File.WriteAllBytes(_licenseFilePath, encryptedData);
                _logger.Information("License saved to cache");
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Failed to save local license");
            }
        }

        private void DeleteLocalLicense()
        {
            try
            {
                if (File.Exists(_licenseFilePath))
                {
                    File.Delete(_licenseFilePath);
                }
            }
            catch { }
        }

        #endregion

        #region Machine ID & Encryption

        /// <summary>
        /// Get formatted Device ID for display to user
        /// </summary>
        public string GetDeviceId()
        {
            var machineId = GetMachineId();
            // Format as XXXX-XXXX-XXXX-XXXX for readability
            if (machineId.Length >= 16)
            {
                return $"{machineId[..4]}-{machineId[4..8]}-{machineId[8..12]}-{machineId[12..16]}".ToUpper();
            }
            return machineId.ToUpper();
        }

        private string GetMachineId()
        {
            try
            {
                var sb = new StringBuilder();

                // CPU ID
                using (var mc = new ManagementClass("Win32_Processor"))
                {
                    foreach (var mo in mc.GetInstances())
                    {
                        sb.Append(mo["ProcessorId"]?.ToString());
                        break;
                    }
                }

                // Motherboard serial
                using (var mc = new ManagementClass("Win32_BaseBoard"))
                {
                    foreach (var mo in mc.GetInstances())
                    {
                        sb.Append(mo["SerialNumber"]?.ToString());
                        break;
                    }
                }

                // BIOS serial
                using (var mc = new ManagementClass("Win32_BIOS"))
                {
                    foreach (var mo in mc.GetInstances())
                    {
                        sb.Append(mo["SerialNumber"]?.ToString());
                        break;
                    }
                }

                // Hash the combined string
                using var sha256 = SHA256.Create();
                var hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(sb.ToString()));
                return BitConverter.ToString(hashBytes).Replace("-", "").Substring(0, 32);
            }
            catch
            {
                // Fallback to machine name + user name hash
                var fallback = $"{Environment.MachineName}-{Environment.UserName}";
                using var sha256 = SHA256.Create();
                var hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(fallback));
                return BitConverter.ToString(hashBytes).Replace("-", "").Substring(0, 32);
            }
        }

        private byte[] EncryptData(string data)
        {
            var key = GetEncryptionKey();
            using var aes = Aes.Create();
            aes.Key = key;
            aes.GenerateIV();

            using var ms = new MemoryStream();
            ms.Write(aes.IV, 0, aes.IV.Length);

            using (var cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
            using (var sw = new StreamWriter(cs))
            {
                sw.Write(data);
            }

            return ms.ToArray();
        }

        private string DecryptData(byte[] encryptedData)
        {
            var key = GetEncryptionKey();
            using var aes = Aes.Create();
            aes.Key = key;

            var iv = new byte[16];
            Array.Copy(encryptedData, 0, iv, 0, 16);
            aes.IV = iv;

            using var ms = new MemoryStream(encryptedData, 16, encryptedData.Length - 16);
            using var cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Read);
            using var sr = new StreamReader(cs);

            return sr.ReadToEnd();
        }

        private byte[] GetEncryptionKey()
        {
            var machineId = GetMachineId();
            using var sha256 = SHA256.Create();
            return sha256.ComputeHash(Encoding.UTF8.GetBytes($"SK-{machineId}-KEY"));
        }

        private string MaskLicenseKey(string key)
        {
            if (string.IsNullOrEmpty(key) || key.Length < 8) return "****";
            return $"{key[..4]}...{key[^4..]}";
        }

        #endregion

        #region Feature Check

        public bool HasFeature(string featureName)
        {
            if (_currentLicense?.Features == null) return false;
            return Array.Exists(_currentLicense.Features, f => f.Equals(featureName, StringComparison.OrdinalIgnoreCase));
        }

        #endregion
    }

    #region Models

    public enum LicenseStatus
    {
        NotActivated,
        Trial,
        Active,
        Expired,
        Invalid
    }

    public class LicenseInfo
    {
        public string LicenseKey { get; set; } = string.Empty;
        public string MachineId { get; set; } = string.Empty;
        public string? Email { get; set; }
        public string? CustomerName { get; set; }
        public string? ProductName { get; set; }
        public DateTime? ExpiresAt { get; set; }
        public DateTime ActivatedAt { get; set; }
        public int MaxDevices { get; set; }
        public int CurrentDevices { get; set; }
        public string[]? Features { get; set; }
        public bool IsTrial { get; set; }
        public bool IsValid { get; set; }

        [JsonIgnore]
        public int DaysRemaining => ExpiresAt.HasValue
            ? Math.Max(0, (ExpiresAt.Value - DateTime.Now).Days)
            : 0;
    }

    public class LicenseResult
    {
        public bool Success { get; set; }
        public string Message { get; set; } = string.Empty;
        public LicenseInfo? License { get; set; }
    }

    // API Request Models
    public class LicenseActivationRequest
    {
        [JsonPropertyName("license_key")]
        public string LicenseKey { get; set; } = string.Empty;

        [JsonPropertyName("machine_id")]
        public string MachineId { get; set; } = string.Empty;

        [JsonPropertyName("product_id")]
        public string ProductId { get; set; } = string.Empty;

        [JsonPropertyName("machine_name")]
        public string MachineName { get; set; } = string.Empty;

        [JsonPropertyName("os_version")]
        public string OsVersion { get; set; } = string.Empty;

        [JsonPropertyName("app_version")]
        public string AppVersion { get; set; } = string.Empty;
    }

    public class LicenseValidationRequest
    {
        [JsonPropertyName("license_key")]
        public string LicenseKey { get; set; } = string.Empty;

        [JsonPropertyName("machine_id")]
        public string MachineId { get; set; } = string.Empty;

        [JsonPropertyName("product_id")]
        public string ProductId { get; set; } = string.Empty;
    }

    public class LicenseDeactivationRequest
    {
        [JsonPropertyName("license_key")]
        public string LicenseKey { get; set; } = string.Empty;

        [JsonPropertyName("machine_id")]
        public string MachineId { get; set; } = string.Empty;

        [JsonPropertyName("product_id")]
        public string ProductId { get; set; } = string.Empty;
    }

    public class DemoRequest
    {
        [JsonPropertyName("machine_id")]
        public string MachineId { get; set; } = string.Empty;

        [JsonPropertyName("product_id")]
        public string ProductId { get; set; } = string.Empty;

        [JsonPropertyName("machine_name")]
        public string MachineName { get; set; } = string.Empty;
    }

    public class DemoCheckRequest
    {
        [JsonPropertyName("machine_id")]
        public string MachineId { get; set; } = string.Empty;

        [JsonPropertyName("product_id")]
        public string ProductId { get; set; } = string.Empty;
    }

    public class DeviceRegistrationRequest
    {
        [JsonPropertyName("device_id")]
        public string DeviceId { get; set; } = string.Empty;

        [JsonPropertyName("machine_id")]
        public string MachineId { get; set; } = string.Empty;

        [JsonPropertyName("machine_name")]
        public string MachineName { get; set; } = string.Empty;

        [JsonPropertyName("os_version")]
        public string OsVersion { get; set; } = string.Empty;

        [JsonPropertyName("app_version")]
        public string AppVersion { get; set; } = string.Empty;

        [JsonPropertyName("product_id")]
        public string ProductId { get; set; } = string.Empty;
    }

    // API Response Models
    public class LicenseApiResponse
    {
        [JsonPropertyName("success")]
        public bool Success { get; set; }

        [JsonPropertyName("message")]
        public string? Message { get; set; }

        [JsonPropertyName("data")]
        public LicenseStatusResponse? Data { get; set; }
    }

    public class LicenseStatusResponse
    {
        [JsonPropertyName("email")]
        public string? Email { get; set; }

        [JsonPropertyName("customer_name")]
        public string? CustomerName { get; set; }

        [JsonPropertyName("product_name")]
        public string? ProductName { get; set; }

        [JsonPropertyName("expires_at")]
        public DateTime? ExpiresAt { get; set; }

        [JsonPropertyName("max_devices")]
        public int MaxDevices { get; set; }

        [JsonPropertyName("current_devices")]
        public int CurrentDevices { get; set; }

        [JsonPropertyName("features")]
        public string[]? Features { get; set; }

        [JsonPropertyName("status")]
        public string? Status { get; set; }
    }

    #endregion
}
