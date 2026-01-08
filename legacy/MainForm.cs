using System;
using System.Drawing;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace SkidrowKiller
{
    public class MainForm : Form
    {
        private ProgressBar progressBar;
        private TextBox logTextBox;
        private Label statusLabel;
        private Label currentItemLabel;
        private Button startButton;
        private Button pauseButton;
        private Button stopButton;
        private Label foundItemsLabel;
        private Label scannedItemsLabel;
        private CheckBox scanFilesCheckBox;
        private CheckBox scanRegistryCheckBox;
        private CheckBox scanProcessesCheckBox;
        private CheckBox autoDeleteCheckBox;
        private Scanner? scanner;
        private MonitoringService? monitoringService;
        private MonitoringPanel? monitoringPanel;
        private Button monitorToggleButton;
        private CheckBox enableAlertsCheckBox;
        private Button updateSignaturesButton;
        private Label signatureInfoLabel;
        private SignatureUpdater? signatureUpdater;

        public MainForm()
        {
            InitializeComponents();
            LoadSignatureInfo();
        }

        private void InitializeComponents()
        {
            this.Text = "Skidrow Killer - Malware Remover & Real-time Monitor";
            this.Size = new Size(900, 850);
            this.StartPosition = FormStartPosition.CenterScreen;
            this.FormBorderStyle = FormBorderStyle.FixedDialog;
            this.MaximizeBox = false;

            Label titleLabel = new Label
            {
                Text = "Skidrow Malware Killer",
                Font = new Font("Segoe UI", 16, FontStyle.Bold),
                Location = new Point(20, 20),
                Size = new Size(400, 30),
                ForeColor = Color.DarkRed
            };
            this.Controls.Add(titleLabel);

            GroupBox optionsGroup = new GroupBox
            {
                Text = "ตัวเลือกการสแกน",
                Location = new Point(20, 60),
                Size = new Size(850, 105),
                Font = new Font("Segoe UI", 10)
            };

            scanFilesCheckBox = new CheckBox
            {
                Text = "สแกนไฟล์ทั้งระบบ",
                Location = new Point(20, 25),
                Size = new Size(200, 25),
                Checked = true
            };
            optionsGroup.Controls.Add(scanFilesCheckBox);

            scanRegistryCheckBox = new CheckBox
            {
                Text = "สแกน Registry",
                Location = new Point(20, 50),
                Size = new Size(200, 25),
                Checked = true
            };
            optionsGroup.Controls.Add(scanRegistryCheckBox);

            scanProcessesCheckBox = new CheckBox
            {
                Text = "สแกน Processes/Memory (RAM)",
                Location = new Point(20, 75),
                Size = new Size(250, 25),
                Checked = true,
                Font = new Font("Segoe UI", 9, FontStyle.Bold),
                ForeColor = Color.DarkOrange
            };
            optionsGroup.Controls.Add(scanProcessesCheckBox);

            autoDeleteCheckBox = new CheckBox
            {
                Text = "ลบ/Kill ทันทีเมื่อพบ (ไม่ถาม)",
                Location = new Point(300, 25),
                Size = new Size(250, 25),
                Checked = false,
                ForeColor = Color.Red
            };
            optionsGroup.Controls.Add(autoDeleteCheckBox);

            this.Controls.Add(optionsGroup);

            GroupBox statusGroup = new GroupBox
            {
                Text = "สถานะ",
                Location = new Point(20, 175),
                Size = new Size(850, 120),
                Font = new Font("Segoe UI", 10)
            };

            statusLabel = new Label
            {
                Text = "พร้อมเริ่มสแกน",
                Location = new Point(20, 25),
                Size = new Size(800, 25),
                Font = new Font("Segoe UI", 10, FontStyle.Bold),
                ForeColor = Color.Green
            };
            statusGroup.Controls.Add(statusLabel);

            currentItemLabel = new Label
            {
                Text = "กำลังสแกน: -",
                Location = new Point(20, 50),
                Size = new Size(800, 20),
                Font = new Font("Segoe UI", 9),
                AutoEllipsis = true
            };
            statusGroup.Controls.Add(currentItemLabel);

            scannedItemsLabel = new Label
            {
                Text = "จำนวนที่สแกนแล้ว: 0",
                Location = new Point(20, 75),
                Size = new Size(300, 20)
            };
            statusGroup.Controls.Add(scannedItemsLabel);

            foundItemsLabel = new Label
            {
                Text = "พบภัยคุกคาม: 0",
                Location = new Point(350, 75),
                Size = new Size(300, 20),
                ForeColor = Color.Red,
                Font = new Font("Segoe UI", 9, FontStyle.Bold)
            };
            statusGroup.Controls.Add(foundItemsLabel);

            this.Controls.Add(statusGroup);

            progressBar = new ProgressBar
            {
                Location = new Point(20, 305),
                Size = new Size(850, 30),
                Style = ProgressBarStyle.Continuous
            };
            this.Controls.Add(progressBar);

            Label logLabel = new Label
            {
                Text = "รายงานการสแกน:",
                Location = new Point(20, 345),
                Size = new Size(200, 20),
                Font = new Font("Segoe UI", 9, FontStyle.Bold)
            };
            this.Controls.Add(logLabel);

            logTextBox = new TextBox
            {
                Location = new Point(20, 370),
                Size = new Size(850, 215),
                Multiline = true,
                ScrollBars = ScrollBars.Vertical,
                ReadOnly = true,
                Font = new Font("Consolas", 9),
                BackColor = Color.Black,
                ForeColor = Color.Lime
            };
            this.Controls.Add(logTextBox);

            startButton = new Button
            {
                Text = "เริ่มสแกน",
                Location = new Point(20, 600),
                Size = new Size(150, 40),
                Font = new Font("Segoe UI", 10, FontStyle.Bold),
                BackColor = Color.Green,
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat
            };
            startButton.Click += StartButton_Click;
            this.Controls.Add(startButton);

            pauseButton = new Button
            {
                Text = "หยุดชั่วคราว",
                Location = new Point(190, 600),
                Size = new Size(150, 40),
                Font = new Font("Segoe UI", 10),
                Enabled = false,
                FlatStyle = FlatStyle.Flat
            };
            pauseButton.Click += PauseButton_Click;
            this.Controls.Add(pauseButton);

            stopButton = new Button
            {
                Text = "หยุด",
                Location = new Point(360, 600),
                Size = new Size(150, 40),
                Font = new Font("Segoe UI", 10),
                Enabled = false,
                BackColor = Color.DarkRed,
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat
            };
            stopButton.Click += StopButton_Click;
            this.Controls.Add(stopButton);

            updateSignaturesButton = new Button
            {
                Text = "อัปเดต Signatures",
                Location = new Point(530, 600),
                Size = new Size(150, 40),
                Font = new Font("Segoe UI", 10),
                BackColor = Color.DarkCyan,
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat
            };
            updateSignaturesButton.Click += UpdateSignaturesButton_Click;
            this.Controls.Add(updateSignaturesButton);

            signatureInfoLabel = new Label
            {
                Text = "Signatures: กำลังโหลด...",
                Location = new Point(700, 600),
                Size = new Size(170, 40),
                Font = new Font("Segoe UI", 8),
                ForeColor = Color.Gray,
                TextAlign = ContentAlignment.MiddleLeft
            };
            this.Controls.Add(signatureInfoLabel);

            // Monitoring Panel
            monitoringPanel = new MonitoringPanel
            {
                Location = new Point(20, 650),
                Size = new Size(850, 120)
            };
            this.Controls.Add(monitoringPanel);

            // Monitoring Controls
            monitorToggleButton = new Button
            {
                Text = "เริ่ม Monitor",
                Location = new Point(20, 780),
                Size = new Size(150, 40),
                Font = new Font("Segoe UI", 10, FontStyle.Bold),
                BackColor = Color.DarkBlue,
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat
            };
            monitorToggleButton.Click += MonitorToggleButton_Click;
            this.Controls.Add(monitorToggleButton);

            enableAlertsCheckBox = new CheckBox
            {
                Text = "เปิดการแจ้งเตือน (Notifications)",
                Location = new Point(190, 785),
                Size = new Size(250, 30),
                Checked = true,
                Font = new Font("Segoe UI", 9)
            };
            this.Controls.Add(enableAlertsCheckBox);

            Label monitorInfo = new Label
            {
                Text = "Real-time Monitor จะตรวจจับ processes และ network activity ที่น่าสงสัยอัตโนมัติ",
                Location = new Point(450, 785),
                Size = new Size(420, 30),
                Font = new Font("Segoe UI", 8),
                ForeColor = Color.Gray
            };
            this.Controls.Add(monitorInfo);

            // Initialize monitoring service
            monitoringService = new MonitoringService();
            monitoringService.ThreatDetected += MonitoringService_ThreatDetected;
            monitoringService.ThreatLevelChanged += MonitoringService_ThreatLevelChanged;
            monitoringService.LogAdded += MonitoringService_LogAdded;

            // Initialize signature updater
            signatureUpdater = new SignatureUpdater();
            signatureUpdater.UpdateProgress += SignatureUpdater_Progress;
            signatureUpdater.UpdateCompleted += SignatureUpdater_Completed;
            signatureUpdater.UpdateFailed += SignatureUpdater_Failed;
        }

        private void LoadSignatureInfo()
        {
            try
            {
                var db = new SignatureDatabase();
                var updateInfo = signatureUpdater?.GetUpdateInfo();

                string infoText = $"Signatures: {db.GetSignatureCount()} รายการ";
                if (updateInfo != null)
                {
                    infoText += $"\nอัปเดต: {updateInfo.UpdatedDate:dd/MM/yyyy}";
                }

                if (signatureInfoLabel != null)
                {
                    signatureInfoLabel.Text = infoText;
                }
            }
            catch
            {
                if (signatureInfoLabel != null)
                {
                    signatureInfoLabel.Text = "Signatures: ไม่ทราบ";
                }
            }
        }

        private async void StartButton_Click(object? sender, EventArgs e)
        {
            if (!scanFilesCheckBox.Checked && !scanRegistryCheckBox.Checked && !scanProcessesCheckBox.Checked)
            {
                MessageBox.Show("กรุณาเลือกอย่างน้อย 1 ตัวเลือก", "ข้อผิดพลาด",
                    MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            var warningMessage = "โปรแกรมจะสแกนและลบไฟล์/Registry";
            if (scanProcessesCheckBox.Checked)
            {
                warningMessage += " และ KILL processes ใน RAM";
            }
            warningMessage += " ที่เกี่ยวข้องกับ Skidrow\n\n" +
                            "ควรสำรองข้อมูลสำคัญก่อนใช้งาน\n\n" +
                            "ต้องการดำเนินการต่อหรือไม่?";

            var result = MessageBox.Show(
                warningMessage,
                "คำเตือน",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Warning
            );

            if (result != DialogResult.Yes)
                return;

            startButton.Enabled = false;
            pauseButton.Enabled = true;
            stopButton.Enabled = true;
            scanFilesCheckBox.Enabled = false;
            scanRegistryCheckBox.Enabled = false;
            scanProcessesCheckBox.Enabled = false;
            autoDeleteCheckBox.Enabled = false;

            progressBar.Value = 0;
            logTextBox.Clear();

            scanner = new Scanner(
                scanFilesCheckBox.Checked,
                scanRegistryCheckBox.Checked,
                scanProcessesCheckBox.Checked,
                autoDeleteCheckBox.Checked
            );

            scanner.ProgressChanged += Scanner_ProgressChanged;
            scanner.LogAdded += Scanner_LogAdded;
            scanner.StatusChanged += Scanner_StatusChanged;
            scanner.ScanCompleted += Scanner_ScanCompleted;

            statusLabel.Text = "กำลังสแกน...";
            statusLabel.ForeColor = Color.Orange;

            await scanner.StartScanAsync();
        }

        private void PauseButton_Click(object? sender, EventArgs e)
        {
            if (scanner == null) return;

            if (scanner.IsPaused)
            {
                scanner.Resume();
                pauseButton.Text = "หยุดชั่วคราว";
                statusLabel.Text = "กำลังสแกนต่อ...";
                statusLabel.ForeColor = Color.Orange;
            }
            else
            {
                scanner.Pause();
                pauseButton.Text = "ดำเนินการต่อ";
                statusLabel.Text = "หยุดชั่วคราว";
                statusLabel.ForeColor = Color.Blue;
            }
        }

        private void StopButton_Click(object? sender, EventArgs e)
        {
            if (scanner == null) return;

            var result = MessageBox.Show(
                "ต้องการหยุดการสแกนหรือไม่?",
                "ยืนยัน",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Question
            );

            if (result == DialogResult.Yes)
            {
                scanner.Stop();
                ResetUI();
            }
        }

        private void Scanner_ProgressChanged(object? sender, ProgressEventArgs e)
        {
            if (InvokeRequired)
            {
                Invoke(new Action(() => Scanner_ProgressChanged(sender, e)));
                return;
            }

            progressBar.Value = Math.Min(e.Percentage, 100);
            currentItemLabel.Text = $"กำลังสแกน: {e.CurrentItem}";
            scannedItemsLabel.Text = $"จำนวนที่สแกนแล้ว: {e.ScannedCount:N0}";
            foundItemsLabel.Text = $"พบภัยคุกคาม: {e.FoundCount}";
        }

        private void Scanner_LogAdded(object? sender, string message)
        {
            if (InvokeRequired)
            {
                Invoke(new Action(() => Scanner_LogAdded(sender, message)));
                return;
            }

            logTextBox.AppendText($"[{DateTime.Now:HH:mm:ss}] {message}\r\n");
        }

        private void Scanner_StatusChanged(object? sender, string status)
        {
            if (InvokeRequired)
            {
                Invoke(new Action(() => Scanner_StatusChanged(sender, status)));
                return;
            }

            statusLabel.Text = status;
        }

        private void Scanner_ScanCompleted(object? sender, ScanResult result)
        {
            if (InvokeRequired)
            {
                Invoke(new Action(() => Scanner_ScanCompleted(sender, result)));
                return;
            }

            ResetUI();

            string logPath = scanner?.LogFilePath ?? "ไม่ทราบ";

            string message = $"การสแกนเสร็จสมบูรณ์!\n\n" +
                           $"จำนวนที่สแกน: {result.TotalScanned:N0}\n" +
                           $"พบภัยคุกคาม: {result.ThreatsFound}\n" +
                           $"ลบแล้ว: {result.ThreatsRemoved}\n" +
                           $"ลบไม่สำเร็จ: {result.FailedToRemove}\n\n" +
                           $"Log file บันทึกที่:\n{logPath}";

            MessageBox.Show(message, "เสร็จสิ้น", MessageBoxButtons.OK,
                result.ThreatsFound > 0 ? MessageBoxIcon.Warning : MessageBoxIcon.Information);

            statusLabel.Text = "เสร็จสิ้น - Log saved";
            statusLabel.ForeColor = Color.Green;

            // Ask if user wants to open log file
            if (!string.IsNullOrEmpty(scanner?.LogFilePath) && System.IO.File.Exists(scanner.LogFilePath))
            {
                var openLog = MessageBox.Show(
                    "ต้องการเปิดไฟล์ log หรือไม่?",
                    "เปิด Log File",
                    MessageBoxButtons.YesNo,
                    MessageBoxIcon.Question
                );

                if (openLog == DialogResult.Yes)
                {
                    try
                    {
                        System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                        {
                            FileName = scanner.LogFilePath,
                            UseShellExecute = true
                        });
                    }
                    catch
                    {
                        MessageBox.Show("ไม่สามารถเปิดไฟล์ log ได้", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    }
                }
            }
        }

        private void MonitorToggleButton_Click(object? sender, EventArgs e)
        {
            if (monitoringService == null || monitoringPanel == null) return;

            if (monitoringService.IsRunning)
            {
                // Stop monitoring
                monitoringService.Stop();
                monitoringPanel.StopMonitoring();

                monitorToggleButton.Text = "เริ่ม Monitor";
                monitorToggleButton.BackColor = Color.DarkBlue;
                enableAlertsCheckBox.Enabled = true;

                Scanner_LogAdded(this, "[MONITOR] Real-time monitoring stopped");
            }
            else
            {
                // Start monitoring
                monitoringService.Start();
                monitoringPanel.StartMonitoring();

                monitorToggleButton.Text = "หยุด Monitor";
                monitorToggleButton.BackColor = Color.DarkRed;
                enableAlertsCheckBox.Enabled = false;

                Scanner_LogAdded(this, "[MONITOR] Real-time monitoring started");
            }
        }

        private void MonitoringService_ThreatDetected(object? sender, ThreatAlert alert)
        {
            if (InvokeRequired)
            {
                Invoke(new Action(() => MonitoringService_ThreatDetected(sender, alert)));
                return;
            }

            monitoringPanel?.IncrementAlertCount();

            // Show notification if enabled
            if (enableAlertsCheckBox.Checked)
            {
                string levelText = alert.Level switch
                {
                    ThreatLevel.Critical => "CRITICAL THREAT",
                    ThreatLevel.Warning => "WARNING",
                    _ => "INFO"
                };

                MessageBox.Show(
                    $"{alert.Description}\n\n" +
                    $"Process: {alert.ProcessName} (PID: {alert.ProcessId})\n" +
                    $"Details: {alert.Details}\n\n" +
                    $"Time: {alert.Timestamp:HH:mm:ss}",
                    levelText,
                    MessageBoxButtons.OK,
                    alert.Level == ThreatLevel.Critical ? MessageBoxIcon.Error : MessageBoxIcon.Warning
                );
            }
        }

        private void MonitoringService_ThreatLevelChanged(object? sender, ThreatLevel level)
        {
            if (InvokeRequired)
            {
                Invoke(new Action(() => MonitoringService_ThreatLevelChanged(sender, level)));
                return;
            }

            monitoringPanel?.UpdateThreatLevel(level);

            // Auto-reset to safe after a delay for warnings
            if (level == ThreatLevel.Warning)
            {
                Task.Delay(10000).ContinueWith(_ =>
                {
                    if (monitoringService != null && monitoringService.CurrentThreatLevel == ThreatLevel.Warning)
                    {
                        monitoringService.ResetThreatLevel();
                    }
                });
            }
        }

        private void MonitoringService_LogAdded(object? sender, string message)
        {
            Scanner_LogAdded(sender, message);
        }

        private async void UpdateSignaturesButton_Click(object? sender, EventArgs e)
        {
            if (signatureUpdater == null) return;

            updateSignaturesButton.Enabled = false;
            Scanner_LogAdded(this, "[UPDATE] เริ่มตรวจสอบและอัปเดต Signatures...");

            try
            {
                // Check if update is needed
                bool needsUpdate = await signatureUpdater.CheckForUpdatesAsync();

                if (!needsUpdate)
                {
                    Scanner_LogAdded(this, "[UPDATE] Signatures อัปเดตล่าสุดแล้ว (ตรวจสอบทุกวัน)");
                    MessageBox.Show(
                        "Signature database เป็นเวอร์ชั่นล่าสุดแล้ว\n" +
                        "จะตรวจสอบอัตโนมัติอีกครั้งในวันถัดไป",
                        "อัปเดตแล้ว",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Information
                    );
                    updateSignaturesButton.Enabled = true;
                    return;
                }

                // Download and update
                bool success = await signatureUpdater.DownloadAndUpdateSignaturesAsync();

                if (success)
                {
                    LoadSignatureInfo(); // Refresh signature count display
                }
            }
            catch (Exception ex)
            {
                Scanner_LogAdded(this, $"[UPDATE ERROR] {ex.Message}");
                MessageBox.Show(
                    $"เกิดข้อผิดพลาดในการอัปเดต:\n{ex.Message}",
                    "Error",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error
                );
            }
            finally
            {
                updateSignaturesButton.Enabled = true;
            }
        }

        private void SignatureUpdater_Progress(object? sender, string message)
        {
            Scanner_LogAdded(sender, $"[UPDATE] {message}");
        }

        private void SignatureUpdater_Completed(object? sender, string message)
        {
            if (InvokeRequired)
            {
                Invoke(new Action(() => SignatureUpdater_Completed(sender, message)));
                return;
            }

            Scanner_LogAdded(sender, $"[UPDATE SUCCESS] {message}");

            MessageBox.Show(
                message,
                "อัปเดตสำเร็จ",
                MessageBoxButtons.OK,
                MessageBoxIcon.Information
            );

            LoadSignatureInfo(); // Refresh the display
        }

        private void SignatureUpdater_Failed(object? sender, string message)
        {
            if (InvokeRequired)
            {
                Invoke(new Action(() => SignatureUpdater_Failed(sender, message)));
                return;
            }

            Scanner_LogAdded(sender, $"[UPDATE FAILED] {message}");

            MessageBox.Show(
                $"การอัปเดตล้มเหลว:\n{message}\n\nจะใช้ signatures เดิมต่อไป",
                "อัปเดตล้มเหลว",
                MessageBoxButtons.OK,
                MessageBoxIcon.Warning
            );
        }

        private void ResetUI()
        {
            startButton.Enabled = true;
            pauseButton.Enabled = false;
            stopButton.Enabled = false;
            pauseButton.Text = "หยุดชั่วคราว";
            scanFilesCheckBox.Enabled = true;
            scanRegistryCheckBox.Enabled = true;
            scanProcessesCheckBox.Enabled = true;
            autoDeleteCheckBox.Enabled = true;
        }

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            base.OnFormClosing(e);

            // Stop monitoring before closing
            if (monitoringService != null && monitoringService.IsRunning)
            {
                monitoringService.Stop();
            }

            monitoringService?.Dispose();
        }
    }
}
