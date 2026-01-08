using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Windows.Forms;

namespace SkidrowKiller
{
    public class MonitoringPanel : Panel
    {
        private Timer animationTimer;
        private float pulsePhase = 0f;
        private ThreatLevel threatLevel = ThreatLevel.Safe;
        private string statusText = "Monitoring: OFF";
        private bool isMonitoring = false;
        private int alertCount = 0;

        public MonitoringPanel()
        {
            this.DoubleBuffered = true;
            this.BackColor = Color.FromArgb(20, 20, 20);
            this.Size = new Size(850, 120);

            animationTimer = new Timer();
            animationTimer.Interval = 50; // 20 FPS
            animationTimer.Tick += AnimationTimer_Tick;
        }

        public void StartMonitoring()
        {
            isMonitoring = true;
            statusText = "Monitoring: ACTIVE";
            animationTimer.Start();
            Invalidate();
        }

        public void StopMonitoring()
        {
            isMonitoring = false;
            statusText = "Monitoring: OFF";
            animationTimer.Stop();
            alertCount = 0;
            threatLevel = ThreatLevel.Safe;
            Invalidate();
        }

        public void UpdateThreatLevel(ThreatLevel level)
        {
            threatLevel = level;
            Invalidate();
        }

        public void IncrementAlertCount()
        {
            alertCount++;
            Invalidate();
        }

        private void AnimationTimer_Tick(object? sender, EventArgs e)
        {
            pulsePhase += 0.15f;
            if (pulsePhase > Math.PI * 2)
                pulsePhase = 0;

            Invalidate();
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            base.OnPaint(e);

            Graphics g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.AntiAlias;

            // Background
            using (var bgBrush = new SolidBrush(Color.FromArgb(20, 20, 20)))
            {
                g.FillRectangle(bgBrush, ClientRectangle);
            }

            if (isMonitoring)
            {
                DrawHeartbeat(g);
                DrawStatus(g);
                DrawStats(g);
            }
            else
            {
                DrawOffState(g);
            }
        }

        private void DrawHeartbeat(Graphics g)
        {
            // Determine color based on threat level
            Color lineColor = threatLevel switch
            {
                ThreatLevel.Safe => Color.FromArgb(0, 255, 100),
                ThreatLevel.Warning => Color.FromArgb(255, 200, 0),
                ThreatLevel.Critical => Color.FromArgb(255, 50, 50),
                _ => Color.Gray
            };

            // Pulsing intensity
            float pulse = (float)Math.Sin(pulsePhase) * 0.3f + 0.7f;
            Color glowColor = Color.FromArgb((int)(lineColor.R * pulse),
                                            (int)(lineColor.G * pulse),
                                            (int)(lineColor.B * pulse));

            // Draw heartbeat wave
            int centerY = Height / 2;
            int waveWidth = 600;
            int startX = 50;

            using (var pen = new Pen(glowColor, 3f))
            {
                var points = new PointF[waveWidth];

                for (int i = 0; i < waveWidth; i++)
                {
                    float x = startX + i;
                    float phase = (i / 100f) - pulsePhase;

                    // Create heartbeat wave pattern
                    float y = centerY;

                    // Main spike
                    if (phase > 0 && phase < 0.5f)
                    {
                        y -= (float)Math.Sin(phase * Math.PI * 2) * 30 * pulse;
                    }
                    // Secondary spike
                    else if (phase > 0.6f && phase < 1.0f)
                    {
                        y -= (float)Math.Sin((phase - 0.6f) * Math.PI * 5) * 15 * pulse;
                    }

                    points[i] = new PointF(x, y);
                }

                g.DrawCurve(pen, points);

                // Draw glow effect
                using (var glowPen = new Pen(Color.FromArgb(50, glowColor), 8f))
                {
                    g.DrawCurve(glowPen, points);
                }
            }

            // Draw pulse indicator circle
            int circleX = startX + waveWidth + 30;
            int circleY = centerY;
            int circleSize = (int)(20 + pulse * 10);

            using (var circleBrush = new SolidBrush(Color.FromArgb(100, glowColor)))
            {
                g.FillEllipse(circleBrush, circleX - circleSize/2, circleY - circleSize/2, circleSize, circleSize);
            }

            using (var circlePen = new Pen(glowColor, 2f))
            {
                g.DrawEllipse(circlePen, circleX - circleSize/2, circleY - circleSize/2, circleSize, circleSize);
            }
        }

        private void DrawStatus(Graphics g)
        {
            string levelText = threatLevel switch
            {
                ThreatLevel.Safe => "SAFE",
                ThreatLevel.Warning => "WARNING",
                ThreatLevel.Critical => "CRITICAL",
                _ => "UNKNOWN"
            };

            Color statusColor = threatLevel switch
            {
                ThreatLevel.Safe => Color.FromArgb(0, 255, 100),
                ThreatLevel.Warning => Color.FromArgb(255, 200, 0),
                ThreatLevel.Critical => Color.FromArgb(255, 50, 50),
                _ => Color.Gray
            };

            // Draw status text
            using (var font = new Font("Segoe UI", 24, FontStyle.Bold))
            using (var brush = new SolidBrush(statusColor))
            {
                var textSize = g.MeasureString(levelText, font);
                g.DrawString(levelText, font, brush, Width - textSize.Width - 20, 10);
            }

            // Draw monitoring status
            using (var font = new Font("Segoe UI", 10))
            using (var brush = new SolidBrush(Color.LightGray))
            {
                g.DrawString(statusText, font, brush, 10, 10);
            }
        }

        private void DrawStats(Graphics g)
        {
            using (var font = new Font("Segoe UI", 10))
            using (var brush = new SolidBrush(Color.LightGray))
            {
                string stats = $"Alerts: {alertCount}  |  Last Check: {DateTime.Now:HH:mm:ss}";
                g.DrawString(stats, font, brush, 10, Height - 30);
            }
        }

        private void DrawOffState(Graphics g)
        {
            using (var font = new Font("Segoe UI", 16, FontStyle.Bold))
            using (var brush = new SolidBrush(Color.Gray))
            {
                string text = "Real-time Monitoring: OFF";
                var textSize = g.MeasureString(text, font);
                g.DrawString(text, font, brush,
                    (Width - textSize.Width) / 2,
                    (Height - textSize.Height) / 2);
            }

            using (var font = new Font("Segoe UI", 10))
            using (var brush = new SolidBrush(Color.DarkGray))
            {
                string text = "Click 'เริ่ม Monitor' to start real-time protection";
                var textSize = g.MeasureString(text, font);
                g.DrawString(text, font, brush,
                    (Width - textSize.Width) / 2,
                    Height / 2 + 20);
            }
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                animationTimer?.Stop();
                animationTimer?.Dispose();
            }
            base.Dispose(disposing);
        }
    }
}
