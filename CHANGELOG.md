# Changelog

All notable changes to Skidrow Killer will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned
- Multi-language UI support (English, Chinese, Japanese, Thai, Korean)
- Email notifications
- REST API for integration
- Linux/macOS support

---

## [3.6.0] - 2026-01-09

### Added
- **Tier 3 Feature Views** - Dedicated UI for premium features
  - USB Protection View - Monitor connected USB drives, auto-scan on connect, block autorun.inf
  - Ransomware Protection View - Manage protected folders, honeypot monitoring, file entropy detection
  - Scheduled Scan View - Configure daily/weekly/monthly automated scans with edit/delete capability
  - Gaming Mode View - Auto-detect games, manual toggle, session tracking, settings management

### Changed
- Added 4 new navigation buttons in sidebar for Tier 3 features
- Improved main window navigation structure

---

## [3.5.1] - 2026-01-08

### Fixed
- Removed all mockup code - services now fully functional
- XAML resource errors and scroll issues in views

---

## [3.5.0] - 2026-01-08

### Added
- **Startup Services Control** - Configure which services start automatically
- **Service Audit** - View status of all protection services

### Changed
- Improved settings organization

---

## [3.4.0] - 2026-01-08

### Added
- **Browser Protection** - Scan and remove malicious browser extensions
  - Support for Chrome, Firefox, Edge, Brave, Opera
  - Extension threat analysis
  - One-click removal
- **System Cleanup** - Disk cleanup utility
  - Temp files, browser cache, recycle bin, Windows logs
  - Space calculation and cleanup
  - Safe cleanup with progress tracking
- **Gaming Mode Service** - Reduce CPU usage while gaming
  - Auto-detect games and fullscreen apps
  - Suppress notifications during gaming
  - Configurable protection pause
- **USB Scan Service** - Protect against infected USB drives
  - Auto-scan on connect
  - Block autorun.inf files
  - Malware detection
- **Ransomware Protection Service** - Protect important files
  - Folder protection with monitoring
  - Honeypot file detection
  - File entropy analysis
  - Alert system for suspicious activity
- **Scheduled Scan Service** - Automate security scans
  - Daily, weekly, monthly schedules
  - Quick, full, or custom scan types
  - Persistent schedule storage

---

## [3.3.0] - 2026-01-08

### Added
- **Scan Report Service** - Export scan results
  - HTML, TXT, CSV, JSON formats
  - Detailed threat information
  - Summary statistics

---

## [3.2.0] - 2026-01-07

### Added
- **Network Protection** - Monitor and block malicious network activity
  - Domain blocking
  - DNS monitoring
  - Connection tracking
- **Self-Protection System** - Prevent tampering
  - Anti-debugging detection
  - DLL injection detection
  - File and registry integrity checks
- **Anti-Evasion Detection** - Detect advanced malware techniques
  - Process hollowing detection
  - Hidden process detection
  - Basic rootkit detection

---

## [3.1.0] - 2026-01-08

### Added
- **Auto-Update Signature System** - Download YARA malware signatures automatically from GitHub
  - Integration with [Yara-Rules/rules](https://github.com/Yara-Rules/rules)
  - Integration with [Neo23x0/signature-base](https://github.com/Neo23x0/signature-base)
  - Smart merge with existing custom signatures
  - Daily automatic update check
  - Retry logic with exponential backoff
- One-click "Update Signatures" button in UI
- Display signature count and last update date
- Update progress logging

### Changed
- Improved signature database management
- Enhanced error handling for network operations

### Fixed
- Network timeout issues during signature downloads

---

## [3.0.0] - 2026-01-07

### Added
- **Real-time Monitoring Mode**
  - Heartbeat animation with color-coded threat levels (Green/Yellow/Red)
  - Process monitoring for new suspicious processes
  - Network activity monitoring
  - Popup notifications for detected threats
  - 24/7 background protection capability
- **Signature Database System**
  - Customizable `signatures.json` file
  - Multiple threat categories support
  - Threat level scoring (1-10)
  - Easy pattern management
- **Portable Version**
  - Self-contained executable
  - No .NET runtime installation required
  - USB drive compatible
  - `build-portable.bat` build script
- **Advanced Protection Service**
  - Smart threat analysis
  - Whitelist management
  - Backup before removal
- **Quarantine System**
  - Safe storage of detected threats
  - Restore capability
  - Automatic cleanup
- **Modern WPF UI**
  - Tabbed interface (Scan/Monitor/Threats/Quarantine/Backups/Whitelist/Settings)
  - Dark theme with professional styling
  - Responsive animations

### Changed
- Complete UI rewrite from WinForms to WPF
- Improved architecture with MVVM pattern
- Enhanced logging with Serilog
- Better configuration management with appsettings.json

### Security
- Thread-safe operations throughout
- Proper exception handling
- Memory leak prevention
- Secure signature validation

---

## [2.1.0] - 2026-01-06

### Added
- Automatic log file creation
- Save all scan results to `.log` files
- Log file location: `Documents\SkidrowKiller\Logs\`
- Prompt to open log file after scan completion

### Changed
- Improved logging format with timestamps
- Better error reporting in logs

---

## [2.0.0] - 2026-01-05

### Added
- **Process/Memory (RAM) Scanning**
  - Scan all running processes
  - Detect malware hiding in RAM
  - DLL Injection detection
  - Process termination capability
- Support for both 32-bit and 64-bit processes
- Detection of cracked Steam API DLLs
- Detection of cracked game DLLs
- WMI integration for accurate process information

### Changed
- Enhanced scanning engine
- Improved detection patterns
- Better performance for large scans

---

## [1.0.0] - 2026-01-04

### Added
- Initial release
- **File Scanning**
  - Scan all fixed and removable drives
  - Scan system folders (Program Files, AppData, Temp, etc.)
  - Pattern-based detection
- **Registry Scanning**
  - Scan HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, HKEY_USERS
  - Check Run/RunOnce keys
  - Detect suspicious registrations
- **Core Features**
  - Progress bar display
  - Real-time logging
  - Status display
  - Pause/Resume/Stop controls
  - Auto-delete option
- Detection patterns for:
  - Skidrow, Reloaded, Codex, Plaza, CPY
  - Crack tools, Keygens, Patchers
  - Suspicious DLL files

---

## Version History Summary

| Version | Release Date | Highlights |
|---------|--------------|------------|
| 3.6.0   | 2026-01-09   | Tier 3 Feature Views (USB, Ransomware, Scheduled, Gaming) |
| 3.5.1   | 2026-01-08   | Bug fixes, remove mockup code |
| 3.5.0   | 2026-01-08   | Startup Services Control |
| 3.4.0   | 2026-01-08   | Browser Protection, System Cleanup, Premium Features |
| 3.3.0   | 2026-01-08   | Scan Report Service |
| 3.2.0   | 2026-01-07   | Network Protection, Self-Protection, Anti-Evasion |
| 3.1.0   | 2026-01-08   | Auto-Update Signatures |
| 3.0.0   | 2026-01-07   | Real-time Monitoring, WPF UI, Portable Build |
| 2.1.0   | 2026-01-06   | Log Files |
| 2.0.0   | 2026-01-05   | RAM/Process Scanning |
| 1.0.0   | 2026-01-04   | Initial Release |

---

[Unreleased]: https://github.com/xjanova/Skidrowkiller/compare/v3.6.0...HEAD
[3.6.0]: https://github.com/xjanova/Skidrowkiller/compare/v3.5.1...v3.6.0
[3.5.1]: https://github.com/xjanova/Skidrowkiller/compare/v3.5.0...v3.5.1
[3.5.0]: https://github.com/xjanova/Skidrowkiller/compare/v3.4.0...v3.5.0
[3.4.0]: https://github.com/xjanova/Skidrowkiller/compare/v3.3.0...v3.4.0
[3.3.0]: https://github.com/xjanova/Skidrowkiller/compare/v3.2.0...v3.3.0
[3.2.0]: https://github.com/xjanova/Skidrowkiller/compare/v3.1.0...v3.2.0
[3.1.0]: https://github.com/xjanova/Skidrowkiller/compare/v3.0.0...v3.1.0
[3.0.0]: https://github.com/xjanova/Skidrowkiller/compare/v2.1.0...v3.0.0
[2.1.0]: https://github.com/xjanova/Skidrowkiller/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/xjanova/Skidrowkiller/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/xjanova/Skidrowkiller/releases/tag/v1.0.0
