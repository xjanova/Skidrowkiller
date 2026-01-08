<p align="center">
  <img src="logo.png" alt="Skidrow Killer Logo" width="200">
</p>

<h1 align="center">Skidrow Killer</h1>

<p align="center">
  <strong>Advanced Malware Scanner with Real-time Protection for Windows</strong>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="#screenshots">Screenshots</a> •
  <a href="#documentation">Documentation</a> •
  <a href="#license">License</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-3.1.0-blue.svg" alt="Version">
  <img src="https://img.shields.io/badge/platform-Windows%2010%2F11-lightgrey.svg" alt="Platform">
  <img src="https://img.shields.io/badge/.NET-8.0-purple.svg" alt=".NET">
  <img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License">
</p>

---

## Overview

**Skidrow Killer** is a powerful, professional-grade security tool designed to detect and remove malware, cracks, keygens, and potentially unwanted programs (PUPs) from Windows systems. With real-time monitoring, automatic signature updates, and comprehensive scanning capabilities, it provides enterprise-level protection for home and business users.

### Why Skidrow Killer?

- **Deep Scanning**: Scans files, registry, and running processes including RAM
- **Real-time Protection**: 24/7 monitoring with instant threat detection
- **Auto-updating Signatures**: Always up-to-date with latest threat patterns
- **Safe & Transparent**: Backup before removal, detailed logging, whitelist support
- **Portable**: No installation required, run from USB drive

---

## Features

### Core Scanning Capabilities

| Feature | Description |
|---------|-------------|
| **File Scanner** | Scans all drives (Fixed, Removable) including system folders |
| **Registry Scanner** | Checks HKCU, HKLM, HKUSERS for malicious entries |
| **Process Scanner** | Detects threats hiding in RAM with DLL injection detection |
| **Smart Detection** | Threat scoring with context-aware analysis |

### Real-time Protection

- **Live Monitoring** - Continuous process and network activity monitoring
- **Heartbeat Display** - Visual threat level indicator (Green/Yellow/Red)
- **Instant Alerts** - Popup notifications when threats are detected
- **Background Mode** - Runs silently without impacting performance

### Signature Management

- **Auto-Update System** - Downloads latest YARA rules from trusted sources
- **Custom Signatures** - Add your own detection patterns
- **Multiple Sources** - Integrates with Yara-Rules and Neo23x0 signature bases
- **Daily Updates** - Automatic check for new signatures

### Safety Features

- **Backup System** - Creates backup before removing any file
- **Quarantine** - Safely isolate threats for later review
- **Whitelist** - Exclude trusted files and folders from scanning
- **Detailed Logs** - Complete audit trail of all actions

### Detection Coverage

Detects threats including:
- Crack groups: Skidrow, Reloaded, Codex, Plaza, CPY, FLT, HOODLUM
- Crack tools: Keygens, Patchers, Loaders
- Game cracks: Steam API emulators, DLL injections
- Trojans & Backdoors: Common malware patterns
- Cryptominers: Hidden mining software

---

## Installation

### System Requirements

| Requirement | Specification |
|-------------|---------------|
| **OS** | Windows 10/11 (64-bit recommended) |
| **RAM** | 2 GB minimum |
| **Disk** | 100 MB free space |
| **Runtime** | .NET 8.0 (or use Portable version) |
| **Privileges** | Administrator required |

### Download Options

#### Option 1: Portable Version (Recommended)
No installation required. Download, extract, and run.

```
SkidrowKiller-x.x.x-win-x64-portable.zip
```

#### Option 2: Framework-dependent Version
Smaller download, requires .NET 8.0 Runtime installed.

```
SkidrowKiller-x.x.x-win-x64-framework.zip
```

### Quick Start

1. **Download** the latest release from [Releases](https://github.com/xjanova/Skidrowkiller/releases)
2. **Extract** the ZIP file to any folder
3. **Right-click** `SkidrowKiller.exe` → **Run as administrator**
4. **Update Signatures** by clicking the update button (recommended)
5. **Start Scanning** or enable **Real-time Monitor**

---

## Usage

### Scanning

1. Select scan options:
   - ☑️ Scan Files (all drives)
   - ☑️ Scan Registry
   - ☑️ Scan Processes/Memory
   - ☐ Auto-delete when found (optional)

2. Click **"Start Scan"**

3. Review results and take action

### Real-time Monitoring

1. Click **"Start Monitor"** to enable protection
2. Watch the heartbeat indicator:
   - 🟢 **Green** = System is safe
   - 🟡 **Yellow** = Suspicious activity detected
   - 🔴 **Red** = Threat detected!
3. Click **"Stop Monitor"** to disable

### Managing Threats

- **Quarantine**: Move threat to safe storage
- **Delete**: Permanently remove (backup created first)
- **Whitelist**: Mark as safe to ignore in future scans
- **Restore**: Recover from quarantine or backup

---

## Documentation

| Document | Description |
|----------|-------------|
| [CHANGELOG.md](CHANGELOG.md) | Version history and release notes |
| [CONTRIBUTING.md](CONTRIBUTING.md) | How to contribute to the project |
| [CLAUDE.md](CLAUDE.md) | AI assistant development guide |
| [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) | Developer setup guide |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Technical architecture |
| [docs/CODE_SIGNING.md](docs/CODE_SIGNING.md) | Code signing information |

---

## Building from Source

### Prerequisites

- [.NET 8.0 SDK](https://dotnet.microsoft.com/download/dotnet/8.0)
- [Visual Studio 2022](https://visualstudio.microsoft.com/) or [VS Code](https://code.visualstudio.com/)

### Build Commands

```bash
# Clone the repository
git clone https://github.com/xjanova/Skidrowkiller.git
cd Skidrowkiller

# Restore dependencies
dotnet restore

# Build Debug
dotnet build -c Debug

# Build Release
dotnet build -c Release

# Build Portable (self-contained)
dotnet publish -c Release -r win-x64 --self-contained true /p:PublishSingleFile=true

# Or use the build script
.\build-portable.bat
```

---

## Security & Privacy

### What We Scan
- File names and paths
- Registry keys and values
- Process names and loaded DLLs
- Network connection ports

### What We DON'T Do
- ❌ Upload files to any server
- ❌ Collect personal information
- ❌ Phone home or track usage
- ❌ Modify system files without consent

### Transparency
- All actions are logged
- Source code is open for audit
- Signatures are from trusted public sources

---

## Support

### Getting Help

1. **Read the Documentation** - Most questions are answered in the docs
2. **Check Issues** - Search existing issues for solutions
3. **Open an Issue** - Report bugs or request features

### Reporting Security Issues

For security vulnerabilities, please use GitHub's private vulnerability reporting or contact maintainers directly. Do not create public issues for security problems.

---

## Contributing

We welcome contributions! Please read our [Contributing Guide](CONTRIBUTING.md) for details on:

- Code of conduct
- Development setup
- Pull request process
- Coding standards

---

## Roadmap

### Planned Features

- [ ] Multi-language UI (English, Chinese, Japanese, Korean)
- [ ] Scheduled scanning
- [ ] Email notifications
- [ ] Cloud signature updates
- [ ] REST API for integration
- [ ] Linux/macOS support

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

### Disclaimer

This software is provided "as is" without warranty. Users are responsible for:
- Backing up important data before use
- Reviewing detected threats before deletion
- Using the software in accordance with applicable laws

---

## Credits

### Signature Sources
- [Yara-Rules/rules](https://github.com/Yara-Rules/rules)
- [Neo23x0/signature-base](https://github.com/Neo23x0/signature-base)

### Technologies
- [.NET 8.0](https://dotnet.microsoft.com/)
- [WPF](https://docs.microsoft.com/en-us/dotnet/desktop/wpf/)
- [Serilog](https://serilog.net/)
- [CommunityToolkit.Mvvm](https://docs.microsoft.com/en-us/dotnet/communitytoolkit/mvvm/)

---

<p align="center">
  <strong>Skidrow Killer</strong> - Protecting Windows Systems Worldwide
  <br>
  Made with ❤️ by <a href="https://github.com/xjanova">xman studio</a>
</p>
