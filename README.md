<p align="center">
  <img src="logo.png" alt="Skidrow Killer Logo" width="200">
</p>

<h1 align="center">Skidrow Killer</h1>

<p align="center">
  <strong>Professional Malware Scanner & Security Suite for Windows</strong>
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
  <img src="https://img.shields.io/badge/version-3.2.0-blue.svg" alt="Version">
  <img src="https://img.shields.io/badge/platform-Windows%2010%2F11-lightgrey.svg" alt="Platform">
  <img src="https://img.shields.io/badge/.NET-8.0-purple.svg" alt=".NET">
  <img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License">
</p>

---

## Overview

**Skidrow Killer** is a powerful, professional-grade security suite designed to detect and remove malware, cracks, keygens, and potentially unwanted programs (PUPs) from Windows systems. With advanced detection engines, network protection, self-defense mechanisms, and real-time monitoring, it provides enterprise-level protection against modern threats.

### Why Skidrow Killer?

- **Multi-Engine Detection**: Hash-based, heuristic, behavioral, and PE analysis
- **Network Protection**: Block malicious domains and analyze suspicious connections
- **Self-Protection**: Defend against malware trying to disable the scanner
- **Deep Scanning**: Scans files, registry, processes, and network connections
- **Real-time Protection**: 24/7 monitoring with instant threat detection
- **Portable**: No installation required, run from USB drive

---

## Features

### Advanced Detection Engines

| Engine | Description |
|--------|-------------|
| **Signature Database** | 1000+ malware hashes, YARA rules, and malware family tracking |
| **PE Analyzer** | Analyzes PE files: imports, sections, entropy, packer detection |
| **Heuristic Engine** | Behavioral analysis and suspicious pattern detection |
| **Threat Analyzer** | Context-aware scoring with false-positive reduction |

### Core Scanning Capabilities

| Feature | Description |
|---------|-------------|
| **File Scanner** | Scans all drives (Fixed, Removable) including system folders |
| **Registry Scanner** | Checks HKCU, HKLM, HKUSERS for malicious entries |
| **Process Scanner** | Detects threats hiding in RAM with DLL injection detection |
| **Smart Detection** | Multi-layered threat scoring with context-aware analysis |

### Network Protection (NEW in v3.2.0)

- **Domain Blocking** - Block connections to warez, crack, and torrent sites
- **DNS Monitoring** - Real-time DNS cache monitoring for suspicious domains
- **Source Analysis** - Find the root cause of malicious network connections
- **Deep Scan** - Targeted scanning of related processes and files
- **Connection Tracking** - Monitor all outbound connections in real-time

### Self-Protection System (NEW in v3.2.0)

Skidrow Killer protects itself from malware attacks:

| Protection | Description |
|------------|-------------|
| **Anti-Debugging** | Detect and block debuggers attempting to analyze the app |
| **DLL Injection Detection** | Block malicious DLL injection attempts |
| **File Integrity** | Detect tampering with program files |
| **Registry Protection** | Detect attempts to disable the scanner via registry |
| **Process Protection** | Prevent malware from terminating the scanner |

### Anti-Evasion Detection (NEW in v3.2.0)

Detect advanced malware hiding techniques:

- **Process Hollowing Detection** - Find malware hiding in legitimate processes
- **Hidden Process Detection** - Compare API vs WMI to find hidden processes
- **Rootkit Detection** - Detect hidden drivers and kernel-level rootkits
- **API Hook Detection** - Find malware intercepting system calls
- **Alternate Data Stream Detection** - Find data hidden in NTFS streams

### Real-time Protection

- **Live Monitoring** - Continuous process and network activity monitoring
- **Heartbeat Display** - Visual threat level indicator (Green/Yellow/Red)
- **Instant Alerts** - Popup notifications when threats are detected
- **Background Mode** - Runs silently without impacting performance

### Signature Management

- **Auto-Update System** - Downloads latest signatures from trusted sources
- **Custom Signatures** - Add your own detection patterns
- **Multiple Sources** - Integrates with Yara-Rules and Neo23x0 signature bases
- **600+ Patterns** - Comprehensive coverage of crack and malware patterns

### Safety Features

- **Backup System** - Creates backup before removing any file
- **Quarantine** - Safely isolate threats for later review
- **Whitelist** - Exclude trusted files and folders from scanning
- **Detailed Logs** - Complete audit trail of all actions

### Detection Coverage

Detects threats including:

**Crack Groups & Tools:**
- Skidrow, Reloaded, Codex, Plaza, CPY, FLT, HOODLUM, EMPRESS, DODI
- Keygens, Patchers, Loaders, Trainers
- Steam API emulators, DLL injections

**Malware Categories:**
- Trojans & Backdoors
- Cryptominers
- Ransomware
- Spyware & Keyloggers
- Adware & PUPs

**Malicious Domains:**
- Warez sites (skidrow-games, oceanofgames, etc.)
- Crack sites (crackwatch, 1337x, etc.)
- Torrent trackers

---

## Installation

### System Requirements

| Requirement | Specification |
|-------------|---------------|
| **OS** | Windows 10/11 (64-bit) |
| **RAM** | 2 GB minimum |
| **Disk** | 200 MB free space |
| **Runtime** | .NET 8.0 (or use Portable version) |
| **Privileges** | Administrator recommended |

### Download Options

#### Option 1: Portable Version (Recommended)
No installation required. Download, extract, and run.

```
SkidrowKiller-v3.2.0-win-x64-portable.zip
```

#### Option 2: Framework-dependent Version
Smaller download, requires .NET 8.0 Runtime installed.

```
SkidrowKiller-v3.2.0-win-x64-framework.zip
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

### Web Protection (NEW)

1. Navigate to **"Web Protection"** tab
2. Enable protection to block malicious domains
3. Monitor blocked connections in real-time
4. Use **"Analyze"** to find the source of suspicious connections
5. Use **"Deep Scan"** to scan related files and processes

### Managing Threats

- **Quarantine**: Move threat to safe storage
- **Delete**: Permanently remove (backup created first)
- **Whitelist**: Mark as safe to ignore in future scans
- **Restore**: Recover from quarantine or backup

---

## What's New in v3.2.0

### Major Features

1. **Advanced Detection Engines**
   - MalwareSignatureDatabase with 1000+ hashes
   - PEAnalyzer for deep PE file analysis
   - HeuristicEngine for behavioral detection

2. **Network Protection**
   - Block warez/crack/torrent domains
   - Source analysis to find infection root cause
   - Deep scan targeting related processes

3. **Self-Protection**
   - Anti-debugging measures
   - DLL injection detection
   - File integrity monitoring
   - Process termination protection

4. **Anti-Evasion**
   - Process hollowing detection
   - Hidden process detection
   - Rootkit detection

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
dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true

# Or use the build script
.\build-portable.bat
```

---

## Security & Privacy

### What We Scan
- File names, paths, and content hashes
- Registry keys and values
- Process names and loaded DLLs
- Network connections and DNS queries

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

- [ ] Multi-language UI (English, Thai, Chinese, Japanese, Korean)
- [ ] Scheduled scanning
- [ ] Email notifications
- [ ] Cloud signature updates
- [ ] REST API for integration
- [ ] Browser extension for real-time web protection

### Completed in v3.2.0
- [x] Advanced malware detection engines
- [x] Network protection with domain blocking
- [x] Self-protection system
- [x] Anti-evasion detection

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
  <strong>Skidrow Killer v3.2.0</strong> - Professional Security for Windows
  <br>
  Made with ❤️ by <a href="https://github.com/xjanova">xman studio</a>
</p>
