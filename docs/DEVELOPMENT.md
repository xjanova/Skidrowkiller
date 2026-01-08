# Development Guide

This guide covers everything you need to set up a development environment for Skidrow Killer.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Environment Setup](#environment-setup)
- [Project Structure](#project-structure)
- [Building](#building)
- [Debugging](#debugging)
- [Code Style](#code-style)
- [Testing](#testing)
- [Common Tasks](#common-tasks)

---

## Prerequisites

### Required Software

| Software | Version | Download |
|----------|---------|----------|
| .NET SDK | 8.0+ | [Download](https://dotnet.microsoft.com/download/dotnet/8.0) |
| Visual Studio | 2022+ | [Download](https://visualstudio.microsoft.com/) |
| Git | Latest | [Download](https://git-scm.com/) |

### Visual Studio Workloads

Install these workloads via Visual Studio Installer:
- **.NET Desktop Development**
- **Desktop development with C++** (optional, for native debugging)

### VS Code Alternative

If using VS Code, install these extensions:
- C# Dev Kit
- .NET Install Tool
- XAML Language Support

---

## Environment Setup

### 1. Clone Repository

```bash
git clone https://github.com/xjanova/Skidrowkiller.git
cd Skidrowkiller
```

### 2. Restore Dependencies

```bash
dotnet restore
```

### 3. Verify Build

```bash
dotnet build
```

### 4. Open in IDE

**Visual Studio:**
```bash
start SkidrowKiller.sln
```

**VS Code:**
```bash
code .
```

---

## Project Structure

```
SkidrowKiller/
├── App.xaml                 # Application resources and startup
├── App.xaml.cs              # Application entry, DI container
├── Program.cs               # Main entry point
├── MainWindow.xaml          # Main window layout
├── MainWindow.xaml.cs       # Navigation and main logic
│
├── Services/                # Business logic
│   ├── SafeScanner.cs       # Core scanning engine
│   ├── ProtectionService.cs # Real-time monitoring
│   ├── ThreatAnalyzer.cs    # Threat scoring
│   ├── QuarantineService.cs # Threat quarantine
│   ├── BackupManager.cs     # Backup system
│   ├── WhitelistManager.cs  # Whitelist handling
│   ├── UpdateService.cs     # Signature updates
│   ├── LoggingService.cs    # Serilog integration
│   └── AppConfiguration.cs  # Settings management
│
├── Views/                   # UI screens
│   ├── ScanView.xaml        # Scanning interface
│   ├── MonitorView.xaml     # Real-time monitor
│   ├── ThreatsView.xaml     # Detected threats
│   ├── QuarantineView.xaml  # Quarantine manager
│   ├── BackupsView.xaml     # Backup manager
│   ├── WhitelistView.xaml   # Whitelist manager
│   └── SettingsView.xaml    # Application settings
│
├── Models/                  # Data structures
│   └── ThreatInfo.cs        # Threat data model
│
├── Themes/                  # UI styling
│   ├── Colors.xaml          # Color palette
│   └── Controls.xaml        # Control templates
│
├── Assets/                  # Resources
│   ├── icon.ico             # App icon
│   └── logo.png             # Logo image
│
├── .github/workflows/       # CI/CD pipelines
│   ├── build.yml            # Build workflow
│   └── release.yml          # Release workflow
│
└── docs/                    # Documentation
    ├── DEVELOPMENT.md       # This file
    ├── ARCHITECTURE.md      # System architecture
    └── CODE_SIGNING.md      # Signing guide
```

---

## Building

### Debug Build

```bash
dotnet build -c Debug
```

Output: `bin/Debug/net8.0-windows/`

### Release Build

```bash
dotnet build -c Release
```

Output: `bin/Release/net8.0-windows/`

### Portable Build (Self-contained)

```bash
dotnet publish -c Release -r win-x64 --self-contained true \
  /p:PublishSingleFile=true \
  /p:PublishReadyToRun=true \
  /p:EnableCompressionInSingleFile=true
```

Or use the build script:

```bash
.\build-portable.bat
```

### Framework-dependent Build

```bash
dotnet publish -c Release -r win-x64 --self-contained false
```

### Build for ARM64

```bash
dotnet publish -c Release -r win-arm64 --self-contained true /p:PublishSingleFile=true
```

---

## Debugging

### Running as Administrator

The application requires admin rights. In Visual Studio:

1. Right-click project → Properties
2. Go to Debug → Open debug launch profiles UI
3. Check "Run as administrator"

Or from command line:
```powershell
Start-Process "dotnet" -ArgumentList "run" -Verb RunAs
```

### Debugging Process Scanning

Process scanning requires elevated privileges. Attach debugger after the app starts as admin.

### Logging for Debug

Set logging level in `appsettings.json`:

```json
{
  "Logging": {
    "MinimumLevel": "Debug",
    "EnableConsoleLogging": true
  }
}
```

### Common Debug Scenarios

#### File Access Issues
- Ensure running as Administrator
- Check if files are locked by other processes
- Verify path permissions

#### Registry Access Issues
- Must run as Administrator
- Some keys require SYSTEM privileges
- Use try-catch for access denied

#### Process Scanning Issues
- Some processes are protected (System, csrss, etc.)
- 32-bit processes need different handling on 64-bit OS
- Check WMI service is running

---

## Code Style

### C# Conventions

```csharp
// Use file-scoped namespaces
namespace SkidrowKiller.Services;

// Private fields with underscore prefix
private readonly ILogger _logger;
private bool _isRunning;

// Use var when type is obvious
var scanner = new SafeScanner();
var threats = new List<ThreatInfo>();

// Async methods end with Async
public async Task<bool> ScanFileAsync(string path)

// Use expression-bodied members for simple operations
public string Name => _name;
public bool IsEmpty => Count == 0;
```

### XAML Conventions

```xml
<!-- 2-space indentation -->
<Button
  Content="Scan"
  Style="{StaticResource PrimaryButton}"
  Command="{Binding ScanCommand}" />

<!-- Group related properties -->
<TextBlock
  Text="Status"
  FontSize="14"
  FontWeight="Bold"
  Foreground="{StaticResource TextPrimary}" />
```

### File Organization

- One class per file (exceptions for small related classes)
- Group using directives (System first, then third-party, then project)
- Order class members: Fields, Properties, Constructors, Methods

---

## Testing

### Manual Testing Checklist

Before submitting changes, verify:

- [ ] Application starts correctly as Administrator
- [ ] All tabs load without errors
- [ ] File scanning finds known patterns
- [ ] Registry scanning works
- [ ] Process scanning detects running processes
- [ ] Real-time monitoring starts/stops correctly
- [ ] Signature update downloads successfully
- [ ] Quarantine operations work
- [ ] Backup/restore functions correctly
- [ ] Whitelist additions are honored
- [ ] Settings persist after restart
- [ ] Logs are generated correctly

### Test Environments

Test on:
- Windows 10 (21H2+)
- Windows 11
- Both x64 and ARM64 if possible

### Creating Test Cases

For testing detection:
1. Create files with known malware pattern names
2. Create registry entries in safe test locations
3. Use process name patterns that match signatures

---

## Common Tasks

### Adding a New Service

1. Create `Services/NewService.cs`:
```csharp
namespace SkidrowKiller.Services;

public class NewService
{
    private readonly LoggingService _logger;

    public NewService(LoggingService logger)
    {
        _logger = logger;
    }

    public void DoSomething()
    {
        _logger.LogInformation("Doing something...");
    }
}
```

2. Register in dependency injection (if using)
3. Inject where needed

### Adding a New View

1. Create `Views/NewView.xaml` and `Views/NewView.xaml.cs`
2. Add navigation button in `MainWindow.xaml`
3. Add navigation logic in `MainWindow.xaml.cs`

### Adding a New Detection Pattern

1. Edit `signatures.json`:
```json
{
  "Name": "New Threat Pattern",
  "Category": "Malware",
  "FileNamePatterns": ["pattern1", "pattern2"],
  "ProcessNamePatterns": ["process_pattern"],
  "ThreatLevel": 8,
  "Description": "Description of what this detects"
}
```

2. Test with sample files/processes

### Updating Dependencies

```bash
# Update all packages
dotnet outdated
dotnet outdated --upgrade

# Update specific package
dotnet add package PackageName --version X.Y.Z
```

### Creating a Release

1. Update version in `SkidrowKiller.csproj`:
```xml
<Version>3.2.0</Version>
<FileVersion>3.2.0.0</FileVersion>
<AssemblyVersion>3.2.0.0</AssemblyVersion>
```

2. Update `CHANGELOG.md`

3. Create and push tag:
```bash
git tag v3.2.0
git push origin v3.2.0
```

4. GitHub Actions will automatically create release

---

## Troubleshooting

### Build Errors

**"SDK not found"**
- Install .NET 8.0 SDK
- Ensure correct path in environment variables

**"WPF reference error"**
- Ensure building on Windows
- Verify workload installed: `dotnet workload install maui-windows`

### Runtime Errors

**"Access denied"**
- Run as Administrator
- Check file/registry permissions

**"DLL not found"**
- Ensure all dependencies are restored
- Check runtime identifier matches system

### Performance Issues

**Slow scanning**
- Normal for systems with many files
- Use progress reporting
- Consider parallel scanning for files

**High memory usage**
- Process large directories in batches
- Dispose resources properly
- Use async enumeration

---

## Getting Help

1. Check existing documentation
2. Search GitHub Issues
3. Ask in Discussions
4. Create new Issue with details

When reporting issues, include:
- Windows version
- .NET version (`dotnet --version`)
- Steps to reproduce
- Error messages/logs
