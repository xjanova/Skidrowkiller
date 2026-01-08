# CLAUDE.md - AI Assistant Guide for Skidrow Killer

This document provides context and guidelines for AI assistants (like Claude) working on this codebase.

## Project Overview

**Skidrow Killer** is a Windows security application for detecting and removing malware, cracks, and potentially unwanted programs (PUPs). Built with WPF (.NET 8.0), it provides real-time protection and comprehensive system scanning.

### Key Characteristics
- **Type**: Desktop security application (WPF)
- **Platform**: Windows 10/11 (64-bit)
- **Framework**: .NET 8.0
- **Architecture**: MVVM-inspired with Services layer
- **Language**: C# with XAML for UI

## Project Structure

```
D:\Code\skidrowkill\
├── App.xaml / App.xaml.cs       # Application entry and configuration
├── Program.cs                    # Main entry point with DI setup
├── MainWindow.xaml / .cs         # Main window with navigation
├── appsettings.json              # Application configuration
├── appsettings.Production.json   # Production overrides
│
├── Services/                     # Business logic layer
│   ├── SafeScanner.cs           # Core scanning engine
│   ├── ProtectionService.cs      # Real-time protection
│   ├── AdvancedProtectionService.cs  # Enhanced protection features
│   ├── ThreatAnalyzer.cs         # Threat scoring and analysis
│   ├── QuarantineService.cs      # Threat quarantine management
│   ├── BackupManager.cs          # Backup before removal
│   ├── WhitelistManager.cs       # Safe file management
│   ├── UpdateService.cs          # Signature updates
│   ├── LoggingService.cs         # Serilog-based logging
│   └── AppConfiguration.cs       # Configuration management
│
├── Views/                        # UI Views (XAML + code-behind)
│   ├── ScanView.xaml / .cs       # Scanning interface
│   ├── MonitorView.xaml / .cs    # Real-time monitoring
│   ├── ThreatsView.xaml / .cs    # Detected threats display
│   ├── QuarantineView.xaml / .cs # Quarantine management
│   ├── BackupsView.xaml / .cs    # Backup management
│   ├── WhitelistView.xaml / .cs  # Whitelist management
│   └── SettingsView.xaml / .cs   # Application settings
│
├── Models/                       # Data models
│   └── ThreatInfo.cs             # Threat data structure
│
├── ViewModels/                   # (Currently minimal, logic in Views)
│
├── Themes/                       # UI styling
│   ├── Colors.xaml               # Color definitions
│   └── Controls.xaml             # Control templates
│
├── Assets/                       # Resources
│   ├── icon.ico                  # Application icon
│   └── logo.png                  # Logo image
│
├── .github/workflows/            # CI/CD
│   ├── build.yml                 # Build and test workflow
│   └── release.yml               # Release workflow
│
├── docs/                         # Documentation
│   └── CODE_SIGNING.md           # Code signing guide
│
└── legacy/                       # Old WinForms code (reference only)
```

## Key Services

### SafeScanner.cs
Main scanning engine that handles:
- File system scanning (all drives)
- Registry scanning (HKCU, HKLM, HKU)
- Process scanning with DLL injection detection
- Thread-safe progress reporting

### ProtectionService.cs / AdvancedProtectionService.cs
Real-time monitoring:
- Process creation monitoring
- Network activity monitoring
- Threat level assessment (Safe/Warning/Critical)
- Event-based notifications

### ThreatAnalyzer.cs
Threat scoring system:
- Pattern matching against signature database
- Booster patterns for higher confidence
- Context-aware scoring (safe directories reduce score)
- Configurable thresholds

### QuarantineService.cs
Safe threat handling:
- Move threats to quarantine
- Restore from quarantine
- Automatic cleanup after retention period

## Configuration

### appsettings.json Structure
```json
{
  "Application": { "Name", "Version", "Environment" },
  "Scanning": { "MaxConcurrentScans", "ScanTimeoutMinutes", ... },
  "Protection": { "Enabled", "MonitorIntervalSeconds", ... },
  "Backup": { "Enabled", "BackupBeforeRemove", "RetentionDays" },
  "Logging": { "MinimumLevel", "EnableFileLogging", ... },
  "Updates": { "CheckForUpdatesOnStartup", "UpdateCheckUrl" },
  "ThreatAnalysis": { "MinimumScoreToReport", "CriticalScoreThreshold", ... }
}
```

## Development Guidelines

### When Modifying Code

1. **Thread Safety**: All UI updates must use `Dispatcher.Invoke`
2. **Async/Await**: Use for all I/O operations
3. **Exception Handling**: Wrap file/registry/process operations in try-catch
4. **Logging**: Use Serilog via `LoggingService` for all important events
5. **Configuration**: Use `AppConfiguration` service, not hardcoded values

### Code Style
- Use `var` when type is obvious
- Private fields start with `_`
- Async methods end with `Async`
- Use file-scoped namespaces

### UI Guidelines
- Follow existing theme in `Themes/Colors.xaml`
- Use `StaticResource` for colors and styles
- Keep XAML readable with proper indentation
- Animations should be subtle and performant

## Common Tasks

### Adding a New Scan Type
1. Add pattern definitions to signature system
2. Implement scan logic in `SafeScanner.cs`
3. Add UI controls in `ScanView.xaml`
4. Update configuration in `appsettings.json`

### Adding a New Detection Pattern
1. Add to `signatures.json` with appropriate category and threat level
2. Test with various file/process names
3. Consider false positive implications

### Adding a New View
1. Create `NewView.xaml` and `NewView.xaml.cs` in `Views/`
2. Add navigation button in `MainWindow.xaml`
3. Add navigation logic in `MainWindow.xaml.cs`
4. Follow existing view patterns for consistency

## Testing Considerations

### Manual Testing Required
- Run as Administrator (required for full functionality)
- Test on Windows 10 and Windows 11
- Test portable and framework-dependent builds
- Verify real-time monitoring doesn't impact system performance

### Areas Requiring Extra Care
- Process termination (can affect running programs)
- Registry modifications (can affect system stability)
- File deletion (ensure backup is created)
- Admin privilege escalation

## Build Commands

```bash
# Debug build
dotnet build -c Debug

# Release build
dotnet build -c Release

# Portable build (self-contained)
dotnet publish -c Release -r win-x64 --self-contained true /p:PublishSingleFile=true

# Framework-dependent build
dotnet publish -c Release -r win-x64 --self-contained false
```

## Important Notes for AI Assistants

1. **Security Focus**: This is a security tool. Be extra careful about:
   - Not introducing vulnerabilities
   - Maintaining proper access controls
   - Validating all inputs

2. **False Positives**: Detection patterns can affect legitimate software. Always consider:
   - Adding context-aware scoring
   - Providing clear user warnings
   - Allowing whitelist additions

3. **Performance**: Scanning operations can be intensive. Consider:
   - Progress reporting
   - Cancellation support
   - Memory efficiency for large scans

4. **User Experience**: Users expect security software to be:
   - Reliable and trustworthy
   - Clear about what actions it takes
   - Transparent about detected threats

5. **Legacy Code**: The `legacy/` folder contains old WinForms code. Reference only, do not modify.

## Questions to Ask Before Making Changes

1. Will this change affect scan accuracy or false positive rates?
2. Is this change thread-safe?
3. Does this require admin privileges?
4. How will this behave on different Windows versions?
5. What happens if the operation fails mid-way?
6. Is proper logging in place for debugging?

## Contact & Resources

- Repository: https://github.com/xjanova/Skidrowkiller
- Issues: https://github.com/xjanova/Skidrowkiller/issues
- Documentation: See `/docs` folder
