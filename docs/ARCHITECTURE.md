# Architecture Overview

This document describes the technical architecture of Skidrow Killer.

## Table of Contents

- [System Overview](#system-overview)
- [Layer Architecture](#layer-architecture)
- [Core Components](#core-components)
- [Data Flow](#data-flow)
- [Threading Model](#threading-model)
- [Configuration System](#configuration-system)
- [Security Considerations](#security-considerations)

---

## System Overview

Skidrow Killer is a Windows desktop application built with WPF (Windows Presentation Foundation) on .NET 8.0. It follows a service-oriented architecture with clear separation between UI and business logic.

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        Presentation                         │
│  ┌─────────────────────────────────────────────────────┐   │
│  │                    MainWindow                        │   │
│  │  ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐      │   │
│  │  │ Scan │ │Monitor│ │Threat│ │Quaran│ │Settin│      │   │
│  │  │ View │ │ View │ │ View │ │ View │ │ View │      │   │
│  │  └──────┘ └──────┘ └──────┘ └──────┘ └──────┘      │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                      Service Layer                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │ SafeScanner │  │ Protection  │  │   Threat    │         │
│  │             │  │   Service   │  │  Analyzer   │         │
│  └─────────────┘  └─────────────┘  └─────────────┘         │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │ Quarantine  │  │   Backup    │  │  Whitelist  │         │
│  │   Service   │  │   Manager   │  │   Manager   │         │
│  └─────────────┘  └─────────────┘  └─────────────┘         │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │   Update    │  │   Logging   │  │    App      │         │
│  │   Service   │  │   Service   │  │   Config    │         │
│  └─────────────┘  └─────────────┘  └─────────────┘         │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    Infrastructure                            │
│  ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌──────────┐ │
│  │   File    │  │  Registry │  │  Process  │  │  Network │ │
│  │   System  │  │           │  │    WMI    │  │          │ │
│  └───────────┘  └───────────┘  └───────────┘  └──────────┘ │
└─────────────────────────────────────────────────────────────┘
```

---

## Layer Architecture

### Presentation Layer

**Technology:** WPF with XAML

**Components:**
- `MainWindow` - Application shell with navigation
- `Views/` - Individual screen implementations
- `Themes/` - Styling and templates

**Responsibilities:**
- User interaction
- Data display
- Navigation
- Progress reporting

### Service Layer

**Purpose:** Business logic and orchestration

**Key Services:**

| Service | Responsibility |
|---------|----------------|
| `SafeScanner` | File, registry, and process scanning |
| `ProtectionService` | Real-time monitoring |
| `ThreatAnalyzer` | Threat scoring and classification |
| `QuarantineService` | Threat isolation |
| `BackupManager` | Pre-removal backups |
| `WhitelistManager` | Safe file management |
| `UpdateService` | Signature updates |
| `LoggingService` | Centralized logging |
| `AppConfiguration` | Settings management |

### Infrastructure Layer

**Purpose:** System interaction

**Components:**
- File system access
- Registry operations
- Process enumeration (WMI)
- Network monitoring

---

## Core Components

### SafeScanner

The main scanning engine responsible for detecting threats.

```
SafeScanner
├── ScanFilesAsync()
│   ├── Enumerate drives
│   ├── Walk directory tree
│   ├── Match against signatures
│   └── Report threats
├── ScanRegistryAsync()
│   ├── Query key locations
│   ├── Enumerate values
│   ├── Pattern matching
│   └── Report threats
└── ScanProcessesAsync()
    ├── Enumerate processes (WMI)
    ├── Check process names
    ├── Enumerate loaded DLLs
    └── Detect injections
```

**Key Features:**
- Async/await for UI responsiveness
- Progress reporting via callbacks
- Cancellation token support
- Thread-safe operations

### ProtectionService

Real-time monitoring service.

```
ProtectionService
├── Start()
│   ├── Initialize monitoring timer
│   ├── Start process watcher
│   └── Start network monitor
├── Stop()
├── OnTimerTick()
│   ├── Check new processes
│   ├── Analyze network activity
│   └── Update threat level
└── Events
    ├── ThreatDetected
    ├── ThreatLevelChanged
    └── StatusChanged
```

**Threat Levels:**
- `Safe` (Green) - No threats detected
- `Warning` (Yellow) - Suspicious activity
- `Critical` (Red) - Active threat

### ThreatAnalyzer

Intelligent threat scoring system.

```
ThreatAnalyzer
├── AnalyzeFile(path)
│   ├── Check filename patterns
│   ├── Apply booster patterns
│   ├── Check safe contexts
│   └── Calculate score
├── AnalyzeProcess(info)
│   ├── Check process name
│   ├── Check loaded modules
│   └── Detect injections
└── GetThreatLevel(score)
    ├── Critical: score >= 80
    ├── High: score >= 60
    ├── Medium: score >= 40
    └── Low: score >= 20
```

### QuarantineService

Safe threat storage.

```
QuarantineService
├── QuarantineAsync(threatPath)
│   ├── Create encrypted backup
│   ├── Move to quarantine folder
│   └── Record metadata
├── RestoreAsync(quarantineId)
│   ├── Decrypt backup
│   └── Restore to original location
└── CleanupExpiredAsync()
    └── Remove items past retention
```

**Storage Location:** `%LOCALAPPDATA%\SkidrowKiller\Quarantine\`

---

## Data Flow

### Scanning Flow

```
User clicks "Start Scan"
         │
         ▼
    ┌─────────┐
    │ScanView │
    └────┬────┘
         │
         ▼
    ┌─────────────┐
    │ SafeScanner │
    └──────┬──────┘
           │
    ┌──────┴──────┐
    │             │
    ▼             ▼
┌───────┐    ┌────────┐
│ Files │    │Registry│
└───┬───┘    └───┬────┘
    │            │
    └─────┬──────┘
          │
          ▼
    ┌─────────────┐
    │ThreatAnalyzer│
    └──────┬──────┘
           │
           ▼
    ┌─────────────┐
    │ ThreatInfo  │
    └──────┬──────┘
           │
           ▼
    Report to UI
```

### Real-time Monitoring Flow

```
    ┌─────────────────┐
    │ProtectionService│
    └────────┬────────┘
             │
     ┌───────┴───────┐
     │  Timer Tick   │
     └───────┬───────┘
             │
    ┌────────┴────────┐
    │                 │
    ▼                 ▼
┌─────────┐    ┌──────────┐
│Processes│    │ Network  │
└────┬────┘    └────┬─────┘
     │              │
     └──────┬───────┘
            │
            ▼
    ┌─────────────┐
    │ThreatAnalyzer│
    └──────┬──────┘
            │
    ┌───────┴───────┐
    │               │
    ▼               ▼
No Threat      Threat Found
    │               │
    ▼               ▼
Update UI     Fire Event
(Green)       → Notify UI
              → Log
              → Optional action
```

---

## Threading Model

### UI Thread
- All WPF controls
- Data binding updates
- Navigation

### Background Threads
- Scanning operations
- File I/O
- Network operations

### Thread Safety Patterns

```csharp
// Dispatcher for UI updates
Application.Current.Dispatcher.Invoke(() =>
{
    ThreatList.Add(threat);
    UpdateProgress(current, total);
});

// Async/await for non-blocking operations
public async Task ScanAsync(CancellationToken token)
{
    await Task.Run(() =>
    {
        // Scanning logic
    }, token);
}

// Lock for shared state
private readonly object _lock = new();
lock (_lock)
{
    _threats.Add(threat);
}
```

### Cancellation

All long-running operations support cancellation:

```csharp
private CancellationTokenSource _cts;

public void StartScan()
{
    _cts = new CancellationTokenSource();
    _ = ScanAsync(_cts.Token);
}

public void StopScan()
{
    _cts?.Cancel();
}
```

---

## Configuration System

### Configuration Files

| File | Purpose | Environment |
|------|---------|-------------|
| `appsettings.json` | Default settings | All |
| `appsettings.Production.json` | Production overrides | Production |
| `appsettings.Development.json` | Dev overrides | Development |

### Configuration Structure

```json
{
  "Application": {
    "Name": "Skidrow Killer",
    "Version": "3.1.0"
  },
  "Scanning": {
    "MaxConcurrentScans": 1,
    "ScanTimeoutMinutes": 60,
    "EnableFileScan": true,
    "EnableRegistryScan": true,
    "EnableProcessScan": true
  },
  "Protection": {
    "Enabled": true,
    "MonitorIntervalSeconds": 3
  },
  "ThreatAnalysis": {
    "MinimumScoreToReport": 20,
    "CriticalScoreThreshold": 80
  },
  "Logging": {
    "MinimumLevel": "Information",
    "EnableFileLogging": true
  }
}
```

### Loading Configuration

```csharp
var config = new ConfigurationBuilder()
    .SetBasePath(Directory.GetCurrentDirectory())
    .AddJsonFile("appsettings.json", optional: false)
    .AddJsonFile($"appsettings.{environment}.json", optional: true)
    .Build();
```

---

## Security Considerations

### Privilege Requirements

| Operation | Required Privilege |
|-----------|-------------------|
| File scanning | Read (Admin for system files) |
| File deletion | Write + Admin |
| Registry scanning | Read |
| Registry modification | Admin |
| Process scanning | Admin |
| Process termination | Admin |

### Secure Coding Practices

1. **Input Validation**
   - Validate all file paths
   - Sanitize registry key names
   - Verify process IDs

2. **Exception Handling**
   - Catch specific exceptions
   - Log errors without exposing internals
   - Graceful degradation

3. **Least Privilege**
   - Request minimum required permissions
   - Drop privileges when not needed

4. **Signature Validation**
   - Verify downloaded signatures
   - Use HTTPS for updates
   - Checksum validation

### Data Protection

- Quarantined files are stored securely
- Logs don't contain sensitive paths (optional redaction)
- Configuration files support encryption (future)

---

## Future Architecture Considerations

### Planned Improvements

1. **Plugin System**
   - Load custom scanners
   - Third-party integrations

2. **Cloud Integration**
   - Cloud-based signature updates
   - Threat intelligence sharing

3. **REST API**
   - Remote management
   - Integration with SIEM

4. **Cross-Platform**
   - .NET MAUI for cross-platform UI
   - Core scanning as library

### Performance Optimizations

1. **Parallel Scanning**
   - Multi-threaded file scanning
   - Concurrent registry queries

2. **Caching**
   - Signature caching
   - File hash caching

3. **Incremental Scanning**
   - Track file changes
   - Skip unchanged files
