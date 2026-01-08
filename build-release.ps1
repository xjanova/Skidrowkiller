#Requires -Version 5.1
<#
.SYNOPSIS
    Production build script for Skidrow Killer

.DESCRIPTION
    This script builds production-ready releases of Skidrow Killer
    for various configurations and architectures.

.PARAMETER Configuration
    Build configuration (Release or Debug). Default: Release

.PARAMETER SignCode
    Whether to sign the executables with code signing certificate

.PARAMETER CertificatePath
    Path to the code signing certificate (.pfx)

.PARAMETER CertificatePassword
    Password for the code signing certificate

.PARAMETER CreateZip
    Whether to create ZIP archives of the builds

.EXAMPLE
    .\build-release.ps1

.EXAMPLE
    .\build-release.ps1 -SignCode -CertificatePath "cert.pfx" -CertificatePassword "password"
#>

param(
    [ValidateSet("Release", "Debug")]
    [string]$Configuration = "Release",

    [switch]$SignCode,

    [string]$CertificatePath,

    [SecureString]$CertificatePassword,

    [switch]$CreateZip
)

$ErrorActionPreference = "Stop"

# Configuration
$ProjectName = "SkidrowKiller"
$Version = "2.1.0"
$OutputDir = "bin\Publish"
$ProjectFile = "SkidrowKiller.csproj"

# Color output functions
function Write-Header {
    param([string]$Message)
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host " $Message" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan
}

function Write-Step {
    param([string]$Step, [string]$Message)
    Write-Host "[$Step] " -ForegroundColor Yellow -NoNewline
    Write-Host $Message -ForegroundColor White
}

function Write-Success {
    param([string]$Message)
    Write-Host "[OK] " -ForegroundColor Green -NoNewline
    Write-Host $Message -ForegroundColor White
}

function Write-Error {
    param([string]$Message)
    Write-Host "[ERROR] " -ForegroundColor Red -NoNewline
    Write-Host $Message -ForegroundColor White
}

# Build targets
$BuildTargets = @(
    @{
        Name = "win-x64-portable"
        RuntimeId = "win-x64"
        SelfContained = $true
        SingleFile = $true
        Description = "Windows x64 Portable (Self-contained)"
    },
    @{
        Name = "win-x64-framework"
        RuntimeId = "win-x64"
        SelfContained = $false
        SingleFile = $false
        Description = "Windows x64 Framework-dependent"
    },
    @{
        Name = "win-arm64-portable"
        RuntimeId = "win-arm64"
        SelfContained = $true
        SingleFile = $true
        Description = "Windows ARM64 Portable (Self-contained)"
    }
)

# Main build process
Write-Header "$ProjectName Production Build v$Version"

Write-Host "Build Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host "Configuration: $Configuration"
Write-Host "Create ZIP: $CreateZip"
Write-Host "Sign Code: $SignCode"
Write-Host ""

# Check prerequisites
Write-Step "1/7" "Checking prerequisites..."

# Check .NET SDK
$dotnetVersion = dotnet --version 2>$null
if (-not $dotnetVersion) {
    Write-Error ".NET SDK is not installed or not in PATH"
    exit 1
}
Write-Host "  .NET SDK: $dotnetVersion"

# Check signtool if signing is requested
if ($SignCode) {
    $signtool = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if (-not $signtool) {
        Write-Error "signtool.exe not found. Install Windows SDK for code signing."
        exit 1
    }

    if (-not $CertificatePath -or -not (Test-Path $CertificatePath)) {
        Write-Error "Certificate path not specified or file not found"
        exit 1
    }
}

Write-Success "Prerequisites OK"

# Clean previous builds
Write-Step "2/7" "Cleaning previous builds..."
$cleanDirs = @($OutputDir, "bin\$Configuration", "obj\$Configuration")
foreach ($dir in $cleanDirs) {
    if (Test-Path $dir) {
        Remove-Item -Path $dir -Recurse -Force
    }
}
Write-Success "Clean complete"

# Restore packages
Write-Step "3/7" "Restoring NuGet packages..."
dotnet restore $ProjectFile
if ($LASTEXITCODE -ne 0) {
    Write-Error "Package restore failed"
    exit 1
}
Write-Success "Packages restored"

# Build Release
Write-Step "4/7" "Building $Configuration configuration..."
dotnet build $ProjectFile -c $Configuration --no-restore
if ($LASTEXITCODE -ne 0) {
    Write-Error "Build failed"
    exit 1
}
Write-Success "Build complete"

# Publish all targets
Write-Step "5/7" "Publishing build targets..."
$env:SKIDROWKILLER_ENVIRONMENT = "Production"

foreach ($target in $BuildTargets) {
    Write-Host "`n  Building: $($target.Description)..." -ForegroundColor Gray

    $publishArgs = @(
        "publish", $ProjectFile,
        "-c", $Configuration,
        "-r", $target.RuntimeId,
        "--self-contained", $target.SelfContained.ToString().ToLower(),
        "-o", "$OutputDir\$($target.Name)",
        "/p:PublishReadyToRun=true",
        "/p:DebugType=none",
        "/p:DebugSymbols=false"
    )

    if ($target.SingleFile) {
        $publishArgs += @(
            "/p:PublishSingleFile=true",
            "/p:EnableCompressionInSingleFile=true",
            "/p:IncludeNativeLibrariesForSelfExtract=true"
        )
    }

    & dotnet @publishArgs

    if ($LASTEXITCODE -ne 0) {
        Write-Error "Publish failed for $($target.Name)"
        exit 1
    }

    # Copy config files
    Copy-Item "appsettings.json" "$OutputDir\$($target.Name)\" -Force
    Copy-Item "appsettings.Production.json" "$OutputDir\$($target.Name)\" -Force -ErrorAction SilentlyContinue
    if (Test-Path "signatures.json") {
        Copy-Item "signatures.json" "$OutputDir\$($target.Name)\" -Force
    }
    if (Test-Path "whitelist.json") {
        Copy-Item "whitelist.json" "$OutputDir\$($target.Name)\" -Force
    }

    Write-Success "$($target.Name) published"
}

# Code signing
if ($SignCode) {
    Write-Step "6/7" "Signing executables..."

    foreach ($target in $BuildTargets) {
        $exePath = "$OutputDir\$($target.Name)\$ProjectName.exe"
        if (Test-Path $exePath) {
            Write-Host "  Signing: $exePath" -ForegroundColor Gray

            $signArgs = @(
                "sign",
                "/f", $CertificatePath,
                "/fd", "SHA256",
                "/tr", "http://timestamp.digicert.com",
                "/td", "SHA256",
                $exePath
            )

            if ($CertificatePassword) {
                $plainPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
                    [Runtime.InteropServices.Marshal]::SecureStringToBSTR($CertificatePassword)
                )
                $signArgs += @("/p", $plainPassword)
            }

            & signtool @signArgs

            if ($LASTEXITCODE -ne 0) {
                Write-Error "Signing failed for $($target.Name)"
                exit 1
            }
        }
    }

    Write-Success "Code signing complete"
} else {
    Write-Step "6/7" "Skipping code signing (not requested)"
}

# Create ZIP archives
if ($CreateZip) {
    Write-Step "7/7" "Creating ZIP archives..."

    foreach ($target in $BuildTargets) {
        $sourcePath = "$OutputDir\$($target.Name)"
        $zipPath = "$OutputDir\$ProjectName-$Version-$($target.Name).zip"

        if (Test-Path $sourcePath) {
            Write-Host "  Creating: $zipPath" -ForegroundColor Gray
            Compress-Archive -Path "$sourcePath\*" -DestinationPath $zipPath -Force

            $zipSize = (Get-Item $zipPath).Length / 1MB
            Write-Host "    Size: $([math]::Round($zipSize, 2)) MB" -ForegroundColor Gray
        }
    }

    Write-Success "ZIP archives created"
} else {
    Write-Step "7/7" "Skipping ZIP creation (not requested)"
}

# Create build info
$buildInfo = @"
$ProjectName v$Version
========================
Build Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Build Type: Production
Configuration: $Configuration
.NET SDK: $dotnetVersion

Build Targets:
"@

foreach ($target in $BuildTargets) {
    $exePath = "$OutputDir\$($target.Name)\$ProjectName.exe"
    $dllPath = "$OutputDir\$($target.Name)\$ProjectName.dll"

    $size = "N/A"
    if (Test-Path $exePath) {
        $size = "$([math]::Round((Get-Item $exePath).Length / 1MB, 2)) MB"
    } elseif (Test-Path $dllPath) {
        $size = "$([math]::Round((Get-Item $dllPath).Length / 1KB, 2)) KB"
    }

    $buildInfo += "`n- $($target.Name): $($target.Description) [$size]"
}

$buildInfo | Out-File "$OutputDir\BUILD_INFO.txt" -Encoding UTF8

# Summary
Write-Header "Build Complete!"

Write-Host "Output Directory: $OutputDir`n" -ForegroundColor White

foreach ($target in $BuildTargets) {
    $exePath = "$OutputDir\$($target.Name)\$ProjectName.exe"
    $dllPath = "$OutputDir\$($target.Name)\$ProjectName.dll"

    if (Test-Path $exePath) {
        $size = [math]::Round((Get-Item $exePath).Length / 1MB, 2)
        Write-Host "  $($target.Name): $size MB" -ForegroundColor Green
    } elseif (Test-Path $dllPath) {
        $size = [math]::Round((Get-Item $dllPath).Length / 1KB, 2)
        Write-Host "  $($target.Name): $size KB" -ForegroundColor Green
    }
}

Write-Host "`nBuild artifacts ready for distribution." -ForegroundColor Cyan
