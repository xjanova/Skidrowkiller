@echo off
setlocal enabledelayedexpansion

echo ========================================
echo  Skidrow Killer - Production Build
echo ========================================
echo.
echo Version: 2.1.0
echo Build Date: %date% %time%
echo.

REM Set environment to Production
set SKIDROWKILLER_ENVIRONMENT=Production

REM Check for .NET SDK
dotnet --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: .NET SDK is not installed or not in PATH
    pause
    exit /b 1
)

echo .NET SDK Version:
dotnet --version
echo.

REM Clean previous builds
echo [1/6] Cleaning previous builds...
if exist "bin\Publish" (
    rmdir /s /q "bin\Publish"
)
if exist "bin\Release" (
    rmdir /s /q "bin\Release"
)
if exist "obj\Release" (
    rmdir /s /q "obj\Release"
)

REM Restore packages
echo.
echo [2/6] Restoring NuGet packages...
dotnet restore
if errorlevel 1 (
    echo ERROR: Package restore failed!
    pause
    exit /b 1
)

REM Build Release
echo.
echo [3/6] Building Release configuration...
dotnet build -c Release --no-restore
if errorlevel 1 (
    echo ERROR: Build failed!
    pause
    exit /b 1
)

REM Publish x64 Portable (Self-contained)
echo.
echo [4/6] Publishing x64 Portable (self-contained)...
dotnet publish -c Release -r win-x64 --self-contained true ^
    /p:PublishSingleFile=true ^
    /p:PublishReadyToRun=true ^
    /p:EnableCompressionInSingleFile=true ^
    /p:IncludeNativeLibrariesForSelfExtract=true ^
    /p:DebugType=none ^
    /p:DebugSymbols=false ^
    -o "bin\Publish\win-x64-portable"
if errorlevel 1 (
    echo ERROR: x64 Portable publish failed!
    pause
    exit /b 1
)

REM Publish x64 Framework-dependent
echo.
echo [5/6] Publishing x64 Framework-dependent...
dotnet publish -c Release -r win-x64 --self-contained false ^
    /p:PublishReadyToRun=true ^
    /p:DebugType=none ^
    /p:DebugSymbols=false ^
    -o "bin\Publish\win-x64-framework"
if errorlevel 1 (
    echo ERROR: x64 Framework publish failed!
    pause
    exit /b 1
)

REM Copy additional files
echo.
echo [6/6] Copying additional files...
copy /Y "appsettings.json" "bin\Publish\win-x64-portable\"
copy /Y "appsettings.Production.json" "bin\Publish\win-x64-portable\"
copy /Y "signatures.json" "bin\Publish\win-x64-portable\" 2>nul
copy /Y "whitelist.json" "bin\Publish\win-x64-portable\" 2>nul

copy /Y "appsettings.json" "bin\Publish\win-x64-framework\"
copy /Y "appsettings.Production.json" "bin\Publish\win-x64-framework\"
copy /Y "signatures.json" "bin\Publish\win-x64-framework\" 2>nul
copy /Y "whitelist.json" "bin\Publish\win-x64-framework\" 2>nul

REM Create version info file
echo.
echo Creating version info...
(
echo Skidrow Killer v2.1.0
echo ======================
echo Build Date: %date% %time%
echo Build Type: Production
echo.
echo x64-portable: Self-contained single executable
echo x64-framework: Requires .NET 8.0 Runtime
echo.
echo Files:
echo - SkidrowKiller.exe: Main application
echo - appsettings.json: Configuration
echo - appsettings.Production.json: Production overrides
echo - signatures.json: Threat signatures database
echo - whitelist.json: User whitelist
) > "bin\Publish\BUILD_INFO.txt"

REM Calculate file sizes
echo.
echo ========================================
echo  Build Complete!
echo ========================================
echo.
echo Output directories:
echo   x64 Portable:  bin\Publish\win-x64-portable\
echo   x64 Framework: bin\Publish\win-x64-framework\
echo.

REM Show file sizes
for %%F in ("bin\Publish\win-x64-portable\SkidrowKiller.exe") do (
    set /a SIZE=%%~zF / 1048576
    echo   x64 Portable Size: !SIZE! MB
)
for %%F in ("bin\Publish\win-x64-framework\SkidrowKiller.dll") do (
    set /a SIZE=%%~zF / 1024
    echo   x64 Framework Size: !SIZE! KB
)

echo.
echo Build artifacts ready for distribution.
echo.
pause
