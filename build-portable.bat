@echo off
echo ========================================
echo  Building Skidrow Killer Portable
echo ========================================
echo.

REM Clean previous builds
if exist "bin\Portable" (
    echo Cleaning previous portable build...
    rmdir /s /q "bin\Portable"
)

REM Build the project
echo Building Release version...
dotnet publish -c Release -r win-x64 --self-contained true /p:PublishSingleFile=true /p:IncludeNativeLibrariesForSelfExtract=true

if errorlevel 1 (
    echo Build failed!
    pause
    exit /b 1
)

REM Create portable directory
echo Creating portable package...
mkdir "bin\Portable"
mkdir "bin\Portable\SkidrowKiller"

REM Copy files
xcopy /Y "bin\Release\net8.0-windows\win-x64\publish\*.*" "bin\Portable\SkidrowKiller\"

REM Create README
echo Creating README.txt...
(
echo ========================================
echo   SKIDROW KILLER - PORTABLE VERSION
echo ========================================
echo.
echo This is a portable version of Skidrow Killer.
echo No installation required!
echo.
echo REQUIREMENTS:
echo - Windows 10/11
echo - Administrator privileges
echo.
echo HOW TO USE:
echo 1. Extract all files to any folder
echo 2. Right-click on SkidrowKiller.exe
echo 3. Select "Run as administrator"
echo.
echo FEATURES:
echo - File/Registry/Process scanning
echo - Real-time monitoring
echo - Network activity detection
echo - Auto-logging to Documents\SkidrowKiller\Logs\
echo.
echo SIGNATURES:
echo - Custom signature database included
echo - Edit signatures.json to add custom patterns
echo.
echo For more info, see README.md
echo.
echo ========================================
) > "bin\Portable\SkidrowKiller\README.txt"

echo.
echo ========================================
echo  Build Complete!
echo ========================================
echo Portable version is in: bin\Portable\SkidrowKiller\
echo.
pause
