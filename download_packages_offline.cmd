@echo off
REM ============================================================================
REM Azure Discovery Tool - Offline Package Downloader
REM ============================================================================
REM Run this script on a system with internet to download all packages
REM Then copy the entire folder to offline systems
REM ============================================================================

echo.
echo ========================================================================
echo   Downloading All Packages for Offline Installation
echo ========================================================================
echo.

REM Create packages directory
if not exist "offline_packages" mkdir offline_packages

REM Check if Python is available
where python >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Python not found!
    echo Please install Python or use bundled Python:
    echo   .\tool\python\python.exe
    pause
    exit /b 1
)

echo [INFO] Using Python to download packages...
python --version
echo.

REM Upgrade pip first
echo [1/3] Upgrading pip...
python -m pip install --upgrade pip

REM Download all packages from requirements.txt
echo.
echo [2/3] Downloading packages from requirements.txt...
echo This will download packages to: offline_packages\
echo.

python -m pip download -r requirements.txt -d offline_packages --no-cache-dir

if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Failed to download packages!
    pause
    exit /b 1
)

REM Download pip and setuptools for offline installation
echo.
echo [3/3] Downloading pip and setuptools...
python -m pip download pip setuptools wheel -d offline_packages --no-cache-dir

echo.
echo ========================================================================
echo   SUCCESS! All packages downloaded
echo ========================================================================
echo.
echo Location: offline_packages\
echo.
echo Package count:
dir /b offline_packages\*.whl | find /c ".whl"
echo.
echo NEXT STEPS:
echo 1. Copy this entire folder to your offline system
echo 2. Run: setup_offline.cmd
echo.
echo The tool will work without internet connection!
echo.
pause
