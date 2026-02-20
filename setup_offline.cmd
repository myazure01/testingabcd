@echo off
REM ============================================================================
REM Azure Discovery Tool - Offline Setup
REM ============================================================================
REM Run this script on an offline/new system after copying the folder
REM This installs all packages from the offline_packages directory
REM ============================================================================

echo.
echo ========================================================================
echo   Azure Discovery Tool - Offline Setup
echo ========================================================================
echo.

REM Check if offline_packages directory exists
if not exist "offline_packages" (
    echo [ERROR] offline_packages directory not found!
    echo.
    echo Did you run download_packages_offline.cmd first?
    echo.
    echo To prepare offline packages:
    echo 1. On a system with internet, run: download_packages_offline.cmd
    echo 2. Copy this entire folder to your offline system
    echo 3. Run this script: setup_offline.cmd
    echo.
    pause
    exit /b 1
)

echo [OK] Found offline_packages directory
echo.

REM Check package count
echo Checking downloaded packages...
dir /b offline_packages\*.whl 2>nul | find /c ".whl" > temp_count.txt
set /p PKG_COUNT=<temp_count.txt
del temp_count.txt

echo [OK] Found %PKG_COUNT% packages ready for installation
echo.

REM Determine which Python to use
set PYTHON_CMD=

if exist ".\tool\python\python.exe" (
    set PYTHON_CMD=.\tool\python\python.exe
    echo [OK] Using bundled Python
) else (
    where python >nul 2>nul
    if %errorlevel% equ 0 (
        set PYTHON_CMD=python
        echo [OK] Using system Python
    ) else (
        echo [ERROR] Python not found!
        echo.
        echo Please ensure:
        echo - Bundled Python exists in: tool\python\python.exe
        echo   OR
        echo - System Python is installed
        echo.
        pause
        exit /b 1
    )
)

%PYTHON_CMD% --version
echo.

REM Install packages from offline directory
echo ========================================================================
echo   Installing packages from offline_packages...
echo ========================================================================
echo.
echo This may take several minutes...
echo.

REM Upgrade pip first (offline)
%PYTHON_CMD% -m pip install --no-index --find-links=offline_packages --upgrade pip setuptools wheel

REM Install all packages from offline directory
%PYTHON_CMD% -m pip install --no-index --find-links=offline_packages -r requirements.txt

if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Package installation failed!
    echo.
    echo Try manually:
    echo %PYTHON_CMD% -m pip install --no-index --find-links=offline_packages -r requirements.txt
    echo.
    pause
    exit /b 1
)

echo.
echo ========================================================================
echo   Verifying Installation...
echo ========================================================================
echo.

REM Verify critical modules
%PYTHON_CMD% verify_python.py

if %errorlevel% neq 0 (
    echo.
    echo [WARNING] Some packages may not be installed correctly
    echo Run verification manually: %PYTHON_CMD% verify_python.py
    echo.
)

echo.
echo ========================================================================
echo   SUCCESS! Offline Setup Complete
echo ========================================================================
echo.
echo All packages installed successfully!
echo.
echo NEXT STEPS:
echo 1. Ensure Azure CLI is installed
echo    Download from: https://aka.ms/installazurecliwindows
echo.
echo 2. Login to Azure:
echo    az login
echo.
echo 3. Run discovery:
echo    run.cmd
echo.
echo The tool is now ready to use offline!
echo.
pause
