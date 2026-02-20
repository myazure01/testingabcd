@echo off
REM ============================================================================
REM Azure Discovery Tool - System Python Fallback
REM ============================================================================
REM Use this if bundled Python has issues (e.g., missing socket module)
REM This script uses your system Python installation instead
REM ============================================================================

echo.
echo ========================================================================
echo   Azure Discovery Tool - Using System Python
echo ========================================================================
echo.

REM Check if Python is available
where python >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Python not found in system PATH!
    echo.
    echo Please install Python 3.11+ from:
    echo https://www.python.org/downloads/
    echo.
    echo Make sure to check "Add Python to PATH" during installation.
    echo.
    pause
    exit /b 1
)

echo [OK] Found system Python
python --version
echo.

REM Check if Azure CLI is available
where az >nul 2>nul
if %errorlevel% neq 0 (
    echo [WARNING] Azure CLI not found!
    echo.
    echo Please install Azure CLI from:
    echo https://aka.ms/installazurecliwindows
    echo.
    echo Then run: az login
    echo.
    pause
    exit /b 1
)

echo [OK] Azure CLI found
echo.

REM Verify socket module
echo Verifying Python installation...
python -c "import socket" 2>nul
if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Python socket module not found!
    echo Your Python installation may be corrupted.
    echo.
    echo Try reinstalling Python from: https://www.python.org/downloads/
    echo.
    pause
    exit /b 1
)

echo [OK] Python socket module verified
echo.

REM Check for required packages
echo Checking Azure SDK packages...
python -c "import azure.identity" 2>nul
if %errorlevel% neq 0 (
    echo.
    echo [INFO] Installing required packages...
    echo This may take a few minutes...
    echo.
    python -m pip install --upgrade pip
    python -m pip install -r requirements.txt
    
    if %errorlevel% neq 0 (
        echo.
        echo [ERROR] Failed to install packages!
        echo.
        echo Try manually:
        echo   python -m pip install -r requirements.txt
        echo.
        pause
        exit /b 1
    )
    echo.
    echo [OK] Packages installed successfully
) else (
    echo [OK] Azure SDK already installed
)

echo.
echo ========================================================================
echo   Starting Azure Discovery...
echo ========================================================================
echo.

REM Run the discovery script
python azure_discovery.py

REM Check result
if %errorlevel% neq 0 (
    echo.
    echo ========================================================================
    echo   Discovery failed!
    echo ========================================================================
    echo.
    echo Check the error messages above for details.
    echo.
    pause
    exit /b 1
)

echo.
echo ========================================================================
echo   Discovery completed successfully!
echo ========================================================================
echo.
echo Reports saved to: discovery_output\
echo.
pause
