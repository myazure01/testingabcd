@echo off
REM ============================================================================
REM Azure Discovery Tool - Windows Launcher
REM ============================================================================
REM This script bypasses PowerShell execution policy restrictions
REM Double-click this file to run the Azure Discovery Tool
REM ============================================================================

echo.
echo ========================================================================
echo   Azure Discovery Tool - Starting...
echo ========================================================================
echo.
echo   This launcher bypasses PowerShell execution policy restrictions
echo   The tool will automatically install Python dependencies if needed
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

REM Run PowerShell script with execution policy bypass
powershell.exe -ExecutionPolicy Bypass -NoProfile -File "%~dp0run_discovery.ps1"

REM Check exit code
if %errorlevel% neq 0 (
    echo.
    echo ========================================================================
    echo   An error occurred during discovery.
    echo ========================================================================
    echo.
    echo Check the error messages above for details.
    echo.
    pause
    exit /b 1
)

echo.
echo ========================================================================
echo   Discovery completed! Check discovery_output\ folder for reports.
echo ========================================================================
echo.
pause
