@echo off
REM ============================================================================
REM Azure Discovery Tool - Windows Launcher
REM ============================================================================
REM This script bypasses PowerShell execution policy restrictions
REM Double-click this file to run the Azure Discovery Tool
REM ============================================================================

echo.
echo ================================================
echo   Azure Discovery Tool - Starting...
echo ================================================
echo.

REM Run PowerShell script with execution policy bypass
powershell.exe -ExecutionPolicy Bypass -NoProfile -File "%~dp0run_discovery.ps1"

REM Keep window open if there was an error
if errorlevel 1 (
    echo.
    echo ================================================
    echo   An error occurred. Press any key to exit...
    echo ================================================
    pause >nul
)
