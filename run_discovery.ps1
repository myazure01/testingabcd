#===================================================================================
# AZURE DISCOVERY TOOL - SIMPLE RUNNER
#===================================================================================
# This script runs the Azure Discovery Tool to scan your Azure environment
# 
# PREREQUISITES:
#   1. Azure CLI installed and logged in (run: az login)
#   2. Python 3.11 installed (bundled version included in tool\python\)
#
# USAGE OPTIONS:
#   Option 1 (Recommended): Double-click run.cmd
#   Option 2: powershell -ExecutionPolicy Bypass -File run_discovery.ps1
#   Option 3: Right-click run_discovery.ps1 -> "Run with PowerShell"
#
# NOTE: This script is not digitally signed. Use run.cmd to bypass execution policy.
#
# OUTPUT:
#   - HTML Reports (interactive web report)
#   - Excel Report (detailed spreadsheet)
#   - JSON Data (raw discovery data)
#
# All reports will be saved in: discovery_output\
#===================================================================================

# Check execution policy
$executionPolicy = Get-ExecutionPolicy -Scope CurrentUser
if ($executionPolicy -eq "Restricted" -or $executionPolicy -eq "AllSigned") {
    Write-Host ""
    Write-Host "========================================================================" -ForegroundColor Red
    Write-Host "  ⚠️  EXECUTION POLICY ERROR - SCRIPT CANNOT RUN" -ForegroundColor Yellow
    Write-Host "========================================================================" -ForegroundColor Red
    Write-Host ""
    Write-Host "Windows is blocking this PowerShell script (not digitally signed)." -ForegroundColor White
    Write-Host ""
    Write-Host "✅ SOLUTION: Use this command instead:" -ForegroundColor Green
    Write-Host ""
    Write-Host "   .\run.cmd" -ForegroundColor Cyan -BackgroundColor Black
    Write-Host ""
    Write-Host "OR from Command Prompt / File Explorer:" -ForegroundColor Yellow
    Write-Host "   Double-click: run.cmd" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "OR run with bypass flag:" -ForegroundColor Yellow
    Write-Host "   powershell -ExecutionPolicy Bypass -File .\run_discovery.ps1" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "========================================================================" -ForegroundColor Red
    Write-Host ""
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "  Azure Discovery Tool - Simple Runner  " -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

# Find Python
$PYTHON_CMD = $null
$BUNDLED_PYTHON = ".\tool\python\python.exe"

if (Test-Path $BUNDLED_PYTHON) {
    $PYTHON_CMD = $BUNDLED_PYTHON
    Write-Host "[OK] Using bundled Python" -ForegroundColor Green
} elseif (Get-Command python -ErrorAction SilentlyContinue) {
    $PYTHON_CMD = "python"
    Write-Host "[OK] Using system Python" -ForegroundColor Green
} else {
    Write-Host "[ERROR] Python not found!" -ForegroundColor Red
    Write-Host "Please install Python 3.11 or use the bundled version" -ForegroundColor Yellow
    exit 1
}

# Check if azure_discovery.py exists
if (-not (Test-Path ".\azure_discovery.py")) {
    Write-Host "[ERROR] azure_discovery.py not found in current directory!" -ForegroundColor Red
    exit 1
}

# Install/Update Python requirements
Write-Host ""
Write-Host "Checking Python dependencies..." -ForegroundColor Cyan

# Check if Azure SDK is installed by trying to import azure.identity
$azureInstalled = & $PYTHON_CMD -c "import azure.identity" 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "[INFO] Installing Python dependencies (this may take a few minutes)..." -ForegroundColor Yellow
    Write-Host "       Installing from requirements.txt..." -ForegroundColor Gray
    
    # Install requirements
    & $PYTHON_CMD -m pip install --upgrade pip --quiet
    & $PYTHON_CMD -m pip install -r requirements.txt --quiet
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "[OK] Python dependencies installed successfully" -ForegroundColor Green
    } else {
        Write-Host "[ERROR] Failed to install Python dependencies!" -ForegroundColor Red
        Write-Host "Try running manually: $PYTHON_CMD -m pip install -r requirements.txt" -ForegroundColor Yellow
        exit 1
    }
} else {
    Write-Host "[OK] Python dependencies already installed" -ForegroundColor Green
}

# Check Azure CLI login
Write-Host ""
Write-Host "Checking Azure authentication..." -ForegroundColor Cyan
$azAccount = az account show 2>$null
if (-not $azAccount) {
    Write-Host "[WARNING] You are not logged in to Azure" -ForegroundColor Yellow
    Write-Host "Running: az login" -ForegroundColor Cyan
    Write-Host ""
    az login
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[ERROR] Azure login failed!" -ForegroundColor Red
        exit 1
    }
} else {
    $accountInfo = $azAccount | ConvertFrom-Json
    Write-Host "[OK] Logged in as: $($accountInfo.user.name)" -ForegroundColor Green
    Write-Host "[OK] Subscription: $($accountInfo.name)" -ForegroundColor Green
}

# Run the discovery
Write-Host ""
Write-Host "Starting Azure Discovery..." -ForegroundColor Cyan
Write-Host "This may take several minutes depending on resources..." -ForegroundColor Gray
Write-Host ""

& $PYTHON_CMD .\azure_discovery.py

if ($LASTEXITCODE -eq 0) {
    Write-Host ""
    Write-Host "==========================================" -ForegroundColor Green
    Write-Host "  Discovery Completed Successfully!     " -ForegroundColor Green
    Write-Host "==========================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Reports saved to: discovery_output\" -ForegroundColor Cyan
    Write-Host ""
    
    # List generated files
    if (Test-Path "discovery_output") {
        Write-Host "Generated files:" -ForegroundColor Yellow
        Get-ChildItem "discovery_output\*.html", "discovery_output\*.xlsx", "discovery_output\*.json" -ErrorAction SilentlyContinue | 
            Where-Object { $_.Name -notlike "sample*" } |
            Sort-Object LastWriteTime -Descending |
            Select-Object -First 10 |
            ForEach-Object {
                Write-Host "  - $($_.Name)" -ForegroundColor White
            }
    }
    
    Write-Host ""
    Write-Host "Open the HTML report in your browser to view results!" -ForegroundColor Green
} else {
    Write-Host ""
    Write-Host "==========================================" -ForegroundColor Red
    Write-Host "  Discovery Failed!                     " -ForegroundColor Red
    Write-Host "==========================================" -ForegroundColor Red
    Write-Host ""
    Write-Host "Check the error messages above for details" -ForegroundColor Yellow
    exit 1
}
