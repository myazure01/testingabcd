# Azure Discovery Tool

Comprehensive Azure resource discovery tool for tenant-to-tenant migration planning.

**✨ Fully Portable - Works Offline!**

This tool includes bundled Python and supports offline package installation. Perfect for air-gapped or restricted environments.

## 🚀 Quick Start

### Option 1: Automated (Recommended)
```bash
# Double-click or run:
run.cmd
```

### Option 2: Offline/New System Deployment

**For systems without internet or new deployments:**

```bash
# On internet-connected system (one-time):
download_packages_offline.cmd

# On target/offline system:
setup_offline.cmd

# Then run:
run.cmd
```

See [OFFLINE_DEPLOYMENT.txt](OFFLINE_DEPLOYMENT.txt) for detailed guide.

### Option 3: Manual Python Execution

#### Using Bundled Python (No Installation Required)
```bash
# 1. Install dependencies
.\tool\python\python.exe -m pip install -r requirements.txt

# 2. Login to Azure
az login

# 3. Run the discovery script
.\tool\python\python.exe azure_discovery.py
```

#### Using System Python
```bash
# 1. Install dependencies
python -m pip install -r requirements.txt

# 2. Login to Azure
az login

# 3. Run the discovery script
python azure_discovery.py
```

## 📦 Package Installation

### Install All Required Packages

**With Bundled Python:**
```bash
.\tool\python\python.exe -m pip install --upgrade pip
.\tool\python\python.exe -m pip install -r requirements.txt
```

**With System Python:**
```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

### Install Individual Packages
```bash
# Core Azure SDK
.\tool\python\python.exe -m pip install azure-identity azure-mgmt-resource

# All Azure Management Libraries
.\tool\python\python.exe -m pip install azure-mgmt-compute azure-mgmt-network azure-mgmt-storage

# Additional Tools
.\tool\python\python.exe -m pip install openpyxl GitPython PyYAML requests
```

## � Offline/Air-Gapped Deployment

**Deploy to systems without internet access:**

### Step 1: Prepare Packages (On Internet-Connected System)

```bash
# Download all packages for offline installation
download_packages_offline.cmd
```

This creates `offline_packages\` folder with all dependencies (~200-300 MB).

### Step 2: Transfer to Target System

Copy entire folder to target system via:
- USB drive
- Network share
- ZIP file transfer

### Step 3: Setup on Target System

```bash
# Install all packages from offline directory
setup_offline.cmd
```

### Step 4: Run Discovery

```bash
# Works completely offline!
run.cmd
```

**Benefits:**
- ✅ No internet required on target system
- ✅ All dependencies bundled
- ✅ Reproducible across systems
- ✅ Perfect for air-gapped environments
- ✅ Complete Python 3.11 included

**Complete Guide:** See [OFFLINE_DEPLOYMENT.txt](OFFLINE_DEPLOYMENT.txt)

## �📋 Prerequisites

1. **Azure CLI** (Required)
   - Download: https://aka.ms/installazurecliwindows
   - Verify: `az --version`
   - Login: `az login`

2. **Python 3.11** (Optional - Bundled in `tool\python\`)
   - Bundled version: `.\tool\python\python.exe --version`
   - Or install from: https://www.python.org/downloads/

## 🔧 Configuration

**Before running, verify your Python installation:**
```bash
# Using bundled Python
.\tool\python\python.exe verify_python.py

# Using system Python
python verify_python.py
```

This will check:
- Python version (3.8+ required)
- Standard library modules (socket, ssl, etc.)
- Azure SDK packages
- Optional packages

Edit `config.json` to customize:

```json
{
  "auth_method": "default",
  "subscription_names": [],
  "subscription_ids": [],
  "scan_code": true,
  "azure_devops": {
    "organization": "YOUR_ORG",
    "pat_token": "YOUR_TOKEN",
    "projects": [...]
  }
}
```

## 📊 Output

Reports are saved in `discovery_output\`:

- **HTML Report**: Interactive web-based report with tabs
- **Excel Report**: Detailed spreadsheet inventory
- **JSON Data**: Raw discovery data for automation

## 🛠️ Manual Commands Reference

### Check Python Version
```bash
# Bundled Python
.\tool\python\python.exe --version

# System Python
python --version
```

### Verify Package Installation
```bash
# Check if Azure SDK is installed
.\tool\python\python.exe -c "import azure.identity; print('Azure SDK OK')"

# List all installed packages
.\tool\python\python.exe -m pip list
```

### Update All Packages
```bash
.\tool\python\python.exe -m pip install --upgrade -r requirements.txt
```

### Filter Subscriptions (Scan Specific Subscriptions)

**Option 1: Scan ALL subscriptions** (default)
```json
{
  "subscription_names": [],
  "subscription_ids": []
}
```

**Option 2: Filter by Subscription NAME(s)**
```json
{
  "subscription_names": ["Production", "Dev"],
  "subscription_ids": []
}
```
- Case-insensitive matching
- Supports partial matches (e.g., "Prod" matches "Production-Subscription")
- Can specify multiple names

**Option 3: Filter by Subscription ID(s)**
```json
{
  "subscription_names": [],
  "subscription_ids": [
    "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy"
  ]
}
```

**Option 4: Mix both names AND IDs**
```json
{
  "subscription_names": ["Production"],
  "subscription_ids": ["xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"]
}
```
- Scans union of both filters

**How to find your subscriptions:**
```bash
# List all subscriptions
az account list --output table

# Show current subscription
az account show

# Get subscription ID
az account show --query id -o tsv
```

Then edit `config.json` and run:
```bash
.\tool\python\python.exe azure_discovery.py
# OR simply:
run.cmd
```

## 🔍 Troubleshooting

### First Step: Run Verification Script
```bash
# This checks your Python installation
.\tool\python\python.exe verify_python.py

# OR with system Python
python verify_python.py
```

### Python Not Found
```bash
# Use bundled Python
.\tool\python\python.exe azure_discovery.py

# Or add to PATH and use:
python azure_discovery.py
```

### Package Installation Fails
```bash
# Upgrade pip first
.\tool\python\python.exe -m pip install --upgrade pip

# Install with verbose output
.\tool\python\python.exe -m pip install -r requirements.txt -v
```

### Azure Authentication Issues
```bash
# Clear cached credentials
az account clear

# Login again
az login

# Verify login
az account show
```

### Import Errors
```bash
# Reinstall specific package
.\tool\python\python.exe -m pip install --force-reinstall azure-identity

# Check what's installed
.\tool\python\python.exe -m pip show azure-identity
```

### "No module named socket" Error

This error indicates the bundled Python installation is incomplete or corrupted.

**Solution 1: Use System Python Instead**
```bash
# Install system Python from python.org
# Then run:
python -m pip install -r requirements.txt
python azure_discovery.py
```

**Solution 2: Verify Bundled Python Installation**
```bash
# Check if standard library is accessible
.\tool\python\python.exe -c "import sys; print(sys.path)"
.\tool\python\python.exe -c "import socket; print('Socket OK')"
```

**Solution 3: Reinstall Bundled Python**
- Delete the `tool\python\` folder
- Download Python 3.11 portable/embedded version
- Extract to `tool\python\`
- Install pip and packages

**Quick Fix: Skip Bundled Python**
```bash
# Just use system Python
python -m pip install -r requirements.txt
python azure_discovery.py
```

## 📁 Project Structure

```
Discovery/
├── azure_discovery.py      # Main discovery script
├── config.json             # Configuration file
├── requirements.txt        # Python dependencies
├── run.cmd                 # Windows launcher
├── run_discovery.ps1       # PowerShell script
├── START_HERE.txt          # Quick start guide
├── QUICK_START_GUIDE.html  # HTML documentation
├── tool\
│   └── python\             # Bundled Python 3.11
└── discovery_output\       # Generated reports
```

## 🔒 Security

- **READ-ONLY**: This tool only reads Azure resources
- **No Modifications**: Does NOT create, modify, or delete anything
- **Minimum Permission**: Requires only "Reader" role
- **Safe for Production**: Can run in live environments

## 💡 Tips

1. **First Time Setup:**
   ```bash
   az login
   .\run.cmd
   ```

2. **Manual Control:**
   ```bash
   .\tool\python\python.exe -m pip install -r requirements.txt
   .\tool\python\python.exe azure_discovery.py
   ```

3. **Custom Configuration:**
   - Edit `config.json` before running
   - Specify subscriptions, repos, and options

4. **Offline Package Installation:**
   ```bash
   # Download packages
   .\tool\python\python.exe -m pip download -r requirements.txt -d packages

   # Install offline
   .\tool\python\python.exe -m pip install --no-index --find-links=packages -r requirements.txt
   ```

## 📞 Support

For issues or questions, check the troubleshooting sections below or review discovery logs in `discovery_output\`.

---

## 🔒 SSL Certificate Errors (Git Clone / Repo Scanning)

If repo scanning fails with SSL errors like:
```
ssl.SSLError: [SSL: CERTIFICATE_VERIFY_FAILED]
fatal: unable to access '...': SSL certificate problem: unable to get local issuer certificate
```

The tool will **automatically retry** with SSL bypassed and log instructions. For a permanent fix:

### ✅ Fix 1: Use Windows Certificate Store (Recommended for corporate environments)
```bash
git config --global http.sslBackend schannel
```

### ✅ Fix 2: Set Custom CA Certificate
```bash
git config --global http.sslCAInfo "C:\path\to\your-company-ca.crt"
```

### ✅ Fix 3: Disable SSL Verification (Quick fix — less secure)
```bash
git config --global http.sslVerify false
```
Re-enable after cloning:
```bash
git config --global http.sslVerify true
```

### ✅ Fix 4: Corporate Proxy with SSL Inspection
```bash
git config --global http.proxy http://proxy.company.com:8080
git config --global http.sslBackend schannel
```

### Reset All Git SSL Settings
```bash
git config --global --unset http.sslVerify
git config --global --unset http.sslCAInfo
git config --global --unset http.sslBackend
git config --global --unset http.proxy
```

---

## 📁 Code Repository Scanning

The tool can scan Azure DevOps or any Git repository for dependencies (connection strings, Azure SDK usage, ARM templates, NuGet packages).

### Configure Azure DevOps Repositories

Edit `config.json`:
```json
{
    "scan_code": true,
    "azure_devops": {
        "organization": "your-org-name",
        "pat_token": "your-personal-access-token",
        "projects": [
            {
                "project_name": "MyProject",
                "repositories": [
                    { "name": "my-api",      "branch": "main" },
                    { "name": "my-frontend", "branch": "develop" }
                ]
            }
        ]
    }
}
```

**Create a PAT token:**
1. Azure DevOps → User Settings (top right) → Personal Access Tokens
2. New Token → Scopes: **Code (Read)**
3. Copy token → paste into `pat_token` in `config.json`

### Configure Any Git Repository (GitHub, Bitbucket, etc.)

```json
{
    "scan_code": true,
    "git_repos": [
        { "url": "https://github.com/org/repo.git",       "branch": "main" },
        { "url": "https://user:token@github.com/org/repo", "branch": "develop" },
        { "url": "https://pat:TOKEN@dev.azure.com/org/proj/_git/repo", "branch": "main" }
    ]
}
```

### Troubleshooting: "No code repositories scanned"

Run the tool and check the log output for the **"Scanning Git Repositories"** section. It will show:

| Message | Cause | Fix |
|---|---|---|
| `azure_devops organization/pat_token is empty` | Config not set | Fill `azure_devops` in `config.json` |
| `still contain placeholder values (YOUR_...)` | Config not updated | Replace `YOUR_ORG_NAME` etc. in `config.json` |
| `Authentication failed` | Invalid PAT token | Regenerate PAT with Code (Read) scope |
| `Repository not found` | Wrong names | Verify org/project/repo names in Azure DevOps |
| `SSL error` | Certificate issue | See SSL fixes above |
| `0 repo(s) configured` | `git_repos` empty | Add repos via `azure_devops` or `git_repos` in `config.json` |

---

See LICENSE.txt for details.
