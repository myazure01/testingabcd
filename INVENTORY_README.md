# Azure Migration Inventory — How to Run

## Production Safety

**This script will not impact your production Azure services.**

Every protection below is enforced in code and cannot be turned off:

| Layer | What it does |
|---|---|
| **Write-verb guard** | `run_az()` checks every `az` command against a blocklist of mutating verbs (`create`, `update`, `delete`, `set`, `assign`, `remove`, `patch`, `rotate`, `reset`, `deploy`, `regenerate`, `revoke`, `enable`, `disable`, `start`, `stop`, `restart`, `scale`, `swap`, `publish`, `trigger`, `invoke`). Any match raises a hard error **before** the command runs. |
| **Only `list` / `show`** | Every Azure CLI call in the script uses only `az … list` or `az … show`. No resource is created, modified, or deleted. |
| **No ARM writes** | The script uses the Azure CLI, not the ARM REST API directly. No PUT, POST, PATCH, or DELETE HTTP calls are made to Azure. |
| **Read-only Git clone** | Git runs with `GIT_TERMINAL_PROMPT=0`, `GIT_ASKPASS=echo`, `--depth 1 --single-branch --no-tags`. No push, commit, or write to the remote is possible. |
| **No local side-effects on Azure** | `az account set --subscription` only switches context in the local CLI process. It does not call any Azure management API. |
| **Output is local only** | All results are written to the local `migration-output` folder. Nothing is written back to Azure. |

The minimum Azure RBAC permission needed to run this script is **Reader** on the subscription.

---

## Step 1 — Install packages

```powershell
.\tool\python\python.exe -m pip install -r requirements.txt
```

## Step 2 — Log in to Azure

```powershell
az login
```

## Step 3 — Set your subscription in `config.json`

Open `config.json` and fill in your subscription ID:

```json
"subscription_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
```

## Step 4 — Run

```powershell
.\tool\python\python.exe azure_migration_inventory.py
```

Output is written to the `migration-output` folder.
