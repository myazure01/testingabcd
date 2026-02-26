import subprocess, json, os, sys, re, argparse, datetime, time
import threading, shutil, csv
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

# Force UTF-8 output on Windows to avoid cp1252 UnicodeEncodeError caused by
# box-drawing and arrow characters used in console output.
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

# ── az CLI detection ──────────────────────────────────────────────────────────
# On Windows, az ships as az.cmd and must run through cmd.exe (shell=True).
# shutil.which respects PATHEXT so it resolves az → az.cmd automatically.
def _detect_az():
    import shutil
    found = shutil.which("az")                   # returns full path e.g. C:\...\az.cmd
    if found:
        is_cmd = found.lower().endswith((".cmd", ".bat"))
        return found, is_cmd
    # hard-coded fallback for default Azure CLI install paths on Windows
    for p in (
        r"C:\Program Files (x86)\Microsoft SDKs\Azure\CLI2\wbin\az.cmd",
        r"C:\Program Files\Microsoft SDKs\Azure\CLI2\wbin\az.cmd",
    ):
        if os.path.isfile(p):
            return p, True
    return "az", False

_AZ_EXE, _AZ_SHELL = _detect_az()
_AZ_CMD = [_AZ_EXE]


def _az_subprocess_args(args_list):
    """Return (cmd, shell) ready for subprocess.run.
    On Windows with a .cmd file, shell=True is required and the command must
    be a properly quoted string (shell=True + list silently drops all args
    after the first on Windows).
    """
    full = _AZ_CMD + list(args_list) + ["--output", "json"]
    if _AZ_SHELL:
        # Quote the exe path in case it contains spaces, join the rest normally
        quoted_exe = f'"{_AZ_EXE}"'
        return quoted_exe + " " + " ".join(full[1:]), True
    return full, False

# ── dependency check ──────────────────────────────────────────────────────────
def _check_deps():
    missing = []
    try: import yaml
    except ImportError: missing.append("pyyaml")
    try: import openpyxl
    except ImportError: missing.append("openpyxl")
    if missing:
        print(f"Missing packages. Run: pip install {' '.join(missing)}")
        sys.exit(1)
_check_deps()

# ── config loader ────────────────────────────────────────────────────────────
def load_config(config_path=None):
    """Load config.json from the script directory (or a given path).
    Returns a dict with all non-comment keys (keys not starting with '_')."""
    if config_path is None:
        config_path = Path(__file__).parent / "config.json"
    try:
        raw = json.loads(Path(config_path).read_text(encoding="utf-8-sig"))
        return {k: v for k, v in raw.items() if not k.startswith("_")}
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError as e:
        print(f"[ERROR] config.json is not valid JSON: {e}")
        sys.exit(1)


# ── helpers ───────────────────────────────────────────────────────────────────
# Verbs that mutate Azure state — never allowed in read-only mode
_AZ_WRITE_VERBS = frozenset({
    "create", "update", "delete", "set", "assign", "add", "remove",
    "patch", "rotate", "reset", "deploy", "import", "export",
    "regenerate", "revoke", "enable", "disable", "start", "stop",
    "restart", "scale", "swap", "publish", "trigger", "invoke",
})

def run_az(args_list, verbose=False, subscription_id=None):
    """Run an az CLI command and return parsed JSON, or None on error.
    This script is permanently READ-ONLY. Any call containing a write verb
    (create/update/delete/set/assign/…) raises RuntimeError immediately.
    Pass subscription_id to target a specific subscription without az account set.
    """
    # ── Read-only guard ───────────────────────────────────────────────────────────
    forbidden = [v for v in args_list if str(v).lower() in _AZ_WRITE_VERBS]
    if forbidden:
        raise RuntimeError(
            f"READ-ONLY VIOLATION: az command contains write verb(s) {forbidden}. "
            f"Full args: {args_list}")
    # Inject --subscription so each call is explicitly scoped (safe for parallel runs)
    if subscription_id:
        args_list = list(args_list) + ["--subscription", subscription_id]
    try:
        cmd, use_shell = _az_subprocess_args(args_list)
        result = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=120, shell=use_shell
        )
        if result.returncode != 0:
            if verbose:
                print(f"[WARN] az {' '.join(args_list)}: {result.stderr[:200]}")
            return None
        return json.loads(result.stdout) if result.stdout.strip() else None
    except FileNotFoundError:
        print(f"[ERROR] Azure CLI not found. Searched for: {_AZ_EXE}")
        print("        Install from : https://aka.ms/installazurecliwindows")
        print("        After install, open a NEW terminal and run: az login")
        sys.exit(1)
    except Exception as e:
        if verbose:
            print(f"[WARN] az {' '.join(args_list)}: {e}")
        return None

def safe_get(obj, *keys, default=None):
    """Safely traverse nested dicts/lists."""
    for key in keys:
        if obj is None:
            return default
        if isinstance(obj, dict):
            obj = obj.get(key)
        elif isinstance(obj, list) and isinstance(key, int):
            obj = obj[key] if 0 <= key < len(obj) else None
        else:
            return default
    return obj if obj is not None else default

def parse_resource_name(resource_id):
    """Return the last segment of an Azure resource ID."""
    if not resource_id or "/" not in str(resource_id):
        return ""
    return str(resource_id).rstrip("/").split("/")[-1]

def parse_vnet_subnet(resource_id):
    """Extract vnet and subnet names from a subnet resource ID."""
    if not resource_id:
        return {"vnet_name": "", "subnet_name": ""}
    m = re.search(r"/virtualNetworks/([^/]+)/subnets/([^/]+)", str(resource_id), re.I)
    if m:
        return {"vnet_name": m.group(1), "subnet_name": m.group(2)}
    return {"raw_id": resource_id}


# ── ProgressTracker ───────────────────────────────────────────────────────────
class ProgressTracker:
    def __init__(self):
        self._lock = threading.Lock()
        self._phase = ""
        self._start = time.time()
        self._active = {}
        self._ansi = os.name != "nt" or bool(os.environ.get("TERM"))

    def _ts(self):
        return datetime.datetime.now().strftime("[%H:%M:%S]")

    def _p(self, msg):
        sys.stdout.write(msg + "\n")
        sys.stdout.flush()

    def start_phase(self, name, total=0):
        with self._lock:
            self._p(f"\n{'━'*50}\n  PHASE: {name}\n{'━'*50}")

    def complete_phase(self, name, summary=""):
        with self._lock:
            self._p(f"{self._ts()} ✓ COMPLETE: {name}  {summary}")

    def log_success(self, msg):
        self._p(f"{self._ts()} ✓ {msg}")

    def log_warning(self, msg):
        self._p(f"{self._ts()} ⚠ {msg}")

    def log_error(self, msg):
        self._p(f"{self._ts()} ✗ {msg}")

    def log_info(self, msg):
        self._p(f"{self._ts()}   {msg}")

    def update_active_task(self, task_id, msg):
        with self._lock:
            self._active[task_id] = msg
            self._p(f"  ⟳ [{task_id}] {msg}")

    def complete_task(self, task_id, msg):
        with self._lock:
            self._active.pop(task_id, None)
            self._p(f"  ✓ [{task_id}] {msg}")

    def print_summary_table(self, headers, rows):
        with self._lock:
            widths = [max(len(str(h)), max((len(str(r[i])) for r in rows), default=0))
                      for i, h in enumerate(headers)]
            sep = "─" + "─┼─".join("─" * w for w in widths) + "─"
            def fmt_row(cells):
                return "│ " + " │ ".join(str(c).ljust(widths[i]) for i, c in enumerate(cells)) + " │"
            self._p(sep)
            self._p(fmt_row(headers))
            self._p(sep)
            for row in rows:
                self._p(fmt_row(row))


# ── AzureInventoryCollector ───────────────────────────────────────────────────
class AzureInventoryCollector:

    def __init__(self, args, tracker, subscription_id=None):
        self.args = args
        self.tracker = tracker
        self._sub_id = subscription_id
        # _az is a bound helper that passes --subscription to every az call,
        # enabling fully parallel multi-subscription scanning without az account set.
        if subscription_id:
            from functools import partial
            self._az = partial(run_az, subscription_id=subscription_id)
        else:
            self._az = run_az

    @staticmethod
    def _empty_resources():
        return {k: [] for k in [
            "app_service_plans", "web_apps", "function_apps",
            "sql_servers", "sql_databases", "storage_accounts",
            "key_vaults", "virtual_networks", "network_security_groups",
            "route_tables", "public_ips", "private_endpoints",
            "private_dns_zones", "application_gateways", "waf_policies",
            "load_balancers", "traffic_managers", "managed_identities",
            "log_analytics_workspaces", "app_insights", "diagnostic_settings",
            "alert_rules", "action_groups", "activity_log_alerts",
            "scheduled_query_alerts", "smart_detector_alert_rules",
            "event_grid_topics", "event_grid_domains",
            "other_resources",
        ]}

    def collect_all(self):
        # Run all three initialisation calls concurrently.
        # "az resource list --query [].resourceGroup" returns only the RG-name
        # field (~95 % less data than the full resource list), so it is much
        # faster to transfer and parse on large subscriptions.
        with ThreadPoolExecutor(max_workers=3) as _init_pool:
            _f_sub  = _init_pool.submit(self._az, ["account", "show"])
            _f_rgs  = _init_pool.submit(self._az, ["group",    "list"])
            _f_flat = _init_pool.submit(self._az, ["resource", "list",
                                                   "--query", "[].resourceGroup"])
        sub     = _f_sub.result()  or {}
        all_rgs = _f_rgs.result()  or []
        # flat is now a list of RG-name strings (may contain None for sub-level
        # resources – those are skipped below)
        flat    = _f_flat.result() or []

        rg_counts = {}
        for rg in flat:
            if rg:
                rg_counts[rg] = rg_counts.get(rg, 0) + 1

        # ── scope filtering from config ──────────────────────────────────────
        excluded = [r.lower() for r in getattr(self.args, "excluded_resource_groups", [])]
        included = [r.lower() for r in getattr(self.args, "included_resource_groups", [])]
        if excluded:
            all_rgs = [r for r in all_rgs if r.get("name", "").lower() not in excluded]
        if included:
            all_rgs = [r for r in all_rgs if r.get("name", "").lower() in included]

        self.tracker.print_summary_table(
            ["Resource Group", "Location", "Resources", "Status"],
            [[rg.get("name"), rg.get("location"),
              rg_counts.get(rg.get("name", ""), 0),
              "EMPTY" if rg_counts.get(rg.get("name", ""), 0) == 0 else "collecting"]
             for rg in all_rgs]
        )

        inventory = {
            "subscription": sub,
            "_output_dir": str(self.args.output_dir),
            "resource_groups": {}
        }

        empty_rgs = [rg for rg in all_rgs if rg_counts.get(rg["name"], 0) == 0]
        non_empty_rgs = [rg for rg in all_rgs if rg_counts.get(rg["name"], 0) > 0]

        for rg in empty_rgs:
            inventory["resource_groups"][rg["name"]] = {
                "metadata": {"name": rg["name"], "location": rg.get("location"),
                             "tags": {}, "provisioningState": "Succeeded"},
                "resource_count": 0, "is_empty": True,
                "resources": self._empty_resources()
            }

        futures = {}
        with ThreadPoolExecutor(max_workers=self.args.parallel_workers) as ex:
            for rg in non_empty_rgs:
                name = rg["name"]
                self.tracker.update_active_task(name, f"Collecting {name}")
                futures[ex.submit(self._collect_rg, name, rg.get("location", ""))] = name

            for fut in as_completed(futures):
                rg_name, rg_dict = fut.result()
                count = rg_dict.get("resource_count", 0)
                self.tracker.complete_task(rg_name, f"{rg_name}: {count} resources")
                inventory["resource_groups"][rg_name] = rg_dict

        out = Path(self.args.output_dir)
        # Use a per-subscription filename when scanning in parallel to avoid
        # race conditions when multiple subscriptions are collected concurrently.
        # The merged result is written by collect_inventory() after all subs finish.
        if self._sub_id:
            safe_sub = self._sub_id.replace("/", "_").replace("\\", "_")
            fname = f"inventory-sub-{safe_sub}.json"
        else:
            fname = "inventory-by-resource-group.json"
        (out / "raw-data" / fname).write_text(
            json.dumps(inventory, indent=2), encoding="utf-8"
        )
        return inventory

    def _collect_rg(self, rg_name, rg_location):
        tags = safe_get(self._az(["group", "show", "--name", rg_name]), "tags") or {}
        rg_dict = {
            "metadata": {"name": rg_name, "location": rg_location,
                         "tags": tags, "provisioningState": "Succeeded"},
            "resource_count": 0, "is_empty": False,
            "resources": self._empty_resources()
        }

        # ── build collector list, respecting config flags ────────────────────
        a = self.args
        FLAG_MAP = [
            ("collect_web_apps",           self.collect_web_apps),
            ("collect_function_apps",       self.collect_function_apps),
            ("collect_app_service_plans",   self.collect_app_service_plans),
            ("collect_sql",                 self.collect_sql),
            ("collect_storage",             self.collect_storage),
            ("collect_key_vaults",          self.collect_key_vaults),
            ("collect_networking",          self.collect_networking),
            ("collect_app_gateways",        self.collect_app_gateways),
            ("collect_load_balancers",      self.collect_load_balancers),
            ("collect_traffic_managers",    self.collect_traffic_managers),
            ("collect_managed_identities",  self.collect_managed_identities),
            ("collect_monitoring",          self.collect_monitoring),
            ("collect_event_grid",          self.collect_event_grid),
            ("collect_other_resources",     self.collect_other_resources),
        ]
        collectors = [fn for flag, fn in FLAG_MAP if getattr(a, flag, True)]

        futures = {}
        # Use enough workers to run all collector types concurrently.
        # Cap at parallel_workers to avoid overwhelming the az CLI process pool.
        _rg_workers = max(getattr(a, 'parallel_workers', 8), len(collectors))
        with ThreadPoolExecutor(max_workers=_rg_workers) as ex:
            for fn in collectors:
                futures[ex.submit(fn, rg_name)] = fn.__name__

        for fut in as_completed(futures):
            try:
                result = fut.result()
                if result:
                    for key, val in result.items():
                        if key in rg_dict["resources"] and isinstance(val, list):
                            rg_dict["resources"][key].extend(val)
            except Exception as e:
                self.tracker.log_warning(f"{futures[fut]} in {rg_name}: {e}")

        rg_dict["resource_count"] = sum(
            len(v) for v in rg_dict["resources"].values()
        )
        return rg_name, rg_dict

    # ── Prompt 5: Web App + Function App collectors ───────────────────────────
    def _collect_app(self, rg, name, is_func):
        """Shared logic for web apps and function apps."""
        cmd = "functionapp" if is_func else "webapp"
        futures = {}
        # 6 independent az CLI calls — run all concurrently
        with ThreadPoolExecutor(max_workers=6) as ex:
            futures["show"]     = ex.submit(self._az, [cmd, "show", "-n", name, "-g", rg])
            futures["settings"] = ex.submit(self._az, [cmd, "config", "appsettings", "list", "-n", name, "-g", rg])
            futures["conn"]     = ex.submit(self._az, [cmd, "config", "connection-string", "list", "-n", name, "-g", rg])
            futures["vnet"]     = ex.submit(self._az, [cmd, "vnet-integration", "list", "-g", rg, "-n", name])
            futures["slots"]    = ex.submit(self._az, [cmd, "deployment", "slot", "list", "-g", rg, "-n", name])
            futures["ident"]    = ex.submit(self._az, [cmd, "identity", "show", "-g", rg, "-n", name])

        res = {k: (f.result() or ([] if k in ("settings", "conn", "vnet", "slots") else None))
               for k, f in futures.items()}
        show, settings, conn, vnet, slots, ident = (
            res["show"], res["settings"], res["conn"], res["vnet"], res["slots"], res["ident"]
        )

        farm_id = safe_get(show, "serverFarmId", default="")
        vnet_sub_id = safe_get(show, "virtualNetworkSubnetId", default="")
        identity_type = (safe_get(ident, "type") or safe_get(show, "identity", "type") or "")
        principal_id  = safe_get(ident, "principalId") or safe_get(show, "identity", "principalId")
        ua_ids = list((safe_get(ident, "userAssignedIdentities") or
                       safe_get(show, "identity", "userAssignedIdentities") or {}).keys())

        app_setting_keys = [s.get("name", "") for s in settings]
        sensitive_keys   = [k for k in app_setting_keys
                            if re.search(r'password|secret|key|token|apikey|accountkey', k, re.I)]
        kv_references = []
        for s in settings:
            val = s.get("value", "") or ""
            if val.startswith("@Microsoft.KeyVault"):
                vault_m  = re.search(r'VaultName=([^;)]+)', val)
                secret_m = re.search(r'SecretName=([^;)]+)', val)
                kv_references.append({
                    "vault_name":  vault_m.group(1)  if vault_m  else "",
                    "secret_name": secret_m.group(1) if secret_m else "",
                    "key_name": s.get("name", "")
                })

        host_names     = safe_get(show, "hostNames") or []
        custom_domains = [h for h in host_names if not h.endswith(".azurewebsites.net")]
        bicep_notes = []
        if custom_domains: bicep_notes.append("Custom domains must be re-verified in new tenant")
        if principal_id:   bicep_notes.append("System-assigned identity principalId will change")
        if kv_references:  bicep_notes.append("Key Vault references must resolve in new tenant")

        d = {
            "id": safe_get(show, "id"), "name": name,
            "type": safe_get(show, "type"), "location": safe_get(show, "location"),
            "resourceGroup": rg, "tags": safe_get(show, "tags") or {},
            "kind": safe_get(show, "kind"), "state": safe_get(show, "state"),
            "defaultHostName": safe_get(show, "defaultHostName"),
            "hostNames": host_names,
            "outboundIpAddresses": safe_get(show, "outboundIpAddresses"),
            "httpsOnly": safe_get(show, "httpsOnly"),
            "https_only": safe_get(show, "httpsOnly"),
            "clientAffinityEnabled": safe_get(show, "clientAffinityEnabled"),
            "clientCertEnabled": safe_get(show, "clientCertEnabled"),
            "virtualNetworkSubnetId": vnet_sub_id,
            "serverFarmId": farm_id, "server_farm_name": parse_resource_name(farm_id),
            "identity_type": identity_type, "principal_id": principal_id,
            "user_assigned_identities": ua_ids,
            "runtime": (safe_get(show, "siteConfig", "linuxFxVersion") or
                        safe_get(show, "siteConfig", "windowsFxVersion") or ""),
            "net_framework_version": safe_get(show, "siteConfig", "netFrameworkVersion"),
            "node_version": safe_get(show, "siteConfig", "nodeVersion"),
            "python_version": safe_get(show, "siteConfig", "pythonVersion"),
            "java_version": safe_get(show, "siteConfig", "javaVersion"),
            "always_on": safe_get(show, "siteConfig", "alwaysOn"),
            "ftps_state": safe_get(show, "siteConfig", "ftpsState"),
            "https20_enabled": safe_get(show, "siteConfig", "http20Enabled"),
            "min_tls": safe_get(show, "siteConfig", "minTlsVersion"),
            "cors_origins": safe_get(show, "siteConfig", "cors", "allowedOrigins") or [],
            "vnet_integration": [
                {"vnet_name": parse_resource_name(v.get("vnetResourceId", "")),
                 "subnet_name": parse_resource_name(v.get("subnetResourceId", ""))}
                for v in vnet
            ],
            "slots_list": [s["name"] for s in slots],
            "app_setting_keys": app_setting_keys,
            "sensitive_keys": sensitive_keys,
            "kv_references": kv_references,
            "conn_string_types": [{"name": c["name"], "type": c["type"]} for c in conn],
            "custom_domains": custom_domains,
            "bicep_notes": bicep_notes,
        }

        if is_func:
            d["has_job_storage"]   = any(s["name"] == "AzureWebJobsStorage" for s in settings)
            d["has_app_insights"]  = any(s["name"] == "APPLICATIONINSIGHTS_CONNECTION_STRING" for s in settings)
            d["functions_runtime"] = next(
                (s.get("value") for s in settings if s["name"] == "FUNCTIONS_WORKER_RUNTIME"), None)
            d["functions_version"] = next(
                (s.get("value") for s in settings if s["name"] == "FUNCTIONS_EXTENSION_VERSION"), None)
            if d.get("has_job_storage"):
                d["bicep_notes"].append("AzureWebJobsStorage must point to new storage account")

        return d

    def collect_web_apps(self, rg):
        apps = self._az(["webapp", "list", "--resource-group", rg]) or []
        result = []
        for app in apps:
            try:
                d = self._collect_app(rg, app["name"], is_func=False)
                result.append(d)
                self.tracker.log_success(f"WebApp: {app['name']} ({rg})")
            except Exception as e:
                self.tracker.log_warning(f"WebApp {app.get('name')} in {rg}: {e}")
        return {"web_apps": result}

    def collect_function_apps(self, rg):
        apps = self._az(["functionapp", "list", "--resource-group", rg]) or []
        result = []
        for app in apps:
            try:
                d = self._collect_app(rg, app["name"], is_func=True)
                result.append(d)
                self.tracker.log_success(f"FunctionApp: {app['name']} ({rg})")
            except Exception as e:
                self.tracker.log_warning(f"FunctionApp {app.get('name')} in {rg}: {e}")
        return {"function_apps": result}

    # ── Prompt 6: App Service Plan + SQL collectors ───────────────────────────
    def collect_app_service_plans(self, rg):
        plans = self._az(["appservice", "plan", "list", "--resource-group", rg]) or []
        result = []
        for p in plans:
            name = p.get("name", "")
            result.append({
                "id": p.get("id"), "name": name, "type": p.get("type"),
                "location": p.get("location"), "resourceGroup": rg,
                "tags": p.get("tags") or {}, "kind": p.get("kind"),
                "provisioningState": safe_get(p, "provisioningState"),
                "sku_name": safe_get(p, "sku", "name"),
                "sku_tier": safe_get(p, "sku", "tier"),
                "sku_size": safe_get(p, "sku", "size"),
                "sku_capacity": safe_get(p, "sku", "capacity"),
                "num_workers": p.get("numberOfWorkers"),
                "max_workers": p.get("maximumNumberOfWorkers"),
                "is_linux": p.get("reserved", False),
                "is_xenon": p.get("isXenon", False),
                "zone_redundant": p.get("zoneRedundant", False),
                "per_site_scaling": p.get("perSiteScaling", False),
                "max_elastic_workers": p.get("maximumElasticWorkerCount"),
                "ase_name": parse_resource_name(safe_get(p, "hostingEnvironmentProfile", "id") or ""),
            })
            self.tracker.log_success(f"AppPlan: {name} ({rg})")
        return {"app_service_plans": result}

    def collect_sql(self, rg):
        servers = self._az(["sql", "server", "list", "--resource-group", rg]) or []
        server_dicts = []
        db_dicts = []

        for svr_obj in servers:
            svr = svr_obj.get("name", "")
            futures = {}
            with ThreadPoolExecutor(max_workers=5) as ex:  # 5 futures
                futures["show"]     = ex.submit(self._az, ["sql", "server", "show", "-n", svr, "-g", rg])
                futures["fw_rules"] = ex.submit(self._az, ["sql", "server", "firewall-rule", "list", "-g", rg, "-s", svr])
                futures["vnet_r"]   = ex.submit(self._az, ["sql", "server", "vnet-rule", "list", "-g", rg, "-s", svr])
                futures["ad_admin"] = ex.submit(self._az, ["sql", "server", "ad-admin", "list", "-g", rg, "--server-name", svr])
                futures["dbs"]      = ex.submit(self._az, ["sql", "db", "list", "-g", rg, "-s", svr])

            show     = futures["show"].result()
            fw_rules = futures["fw_rules"].result() or []
            vnet_r   = futures["vnet_r"].result() or []
            ad_admin = futures["ad_admin"].result() or []
            dbs      = futures["dbs"].result() or []

            server_dict = {
                "id": safe_get(show, "id"), "name": svr, "type": safe_get(show, "type"),
                "location": safe_get(show, "location"), "resourceGroup": rg,
                "tags": safe_get(show, "tags") or {},
                "fqdn": safe_get(show, "fullyQualifiedDomainName"),
                "admin_login": safe_get(show, "administratorLogin"),
                "version": safe_get(show, "version"), "state": safe_get(show, "state"),
                "min_tls": safe_get(show, "minimalTlsVersion"),
                "public_network_access": safe_get(show, "publicNetworkAccess"),
                "ad_admin_login":  safe_get(ad_admin[0], "login") if ad_admin else None,
                "ad_admin_tenant": safe_get(ad_admin[0], "tenantId") if ad_admin else None,
                "firewall_rules": [
                    {"name": r.get("name"), "start": r.get("startIpAddress"),
                     "end": r.get("endIpAddress"),
                     "is_public_warning": r.get("startIpAddress") == "0.0.0.0" and r.get("endIpAddress") == "255.255.255.255"}
                    for r in fw_rules
                ],
                "vnet_rules": [
                    {"name": r.get("name"),
                     "subnet": parse_vnet_subnet(safe_get(r, "virtualNetworkSubnetId") or "")}
                    for r in vnet_r
                ],
            }
            server_dicts.append(server_dict)
            self.tracker.log_success(f"SQL Server: {svr} ({rg})")

            for db in [d for d in dbs if d.get("name") != "master"]:
                db_name = db.get("name", "")
                with ThreadPoolExecutor(max_workers=4) as ex:  # 4 futures
                    f_show = ex.submit(self._az, ["sql", "db", "show", "-g", rg, "-s", svr, "-n", db_name])
                    f_tde  = ex.submit(self._az, ["sql", "db", "tde", "show", "-g", rg, "-s", svr, "-n", db_name])
                    f_ltr  = ex.submit(self._az, ["sql", "db", "ltr-policy", "show", "-g", rg, "-s", svr, "-n", db_name])
                    f_str  = ex.submit(self._az, ["sql", "db", "str-policy", "show", "-g", rg, "-s", svr, "-n", db_name])

                db_show = f_show.result()
                tde     = f_tde.result()
                ltr     = f_ltr.result()
                str_pol = f_str.result()

                max_bytes = safe_get(db_show, "maxSizeBytes") or 0
                db_dicts.append({
                    "id": safe_get(db_show, "id"), "name": db_name,
                    "type": safe_get(db_show, "type"), "location": safe_get(db_show, "location"),
                    "resourceGroup": rg, "tags": safe_get(db_show, "tags") or {},
                    "server_name": svr,
                    "sku_name": (safe_get(db_show, "currentSku", "name") or safe_get(db_show, "sku", "name")),
                    "sku_tier": (safe_get(db_show, "currentSku", "tier") or safe_get(db_show, "sku", "tier")),
                    "sku_capacity": safe_get(db_show, "currentSku", "capacity"),
                    "collation": safe_get(db_show, "collation"),
                    "status": safe_get(db_show, "status"),
                    "max_size_gb": round(max_bytes / 1073741824, 2),
                    "zone_redundant": safe_get(db_show, "zoneRedundant", default=False),
                    "license_type": safe_get(db_show, "licenseType"),
                    "read_scale": safe_get(db_show, "readScale"),
                    "elastic_pool": parse_resource_name(safe_get(db_show, "elasticPoolId") or ""),
                    "auto_pause_delay": safe_get(db_show, "autoPauseDelay"),
                    "min_capacity": safe_get(db_show, "minCapacity"),
                    "tde_status": safe_get(tde, "status"),
                    "ltr_weekly": safe_get(ltr, "weeklyRetention"),
                    "ltr_monthly": safe_get(ltr, "monthlyRetention"),
                    "str_days": safe_get(str_pol, "retentionDays"),
                })

        return {"sql_servers": server_dicts, "sql_databases": db_dicts}

    # ── Prompt 7: Storage + Key Vault collectors ──────────────────────────────
    def collect_storage(self, rg):
        accounts = self._az(["storage", "account", "list", "--resource-group", rg]) or []
        result = []
        for a in accounts:
            name = a.get("name", "")
            futures = {}
            with ThreadPoolExecutor(max_workers=4) as ex:  # 4 futures
                futures["show"]       = ex.submit(self._az, ["storage", "account", "show", "-n", name, "-g", rg])
                futures["blob_svc"]   = ex.submit(self._az, ["storage", "account", "blob-service-properties", "show", "--account-name", name])
                futures["containers"] = ex.submit(self._az, ["storage", "container", "list", "--account-name", name, "--auth-mode", "login", "--num-results", "100"])
                futures["shares"]     = ex.submit(self._az, ["storage", "share-rm", "list", "-g", rg, "--storage-account", name])

            show       = futures["show"].result()
            blob_svc   = futures["blob_svc"].result()
            containers = futures["containers"].result()
            shares     = futures["shares"].result() or []

            result.append({
                "id": safe_get(show, "id"), "name": name,
                "type": safe_get(show, "type"), "location": safe_get(show, "location"),
                "resourceGroup": rg, "tags": safe_get(show, "tags") or {},
                "kind": safe_get(show, "kind"),
                "sku_name": safe_get(show, "sku", "name"),
                "sku_tier": safe_get(show, "sku", "tier"),
                "access_tier": safe_get(show, "accessTier"),
                "min_tls": safe_get(show, "minimumTlsVersion"),
                "https_only": safe_get(show, "supportsHttpsTrafficOnly"),
                "allow_blob_public": safe_get(show, "allowBlobPublicAccess"),
                "allow_shared_key": safe_get(show, "allowSharedKeyAccess"),
                "hns_enabled": safe_get(show, "isHnsEnabled", default=False),
                "sftp_enabled": safe_get(show, "isSftpEnabled", default=False),
                "public_network": safe_get(show, "publicNetworkAccess"),
                "identity_type": safe_get(show, "identity", "type"),
                "net_default": safe_get(show, "networkRuleSet", "defaultAction"),
                "net_bypass": safe_get(show, "networkRuleSet", "bypass"),
                "net_ip_rules": [r.get("iPAddressOrRange", "")
                                 for r in safe_get(show, "networkRuleSet", "ipRules", default=[])],
                "net_vnet_rules": [parse_vnet_subnet(r.get("virtualNetworkResourceId", ""))
                                   for r in safe_get(show, "networkRuleSet", "virtualNetworkRules", default=[])],
                "blob_versioning": safe_get(blob_svc, "isVersioningEnabled"),
                "blob_soft_delete_days": safe_get(blob_svc, "deleteRetentionPolicy", "days"),
                "containers_skipped": containers is None,
                "containers_list": [{"name": c["name"],
                                     "public_access": c.get("publicAccess"),
                                     "has_immutability": c.get("hasImmutabilityPolicy", False),
                                     "has_legal_hold": c.get("hasLegalHold", False)}
                                    for c in (containers or [])],
                "file_shares": [{"name": s["name"],
                                 "quota_gb": s.get("shareQuota"),
                                 "protocol": safe_get(s, "enabledProtocols"),
                                 "access_tier": safe_get(s, "accessTier")}
                                for s in shares],
            })
            self.tracker.log_success(f"Storage: {name} ({rg})")
        return {"storage_accounts": result}

    def collect_key_vaults(self, rg):
        vaults = self._az(["keyvault", "list", "--resource-group", rg]) or []
        result = []
        for v in vaults:
            name = v.get("name", "")
            futures = {}
            with ThreadPoolExecutor(max_workers=4) as ex:  # 4 futures
                futures["show"]    = ex.submit(self._az, ["keyvault", "show", "-n", name, "-g", rg])
                futures["secrets"] = ex.submit(self._az, ["keyvault", "secret", "list", "--vault-name", name])
                futures["keys"]    = ex.submit(self._az, ["keyvault", "key", "list", "--vault-name", name])
                futures["certs"]   = ex.submit(self._az, ["keyvault", "certificate", "list", "--vault-name", name])

            show    = futures["show"].result()
            secrets = futures["secrets"].result() or []
            keys    = futures["keys"].result() or []
            certs   = futures["certs"].result() or []

            access_policies = [
                {"objectId": p.get("objectId"), "tenantId": p.get("tenantId"),
                 "perms_keys":    safe_get(p, "permissions", "keys") or [],
                 "perms_secrets": safe_get(p, "permissions", "secrets") or [],
                 "perms_certs":   safe_get(p, "permissions", "certificates") or [],
                 "migration_required": True}
                for p in safe_get(show, "properties", "accessPolicies", default=[])
            ]

            result.append({
                "id": safe_get(show, "id"), "name": name,
                "type": safe_get(show, "type"), "location": safe_get(show, "location"),
                "resourceGroup": rg, "tags": safe_get(show, "tags") or {},
                "sku_name": safe_get(show, "properties", "sku", "name"),
                "tenant_id": safe_get(show, "properties", "tenantId"),
                "vault_uri": safe_get(show, "properties", "vaultUri"),
                "enable_soft_delete": safe_get(show, "properties", "enableSoftDelete"),
                "soft_delete_days": safe_get(show, "properties", "softDeleteRetentionInDays"),
                "enable_purge_protect": safe_get(show, "properties", "enablePurgeProtection"),
                "enable_rbac": safe_get(show, "properties", "enableRbacAuthorization"),
                "net_default": safe_get(show, "properties", "networkAcls", "defaultAction"),
                "net_bypass":  safe_get(show, "properties", "networkAcls", "bypass"),
                "net_ip_rules": [r.get("value", "")
                                 for r in safe_get(show, "properties", "networkAcls", "ipRules", default=[])],
                "pe_count": len(safe_get(show, "properties", "privateEndpointConnections", default=[])),
                "access_policies": access_policies,
                # NEVER retrieve secret/key/cert VALUES — names and attributes only
                "secrets_list": [{"name": parse_resource_name(s.get("id", "")),
                                  "enabled": safe_get(s, "attributes", "enabled"),
                                  "expires": safe_get(s, "attributes", "expires")}
                                 for s in secrets],
                "keys_list": [{"name": parse_resource_name(k.get("kid", "")),
                               "enabled": safe_get(k, "attributes", "enabled"),
                               "managed": k.get("managed", False)}
                              for k in keys],
                "certs_list": [{"name": parse_resource_name(c.get("id", "")),
                                "enabled": safe_get(c, "attributes", "enabled"),
                                "expires": safe_get(c, "attributes", "expires")}
                               for c in certs],
            })
            self.tracker.log_success(f"KeyVault: {name} ({rg})")
        return {"key_vaults": result}

    # ── Prompt 8: Networking + App Gateway collectors ──────────────────────────
    def collect_networking(self, rg):
        def _vnets():
            result = []
            for v in (self._az(["network", "vnet", "list", "-g", rg]) or []):
                show = self._az(["network", "vnet", "show", "-n", v["name"], "-g", rg]) or v
                result.append({
                    "id": show.get("id"), "name": show.get("name"),
                    "location": show.get("location"), "resourceGroup": rg,
                    "tags": show.get("tags") or {},
                    "address_prefixes": safe_get(show, "addressSpace", "addressPrefixes") or [],
                    "dns_servers": safe_get(show, "dhcpOptions", "dnsServers") or [],
                    "ddos_protection": safe_get(show, "enableDdosProtection", default=False),
                    "subnets": [
                        {"name": s["name"], "address_prefix": s.get("addressPrefix"),
                         "nsg_name": parse_resource_name(safe_get(s, "networkSecurityGroup", "id") or ""),
                         "route_table": parse_resource_name(safe_get(s, "routeTable", "id") or ""),
                         "service_endpoints": [e["service"] for e in s.get("serviceEndpoints", [])],
                         "delegations": [d.get("properties", {}).get("serviceName", "") for d in s.get("delegations", [])],
                         "pe_policies": s.get("privateEndpointNetworkPolicies")}
                        for s in safe_get(show, "subnets", default=[])
                    ],
                    "peerings": [
                        {"name": p["name"], "state": p.get("peeringState"),
                         "remote_vnet": parse_resource_name(safe_get(p, "remoteVirtualNetwork", "id") or ""),
                         "allow_forwarded": p.get("allowForwardedTraffic"),
                         "use_remote_gw": p.get("useRemoteGateways")}
                        for p in safe_get(show, "virtualNetworkPeerings", default=[])
                    ],
                })
            return {"virtual_networks": result}

        def _nsgs():
            result = []
            for n in (self._az(["network", "nsg", "list", "-g", rg]) or []):
                show = self._az(["network", "nsg", "show", "-n", n["name"], "-g", rg]) or n
                def _rules(key):
                    return [{"name": r["name"], "priority": r.get("priority"),
                             "direction": r.get("direction"), "access": r.get("access"),
                             "protocol": r.get("protocol"),
                             "src_port": r.get("sourcePortRange"), "dst_port": r.get("destinationPortRange"),
                             "src_addr": r.get("sourceAddressPrefix"), "dst_addr": r.get("destinationAddressPrefix")}
                            for r in safe_get(show, key, default=[])]
                result.append({
                    "id": show.get("id"), "name": show.get("name"),
                    "location": show.get("location"), "resourceGroup": rg,
                    "tags": show.get("tags") or {},
                    "associated_subnets": [parse_vnet_subnet(s["id"]) for s in safe_get(show, "subnets", default=[])],
                    "security_rules": _rules("securityRules"),
                    "default_rules": _rules("defaultSecurityRules"),
                })
            return {"network_security_groups": result}

        def _routes():
            result = []
            for t in (self._az(["network", "route-table", "list", "-g", rg]) or []):
                show = self._az(["network", "route-table", "show", "-n", t["name"], "-g", rg]) or t
                result.append({
                    "id": show.get("id"), "name": show.get("name"),
                    "location": show.get("location"), "resourceGroup": rg,
                    "tags": show.get("tags") or {},
                    "disable_bgp": safe_get(show, "disableBgpRoutePropagation", default=False),
                    "routes": [{"name": r["name"], "prefix": r.get("addressPrefix"),
                                "next_hop_type": r.get("nextHopType"), "next_hop_ip": r.get("nextHopIpAddress")}
                               for r in safe_get(show, "routes", default=[])],
                })
            return {"route_tables": result}

        def _public_ips():
            result = []
            for p in (self._az(["network", "public-ip", "list", "-g", rg]) or []):
                show = self._az(["network", "public-ip", "show", "-n", p["name"], "-g", rg]) or p
                result.append({
                    "id": show.get("id"), "name": show.get("name"),
                    "location": show.get("location"), "resourceGroup": rg,
                    "tags": show.get("tags") or {}, "zones": show.get("zones", []),
                    "sku_name": safe_get(show, "sku", "name"),
                    "allocation": safe_get(show, "publicIPAllocationMethod"),
                    "ip_address": safe_get(show, "ipAddress"),
                    "fqdn": safe_get(show, "dnsSettings", "fqdn"),
                    "associated": parse_resource_name(safe_get(show, "ipConfiguration", "id") or ""),
                })
            return {"public_ips": result}

        def _private_endpoints():
            result = []
            for pe in (self._az(["network", "private-endpoint", "list", "-g", rg]) or []):
                show = self._az(["network", "private-endpoint", "show", "-n", pe["name"], "-g", rg]) or pe
                result.append({
                    "id": show.get("id"), "name": show.get("name"),
                    "location": show.get("location"), "resourceGroup": rg,
                    "tags": show.get("tags") or {},
                    "subnet": parse_vnet_subnet(safe_get(show, "subnet", "id") or ""),
                    "connections": [
                        {"name": c["name"],
                         "linked_resource_id": safe_get(c, "privateLinkServiceId"),
                         "linked_resource": parse_resource_name(safe_get(c, "privateLinkServiceId") or ""),
                         "group_ids": c.get("groupIds", []),
                         "status": safe_get(c, "privateLinkServiceConnectionState", "status")}
                        for c in safe_get(show, "privateLinkServiceConnections", default=[])
                    ],
                    "custom_dns": [{"fqdn": d.get("fqdn"), "ips": d.get("ipAddresses", [])}
                                   for d in safe_get(show, "customDnsConfigs", default=[])],
                })
            return {"private_endpoints": result}

        def _private_dns():
            result = []
            for zone in (self._az(["network", "private-dns", "zone", "list", "-g", rg]) or []):
                zone_name = zone.get("name", "")
                show  = self._az(["network", "private-dns", "zone", "show", "-n", zone_name, "-g", rg]) or zone
                links = self._az(["network", "private-dns", "link", "vnet", "list", "-g", rg, "-z", zone_name]) or []
                result.append({
                    "id": show.get("id"), "name": zone_name,
                    "location": show.get("location"), "resourceGroup": rg,
                    "tags": show.get("tags") or {},
                    "record_sets": safe_get(show, "numberOfRecordSets"),
                    "vnet_links": [{"name": l["name"],
                                    "vnet_name": parse_resource_name(safe_get(l, "virtualNetwork", "id") or ""),
                                    "registration_enabled": l.get("registrationEnabled"),
                                    "state": l.get("virtualNetworkLinkState")}
                                   for l in links],
                })
            return {"private_dns_zones": result}

        merged = {}
        with ThreadPoolExecutor(max_workers=6) as ex:  # 6 sub-collectors
            futs = [ex.submit(fn) for fn in [_vnets, _nsgs, _routes, _public_ips, _private_endpoints, _private_dns]]
        for fut in as_completed(futs):
            try:
                merged.update(fut.result())
            except Exception as e:
                self.tracker.log_warning(f"Networking sub-collector in {rg}: {e}")
        return merged

    def collect_app_gateways(self, rg):
        agws = self._az(["network", "application-gateway", "list", "-g", rg]) or []
        agw_list = []
        for agw in agws:
            name = agw.get("name", "")
            show = self._az(["network", "application-gateway", "show", "-n", name, "-g", rg]) or agw
            gw_subnet_raw = safe_get(show, "gatewayIPConfigurations", default=[{}])
            gw_subnet = parse_vnet_subnet(safe_get(gw_subnet_raw[0], "subnet", "id") or "") if gw_subnet_raw else {}
            agw_list.append({
                "id": show.get("id"), "name": name,
                "location": show.get("location"), "resourceGroup": rg,
                "tags": show.get("tags") or {}, "zones": show.get("zones", []),
                "sku_name": safe_get(show, "sku", "name"),
                "sku_tier": safe_get(show, "sku", "tier"),
                "sku_capacity": safe_get(show, "sku", "capacity"),
                "autoscale_min": safe_get(show, "autoscaleConfiguration", "minCapacity"),
                "autoscale_max": safe_get(show, "autoscaleConfiguration", "maxCapacity"),
                "enable_http2": safe_get(show, "enableHttp2"),
                "operational_state": safe_get(show, "operationalState"),
                "gateway_subnet": gw_subnet,
                "waf_policy_id": safe_get(show, "firewallPolicy", "id"),
                "frontend_ips": [{"name": f["name"], "private_ip": f.get("privateIPAddress"),
                                  "public_ip_name": parse_resource_name(safe_get(f, "publicIPAddress", "id") or "")}
                                 for f in safe_get(show, "frontendIPConfigurations", default=[])],
                "frontend_ports": [{"name": fp["name"], "port": fp.get("port")}
                                   for fp in safe_get(show, "frontendPorts", default=[])],
                "backend_pools": [{"name": bp["name"],
                                   "targets": [a.get("fqdn") or a.get("ipAddress")
                                               for a in bp.get("backendAddresses", [])]}
                                  for bp in safe_get(show, "backendAddressPools", default=[])],
                "backend_settings": [{"name": bs["name"], "port": bs.get("port"),
                                      "protocol": bs.get("protocol"),
                                      "cookie_affinity": bs.get("cookieBasedAffinity"),
                                      "timeout": bs.get("requestTimeout"),
                                      "probe_name": parse_resource_name(safe_get(bs, "probe", "id") or "")}
                                     for bs in safe_get(show, "backendHttpSettingsCollection", default=[])],
                "listeners": [{"name": l["name"], "protocol": l.get("protocol"),
                               "host_name": l.get("hostName"), "host_names": l.get("hostNames", []),
                               "ssl_cert": parse_resource_name(safe_get(l, "sslCertificate", "id") or ""),
                               "waf_policy": parse_resource_name(safe_get(l, "firewallPolicy", "id") or "")}
                              for l in safe_get(show, "httpListeners", default=[])],
                "routing_rules": [{"name": r["name"], "priority": r.get("priority"),
                                   "rule_type": r.get("ruleType"),
                                   "listener": parse_resource_name(safe_get(r, "httpListener", "id") or ""),
                                   "pool": parse_resource_name(safe_get(r, "backendAddressPool", "id") or ""),
                                   "settings": parse_resource_name(safe_get(r, "backendHttpSettings", "id") or "")}
                                  for r in safe_get(show, "requestRoutingRules", default=[])],
                "probes": [{"name": p["name"], "protocol": p.get("protocol"), "host": p.get("host"),
                            "path": p.get("path"), "interval": p.get("interval"), "timeout": p.get("timeout")}
                           for p in safe_get(show, "probes", default=[])],
            })
            self.tracker.log_success(f"AppGateway: {name} ({rg})")

        waf_policies = []
        for pol in (self._az(["network", "application-gateway", "waf-policy", "list", "-g", rg]) or []):
            pname = pol.get("name", "")
            show = self._az(["network", "application-gateway", "waf-policy", "show", "-n", pname, "-g", rg]) or pol
            waf_policies.append({
                "id": show.get("id"), "name": pname,
                "location": show.get("location"), "resourceGroup": rg,
                "tags": show.get("tags") or {},
                "mode": safe_get(show, "properties", "policySettings", "mode"),
                "state": safe_get(show, "properties", "policySettings", "state"),
                "managed_rule_sets": [{"type": rs["ruleSetType"], "version": rs["ruleSetVersion"]}
                                      for rs in safe_get(show, "properties", "managedRules", "managedRuleSets", default=[])],
                "custom_rules_count": len(safe_get(show, "properties", "customRules", default=[])),
                "exclusions_count": len(safe_get(show, "properties", "managedRules", "exclusions", default=[])),
            })
        return {"application_gateways": agw_list, "waf_policies": waf_policies}

    # ── Prompt 9: LB + TM + Identities + Monitoring + Other ──────────────────
    def collect_load_balancers(self, rg):
        lbs = self._az(["network", "lb", "list", "-g", rg]) or []
        result = []
        for lb in lbs:
            name = lb.get("name", "")
            show = self._az(["network", "lb", "show", "-n", name, "-g", rg]) or lb
            result.append({
                "id": show.get("id"), "name": name,
                "location": show.get("location"), "resourceGroup": rg,
                "tags": show.get("tags") or {},
                "sku_name": safe_get(show, "sku", "name"),
                "sku_tier": safe_get(show, "sku", "tier"),
                "frontend_ips": [
                    {"name": f["name"], "private_ip": f.get("privateIPAddress"),
                     "public_ip": parse_resource_name(safe_get(f, "publicIPAddress", "id") or ""),
                     "subnet": parse_vnet_subnet(safe_get(f, "subnet", "id") or "")}
                    for f in safe_get(show, "frontendIPConfigurations", default=[])
                ],
                "backend_pools": [bp["name"] for bp in safe_get(show, "backendAddressPools", default=[])],
                "rules": [
                    {"name": r["name"], "protocol": r.get("protocol"),
                     "frontend_port": r.get("frontendPort"), "backend_port": r.get("backendPort"),
                     "frontend_ip": parse_resource_name(safe_get(r, "frontendIPConfiguration", "id") or ""),
                     "backend_pool": parse_resource_name(safe_get(r, "backendAddressPool", "id") or ""),
                     "probe": parse_resource_name(safe_get(r, "probe", "id") or "")}
                    for r in safe_get(show, "loadBalancingRules", default=[])
                ],
                "probes": [
                    {"name": p["name"], "protocol": p.get("protocol"),
                     "port": p.get("port"), "interval": p.get("intervalInSeconds")}
                    for p in safe_get(show, "probes", default=[])
                ],
            })
        return {"load_balancers": result}

    def collect_traffic_managers(self, rg):
        profiles = self._az(["network", "traffic-manager", "profile", "list", "-g", rg]) or []
        result = []
        for profile in profiles:
            name = profile.get("name", "")
            show = self._az(["network", "traffic-manager", "profile", "show", "-n", name, "-g", rg]) or profile
            result.append({
                "id": show.get("id"), "name": name,
                "resourceGroup": rg, "location": show.get("location"),
                "tags": show.get("tags") or {},
                "status":  safe_get(show, "properties", "profileStatus"),
                "routing": safe_get(show, "properties", "trafficRoutingMethod"),
                "dns_name": safe_get(show, "properties", "dnsConfig", "relativeName"),
                "dns_fqdn": safe_get(show, "properties", "dnsConfig", "fqdn"),
                "dns_ttl":  safe_get(show, "properties", "dnsConfig", "ttl"),
                "monitor_protocol": safe_get(show, "properties", "monitorConfig", "protocol"),
                "monitor_port":     safe_get(show, "properties", "monitorConfig", "port"),
                "monitor_path":     safe_get(show, "properties", "monitorConfig", "path"),
                "endpoints": [
                    {"name": e["name"],
                     "status": safe_get(e, "properties", "endpointStatus"),
                     "target": safe_get(e, "properties", "target"),
                     "target_resource": parse_resource_name(safe_get(e, "properties", "targetResourceId") or ""),
                     "weight":   safe_get(e, "properties", "weight"),
                     "priority": safe_get(e, "properties", "priority")}
                    for e in safe_get(show, "properties", "endpoints", default=[])
                ],
            })
        return {"traffic_managers": result}

    def collect_managed_identities(self, rg):
        ids = self._az(["identity", "list", "-g", rg]) or []
        result = []
        for identity in ids:
            name = identity.get("name", "")
            show = self._az(["identity", "show", "-n", name, "-g", rg]) or identity
            pid = safe_get(show, "principalId")
            try:
                ra = self._az(["role", "assignment", "list", "--assignee", pid, "--all-namespaces"]) or [] if pid else []
            except Exception:
                ra = []
            result.append({
                "id": show.get("id"), "name": name,
                "location": show.get("location"), "resourceGroup": rg,
                "tags": show.get("tags") or {},
                "principal_id": pid,
                "client_id": safe_get(show, "clientId"),
                "tenant_id":  safe_get(show, "tenantId"),
                "role_assignments": [
                    {"role": r.get("roleDefinitionName"), "scope": r.get("scope"), "migration_required": True}
                    for r in ra
                ],
            })
        return {"managed_identities": result}

    def collect_monitoring(self, rg):
        def _log_analytics():
            result = []
            for ws in (self._az(["monitor", "log-analytics", "workspace", "list", "-g", rg]) or []):
                name = ws.get("name", "")
                show = self._az(["monitor", "log-analytics", "workspace", "show", "-n", name, "-g", rg]) or ws
                result.append({
                    "id": show.get("id"), "name": name,
                    "location": show.get("location"), "resourceGroup": rg,
                    "tags": show.get("tags") or {},
                    "sku": safe_get(show, "sku", "name"),
                    "retention_days": safe_get(show, "retentionInDays"),
                    "daily_quota": safe_get(show, "workspaceCapping", "dailyQuotaGb"),
                    "customer_id": safe_get(show, "customerId"),
                    "public_ingestion": safe_get(show, "publicNetworkAccessForIngestion"),
                })
            return {"log_analytics_workspaces": result}

        def _app_insights():
            result = []
            for ai in (self._az(["monitor", "app-insights", "component", "list", "-g", rg]) or []):
                name = ai.get("name", "")
                show = self._az(["monitor", "app-insights", "component", "show", "-n", name, "-g", rg]) or ai
                result.append({
                    "id": show.get("id"), "name": name,
                    "location": show.get("location"), "resourceGroup": rg,
                    "tags": show.get("tags") or {}, "kind": show.get("kind"),
                    "application_type": safe_get(show, "applicationType"),
                    "retention_days": safe_get(show, "retentionInDays"),
                    "has_connection_string": True,
                    "has_instrumentation_key": True,
                    "workspace_name": parse_resource_name(safe_get(show, "workspaceResourceId") or ""),
                    "ingestion_mode": safe_get(show, "ingestionMode"),
                    "disable_local_auth": safe_get(show, "disableLocalAuth"),
                    "connection_string": safe_get(show, "connectionString"),
                    "instrumentation_key": safe_get(show, "instrumentationKey"),
                    "sampling_percentage": safe_get(show, "samplingPercentage"),
                    "flow_type": safe_get(show, "flowType"),
                })
            return {"app_insights": result}

        def _metric_alerts():
            alerts = self._az(["monitor", "metrics", "alert", "list", "-g", rg]) or []
            result = []
            for a in alerts:
                result.append({
                    "name": a.get("name"), "id": a.get("id"),
                    "location": a.get("location"), "resourceGroup": rg,
                    "tags": a.get("tags") or {},
                    "severity": safe_get(a, "severity"),
                    "enabled": safe_get(a, "enabled"),
                    "description": safe_get(a, "description"),
                    "evaluation_frequency": safe_get(a, "evaluationFrequency"),
                    "window_size": safe_get(a, "windowSize"),
                    "scopes": safe_get(a, "scopes") or [],
                    "alert_type": "metric",
                })
            return {"alert_rules": result}

        def _action_groups():
            ags = self._az(["monitor", "action-group", "list", "-g", rg]) or []
            result = []
            for ag in ags:
                name = ag.get("name", "")
                show = self._az(["monitor", "action-group", "show", "-n", name, "-g", rg]) or ag
                result.append({
                    "id": show.get("id"), "name": name,
                    "location": show.get("location"), "resourceGroup": rg,
                    "tags": show.get("tags") or {},
                    "short_name": safe_get(show, "groupShortName"),
                    "enabled": safe_get(show, "enabled"),
                    "email_count": len(safe_get(show, "emailReceivers", default=[])),
                    "sms_count": len(safe_get(show, "smsReceivers", default=[])),
                    "webhook_count": len(safe_get(show, "webhookReceivers", default=[])),
                    "logic_app_count": len(safe_get(show, "logicAppReceivers", default=[])),
                    "azure_function_count": len(safe_get(show, "azureFunctionReceivers", default=[])),
                    "arm_role_count": len(safe_get(show, "armRoleReceivers", default=[])),
                    "email_receivers": [{"name": r.get("name"), "address": r.get("emailAddress")}
                                        for r in (safe_get(show, "emailReceivers") or [])],
                })
            return {"action_groups": result}

        def _activity_log_alerts():
            alerts = self._az(["monitor", "activity-log", "alert", "list", "-g", rg]) or []
            result = []
            for a in alerts:
                name = a.get("name", "")
                show = self._az(["monitor", "activity-log", "alert", "show", "-n", name, "-g", rg]) or a
                result.append({
                    "id": show.get("id"), "name": name,
                    "location": show.get("location"), "resourceGroup": rg,
                    "tags": show.get("tags") or {},
                    "enabled": safe_get(show, "enabled"),
                    "description": safe_get(show, "description"),
                    "scopes": safe_get(show, "scopes") or [],
                    "conditions": [
                        {"field": c.get("field"), "equals": c.get("equals")}
                        for c in (safe_get(show, "condition", "allOf") or [])
                    ],
                    "action_group_ids": [
                        ag.get("actionGroupId")
                        for ag in (safe_get(show, "actions", "actionGroups") or [])
                    ],
                    "alert_type": "activity_log",
                })
            return {"activity_log_alerts": result}

        def _scheduled_query_alerts():
            rules = self._az(["monitor", "scheduled-query", "list", "-g", rg]) or []
            result = []
            for r in rules:
                name = r.get("name", "")
                show = self._az(["monitor", "scheduled-query", "show", "-n", name, "-g", rg]) or r
                result.append({
                    "id": show.get("id"), "name": name,
                    "location": show.get("location"), "resourceGroup": rg,
                    "tags": show.get("tags") or {},
                    "severity": safe_get(show, "severity"),
                    "enabled": safe_get(show, "enabled"),
                    "description": safe_get(show, "description"),
                    "evaluation_frequency": safe_get(show, "evaluationFrequency"),
                    "window_duration": safe_get(show, "windowDuration"),
                    "scopes": safe_get(show, "scopes") or [],
                    "criteria_queries": [
                        {"query": c.get("query", "")[:200], "operator": c.get("operator"),
                         "threshold": c.get("threshold")}
                        for c in (safe_get(show, "criteria", "allOf") or [])
                    ],
                    "alert_type": "scheduled_query",
                })
            return {"scheduled_query_alerts": result}

        def _smart_detector_alerts():
            # Smart Detector Alert Rules live under microsoft.alertsmanagement/smartDetectorAlertRules
            alerts = self._az([
                "rest", "--method", "get",
                "--url", f"https://management.azure.com/subscriptions/{{sub}}/resourceGroups/{rg}"
                         f"/providers/microsoft.alertsmanagement/smartDetectorAlertRules"
                         f"?api-version=2021-04-01",
            ]) or {}
            items = alerts.get("value", []) if isinstance(alerts, dict) else []
            result = []
            for a in items:
                props = a.get("properties", {})
                result.append({
                    "id": a.get("id"), "name": a.get("name"),
                    "location": a.get("location"), "resourceGroup": rg,
                    "tags": a.get("tags") or {},
                    "severity": props.get("severity"),
                    "enabled": props.get("state", "").lower() == "enabled",
                    "description": props.get("description"),
                    "frequency": props.get("frequency"),
                    "scope": props.get("scope", []),
                    "detector_id": safe_get(props, "detector", "id"),
                    "action_group_ids": [
                        ag.get("actionGroupId")
                        for ag in (safe_get(props, "actionGroups", "groupIds") or [])
                    ],
                    "alert_type": "smart_detector",
                })
            return {"smart_detector_alert_rules": result}

        merged = {}
        fns = [_log_analytics, _app_insights, _metric_alerts, _action_groups,
               _activity_log_alerts, _scheduled_query_alerts, _smart_detector_alerts]
        with ThreadPoolExecutor(max_workers=7) as ex:
            futs = [ex.submit(fn) for fn in fns]
        for fut in as_completed(futs):
            try:
                merged.update(fut.result())
            except Exception as e:
                self.tracker.log_warning(f"Monitoring in {rg}: {e}")
        merged["diagnostic_settings"] = []
        return merged

    def collect_event_grid(self, rg):
        def _topics():
            topics = self._az(["eventgrid", "topic", "list", "-g", rg]) or []
            result = []
            for t in topics:
                name = t.get("name", "")
                show = self._az(["eventgrid", "topic", "show", "-n", name, "-g", rg]) or t
                # fetch event subscriptions for each topic
                subs = self._az([
                    "eventgrid", "event-subscription", "list",
                    "--source-resource-id", show.get("id", ""),
                ]) or [] if show.get("id") else []
                result.append({
                    "id": show.get("id"), "name": name,
                    "location": show.get("location"), "resourceGroup": rg,
                    "tags": show.get("tags") or {},
                    "endpoint": safe_get(show, "endpoint"),
                    "input_schema": safe_get(show, "inputSchema"),
                    "public_network_access": safe_get(show, "publicNetworkAccess"),
                    "provisioning_state": safe_get(show, "provisioningState"),
                    "event_subscriptions": [
                        {"name": s.get("name"),
                         "endpoint_type": safe_get(s, "properties", "destination", "endpointType"),
                         "endpoint_url": safe_get(s, "properties", "destination", "properties", "endpointUrl"),
                         "event_types": safe_get(s, "properties", "filter", "includedEventTypes") or []}
                        for s in subs
                    ],
                })
                self.tracker.log_success(f"EventGridTopic: {name} ({rg})")
            return {"event_grid_topics": result}

        def _domains():
            domains = self._az(["eventgrid", "domain", "list", "-g", rg]) or []
            result = []
            for d in domains:
                name = d.get("name", "")
                show = self._az(["eventgrid", "domain", "show", "-n", name, "-g", rg]) or d
                dom_topics = self._az([
                    "eventgrid", "domain", "topic", "list", "-g", rg, "--domain-name", name,
                ]) or []
                result.append({
                    "id": show.get("id"), "name": name,
                    "location": show.get("location"), "resourceGroup": rg,
                    "tags": show.get("tags") or {},
                    "endpoint": safe_get(show, "endpoint"),
                    "input_schema": safe_get(show, "inputSchema"),
                    "public_network_access": safe_get(show, "publicNetworkAccess"),
                    "provisioning_state": safe_get(show, "provisioningState"),
                    "domain_topics": [{"name": dt.get("name")} for dt in dom_topics],
                    "domain_topics_count": len(dom_topics),
                })
                self.tracker.log_success(f"EventGridDomain: {name} ({rg})")
            return {"event_grid_domains": result}

        merged = {}
        with ThreadPoolExecutor(max_workers=2) as ex:
            futs = [ex.submit(_topics), ex.submit(_domains)]
        for fut in as_completed(futs):
            try:
                merged.update(fut.result())
            except Exception as e:
                self.tracker.log_warning(f"EventGrid in {rg}: {e}")
        return merged

    def collect_other_resources(self, rg):
        SKIP_TYPES = {
            "microsoft.web/sites", "microsoft.web/serverfarms",
            "microsoft.sql/servers", "microsoft.sql/servers/databases",
            "microsoft.storage/storageaccounts", "microsoft.keyvault/vaults",
            "microsoft.insights/components",
            "microsoft.operationalinsights/workspaces",
            "microsoft.managedidentity/userassignedidentities",
            "microsoft.eventgrid/topics",
            "microsoft.eventgrid/domains",
            "microsoft.eventgrid/domains/topics",
            "microsoft.alertsmanagement/smartdetectoralertrules",
            "microsoft.insights/metricalerts",
            "microsoft.insights/scheduledqueryrules",
            "microsoft.insights/activitylogalerts",
            "microsoft.insights/actiongroups",
        }
        all_res = self._az(["resource", "list", "-g", rg]) or []
        others = [r for r in all_res
                  if r.get("type", "").lower() not in SKIP_TYPES
                  and not r.get("type", "").lower().startswith("microsoft.network/")]
        result = []
        for r in others:
            try:
                details = self._az(["resource", "show", "--ids", r["id"]])
            except Exception:
                details = None
            result.append({
                "id": r["id"], "name": r["name"], "type": r["type"],
                "location": r["location"], "resourceGroup": rg,
                "tags": r.get("tags") or {},
                "sku": safe_get(details, "sku"),
                "kind": safe_get(details, "kind"),
                "note": "Full config in raw-data JSON",
            })
        return {"other_resources": result}


# ── Prompts 10+11: DependencyMapper ──────────────────────────────────────────
class DependencyMapper:

    def __init__(self, inventory, tracker):
        self.inventory = inventory
        self.tracker = tracker
        self._nodes = {}
        self._edges = []
        self._edge_counter = 0

    def _node_id(self, rg, short_type, name):
        return f"{short_type}__{rg}__{name}".lower().replace(" ", "_").replace("/", "_")

    def _add_edge(self, src, tgt, rel, confidence, impact, evidence, note=""):
        if not src or not tgt or src == tgt:
            return
        self._edge_counter += 1
        self._edges.append({
            "edge_id": f"edge_{self._edge_counter:04d}",
            "source_node_id": src, "target_node_id": tgt,
            "relationship": rel, "confidence": confidence,
            "migration_impact": impact, "evidence_detail": evidence,
            "migration_note": note,
        })

    def build_nodes(self):
        TYPE_MAP = {
            "web_apps": "WebApp", "function_apps": "FunctionApp",
            "app_service_plans": "AppPlan", "sql_servers": "SQLServer",
            "sql_databases": "SQLDatabase", "storage_accounts": "Storage",
            "key_vaults": "KeyVault", "virtual_networks": "VNet",
            "network_security_groups": "NSG", "application_gateways": "AppGateway",
            "waf_policies": "WAFPolicy", "load_balancers": "LoadBalancer",
            "traffic_managers": "TrafficManager", "managed_identities": "ManagedIdentity",
            "log_analytics_workspaces": "LogAnalytics", "app_insights": "AppInsights",
            "private_endpoints": "PrivateEndpoint", "private_dns_zones": "PrivateDNS",
            "route_tables": "RouteTable", "public_ips": "PublicIP",
            "other_resources": "Other",
        }
        COMPUTE_TYPES = {"web_apps", "function_apps", "application_gateways"}
        for rg_name, rg_data in self.inventory.get("resource_groups", {}).items():
            for resource_type, resource_list in rg_data.get("resources", {}).items():
                short = TYPE_MAP.get(resource_type, resource_type)
                for r in resource_list:
                    nid = self._node_id(rg_name, short, r.get("name", ""))
                    self._nodes[nid] = {
                        "node_id": nid, "display_name": r.get("name"),
                        "short_type": short, "resource_group": rg_name,
                        "location": r.get("location"),
                        "is_compute": resource_type in COMPUTE_TYPES,
                        "resource_ref": r,
                    }

    def build_edges(self):
        def find_node(short_type, name, preferred_rg=None):
            if not name:
                return None
            direct = self._node_id(preferred_rg or rg_name, short_type, name)
            if direct in self._nodes:
                return direct
            for nid, n in self._nodes.items():
                if n["short_type"] == short_type and n["display_name"] == name:
                    return nid
            return None

        for rg_name, rg_data in self.inventory.get("resource_groups", {}).items():
            resources = rg_data.get("resources", {})

            all_apps = [(a, False) for a in resources.get("web_apps", [])] + \
                       [(a, True)  for a in resources.get("function_apps", [])]
            for app, is_func in all_apps:
                app_type = "FunctionApp" if is_func else "WebApp"
                src = self._node_id(rg_name, app_type, app["name"])

                plan = find_node("AppPlan", app.get("server_farm_name"), rg_name)
                if plan:
                    self._add_edge(src, plan, "HOSTED_ON_APP_SERVICE_PLAN",
                        "CONFIRMED", "CRITICAL", "serverFarmId reference",
                        "Plan must exist before app deployment")

                for vi in app.get("vnet_integration", []):
                    vnet = find_node("VNet", vi.get("vnet_name"), rg_name)
                    if vnet:
                        self._add_edge(src, vnet, "VNET_INTEGRATION",
                            "CONFIRMED", "CRITICAL", "virtualNetworkSubnetId",
                            "Subnet needs Microsoft.Web/serverFarms delegation")

                for kvr in app.get("kv_references", []):
                    kv = find_node("KeyVault", kvr.get("vault_name"))
                    if kv:
                        self._add_edge(src, kv, "READS_SECRET_FROM_KEYVAULT",
                            "CONFIRMED", "CRITICAL", f"@KeyVault ref: {kvr.get('key_name')}",
                            "App fails if KV reference resolution fails in new tenant")

                pid = app.get("principal_id")
                if pid:
                    for kv_rg, kv_rg_data in self.inventory.get("resource_groups", {}).items():
                        for kv in kv_rg_data.get("resources", {}).get("key_vaults", []):
                            for pol in kv.get("access_policies", []):
                                if pol.get("objectId") == pid:
                                    kv_nid = self._node_id(kv_rg, "KeyVault", kv["name"])
                                    self._add_edge(src, kv_nid, "ACCESSES_KEYVAULT",
                                        "CONFIRMED", "CRITICAL",
                                        "KV access policy objectId matches principalId",
                                        "Access policy objectId is tenant-specific - must be remapped")

                sql_keys = [k for k in app.get("app_setting_keys", [])
                            if re.search(r'sql|database|dbconn|connectionstr', k, re.I)]
                if sql_keys:
                    for sql_s in resources.get("sql_servers", []):
                        tgt = self._node_id(rg_name, "SQLServer", sql_s["name"])
                        self._add_edge(src, tgt, "CONNECTS_TO_SQL", "INFERRED", "CRITICAL",
                            f"Key names: {', '.join(sql_keys[:3])}",
                            "Connection string must be updated with new server FQDN")

                st_keys = [k for k in app.get("app_setting_keys", [])
                           if re.search(r'storage|blob|azurewebjobs', k, re.I)]
                if st_keys:
                    for sa in resources.get("storage_accounts", []):
                        tgt = self._node_id(rg_name, "Storage", sa["name"])
                        self._add_edge(src, tgt, "READS_WRITES_STORAGE", "INFERRED", "HIGH",
                            f"Key names: {', '.join(st_keys[:3])}",
                            "Storage endpoint changes; SAS tokens invalidated")

                if is_func and app.get("has_job_storage"):
                    sas = resources.get("storage_accounts", [])
                    conf = "CONFIRMED" if len(sas) == 1 else "INFERRED"
                    for sa in sas:
                        tgt = self._node_id(rg_name, "Storage", sa["name"])
                        self._add_edge(src, tgt, "FUNCTION_JOB_STORAGE", conf, "CRITICAL",
                            "AzureWebJobsStorage key present",
                            "Storage must exist BEFORE Function App deployment")

                for ua_id in app.get("user_assigned_identities", []):
                    mi = find_node("ManagedIdentity", parse_resource_name(ua_id))
                    if mi:
                        self._add_edge(src, mi, "USES_USER_ASSIGNED_IDENTITY",
                            "CONFIRMED", "HIGH", "userAssignedIdentities reference",
                            "Identity principalId changes - RBAC must be reassigned")

                if is_func and app.get("has_app_insights"):
                    for ai in resources.get("app_insights", []):
                        tgt = self._node_id(rg_name, "AppInsights", ai["name"])
                        self._add_edge(src, tgt, "MONITORED_BY_APP_INSIGHTS", "INFERRED", "MEDIUM",
                            "APPLICATIONINSIGHTS_CONNECTION_STRING key present",
                            "Instrumentation key must be updated after migration")

                for ds_entry in resources.get("diagnostic_settings", []):
                    if ds_entry.get("resource_name") == app["name"]:
                        for s in ds_entry.get("settings", []):
                            ws = find_node("LogAnalytics", s.get("workspace"))
                            if ws:
                                self._add_edge(src, ws, "LOGS_TO_LOG_ANALYTICS",
                                    "CONFIRMED", "LOW", f"Diagnostic setting: {s.get('name')}",
                                    "Workspace must exist before diagnostic settings")

                for pe in resources.get("private_endpoints", []):
                    for conn in pe.get("connections", []):
                        if conn.get("linked_resource", "").lower() == app["name"].lower():
                            pe_nid = self._node_id(rg_name, "PrivateEndpoint", pe["name"])
                            self._add_edge(pe_nid, src, "ACCESSED_VIA_PRIVATE_ENDPOINT",
                                "CONFIRMED", "HIGH", "privateLinkServiceId reference",
                                "Private endpoint must be in correct subnet in new VNet")

            for agw in resources.get("application_gateways", []):
                agw_nid = self._node_id(rg_name, "AppGateway", agw["name"])
                all_apps_flat = resources.get("web_apps", []) + resources.get("function_apps", [])
                func_names = {a["name"] for a in resources.get("function_apps", [])}
                for pool in agw.get("backend_pools", []):
                    for target in pool.get("targets", []):
                        if not target:
                            continue
                        for app in all_apps_flat:
                            if target == app.get("defaultHostName") or target in app.get("hostNames", []):
                                app_type = "FunctionApp" if app["name"] in func_names else "WebApp"
                                app_nid = self._node_id(rg_name, app_type, app["name"])
                                self._add_edge(agw_nid, app_nid, "APP_GATEWAY_ROUTES_TO",
                                    "CONFIRMED", "CRITICAL", f"Backend pool target: {target}",
                                    "Backend pool must be updated with new hostname after migration")
                waf_name = parse_resource_name(agw.get("waf_policy_id") or "")
                if waf_name:
                    waf = find_node("WAFPolicy", waf_name, rg_name)
                    if waf:
                        self._add_edge(waf, agw_nid, "WAF_PROTECTS",
                            "CONFIRMED", "HIGH", "firewallPolicy reference",
                            "WAF policy must be deployed before App Gateway")

            for tm in resources.get("traffic_managers", []):
                tm_nid = self._node_id(rg_name, "TrafficManager", tm["name"])
                all_apps_flat = resources.get("web_apps", []) + resources.get("function_apps", [])
                func_names = {a["name"] for a in resources.get("function_apps", [])}
                for ep in tm.get("endpoints", []):
                    target = ep.get("target", "")
                    for app in all_apps_flat:
                        if target and (target == app.get("defaultHostName") or target in app.get("hostNames", [])):
                            app_type = "FunctionApp" if app["name"] in func_names else "WebApp"
                            app_nid = self._node_id(rg_name, app_type, app["name"])
                            self._add_edge(tm_nid, app_nid, "TRAFFIC_MANAGER_ROUTES_TO",
                                "CONFIRMED", "CRITICAL", f"TM endpoint target: {target}",
                                "DNS cutover must be coordinated")

            for pe in resources.get("private_endpoints", []):
                pe_nid = self._node_id(rg_name, "PrivateEndpoint", pe["name"])
                for dns_entry in pe.get("custom_dns", []):
                    fqdn = dns_entry.get("fqdn", "")
                    for zone in resources.get("private_dns_zones", []):
                        if fqdn.endswith(zone["name"]):
                            zone_nid = self._node_id(rg_name, "PrivateDNS", zone["name"])
                            self._add_edge(pe_nid, zone_nid, "RESOLVES_VIA_PRIVATE_DNS",
                                "CONFIRMED", "HIGH", f"FQDN {fqdn} matches zone {zone['name']}",
                                "DNS zone VNet links must be recreated")

    def build_compute_flows(self):
        INBOUND  = {"APP_GATEWAY_ROUTES_TO", "TRAFFIC_MANAGER_ROUTES_TO", "ACCESSED_VIA_PRIVATE_ENDPOINT"}
        DATA     = {"CONNECTS_TO_SQL", "READS_WRITES_STORAGE", "FUNCTION_JOB_STORAGE"}
        SECURITY = {"READS_SECRET_FROM_KEYVAULT", "ACCESSES_KEYVAULT", "USES_USER_ASSIGNED_IDENTITY"}
        MONITOR  = {"MONITORED_BY_APP_INSIGHTS", "LOGS_TO_LOG_ANALYTICS"}
        NETWORK  = {"VNET_INTEGRATION", "RESOLVES_VIA_PRIVATE_DNS", "WAF_PROTECTS"}
        ORD      = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        flows = {}
        for nid, node in self._nodes.items():
            if not node.get("is_compute"):
                continue
            def get_edges(rel_set, as_target=False, _nid=nid):
                result = [e for e in self._edges
                          if e["relationship"] in rel_set and
                          (e["target_node_id"] == _nid if as_target else e["source_node_id"] == _nid)]
                return sorted(result, key=lambda e: ORD.get(e["migration_impact"], 9))
            total = sum(1 for e in self._edges
                        if e["source_node_id"] == nid or e["target_node_id"] == nid)
            flows[nid] = {
                "summary": f"{node['display_name']} - {total} relationships",
                "inbound_traffic":         get_edges(INBOUND, as_target=True),
                "outbound_data":           get_edges(DATA),
                "security_dependencies":   get_edges(SECURITY),
                "monitoring_dependencies": get_edges(MONITOR),
                "network_dependencies":    get_edges(NETWORK),
            }
        return flows

    def generate_risk_register(self):
        risks = []
        counter = [0]

        def add_risk(resource, rg, level, category, desc, action, phase, effort):
            counter[0] += 1
            risks.append({
                "risk_id": f"RISK-{counter[0]:03d}",
                "resource_name": resource.get("name"),
                "resource_type": resource.get("type", ""),
                "resource_group": rg,
                "risk_level": level, "risk_category": category,
                "description": desc, "recommended_action": action,
                "migration_phase": phase, "estimated_effort": effort,
            })

        for rg_name, rg_data in self.inventory.get("resource_groups", {}).items():
            r = rg_data.get("resources", {})

            for s in r.get("sql_servers", []):
                for fw in s.get("firewall_rules", []):
                    if fw.get("is_public_warning"):
                        add_risk(s, rg_name, "HIGH", "Security",
                            f"SQL Server {s['name']}: firewall rule allows full public access (0.0.0.0-255.255.255.255)",
                            "Remove public rule; use private endpoint or specific IP allowlist",
                            "Before migration", "Hours")
                if s.get("ad_admin_tenant"):
                    add_risk(s, rg_name, "HIGH", "Identity",
                        "SQL AAD admin tenantId is source tenant - must be recreated in new tenant",
                        "Recreate AAD admin assignment with new tenant admin identity",
                        "During migration", "Minutes")

            for sa in r.get("storage_accounts", []):
                if sa.get("allow_blob_public"):
                    add_risk(sa, rg_name, "HIGH", "Security",
                        "Storage account allows public blob access",
                        "Set allowBlobPublicAccess=false unless specifically required",
                        "Before migration", "Minutes")

            for kv in r.get("key_vaults", []):
                if kv.get("access_policies"):
                    add_risk(kv, rg_name, "HIGH", "Identity",
                        f"Key Vault {kv['name']}: {len(kv['access_policies'])} access policies use source-tenant objectIds",
                        "Re-map all access policies with new tenant object IDs after identity recreation",
                        "During migration", "Hours")
                if safe_get(kv, "net_default") == "Allow" and kv.get("pe_count", 0) == 0:
                    add_risk(kv, rg_name, "HIGH", "Security",
                        "Key Vault has no network restrictions and no private endpoint",
                        "Add network ACL or private endpoint to restrict access",
                        "Before migration", "Hours")

            for mi in r.get("managed_identities", []):
                if mi.get("role_assignments"):
                    add_risk(mi, rg_name, "HIGH", "Identity",
                        f"Managed identity {mi['name']} has {len(mi['role_assignments'])} RBAC assignments to recreate",
                        "After recreating identity in new tenant, re-assign all roles. PrincipalId will change.",
                        "After migration", "Hours")

            for app in r.get("web_apps", []) + r.get("function_apps", []):
                if app.get("httpsOnly") is False:
                    add_risk(app, rg_name, "HIGH", "Security",
                        f"{app['name']}: HTTPS not enforced",
                        "Set httpsOnly=true on app and redirect HTTP requests",
                        "Before migration", "Minutes")
                is_func = "function" in (app.get("kind") or "").lower()
                if is_func and not app.get("has_job_storage"):
                    add_risk(app, rg_name, "HIGH", "Config",
                        f"Function App {app['name']}: AzureWebJobsStorage key not detected",
                        "Ensure AzureWebJobsStorage is configured - Function App will not start without it",
                        "During migration", "Minutes")

            for app in r.get("web_apps", []) + r.get("function_apps", []):
                if not app.get("vnet_integration"):
                    add_risk(app, rg_name, "MEDIUM", "Network",
                        f"{app['name']}: No VNet integration - outbound traffic is public",
                        "Consider adding VNet integration for secure outbound connectivity",
                        "Before migration", "Hours")
                if app.get("custom_domains"):
                    add_risk(app, rg_name, "MEDIUM", "Config",
                        f"{app['name']}: Has custom domain(s): {', '.join(app.get('custom_domains', []))}",
                        "Custom domains require re-verification in new tenant. Prepare TXT/CNAME records.",
                        "Before migration", "Hours")

            for sa in r.get("storage_accounts", []):
                if sa.get("allow_shared_key") is True:
                    add_risk(sa, rg_name, "MEDIUM", "Security",
                        f"Storage {sa['name']}: Shared Key access enabled - prefer Managed Identity",
                        "Evaluate migrating to Managed Identity-based access, disable shared key if possible",
                        "After migration", "Days")

            for res_type, res_list in r.items():
                for res in res_list:
                    if not res.get("tags"):
                        add_risk(res, rg_name, "LOW", "Governance",
                            f"{res.get('name', '?')} ({res_type}) has no tags",
                            "Add required tags (environment, team, cost-center) before migration",
                            "Before migration", "Minutes")
        return risks

    def generate_migration_order(self):
        GROUP_RULES = [
            (1, "Foundation - no Azure dependencies",
             {"private_dns_zones", "log_analytics_workspaces", "managed_identities",
              "network_security_groups", "route_tables"}),
            (2, "Networking",
             {"virtual_networks", "public_ips"}),
            (3, "Data + Security Foundations",
             {"key_vaults", "storage_accounts", "sql_servers"}),
            (4, "Compute Prerequisites",
             {"app_service_plans", "sql_databases", "app_insights", "private_endpoints"}),
            (5, "Compute Services",
             {"web_apps", "function_apps", "application_gateways", "waf_policies"}),
            (6, "Traffic + Monitoring",
             {"load_balancers", "traffic_managers", "alert_rules", "diagnostic_settings"}),
            (7, "Post-Deployment Manual Steps", set()),
        ]
        groups = []
        for group_num, desc, types in GROUP_RULES:
            items = []
            if group_num == 7:
                items = [{"group": 7, "rg": "all", "name": step, "type": "manual", "note": desc}
                         for step in [
                             "Re-verify custom domains", "Rebind SSL certificates",
                             "Re-assign all RBAC role assignments",
                             "Restore managed identity roles", "Coordinate DNS cutover",
                         ]]
            else:
                for rg_name, rg_data in self.inventory.get("resource_groups", {}).items():
                    for rt in types:
                        for res in rg_data.get("resources", {}).get(rt, []):
                            items.append({"group": group_num, "rg": rg_name,
                                          "name": res.get("name"), "type": rt, "note": desc})
            groups.append({"group": group_num, "description": desc, "resources": items})
        return {"groups": groups}

    def build_git_edges(self):
        """Create dependency edges from Git code-scan findings.
        Edges are added FROM the matched compute app TO the found Azure resource."""
        findings      = self.inventory.get("git_findings", [])
        repo_to_apps  = self.inventory.get("git_repo_to_apps", {})
        nodes_by_name = {}   # lower_name -> node_id (for quick lookup)
        for nid, node in self._nodes.items():
            nodes_by_name[node["display_name"].lower()] = nid

        PATTERN_TO_REL = {
            # Compute
            "WEBAPP_ENDPOINT":             "CODE_CALLS_WEBAPP",
            "CONTAINER_APP_ENDPOINT":      "CODE_CALLS_CONTAINER_APP",
            "FRONTDOOR_ENDPOINT":          "CODE_BEHIND_FRONTDOOR",
            "CDN_ENDPOINT":                "CODE_BEHIND_CDN",
            # Data / Storage
            "SQL_SERVER_ENDPOINT":         "CODE_CONNECTS_TO_SQL",
            "HARDCODED_SQL_PASSWORD":      "CODE_CONNECTS_TO_SQL",
            "STORAGE_ENDPOINT":            "CODE_READS_WRITES_STORAGE",
            "STORAGE_ACCOUNT_NAME":        "CODE_READS_WRITES_STORAGE",
            "HARDCODED_STORAGE_KEY":       "CODE_READS_WRITES_STORAGE",
            "SAS_TOKEN":                   "CODE_READS_WRITES_STORAGE",
            "COSMOS_ENDPOINT":             "CODE_CONNECTS_TO_COSMOS",
            "COSMOS_CONN_STR":             "CODE_CONNECTS_TO_COSMOS",
            "REDIS_ENDPOINT":              "CODE_CONNECTS_TO_REDIS",
            "REDIS_CONN_STR":              "CODE_CONNECTS_TO_REDIS",
            # Messaging / Events
            "SERVICE_BUS_ENDPOINT":        "CODE_USES_SERVICE_BUS",
            "SERVICEBUS_CONN_STR":         "CODE_USES_SERVICE_BUS",
            "EVENTHUB_ENTITY":             "CODE_USES_EVENT_HUB",
            "EVENTHUB_CONN_STR":           "CODE_USES_EVENT_HUB",
            "EVENT_GRID_ENDPOINT":         "CODE_PUBLISHES_TO_EVENT_GRID",
            "EVENT_GRID_KEY":              "CODE_PUBLISHES_TO_EVENT_GRID",
            # Security / Identity
            "KEY_VAULT_ENDPOINT":          "CODE_READS_KEYVAULT",
            "KEY_VAULT_REF":               "CODE_READS_KEYVAULT",
            # AI / Cognitive / Search
            "COGNITIVE_ENDPOINT":          "CODE_CALLS_COGNITIVE_SERVICES",
            "OPENAI_ENDPOINT":             "CODE_CALLS_AZURE_OPENAI",
            "SEARCH_ENDPOINT":             "CODE_USES_AZURE_SEARCH",
            "SEARCH_CONN_STR":             "CODE_USES_AZURE_SEARCH",
            # Monitoring
            "APP_INSIGHTS_KEY":            "CODE_SENDS_TO_APP_INSIGHTS",
            "APP_INSIGHTS_CONN":           "CODE_SENDS_TO_APP_INSIGHTS",
            "APP_INSIGHTS_SDK":            "CODE_SENDS_TO_APP_INSIGHTS",
            # Registry / DevOps
            "CONTAINER_REGISTRY_ENDPOINT": "CODE_PULLS_FROM_CONTAINER_REGISTRY",
            # IoT / RT
            "IOT_HUB_ENDPOINT":            "CODE_CONNECTS_TO_IOT_HUB",
            "SIGNALR_ENDPOINT":            "CODE_USES_SIGNALR",
            # Config
            "APP_CONFIG_ENDPOINT":         "CODE_READS_APP_CONFIGURATION",
        }

        for f in findings:
            repo_lc   = f["repo_name"].lower()
            rname     = f["matched_resource_name"].lower()
            ptype     = f["pattern_type"]
            rel       = PATTERN_TO_REL.get(ptype)
            if not rel or not rname:
                continue

            # find which compute apps own this repo
            source_node_ids = []
            for app_entry in repo_to_apps.get(repo_lc, []):
                nid = nodes_by_name.get(app_entry["app_name"].lower())
                if nid:
                    source_node_ids.append(nid)

            # find target node by resource name
            tgt_nid = nodes_by_name.get(rname)
            if not tgt_nid:
                continue   # resource not in inventory, skip edge

            confidence = "CONFIRMED" if f["confirmed_in_inventory"] else "INFERRED"
            impact     = "CRITICAL" if f["is_hardcoded_secret"] else \
                         "HIGH"     if f["severity"] == "HIGH" else "MEDIUM"
            evidence   = f"Code: {f['file_path']}:{f['line_number']}"
            note       = ("Hardcoded secret found in code — MUST rotate after migration. "
                          if f["is_hardcoded_secret"] else
                          "Endpoint/name hardcoded in code — update after migration.")

            for src_nid in source_node_ids:
                self._add_edge(src_nid, tgt_nid, rel, confidence, impact, evidence, note)

            # if no app matched, still add a standalone finding node
            if not source_node_ids:
                # create a virtual node for the repo itself
                repo_node_id = f"repo__{repo_lc.replace(' ', '_')}"
                if repo_node_id not in self._nodes:
                    self._nodes[repo_node_id] = {
                        "node_id": repo_node_id,
                        "display_name": f["repo_name"],
                        "short_type": "GitRepo",
                        "resource_group": f["project"],
                        "location": "Azure DevOps",
                        "is_compute": True,
                        "resource_ref": {"name": f["repo_name"],
                                         "type": "GitRepo",
                                         "project": f["project"]},
                    }
                self._add_edge(repo_node_id, tgt_nid, rel, confidence, impact,
                               evidence, note)

    def build_full_dependency_map(self):
        self.tracker.start_phase("Building Dependency Map - Nodes", 1)
        self.build_nodes()
        self.tracker.log_success(f"Nodes: {len(self._nodes)}")
        self.tracker.start_phase("Building Dependency Map - Edges", 1)
        self.build_edges()
        self.tracker.log_success(f"Infrastructure edges: {len(self._edges)}")

        if self.inventory.get("git_findings"):
            self.tracker.start_phase("Building Git Code Edges", 1)
            before = len(self._edges)
            self.build_git_edges()
            self.tracker.log_success(
                f"Git code edges added: {len(self._edges) - before}")

        flows = self.build_compute_flows()
        return {
            "nodes": list(self._nodes.values()),
            "edges": self._edges,
            "compute_dependency_flows": flows,
        }


# ── Prompts 12+13: HTMLReportGenerator ───────────────────────────────────────
class HTMLReportGenerator:

    # ── service-team mappings ─────────────────────────────────────────────────
    _TEAM_MAP = {
        "web_apps":                   "compute",
        "function_apps":              "compute",
        "app_service_plans":          "compute",
        "virtual_machines":           "compute",
        "container_registries":       "compute",
        "aks_clusters":               "compute",
        "container_apps":             "compute",
        "sql_servers":                "data",
        "sql_databases":              "data",
        "storage_accounts":           "data",
        "cosmos_db":                  "data",
        "redis_caches":               "data",
        "data_factories":             "data",
        "databricks_workspaces":      "data",
        "search_services":            "data",
        "key_vaults":                 "security",
        "managed_identities":         "security",
        "virtual_networks":           "networking",
        "network_security_groups":    "networking",
        "route_tables":               "networking",
        "public_ips":                 "networking",
        "private_endpoints":          "networking",
        "private_dns_zones":          "networking",
        "application_gateways":       "networking",
        "waf_policies":               "networking",
        "load_balancers":             "networking",
        "traffic_managers":           "networking",
        "log_analytics_workspaces":   "monitoring",
        "app_insights":               "monitoring",
        "diagnostic_settings":        "monitoring",
        "alert_rules":                "monitoring",
        "action_groups":              "monitoring",
        "activity_log_alerts":        "monitoring",
        "scheduled_query_alerts":     "monitoring",
        "smart_detector_alert_rules": "monitoring",
        "event_grid_topics":          "integration",
        "event_grid_domains":         "integration",
        "service_bus":                "integration",
        "event_hubs":                 "integration",
        "api_management":             "integration",
        "notification_hubs":          "integration",
        "cdn_profiles":               "integration",
    }
    _TEAM_LABELS = {
        "compute":     ("Compute",     "#0078D4"),
        "data":        ("Data",        "#217346"),
        "networking":  ("Networking",  "#8764B8"),
        "security":    ("Security",    "#C50F1F"),
        "monitoring":  ("Monitoring",  "#CA5010"),
        "integration": ("Integration", "#986F0B"),
    }
    # Risk category → team slug
    _CATEGORY_TO_TEAM = {
        "Security":   "security",
        "Identity":   "security",
        "Secret":     "security",
        "Config":     "compute",
        "Network":    "networking",
        "Governance": "monitoring",
        "Performance":"compute",
        "Cost":       "monitoring",
    }
    # Checklist owner → team slug (space-separated for multi-team)
    _OWNER_TO_TEAM = {
        "Ops":          "monitoring",
        "DBA":          "data",
        "Security":     "security",
        "Network":      "networking",
        "DevOps":       "compute",
        "Identity":     "security",
        "QA":           "compute",
        "DBA/Security": "data security",
        "All":          "",
    }

    def __init__(self, inventory, dep_map, risks, order):
        self.inv   = inventory
        self.dep   = dep_map
        self.risks = risks
        self.order = order

    def generate(self, output_dir):
        path = Path(output_dir) / "reports" / "azure-migration-inventory-report.html"
        path.write_text(self._build_html(), encoding="utf-8")
        return str(path)

    def _esc(self, s):
        return str(s).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace('"',"&quot;")

    def _all_resources(self):
        for rg_data in self.inv.get("resource_groups", {}).values():
            for res_type, res_list in rg_data.get("resources", {}).items():
                yield res_type, res_list

    # ── service-team tag helpers ──────────────────────────────────────────────
    _SVC_TEAM_TAG_KEYS = frozenset(('serviceteam', 'service-team', 'service_team'))

    def _get_res_svc_team(self, res: dict) -> str:
        """Return the value of the serviceTeam/service-team/service_team tag, or ''."""
        for k, v in (res.get("tags") or {}).items():
            if k.lower() in self._SVC_TEAM_TAG_KEYS:
                return str(v)
        return ''

    def _collect_tag_teams(self) -> dict:
        """Return {team_name: [(rg_name, res_type, res), ...]} for all tag-based teams."""
        result: dict = {}
        for rg_name, rg_data in self.inv.get("resource_groups", {}).items():
            for res_type, res_list in rg_data.get("resources", {}).items():
                for res in res_list:
                    t = self._get_res_svc_team(res)
                    if t:
                        result.setdefault(t, []).append((rg_name, res_type, res))
        return result

    def _css(self):
        return """<style>
*{box-sizing:border-box}
body{font-family:Segoe UI,Arial,sans-serif;margin:0;background:#f5f5f5;color:#333}
nav{position:sticky;top:0;background:#0078D4;padding:8px 16px;z-index:100;display:flex;gap:12px;flex-wrap:wrap;align-items:center}
nav a{color:white;text-decoration:none;font-size:13px;padding:4px 8px;border-radius:4px}
nav a:hover{background:rgba(255,255,255,.2)}
#global-search{padding:5px 10px;border:none;border-radius:4px;font-size:13px;width:240px;margin-left:auto;outline:none}
#global-search:focus{box-shadow:0 0 0 2px rgba(255,255,255,.5)}
#search-count{color:rgba(255,255,255,.85);font-size:12px;min-width:80px}
.page{max-width:1400px;margin:0 auto;padding:16px}
h1{color:#0078D4}
h2{background:#0078D4;color:white;padding:10px 16px;border-radius:6px}
h3{color:#005a9e;border-bottom:2px solid #0078D4;padding-bottom:4px}
details{background:white;border:1px solid #ddd;border-radius:6px;margin-bottom:8px}
summary{padding:10px 16px;cursor:pointer;font-weight:bold;background:#EBF3FB;border-radius:6px}
summary:hover{background:#d0e8f8}
table{width:100%;border-collapse:collapse;font-size:13px;margin-top:8px}
th{background:#0078D4;color:white;padding:8px;text-align:left;cursor:pointer}
td{padding:6px 8px;border-bottom:1px solid #e0e0e0;vertical-align:top}
tr:nth-child(even) td{background:#EBF3FB}
tr:hover td{background:#d0e8f8}
.card{background:white;border:1px solid #ddd;border-radius:8px;padding:16px;margin-bottom:12px;box-shadow:0 1px 4px rgba(0,0,0,.08)}
.rg-header{background:#0078D4;color:white;border-radius:8px 8px 0 0;padding:12px 16px}
.rg-empty{background:#aaa}
.cards-grid{display:flex;flex-wrap:wrap;gap:12px;margin-bottom:16px}
.count-card{background:white;border:1px solid #ddd;border-radius:8px;padding:12px 16px;min-width:140px;text-align:center}
.count-card .num{font-size:2em;font-weight:bold;color:#0078D4}
.count-card .label{font-size:12px;color:#666}
.chip{display:inline-block;padding:2px 8px;border-radius:12px;font-size:11px;margin:2px}
.chip-sql{background:#dbeeff;color:#003a70}
.chip-storage{background:#d4efdf;color:#1a5c2e}
.chip-kv{background:#fde7e9;color:#8b0000}
.chip-inbound{background:#e8f5e9;color:#2e7d32}
.chip-other{background:#f0f0f0;color:#555}
.risk-HIGH{background:#FFB3B3;color:#8B0000;padding:2px 6px;border-radius:4px;font-weight:bold}
.risk-MEDIUM{background:#FFF3B3;color:#7A5C00;padding:2px 6px;border-radius:4px;font-weight:bold}
.risk-LOW{background:#C6EFCE;color:#276221;padding:2px 6px;border-radius:4px}
.filter-input{padding:6px 10px;border:1px solid #ccc;border-radius:4px;margin-bottom:8px;width:300px;font-size:13px}
.flow-box{background:#1e1e1e;color:#d4d4d4;font-family:monospace;font-size:12px;padding:16px;border-radius:6px;overflow-x:auto;white-space:pre}
.btn{padding:8px 16px;background:#0078D4;color:white;border:none;border-radius:4px;cursor:pointer;margin:4px}
.btn:hover{background:#005a9e}
#backToTop{position:fixed;bottom:24px;right:24px;background:#0078D4;color:white;border:none;border-radius:50%;width:40px;height:40px;font-size:18px;cursor:pointer;z-index:200}
@media print{nav,#backToTop,.btn,#team-filter-bar{display:none!important}}
#team-filter-bar{position:sticky;top:43px;z-index:99;background:#1a4f8a;padding:5px 16px;display:flex;gap:6px;align-items:center;flex-wrap:wrap;border-bottom:1px solid rgba(255,255,255,.15)}
#team-filter-bar span{color:rgba(255,255,255,.75);font-size:11px;margin-right:4px;text-transform:uppercase;letter-spacing:0.5px}
.team-pill{border:none;border-radius:20px;padding:3px 12px;font-size:12px;cursor:pointer;font-weight:600;opacity:.7;transition:opacity .15s,box-shadow .15s;color:white}
.team-pill:hover{opacity:.9}
.team-pill.active{opacity:1;box-shadow:0 0 0 2px white,0 0 0 4px var(--tc)}
.team-pill[data-team='all']{background:#555}
.team-pill[data-team='compute']{background:#0078D4;--tc:#0078D4}
.team-pill[data-team='data']{background:#217346;--tc:#217346}
.team-pill[data-team='networking']{background:#8764B8;--tc:#8764B8}
.team-pill[data-team='security']{background:#C50F1F;--tc:#C50F1F}
.team-pill[data-team='monitoring']{background:#CA5010;--tc:#CA5010}
.team-pill[data-team='integration']{background:#986F0B;--tc:#986F0B}
</style>"""

    def _js(self):
        return """<script>
function filterTable(inputId,tableId){
  var v=document.getElementById(inputId).value.toLowerCase().trim();
  document.querySelectorAll('#'+tableId+' tbody tr').forEach(function(tr){
    tr.style.display=tr.textContent.toLowerCase().includes(v)?'':'none';
  });
}
var _gsTimer=null;
var _activeTeam='';
function globalSearch(val){
  if(_gsTimer) clearTimeout(_gsTimer);
  _gsTimer=setTimeout(function(){ _doGlobalSearch(val); }, 150);
}
function filterByTeam(team){
  _activeTeam=(team==='all')?'':team;
  document.querySelectorAll('.team-pill').forEach(function(p){
    p.classList.toggle('active', p.dataset.team===(team||'all'));
  });
  _doGlobalSearch(document.getElementById('global-search').value);
}
function _rowMatchesTeam(tr){
  if(!_activeTeam) return true;
  var t=tr.dataset.team||'';
  return t===_activeTeam || t.split(' ').indexOf(_activeTeam)!==-1;
}
function _doGlobalSearch(val){
  var v=(val||'').toLowerCase().trim();
  var countEl=document.getElementById('search-count');
  if(!v && !_activeTeam){
    // restore everything
    document.querySelectorAll('table tbody tr').forEach(function(tr){tr.style.display='';});
    document.querySelectorAll('details').forEach(function(d){d.style.display='';d.open=false;});
    document.querySelectorAll('.card').forEach(function(el){el.style.display='';});
    document.querySelectorAll('.rg-header').forEach(function(el){el.style.display='';});
    if(countEl) countEl.textContent='';
    return;
  }
  var found=0;
  // Use textContent (not innerText) so rows inside closed <details> are still searchable
  document.querySelectorAll('table tbody tr').forEach(function(tr){
    var matchSearch=!v || tr.textContent.toLowerCase().includes(v);
    var matchTeam=_rowMatchesTeam(tr);
    var show=matchSearch && matchTeam;
    tr.style.display=show?'':'none';
    if(show) found++;
  });
  // Show/hide parent <details> based on visible child rows; auto-expand matching ones
  document.querySelectorAll('details').forEach(function(d){
    var hasMatch=Array.from(d.querySelectorAll('tbody tr')).some(function(tr){return tr.style.display!=='none';});
    d.style.display=hasMatch?'':'none';
    if(hasMatch) d.open=true;
  });
  // Also search dependency flow boxes (pre.flow-box) in the Dep Flows section
  document.querySelectorAll('pre.flow-box').forEach(function(pre){
    var card=pre.closest('.card');
    if(!card) return;
    var match=!v || pre.textContent.toLowerCase().includes(v);
    card.style.display=match?'':'none';
    if(match) found++;
  });
  // Show/hide rg-header along with its following sibling cards
  document.querySelectorAll('.rg-header').forEach(function(hdr){
    var el=hdr.nextElementSibling;
    var anyVisible=false;
    while(el && !el.classList.contains('rg-header')){
      if(el.style.display!=='none') anyVisible=true;
      el=el.nextElementSibling;
    }
    hdr.style.display=anyVisible?'':'none';
  });
  if(countEl) countEl.textContent=found+' match'+(found===1?'':'es');
}
function sortTable(th){
  var table=th.closest('table'),tbody=table.querySelector('tbody');
  var idx=Array.from(th.parentNode.children).indexOf(th);
  var asc=th.dataset.asc!=='true';
  th.dataset.asc=asc;
  Array.from(tbody.querySelectorAll('tr'))
    .sort(function(a,b){
      var av=a.cells[idx]?a.cells[idx].innerText:'';
      var bv=b.cells[idx]?b.cells[idx].innerText:'';
      return asc?av.localeCompare(bv):bv.localeCompare(av);
    })
    .forEach(function(tr){tbody.appendChild(tr);});
}
document.addEventListener('DOMContentLoaded',function(){
  document.querySelectorAll('th').forEach(function(th){
    th.addEventListener('click',function(){sortTable(th);});
  });
  document.getElementById('backToTop').onclick=function(){window.scrollTo({top:0,behavior:'smooth'});};
});
</script>"""

    def _section_summary(self):
        sub = self.inv.get("subscription", {})
        rgs = self.inv.get("resource_groups", {})
        counts = {}
        for res_type, res_list in self._all_resources():
            counts[res_type] = counts.get(res_type, 0) + len(res_list)
        high   = sum(1 for r in self.risks if r["risk_level"] == "HIGH")
        medium = sum(1 for r in self.risks if r["risk_level"] == "MEDIUM")
        low    = sum(1 for r in self.risks if r["risk_level"] == "LOW")
        empty  = sum(1 for r in rgs.values() if r.get("is_empty"))
        parts = []
        parts.append('<div id="summary" class="page">')
        parts.append('<h1>Azure Migration Inventory Report</h1>')
        parts.append('<div class="card"><table><tr><th>Field</th><th>Value</th></tr>')
        parts.append(f'<tr><td>Generated</td><td>{datetime.datetime.now().strftime("%Y-%m-%d %H:%M")}</td></tr>')
        parts.append(f'<tr><td>Subscription</td><td>{self._esc(sub.get("name",""))} ({self._esc(sub.get("id",""))})</td></tr>')
        parts.append(f'<tr><td>Tenant ID</td><td>{self._esc(sub.get("tenantId",""))}</td></tr>')
        parts.append(f'<tr><td>Resource Groups</td><td>{len(rgs)} ({empty} empty)</td></tr>')
        parts.append('</table></div>')
        parts.append('<div class="cards-grid">')
        for rt, cnt in sorted(counts.items()):
            if cnt:
                parts.append(f'<div class="count-card"><div class="num">{cnt}</div><div class="label">{self._esc(rt.replace("_"," ").title())}</div></div>')
        parts.append(f'<div class="count-card" style="border-color:#c00"><div class="num" style="color:#c00">{high}</div><div class="label">HIGH Risks</div></div>')
        parts.append(f'<div class="count-card" style="border-color:#c90"><div class="num" style="color:#c90">{medium}</div><div class="label">MEDIUM Risks</div></div>')
        parts.append(f'<div class="count-card" style="border-color:#090"><div class="num" style="color:#090">{low}</div><div class="label">LOW Risks</div></div>')
        parts.append('</div></div>')
        return "\n".join(parts)

    def _build_html(self):
        tag_teams = self._collect_tag_teams()   # {team_name: [(rg, res_type, res), ...]}
        nav_links = [
            ("#summary","Summary"), ("#resource-groups","Resource Groups"),
            ("#service-teams","Service Teams"),
            ("#dep-flows","Dep Flows"), ("#dep-table","Dep Table"),
            ("#risks","Risk Register"), ("#migration-order","Migration Order"),
            ("#checklist","Checklist"),
        ]
        nav = ('<nav>'
               + ''.join(f'<a href="{h}">{t}</a>' for h, t in nav_links)
               + '<input id="global-search" type="search" placeholder="&#128269; Search all resources..." '
               + 'oninput="globalSearch(this.value)" autocomplete="off">'
               + '<span id="search-count"></span>'
               + '</nav>')
        # Static type-based team pills
        static_pills = (
            '<button class="team-pill active" data-team="all" onclick="filterByTeam(\'all\')">All</button>'
            + ''.join(
                f'<button class="team-pill" data-team="{slug}" '
                f'onclick="filterByTeam(\'{slug}\')">'
                f'{label}</button>'
                for slug, (label, _) in self._TEAM_LABELS.items()
            )
        )
        # Dynamic tag-based service-team pills (prefixed with "tag:")
        tag_pills_html = ''.join(
            f'<button class="team-pill" style="background:#f0f8ff;color:#0078D4;border-color:#0078D4" '
            f'data-team="{self._esc(t)}" onclick="filterByTeam(\'{self._esc(t)}\')">'
            f'&#128101; {self._esc(t)}</button>'
            for t in sorted(tag_teams.keys())
        )
        tag_section_html = (
            '<span style="margin-left:12px;color:#666;font-size:12px">Service Team tags:</span>'
            + tag_pills_html
        ) if tag_teams else ''
        team_pills = (
            '<div id="team-filter-bar">'
            + '<span>Filter by team:</span>'
            + static_pills
            + tag_section_html
            + '</div>'
        )
        parts = [
            "<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'>",
            "<meta name='viewport' content='width=device-width,initial-scale=1'>",
            "<title>Azure Migration Inventory</title>",
            self._css(),
            "</head><body>",
            nav,
            team_pills,
            self._section_summary(),
            self._section_resource_groups(),
            self._section_service_teams(tag_teams),
            self._section_dep_flows(),
            self._section_dep_table(),
            self._section_risks(),
            self._section_migration_order(),
            self._section_checklist(),
            "<button id='backToTop'>&#8679;</button>",
            self._js(),
            "</body></html>",
        ]
        return "\n".join(parts)

    def _section_resource_groups(self):
        edge_index = {}
        for e in self.dep.get("edges", []):
            for nid in (e["source_node_id"], e["target_node_id"]):
                edge_index.setdefault(nid, []).append(e)
        parts = ['<div id="resource-groups" class="page"><h2>Resource Groups</h2>']
        for rg_name, rg_data in sorted(self.inv.get("resource_groups", {}).items()):
            is_empty = rg_data.get("is_empty", False)
            header_cls = "rg-header rg-empty" if is_empty else "rg-header"
            loc = safe_get(rg_data, "metadata", "location") or ""
            cnt = rg_data.get("resource_count", 0)
            parts.append(f'<div class="{header_cls}">&#128230; {self._esc(rg_name)} | {self._esc(loc)} | {cnt} resources</div>')
            if is_empty:
                parts.append('<div class="card"><em>Empty resource group - no resources to collect.</em></div>')
                continue
            tags = safe_get(rg_data, "metadata", "tags") or {}
            if tags:
                tag_html = " ".join(f'<span class="chip chip-other">{self._esc(k)}: {self._esc(v)}</span>' for k, v in tags.items())
                parts.append(f'<div class="card">{tag_html}</div>')
            resources = rg_data.get("resources", {})
            for res_type, res_list in resources.items():
                if not res_list:
                    continue
                team = self._TEAM_MAP.get(res_type, "")
                team_attr = f' data-team="{team}"' if team else ''
                label = res_type.replace("_", " ").title()
                team_label, team_color = self._TEAM_LABELS.get(team, (team.title() if team else "", "#888"))
                team_badge = (f' <span style="font-size:10px;background:{team_color};color:white;'
                              f'padding:1px 7px;border-radius:10px;font-weight:normal;vertical-align:middle">'
                              f'{team_label}</span>') if team_label else ''
                parts.append(f'<details{team_attr}><summary>{label} ({len(res_list)}){team_badge}</summary><div class="card">')
                parts.append('<table><thead><tr><th>Name</th><th>Location</th><th>Tags</th><th>Service Team</th><th>Details</th><th>Migration Notes</th></tr></thead><tbody>')
                for res in res_list:
                    name = self._esc(res.get("name",""))
                    loc2 = self._esc(res.get("location",""))
                    tag_pills = " ".join(
                        f'<span class="chip chip-other">{self._esc(k)}</span>'
                        for k in (res.get("tags") or {}).keys()
                    )
                    # ── service-team tag override ──────────────────────────
                    svc_team_val = self._get_res_svc_team(res)
                    res_team_attr = (f' data-team="{self._esc(svc_team_val)}"'
                                     if svc_team_val else team_attr)
                    svc_team_pill = (
                        f'<span class="chip" style="background:#0078D4;color:white;font-size:10px">'
                        f'{self._esc(svc_team_val)}</span>'
                        if svc_team_val else '<span style="color:#999;font-size:11px">—</span>'
                    )
                    # ──────────────────────────────────────────────────────
                    nid_candidates = [k for k in edge_index if res.get("name","").lower() in k.lower()]
                    dep_chips = ""
                    for nid in nid_candidates:
                        for e in edge_index.get(nid, []):
                            rel = e["relationship"]
                            if "SQL" in rel: dep_chips += '<span class="chip chip-sql">SQL</span>'
                            elif "STORAGE" in rel or "JOB_STORAGE" in rel: dep_chips += '<span class="chip chip-storage">Storage</span>'
                            elif "KEYVAULT" in rel: dep_chips += '<span class="chip chip-kv">KV</span>'
                            elif "GATEWAY" in rel or "TRAFFIC" in rel: dep_chips += '<span class="chip chip-inbound">Inbound</span>'
                    details = ""
                    if res_type == "web_apps":
                        details = f"Plan: {self._esc(res.get('server_farm_name',''))} | Runtime: {self._esc(res.get('runtime',''))} | HTTPS: {res.get('httpsOnly')}"
                    elif res_type == "sql_servers":
                        details = f"FQDN: {self._esc(res.get('fqdn',''))} | Ver: {self._esc(res.get('version',''))}"
                    elif res_type == "storage_accounts":
                        details = f"Kind: {self._esc(res.get('kind',''))} | SKU: {self._esc(res.get('sku_name',''))}"
                    elif res_type == "key_vaults":
                        details = f"URI: {self._esc(res.get('vault_uri',''))} | RBAC: {res.get('enable_rbac')}"
                    notes = " | ".join(res.get("bicep_notes", []))
                    parts.append(f'<tr{res_team_attr}><td><strong>{name}</strong>{dep_chips}</td><td>{loc2}</td><td>{tag_pills}</td><td>{svc_team_pill}</td><td>{details}</td><td>{self._esc(notes)}</td></tr>')
                parts.append('</tbody></table></div></details>')
        parts.append('</div>')
        return "\n".join(parts)

    def _section_service_teams(self, tag_teams: dict):
        """Render a section grouping all resources by their serviceTeam/service-team tag."""
        parts = ['<div id="service-teams" class="page"><h2>&#128101; Service Teams</h2>']
        if not tag_teams:
            parts.append('<div class="card"><em>No resources have a <code>serviceTeam</code>, '
                         '<code>service-team</code>, or <code>service_team</code> tag. '
                         'Add that tag to your Azure resources to enable grouping here.</em></div>')
            parts.append('</div>')
            return "\n".join(parts)

        total = sum(len(v) for v in tag_teams.values())
        parts.append(f'<div class="card" style="margin-bottom:12px">'
                     f'<strong>{total}</strong> resources tagged across '
                     f'<strong>{len(tag_teams)}</strong> service team(s).</div>')

        for team_name in sorted(tag_teams.keys()):
            entries = tag_teams[team_name]
            esc_name = self._esc(team_name)
            parts.append(
                f'<details open data-team="{esc_name}">'
                f'<summary>'
                f'<span style="display:inline-block;background:#0078D4;color:white;'
                f'padding:2px 10px;border-radius:12px;font-size:12px;margin-right:6px">'
                f'{esc_name}</span>'
                f'{len(entries)} resource(s)'
                f'</summary>'
                f'<div class="card">'
            )
            parts.append('<table><thead><tr>'
                         '<th>Resource Name</th><th>Type</th>'
                         '<th>Resource Group</th><th>Location</th>'
                         '<th>Other Tags</th></tr></thead><tbody>')
            for rg_name, res_type, res in sorted(entries, key=lambda x: x[2].get("name","").lower()):
                rname = self._esc(res.get("name", ""))
                rloc  = self._esc(res.get("location", ""))
                rtype = self._esc(res_type.replace("_", " ").title())
                rrg   = self._esc(rg_name)
                other_tags = " ".join(
                    f'<span class="chip chip-other">{self._esc(k)}: {self._esc(v)}</span>'
                    for k, v in (res.get("tags") or {}).items()
                    if k.lower() not in self._SVC_TEAM_TAG_KEYS
                ) or '<span style="color:#999;font-size:11px">—</span>'
                parts.append(
                    f'<tr data-team="{esc_name}">'
                    f'<td><strong>{rname}</strong></td>'
                    f'<td>{rtype}</td>'
                    f'<td>{rrg}</td>'
                    f'<td>{rloc}</td>'
                    f'<td>{other_tags}</td>'
                    f'</tr>'
                )
            parts.append('</tbody></table></div></details>')

        parts.append('</div>')
        return "\n".join(parts)

    def _section_dep_flows(self):
        parts = ['<div id="dep-flows" class="page"><h2>Dependency Flows</h2>']
        flows = self.dep.get("compute_dependency_flows", {})
        nodes_by_id = {n["node_id"]: n for n in self.dep.get("nodes", [])}
        for nid, flow in flows.items():
            node  = nodes_by_id.get(nid, {})
            name  = node.get("display_name", "?")
            rg    = node.get("resource_group", "?")
            stype = node.get("short_type", "?")
            lines = [f"┌── {name} ({stype}) - {rg} " + "─" * max(1, 55 - len(name) - len(stype) - len(rg)) + "┐"]
            def section(title, edges, as_target=False):
                if not edges: return
                lines.append(f"│ {title}:")
                for e in edges:
                    other_id   = e["source_node_id"] if as_target else e["target_node_id"]
                    other_node = nodes_by_id.get(other_id, {})
                    other_name = other_node.get("display_name", "?")
                    direction  = f"  {other_name} --[{e['relationship']}]→ THIS" if as_target else f"  → {other_name} [{e['relationship']}]"
                    lines.append(f"│   {direction}  ({e['migration_impact']})  {e.get('evidence_detail','')[:50]}")
            section("INBOUND",  flow.get("inbound_traffic", []),         as_target=True)
            section("DATA",     flow.get("outbound_data", []))
            section("SECURITY", flow.get("security_dependencies", []))
            section("MONITOR",  flow.get("monitoring_dependencies", []))
            section("NETWORK",  flow.get("network_dependencies", []))
            lines.append("└" + "─" * 70 + "┘")
            box = self._esc("\n".join(lines))
            parts.append(f'<div class="card"><pre class="flow-box">{box}</pre></div>')
        parts.append('</div>')
        return "\n".join(parts)

    def _section_dep_table(self):
        nodes_by_id = {n["node_id"]: n for n in self.dep.get("nodes", [])}
        parts = ['<div id="dep-table" class="page"><h2>Dependency Table</h2>']
        parts.append('<input class="filter-input" id="dep-filter" oninput="filterTable(\'dep-filter\',\'dep-tbl\')" placeholder="Filter dependencies...">')
        parts.append('<table id="dep-tbl"><thead><tr>')
        for h in ["Source", "Relationship", "Target", "Confidence", "Impact", "Evidence", "Migration Note"]:
            parts.append(f'<th>{h}</th>')
        parts.append('</tr></thead><tbody>')
        IMPACT_COLORS = {"CRITICAL": "#FFB3B3", "HIGH": "#FFE4B3"}
        for e in self.dep.get("edges", []):
            src_n = nodes_by_id.get(e["source_node_id"], {})
            tgt_n = nodes_by_id.get(e["target_node_id"], {})
            bg    = IMPACT_COLORS.get(e.get("migration_impact", ""), "")
            style = f' style="background:{bg}"' if bg else ""
            row_vals = [
                f"{self._esc(src_n.get('display_name','?'))} <small>({self._esc(src_n.get('short_type',''))})</small>",
                f"<code>{self._esc(e.get('relationship',''))}</code>",
                f"{self._esc(tgt_n.get('display_name','?'))} <small>({self._esc(tgt_n.get('short_type',''))})</small>",
                self._esc(e.get("confidence","")),
                f'<span class="risk-{self._esc(e.get("migration_impact",""))}">{self._esc(e.get("migration_impact",""))}</span>',
                self._esc(e.get("evidence_detail","")),
                self._esc(e.get("migration_note","")),
            ]
            parts.append(f'<tr{style}><td>' + '</td><td>'.join(row_vals) + '</td></tr>')
        parts.append('</tbody></table></div>')
        return "\n".join(parts)

    def _section_risks(self):
        parts = ['<div id="risks" class="page"><h2>Risk Register</h2>']
        parts.append('<input class="filter-input" id="risk-filter" oninput="filterTable(\'risk-filter\',\'risk-tbl\')" placeholder="Filter risks...">')
        parts.append('<table id="risk-tbl"><thead><tr>')
        for h in ["ID","RG","Resource","Type","Level","Category","Description","Action","Phase","Effort"]:
            parts.append(f'<th>{h}</th>')
        parts.append('</tr></thead><tbody>')
        LEVEL_COLORS = {"HIGH": "#FFB3B3", "MEDIUM": "#FFF3B3", "LOW": "#C6EFCE"}
        for r in sorted(self.risks, key=lambda x: {"HIGH": 0, "MEDIUM": 1, "LOW": 2}.get(x["risk_level"], 3)):
            bg = LEVEL_COLORS.get(r["risk_level"], "")
            style = f' style="background:{bg}"' if bg else ""
            team = self._CATEGORY_TO_TEAM.get(r.get("risk_category", ""), "")
            team_attr = f' data-team="{team}"' if team else ''
            parts.append(f'<tr{style}{team_attr}>'
                + f'<td>{self._esc(r["risk_id"])}</td>'
                + f'<td>{self._esc(r["resource_group"])}</td>'
                + f'<td>{self._esc(r["resource_name"])}</td>'
                + f'<td>{self._esc(r["resource_type"])}</td>'
                + f'<td><span class="risk-{self._esc(r["risk_level"])}">{self._esc(r["risk_level"])}</span></td>'
                + f'<td>{self._esc(r["risk_category"])}</td>'
                + f'<td>{self._esc(r["description"])}</td>'
                + f'<td>{self._esc(r["recommended_action"])}</td>'
                + f'<td>{self._esc(r["migration_phase"])}</td>'
                + f'<td>{self._esc(r["estimated_effort"])}</td>'
                + '</tr>')
        parts.append('</tbody></table></div>')
        return "\n".join(parts)

    def _section_migration_order(self):
        parts = ['<div id="migration-order" class="page"><h2>Migration Order</h2>']
        for group in self.order.get("groups", []):
            parts.append(f'<div class="card"><h3>Group {group["group"]}: {self._esc(group["description"])}</h3>')
            if group["resources"]:
                parts.append('<table><thead><tr><th>RG</th><th>Name</th><th>Type</th><th>Note</th></tr></thead><tbody>')
                for res in group["resources"]:
                    team = self._TEAM_MAP.get(res.get("type", ""), "")
                    team_attr = f' data-team="{team}"' if team else ''
                    parts.append(f'<tr{team_attr}><td>{self._esc(res.get("rg",""))}</td><td>{self._esc(res.get("name",""))}</td><td>{self._esc(res.get("type",""))}</td><td>{self._esc(res.get("note",""))}</td></tr>')
                parts.append('</tbody></table>')
            parts.append('</div>')
        parts.append('</div>')
        return "\n".join(parts)

    def _section_checklist(self):
        tasks = [
            ("Pre-Migration","Create new subscription & resource groups in target tenant","Ops",""),
            ("Pre-Migration","Verify AAD tenant configuration and admin access","Identity",""),
            ("Pre-Migration","Recreate all user-assigned managed identities","Identity","PrincipalIds will differ"),
            ("Pre-Migration","Export all SQL databases (bacpac)","DBA",""),
            ("Pre-Migration","Document all custom domain DNS records","Ops",""),
            ("Pre-Migration","Audit all Key Vault access policy objectIds","Security",""),
            ("Pre-Migration","Review all NSG rules for hardcoded external IPs","Network",""),
            ("Pre-Migration","Recreate DevOps service connections for new subscription","DevOps",""),
            ("During Migration","Deploy Group 1: Foundation (DNS Zones, Log Analytics, NSGs, Routes)","Ops",""),
            ("During Migration","Deploy Group 2: Networking (VNets, Subnets, Public IPs)","Network",""),
            ("During Migration","Deploy Group 3: Data+Security (Key Vaults, Storage, SQL Servers)","DBA/Security",""),
            ("During Migration","Assign initial KV access policies using new tenant objectIds","Security",""),
            ("During Migration","Deploy Group 4: Compute Prerequisites (Plans, SQL DBs, App Insights, PEs)","Ops",""),
            ("During Migration","Deploy Group 5: Compute Services (Web Apps, Function Apps, App Gateways)","DevOps",""),
            ("During Migration","Update all connection strings and app settings","DevOps",""),
            ("During Migration","Deploy Group 6: Traffic+Monitoring (LB, TM, Diagnostics, Alerts)","Ops",""),
            ("Post-Migration","Verify all apps start and respond (smoke test)","QA",""),
            ("Post-Migration","Re-verify and rebind all custom domains and SSL certificates","Ops",""),
            ("Post-Migration","Re-assign all RBAC role assignments for managed identities","Security",""),
            ("Post-Migration","Validate Application Insights telemetry flowing","Ops",""),
            ("Post-Migration","Coordinate and execute DNS cutover","Network",""),
            ("Validation","Smoke test all public and internal endpoints","QA",""),
            ("Validation","Verify SQL database connectivity from apps","DBA",""),
            ("Validation","Validate Key Vault secret reads succeed","Security",""),
            ("Validation","Check Function App triggers firing correctly","DevOps",""),
            ("Validation","Confirm diagnostic logs streaming to Log Analytics","Ops",""),
            ("Validation","Sign-off and decommission source environment","All",""),
        ]
        parts = ['<div id="checklist" class="page"><h2>Migration Checklist</h2><div class="card">']
        parts.append('<table><thead><tr><th>Phase</th><th>Task</th><th>Owner</th><th>Notes</th></tr></thead><tbody>')
        for phase, task, owner, notes in tasks:
            team = self._OWNER_TO_TEAM.get(owner, "")
            team_attr = f' data-team="{team}"' if team else ''
            parts.append(f'<tr{team_attr}><td>{self._esc(phase)}</td><td>{self._esc(task)}</td><td>{self._esc(owner)}</td><td>{self._esc(notes)}</td></tr>')
        parts.append('</tbody></table></div></div>')
        return "\n".join(parts)


# ── top-level functions ───────────────────────────────────────────────────────
# ── GitRepoScanner ───────────────────────────────────────────────────────────────────
class GitRepoScanner:
    """Clones Azure DevOps repos and scans every source file for Azure service
    endpoint patterns, hardcoded connection strings, and secret references."""

    # ── detection patterns ─────────────────────────────────────────────────────
    # Each tuple: (pattern_type, regex, resource_name_capture_group, severity, is_secret)
    # resource_name_capture_group: 1-based group index that holds the Azure resource name,
    #   or 0 meaning no resource name is extractable from this pattern.
    _RAW_PATTERNS = [
        # ── Compute / Hosting ────────────────────────────────────────────────
        # Web App / Function App hostname (.azurewebsites.net)
        ("WEBAPP_ENDPOINT",
         r'https?://([\w-]+)\.azurewebsites\.net',
         1, "HIGH", False),
        # Azure Container Apps endpoint
        ("CONTAINER_APP_ENDPOINT",
         r'https?://([\w-]+)\.azurecontainerapps\.io',
         1, "MEDIUM", False),
        # Azure Front Door
        ("FRONTDOOR_ENDPOINT",
         r'([\w-]+)\.azurefd\.net',
         1, "MEDIUM", False),
        # Azure CDN
        ("CDN_ENDPOINT",
         r'([\w-]+)\.azureedge\.net',
         1, "LOW", False),

        # ── Data / Storage ───────────────────────────────────────────────────
        # SQL Server FQDN
        ("SQL_SERVER_ENDPOINT",
         r'([\w-]+)\.database\.windows\.net',
         1, "HIGH", False),
        # Storage service endpoints (blob/queue/table/file/dfs)
        ("STORAGE_ENDPOINT",
         r'([\w-]+)\.(blob|queue|table|file|dfs)\.core\.windows\.net',
         1, "HIGH", False),
        # Storage connection string AccountName
        ("STORAGE_ACCOUNT_NAME",
         r'AccountName=([\w-]+)[;,\'"\s]',
         1, "HIGH", False),
        # Cosmos DB SQL API endpoint
        ("COSMOS_ENDPOINT",
         r'https?://([\w-]+)\.documents\.azure\.com',
         1, "HIGH", False),
        # Cosmos DB account name in env var patterns
        ("COSMOS_CONN_STR",
         r'(?:CosmosDb|COSMOS(?:DB)?)[_\-]?(?:CONNECTION[_\-]?STRING|ENDPOINT|ACCOUNT'  # noqa
         r'|URI|HOST)\s*[=:]\s*[\"\']?([\w-]+)',
         1, "HIGH", False),
        # Redis Cache endpoint
        ("REDIS_ENDPOINT",
         r'([\w-]+)\.redis\.cache\.windows\.net',
         1, "HIGH", False),
        # Redis env var pattern
        ("REDIS_CONN_STR",
         r'(?:REDIS|CACHE)[_\-]?(?:CONNECTION[_\-]?STRING|HOST|ENDPOINT)\s*[=:]\s*[\"\']?([\w-]+)',
         1, "MEDIUM", False),

        # ── Messaging / Events ───────────────────────────────────────────────
        # Service Bus namespace endpoint (also matches Event Hub namespace)
        ("SERVICE_BUS_ENDPOINT",
         r'([\w-]+)\.servicebus\.windows\.net',
         1, "HIGH", False),
        # Event Hub: explicit EntityPath (hub name in group 2)
        ("EVENTHUB_ENTITY",
         r'([\w-]+)\.servicebus\.windows\.net[^\n]*EntityPath=([\w-]+)',
         2, "HIGH", False),
        # Service Bus SDK env var reference
        ("SERVICEBUS_CONN_STR",
         r'(?:SERVICE[_\-]?BUS|AzureServiceBus|AzureWebJobsServiceBus)[_\-]?(?:CONNECTION[_\-]?STRING)?\s*[=:]\s*[\"\']?([\w-]+)',
         1, "HIGH", False),
        # Event Hub SDK env var reference
        ("EVENTHUB_CONN_STR",
         r'(?:EVENT[_\-]?HUB|AzureWebJobsEventHub|EventHubConnection)[_\-]?(?:CONNECTION[_\-]?STRING)?\s*[=:]\s*[\"\']?([\w-]+)',
         1, "HIGH", False),
        # Event Grid topic endpoint
        ("EVENT_GRID_ENDPOINT",
         r'https?://([\w-]+)\.(?:[\w-]+\.)?eventgrid\.azure\.net',
         1, "HIGH", False),
        # Event Grid topic key env var
        ("EVENT_GRID_KEY",
         r'(?:EVENT[_\-]?GRID|EVENTGRID)[_\-]?(?:KEY|TOPIC[_\-]?KEY|ACCESS[_\-]?KEY)\s*[=:]\s*[\"\']?([\w+/=]{10,})',
         0, "HIGH", True),

        # ── Security / Identity ──────────────────────────────────────────────
        # Key Vault FQDN
        ("KEY_VAULT_ENDPOINT",
         r'https?://([\w-]+)\.vault\.azure\.net',
         1, "HIGH", False),
        # Key Vault @Microsoft.KeyVault() reference
        ("KEY_VAULT_REF",
         r'@Microsoft\.KeyVault\((?:VaultName=([\w-]+)|SecretUri=https://([\w-]+)\.vault)',
         1, "HIGH", False),

        # ── AI / Cognitive / Search ──────────────────────────────────────────
        # Cognitive Services endpoint
        ("COGNITIVE_ENDPOINT",
         r'https?://([\w-]+)\.cognitiveservices\.azure\.com',
         1, "MEDIUM", False),
        # Azure OpenAI endpoint
        ("OPENAI_ENDPOINT",
         r'https?://([\w-]+)\.openai\.azure\.com',
         1, "MEDIUM", False),
        # Azure Cognitive Search endpoint
        ("SEARCH_ENDPOINT",
         r'https?://([\w-]+)\.search\.windows\.net',
         1, "MEDIUM", False),
        # Azure Search env var pattern
        ("SEARCH_CONN_STR",
         r'(?:AZURE[_\-]?SEARCH|SEARCH[_\-]?SERVICE)[_\-]?(?:ENDPOINT|NAME|KEY|URL)\s*[=:]\s*[\"\']?([\w-]+)',
         1, "MEDIUM", False),

        # ── Monitoring / Observability ───────────────────────────────────────
        # App Insights instrumentation key (GUID)
        ("APP_INSIGHTS_KEY",
         r'InstrumentationKey=[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
         0, "MEDIUM", False),
        # App Insights connection string env var
        ("APP_INSIGHTS_CONN",
         r'APPLICATIONINSIGHTS[_\-]CONNECTION[_\-]STRING',
         0, "MEDIUM", False),
        # App Insights SDK: ApplicationInsights.config or code reference
        ("APP_INSIGHTS_SDK",
         r'(?:TelemetryClient|ApplicationInsights|ILogger).*(?:InstrumentationKey|ConnectionString)',
         0, "LOW", False),

        # ── DevOps / Registry ────────────────────────────────────────────────
        # Azure Container Registry
        ("CONTAINER_REGISTRY_ENDPOINT",
         r'([\w-]+)\.azurecr\.io',
         1, "MEDIUM", False),

        # ── IoT / RT Communication ───────────────────────────────────────────
        # Azure IoT Hub endpoint
        ("IOT_HUB_ENDPOINT",
         r'([\w-]+)\.azure-devices\.net',
         1, "MEDIUM", False),
        # Azure SignalR endpoint
        ("SIGNALR_ENDPOINT",
         r'https?://([\w-]+)\.service\.signalr\.net',
         1, "MEDIUM", False),

        # ── Configuration ────────────────────────────────────────────────────
        # Azure App Configuration store endpoint
        ("APP_CONFIG_ENDPOINT",
         r'https?://([\w-]+)\.azconfig\.io',
         1, "MEDIUM", False),

        # ── Secrets / Keys (always is_secret=True) ───────────────────────────
        # Hardcoded SQL password in connection string
        ("HARDCODED_SQL_PASSWORD",
         r'[Pp]assword\s*=\s*(?!\{|\$|%|@|<)([^;"\'{\s]{3,})',
         0, "HIGH", True),
        # Hardcoded storage account key (base64, 88 chars)
        ("HARDCODED_STORAGE_KEY",
         r'AccountKey=([A-Za-z0-9+/]{40,}={0,2})',
         0, "HIGH", True),
        # SAS token in query string
        ("SAS_TOKEN",
         r'[?&]sv=\d{4}-\d{2}-\d{2}&',
         0, "HIGH", True),
        # Private key / certificate PEM header
        ("PRIVATE_KEY",
         r'-----BEGIN (RSA |EC |OPENSSH |)PRIVATE KEY-----',
         0, "HIGH", True),
        # Generic hardcoded credentials (env var name patterns)
        ("GENERIC_SECRET",
         r'(?:API_KEY|SECRET_KEY|CLIENT_SECRET|ACCESS_TOKEN|AUTH_TOKEN|ACCOUNT_KEY)'  # noqa
         r'\s*[=:]\s*[^\s"\'{<>]{8,}',
         0, "HIGH", True),
    ]

    _COMPILED = [(ptype, re.compile(pat, re.IGNORECASE), grp, sev, is_sec)
                 for ptype, pat, grp, sev, is_sec in _RAW_PATTERNS]

    # Pattern type → inventory resource type (None = external/untracked service)
    _TYPE_TO_RES = {
        # Compute
        "WEBAPP_ENDPOINT":              "web_apps",
        "CONTAINER_APP_ENDPOINT":       "other_resources",
        "FRONTDOOR_ENDPOINT":           "other_resources",
        "CDN_ENDPOINT":                 "other_resources",
        # Data / Storage
        "SQL_SERVER_ENDPOINT":          "sql_servers",
        "STORAGE_ENDPOINT":             "storage_accounts",
        "STORAGE_ACCOUNT_NAME":         "storage_accounts",
        "COSMOS_ENDPOINT":              "other_resources",
        "COSMOS_CONN_STR":              "other_resources",
        "REDIS_ENDPOINT":               "other_resources",
        "REDIS_CONN_STR":               "other_resources",
        # Messaging / Events
        "SERVICE_BUS_ENDPOINT":         "other_resources",
        "EVENTHUB_ENTITY":              "other_resources",
        "SERVICEBUS_CONN_STR":          "other_resources",
        "EVENTHUB_CONN_STR":            "other_resources",
        "EVENT_GRID_ENDPOINT":          "event_grid_topics",
        "EVENT_GRID_KEY":               "event_grid_topics",
        # Security / Identity
        "KEY_VAULT_ENDPOINT":           "key_vaults",
        "KEY_VAULT_REF":                "key_vaults",
        # AI / Cognitive / Search
        "COGNITIVE_ENDPOINT":           "other_resources",
        "OPENAI_ENDPOINT":              "other_resources",
        "SEARCH_ENDPOINT":              "other_resources",
        "SEARCH_CONN_STR":              "other_resources",
        # Monitoring
        "APP_INSIGHTS_KEY":             "app_insights",
        "APP_INSIGHTS_CONN":            "app_insights",
        "APP_INSIGHTS_SDK":             "app_insights",
        # Registry / DevOps
        "CONTAINER_REGISTRY_ENDPOINT":  "other_resources",
        # IoT / RT
        "IOT_HUB_ENDPOINT":             "other_resources",
        "SIGNALR_ENDPOINT":             "other_resources",
        # Config
        "APP_CONFIG_ENDPOINT":          "other_resources",
        # Secrets
        "HARDCODED_SQL_PASSWORD":       "sql_servers",
        "HARDCODED_STORAGE_KEY":        "storage_accounts",
        "SAS_TOKEN":                    "storage_accounts",
        "PRIVATE_KEY":                  None,
        "GENERIC_SECRET":               None,
    }

    def __init__(self, args, tracker):
        self.args    = args
        self.tracker = tracker
        self._org    = getattr(args, "devops_organization", "").strip()
        self._pat    = getattr(args, "devops_pat_token",    "").strip()
        self._projects_filter = [p.lower() for p in getattr(args, "devops_projects", []) if p]
        self._repos_filter    = [r.lower() for r in getattr(args, "devops_repos",    []) if r]
        self._branch          = getattr(args, "devops_branch",    "main")
        # Per-repo branch overrides: {repo_name_lower: branch} — populated when config.json
        # specifies repositories as objects with a "branch" field.
        self._repo_branch_map = {k.lower(): v
                                 for k, v in (getattr(args, "devops_repo_branch_map", {}) or {}).items()}
        self._depth           = getattr(args, "git_clone_depth",  1)
        self._workers         = getattr(args, "git_clone_workers", 3)
        self._max_kb          = getattr(args, "git_max_file_kb",  512)
        self._extensions      = set(getattr(args, "git_scan_extensions",
            [".cs",".py",".js",".ts",".json",".yaml",".yml",".xml",".config",".env"]))
        self._skip_dirs       = set(getattr(args, "git_skip_dirs",
            [".git","node_modules","bin","obj","dist","build","__pycache__",".vs"]))
        self._findings  = []
        self._repo_meta = []
        self._counter   = 0

    # ── public entry point ────────────────────────────────────────────────────
    def scan_all(self):
        """Return {findings, repo_summaries}. Empty if not configured."""
        if not self._org or not self._pat or self._pat == "YOUR_PAT_TOKEN_HERE":
            self.tracker.log_warning("Git scanning skipped: devops_organization or devops_pat_token not set in config.json")
            return {"findings": [], "repo_summaries": []}

        self.tracker.start_phase("Git/DevOps Code Scanning")

        repos = self._list_repos()
        if not repos:
            self.tracker.log_warning("No Azure DevOps repos found (check org/PAT/project names)")
            return {"findings": [], "repo_summaries": []}

        self.tracker.log_info(f"Found {len(repos)} repo(s) to clone and scan")

        import tempfile
        tmpdir = tempfile.mkdtemp(prefix="az_inv_git_")
        try:
            with ThreadPoolExecutor(max_workers=self._workers) as ex:
                futs = {ex.submit(self._clone_and_scan, r, tmpdir): r for r in repos}
                for fut in as_completed(futs):
                    repo = futs[fut]
                    try:
                        meta = fut.result()
                        self._repo_meta.append(meta)
                        self.tracker.log_success(
                            f"Repo: {repo['name']} | "
                            f"files: {meta['files_scanned']} | "
                            f"findings: {meta['findings_count']}")
                    except Exception as e:
                        self.tracker.log_warning(f"Repo {repo['name']}: {e}")
        finally:
            try:
                shutil.rmtree(tmpdir, ignore_errors=True)
            except Exception:
                pass

        self.tracker.log_success(
            f"Code scan complete — {len(self._findings)} findings across {len(repos)} repos")
        return {"findings": self._findings, "repo_summaries": self._repo_meta}

    # ── Azure DevOps REST API ──────────────────────────────────────────────────
    def _list_repos(self):
        """Call Azure DevOps REST API to list repos. Returns list of repo dicts."""
        import urllib.request, urllib.error, base64

        creds = base64.b64encode(f":{self._pat}".encode()).decode()
        headers = {"Authorization": f"Basic {creds}", "Accept": "application/json"}

        def _api(url):
            # READ-ONLY: always explicit GET, never POST/PUT/PATCH/DELETE
            req = urllib.request.Request(url, method="GET", headers=headers)
            try:
                with urllib.request.urlopen(req, timeout=30) as resp:
                    if resp.status not in (200, 203, 206):
                        self.tracker.log_warning(
                            f"DevOps API unexpected status {resp.status} for {url}")
                        return None
                    return json.loads(resp.read().decode())
            except urllib.error.HTTPError as e:
                body = e.read().decode(errors="ignore")[:200]
                self.tracker.log_warning(f"DevOps API {url}: HTTP {e.code} {body}")
                return None
            except Exception as e:
                self.tracker.log_warning(f"DevOps API {url}: {e}")
                return None

        base = f"https://dev.azure.com/{self._org}"

        # list projects
        proj_data = _api(f"{base}/_apis/projects?api-version=7.1")
        if not proj_data:
            return []
        projects = proj_data.get("value", [])
        if self._projects_filter:
            projects = [p for p in projects
                        if p.get("name", "").lower() in self._projects_filter]

        repos = []
        for proj in projects:
            proj_name = proj["name"]
            repo_data = _api(f"{base}/{proj_name}/_apis/git/repositories?api-version=7.1")
            if not repo_data:
                continue
            for repo in repo_data.get("value", []):
                rname = repo.get("name", "")
                if self._repos_filter and rname.lower() not in self._repos_filter:
                    continue
                clone_url = repo.get("remoteUrl", "")
                # embed PAT into URL for git clone
                pat_url = clone_url.replace(
                    "https://",
                    f"https://pat:{self._pat}@"
                ).replace("https://pat:@", f"https://pat:{self._pat}@")
                repos.append({
                    "name":      rname,
                    "project":   proj_name,
                    "clone_url": pat_url,
                    "web_url":   repo.get("webUrl", ""),
                    "default_branch": repo.get("defaultBranch", "refs/heads/main")
                                      .replace("refs/heads/", ""),
                })
        return repos

    # ── clone + scan one repo ────────────────────────────────────────────────────────
    def _clone_and_scan(self, repo, tmpdir):
        import tempfile
        repo_dir = Path(tmpdir) / f"{repo['project']}__{repo['name']}"
        repo_dir.mkdir(parents=True, exist_ok=True)

        # Per-repo branch from config takes priority, then global devops_branch,
        # then the repo's own default branch reported by the DevOps API.
        branch = (self._repo_branch_map.get(repo["name"].lower())
                  or self._branch
                  or repo["default_branch"]
                  or "main")

        # READ-ONLY git environment: disable all credential prompts,
        # prevent any accidental push, disable system/global git config
        ro_env = os.environ.copy()
        ro_env["GIT_TERMINAL_PROMPT"]  = "0"   # never prompt for credentials
        ro_env["GIT_ASKPASS"]          = "echo" # return empty string for any auth prompt
        ro_env["GIT_SSH_COMMAND"]      = "ssh -o BatchMode=yes -o StrictHostKeyChecking=no"
        ro_env["GIT_CONFIG_NOSYSTEM"]  = "1"   # ignore system-level git config

        # Clone flags that guarantee read-only:
        #   --depth N        shallow clone (no full history)
        #   --single-branch  only download the target branch
        #   --no-tags        skip tag objects
        #   --filter=blob:none  blobless clone (metadata only, fetch blobs on demand)
        #     -> removed because we need file contents for scanning
        cmd = ["git", "clone",
               "--depth",         str(self._depth),
               "--branch",        branch,
               "--single-branch",
               "--no-tags",
               "-c", "core.askPass=echo",     # no credential popups
               "-c", "receive.denyNonFastForwards=true",  # extra safety
               "-q",
               repo["clone_url"], str(repo_dir)]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True,
                                    timeout=300, env=ro_env)
            if result.returncode != 0:
                # retry without specifying branch in case branch name differs
                cmd2 = ["git", "clone",
                        "--depth", str(self._depth),
                        "--single-branch", "--no-tags",
                        "-c", "core.askPass=echo",
                        "-q",
                        repo["clone_url"], str(repo_dir)]
                subprocess.run(cmd2, capture_output=True, text=True,
                               timeout=300, env=ro_env, check=True)
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"git clone failed: {e.stderr[:200] if e.stderr else str(e)}")
        except FileNotFoundError:
            raise RuntimeError(
                "git not found on PATH. Install Git and add it to PATH.")

        files_scanned, findings_here = self._scan_repo(repo_dir, repo["name"], repo["project"])
        return {
            "repo_name":      repo["name"],
            "project":        repo["project"],
            "web_url":        repo["web_url"],
            "branch":         branch,
            "files_scanned":  files_scanned,
            "findings_count": findings_here,
        }

    # ── walk directory tree ────────────────────────────────────────────────────────────
    def _scan_repo(self, repo_dir, repo_name, project):
        files_scanned = 0
        findings_in_repo = 0
        max_bytes = self._max_kb * 1024

        for dirpath, dirnames, filenames in os.walk(str(repo_dir)):
            # prune skip dirs in-place
            dirnames[:] = [d for d in dirnames if d not in self._skip_dirs]
            for fname in filenames:
                suffix = Path(fname).suffix.lower()
                if suffix not in self._extensions:
                    continue
                fpath = Path(dirpath) / fname
                try:
                    if fpath.stat().st_size > max_bytes:
                        continue
                    content = fpath.read_text(encoding="utf-8", errors="ignore")
                except Exception:
                    continue

                rel = str(fpath.relative_to(repo_dir)).replace("\\", "/")
                new = self._scan_content(content, rel, repo_name, project)
                findings_in_repo += len(new)
                files_scanned += 1

        return files_scanned, findings_in_repo

    # ── scan a single file’s content ───────────────────────────────────────────────
    def _scan_content(self, content, rel_path, repo_name, project):
        new_findings = []
        seen_on_file = set()

        for lineno, line in enumerate(content.splitlines(), 1):
            # skip comment-only lines (quick heuristic)
            stripped = line.strip()
            if stripped.startswith(("//", "#", "*", "<!--", "--")):
                # only skip if it looks like a pure comment, not a commented-out conn string
                if not any(kw in stripped for kw in
                           (".windows.net", ".azure.net", "AccountKey", "Password=", "SECRET")):
                    continue

            for ptype, regex, grp, severity, is_secret in self._COMPILED:
                for m in regex.finditer(line):
                    try:
                        rname = m.group(grp) if grp and grp <= len(m.groups()) else ""
                    except IndexError:
                        rname = ""

                    # de-dup per file: same pattern + same resource name
                    dedup_key = (ptype, rname.lower())
                    if dedup_key in seen_on_file:
                        continue
                    seen_on_file.add(dedup_key)

                    # sanitize raw match: never store actual keys/passwords
                    raw = self._sanitize(m.group(0), ptype, is_secret)

                    self._counter += 1
                    finding = {
                        "finding_id":            f"GIT-{self._counter:04d}",
                        "repo_name":             repo_name,
                        "project":               project,
                        "file_path":             rel_path,
                        "line_number":           lineno,
                        "pattern_type":          ptype,
                        "matched_resource_name": rname,
                        "raw_match":             raw,
                        "severity":              severity,
                        "is_hardcoded_secret":   is_secret,
                        "inventory_resource_type": self._TYPE_TO_RES.get(ptype, ""),
                        "confirmed_in_inventory": False,   # filled later by DependencyMapper
                    }
                    self._findings.append(finding)
                    new_findings.append(finding)

        return new_findings

    @staticmethod
    def _sanitize(raw, ptype, is_secret):
        """Replace actual secret/key values with [REDACTED] in the stored match."""
        if not is_secret:
            return raw[:120]
        # redact anything after = or : that looks like a value
        redacted = re.sub(
            r'(=|:\s*)([A-Za-z0-9+/=_\-]{8,})',
            r'\1[REDACTED]',
            raw
        )
        return redacted[:120]

    # ── cross-reference with inventory ───────────────────────────────────────────────
    @staticmethod
    def cross_reference(findings, inventory):
        """Mark findings as confirmed if the resource name is found in inventory.
        Also builds a reverse index: repo_name -> [matching_app_names].

        Matching strategy (in order):
          1. Exact resource-name lookup in inventory (SQL, Storage, KV, etc.)
          2. For SERVICE_BUS_ENDPOINT / EVENTHUB_ENTITY: match namespace prefix against
             event_grid_topics, other_resources by resource name
          3. Repo-to-App matching uses five strategies, all case-insensitive:
             a. Substring: app_name ⊂ repo_name OR repo_name ⊂ app_name
             b. Normalized (strip hyphens/underscores): same substring check
             c. Hostname: if code references <name>.azurewebsites.net, match to that app
             d. App-setting value: if an app setting VALUE contains the repo name
             e. defaultHostName prefix match
        """
        # ── 1. Build resource name index ─────────────────────────────────────
        res_index = {}   # res_type -> {lower_name: resource_dict}
        for rg_data in inventory.get("resource_groups", {}).values():
            for res_type, res_list in rg_data.get("resources", {}).items():
                bucket = res_index.setdefault(res_type, {})
                for res in res_list:
                    bucket[res.get("name", "").lower()] = res

        # Flat name lookup across ALL resource types (for patterns that don't have a
        # specific res_type, e.g. SERVICE_BUS_ENDPOINT could be a Service Bus namespace
        # or Event Hub namespace both ending in .servicebus.windows.net)
        all_resource_names = {}   # lower_name -> (res_type, resource_dict)
        for res_type, bucket in res_index.items():
            for name_lower, res in bucket.items():
                all_resource_names[name_lower] = (res_type, res)

        # ── 2. Build repo → app mapping ───────────────────────────────────────
        # Collect all web apps + function apps with multiple lookup keys
        all_apps = {}  # lower_name -> (rg_name, res_type, app_dict)
        app_hostname_map = {}  # lower_hostname_prefix -> (rg_name, res_type, app_dict)
        for rg_name, rg_data in inventory.get("resource_groups", {}).items():
            for rt in ("web_apps", "function_apps"):
                for app in rg_data.get("resources", {}).get(rt, []):
                    aname_lc = app["name"].lower()
                    all_apps[aname_lc] = (rg_name, rt, app)
                    # index by defaultHostName prefix (the part before .azurewebsites.net)
                    dhn = (app.get("defaultHostName") or "").lower()
                    if dhn:
                        app_hostname_map[dhn] = (rg_name, rt, app)
                        prefix = dhn.split(".azurewebsites.net")[0]
                        app_hostname_map[prefix] = (rg_name, rt, app)

        def _normalize(s):
            """Strip hyphens and underscores for fuzzy matching."""
            return re.sub(r'[-_]', '', s.lower())

        def _match_repo_to_apps(repo_name):
            repo_lc   = repo_name.lower()
            repo_norm = _normalize(repo_name)
            matches   = []
            seen      = set()

            def _add(app_name, rg, rt):
                if app_name not in seen:
                    seen.add(app_name)
                    matches.append({"app_name": app_name, "rg": rg,
                                    "resource_type": rt})

            for aname_lc, (rg, rt, app) in all_apps.items():
                # (a) substring match
                if aname_lc in repo_lc or repo_lc in aname_lc:
                    _add(app["name"], rg, rt)
                    continue
                # (b) normalized substring match (handles hyphens vs underscores)
                anorm = _normalize(aname_lc)
                if anorm and (anorm in repo_norm or repo_norm in anorm):
                    _add(app["name"], rg, rt)
                    continue
                # (d) app setting VALUE references the repo name
                for s in (app.get("app_setting_keys") or []):
                    if repo_lc in s.lower():
                        _add(app["name"], rg, rt)
                        break
            return matches

        # ── 3. Iterate findings: confirm + build repo_to_apps ─────────────────
        repo_to_apps = {}
        for finding in findings:
            repo_lc = finding["repo_name"].lower()

            # Populate repo_to_apps once per repo
            if repo_lc not in repo_to_apps:
                repo_to_apps[repo_lc] = _match_repo_to_apps(finding["repo_name"])

            # (c) hostname: WEBAPP_ENDPOINT findings contain the app's hostname prefix
            if finding.get("pattern_type") == "WEBAPP_ENDPOINT":
                rname_lc = finding.get("matched_resource_name", "").lower()
                if rname_lc in app_hostname_map:
                    rg, rt, app = app_hostname_map[rname_lc]
                    entry = {"app_name": app["name"], "rg": rg, "resource_type": rt}
                    if entry not in repo_to_apps[repo_lc]:
                        repo_to_apps[repo_lc].append(entry)
                    finding["confirmed_in_inventory"] = True
                    finding["matched_resource_name"]  = app["name"]
                    continue

            # Confirm finding if matched resource name is in inventory
            rt_inv = finding.get("inventory_resource_type", "")
            rname  = finding.get("matched_resource_name", "").lower()
            if rname:
                # Try the specific resource type first
                if rt_inv and rname in res_index.get(rt_inv, {}):
                    finding["confirmed_in_inventory"] = True
                # Fall back to global name search across all types
                elif rname in all_resource_names:
                    finding["confirmed_in_inventory"] = True
                    # Fill in the correct resource type if it was missing/other
                    if not rt_inv or rt_inv == "other_resources":
                        finding["inventory_resource_type"] = all_resource_names[rname][0]

        return repo_to_apps


def resolve_subscriptions(args, tracker):
    """Resolve and validate subscriptions from config.json.

    Reads subscription_ids and subscription_names from args (loaded from config.json).
    Exits with a clear error if neither field is populated – the script will NOT fall
    back to scanning all subscriptions; an explicit list is required.

    Returns a list of {"id": ..., "name": ...} dicts for every matched subscription.
    """
    sub_ids_cfg   = [s.strip() for s in getattr(args, "subscription_ids",   []) if str(s).strip()]
    sub_names_cfg = [s.strip() for s in getattr(args, "subscription_names", []) if str(s).strip()]
    ids_lower     = [i.lower() for i in sub_ids_cfg]
    names_lower   = [n.lower() for n in sub_names_cfg]

    if not sub_ids_cfg and not sub_names_cfg:
        print("")
        print("  " + "!" * 70)
        print("  !! ERROR: No subscriptions mentioned in config.json.")
        print("  !!")
        print("  !! The script requires at least one of these fields in config.json:")
        print("  !!   \"subscription_ids\":   [\"xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx\"]")
        print("  !!   \"subscription_names\": [\"My Production Subscription\"]")
        print("  !!")
        print("  !! Names are case-insensitive and support partial matching.")
        print("  !! Or pass --subscription-id <GUID> on the command line.")
        print("  " + "!" * 70)
        print("")
        sys.exit(1)

    all_subs = run_az(["account", "list"]) or []
    if not all_subs:
        tracker.log_error("Could not list Azure subscriptions. Ensure 'az login' is valid.")
        sys.exit(1)

    matched  = []
    seen_ids = set()
    for sub in all_subs:
        sub_id   = (sub.get("id") or sub.get("subscriptionId", "")).strip()
        sub_name = sub.get("name", "")
        sub_state = sub.get("state", "Enabled")
        by_id   = sub_id.lower() in ids_lower
        by_name = any(n in sub_name.lower() for n in names_lower)
        # Only skip non-Enabled subscriptions when they weren't explicitly requested by ID/name
        if sub_state != "Enabled" and not by_id and not by_name:
            continue
        if (by_id or by_name) and sub_id not in seen_ids:
            matched.append({"id": sub_id, "name": sub_name})
            seen_ids.add(sub_id)

    if not matched:
        tracker.log_error("No matching subscriptions found!")
        tracker.log_warning(f"  Requested IDs  : {sub_ids_cfg}")
        tracker.log_warning(f"  Requested names: {sub_names_cfg}")
        tracker.log_warning("  Available enabled subscriptions:")
        for s in [s for s in all_subs if s.get("state") == "Enabled"][:10]:
            sid = s.get("id") or s.get("subscriptionId", "")
            tracker.log_warning(f"    - {s.get('name')} ({sid})")
        tracker.log_warning("  Update subscription_ids or subscription_names in config.json.")
        sys.exit(1)

    tracker.log_info(f"Subscriptions to scan ({len(matched)}):")
    for s in matched:
        tracker.log_info(f"  • {s['name']} ({s['id']})")
    return matched


def collect_inventory(args, tracker):
    tracker.start_phase("Azure Resource Collection")

    target_subs = resolve_subscriptions(args, tracker)
    multi_sub   = len(target_subs) > 1

    # Combined inventory that merges RGs from all subscriptions.
    # "subscription"  kept for backwards-compat with single-sub downstream code.
    # "subscriptions" carries the full list for multi-sub reporting.
    combined = {
        "_output_dir":   str(args.output_dir),
        "subscription":  target_subs[0],
        "subscriptions": target_subs,
        "resource_groups": {},
    }
    _lock = threading.Lock()

    def _scan_sub(sub_info):
        sub_id, sub_name = sub_info["id"], sub_info["name"]
        tracker.log_info(f"Scanning subscription: {sub_name} ({sub_id})")
        c   = AzureInventoryCollector(args, tracker, subscription_id=sub_id)
        inv = c.collect_all()
        rgs = inv.get("resource_groups", {})
        # Prefix RG keys with "[SubName] " when scanning multiple subscriptions
        # to prevent key name collisions in the merged inventory.
        prefix = f"[{sub_name}] " if multi_sub else ""
        with _lock:
            for rg_key, rg_data in rgs.items():
                merged_key = f"{prefix}{rg_key}" if prefix else rg_key
                combined["resource_groups"][merged_key] = rg_data

    # Run subscription scans in parallel – each collector independently passes
    # --subscription to every az CLI call so there is no shared CLI context.
    max_workers = min(len(target_subs), getattr(args, "parallel_workers", 4))
    if max_workers > 1:
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futs = {ex.submit(_scan_sub, s): s for s in target_subs}
            for fut in as_completed(futs):
                s = futs[fut]
                try:
                    fut.result()
                    tracker.log_success(f"Subscription complete: {s['name']}")
                except Exception as e:
                    tracker.log_error(f"Subscription failed – {s['name']}: {e}")
    else:
        _scan_sub(target_subs[0])

    # Persist the merged raw inventory
    out = Path(args.output_dir)
    (out / "raw-data" / "inventory-by-resource-group.json").write_text(
        json.dumps(combined, indent=2), encoding="utf-8"
    )

    # ── optional Git/DevOps code scanning ─────────────────────────────────────
    if getattr(args, "scan_code", False):
        scanner = GitRepoScanner(args, tracker)
        git_results = scanner.scan_all()
        repo_to_apps = GitRepoScanner.cross_reference(
            git_results["findings"], combined)
        combined["git_findings"]       = git_results["findings"]
        combined["git_repo_summaries"] = git_results["repo_summaries"]
        combined["git_repo_to_apps"]   = repo_to_apps

        out2 = Path(combined.get("_output_dir", "./migration-output"))
        (out2 / "raw-data" / "git-code-scan-findings.json").write_text(
            json.dumps(git_results["findings"], indent=2), encoding="utf-8")
        (out2 / "raw-data" / "git-repo-summaries.json").write_text(
            json.dumps(git_results["repo_summaries"], indent=2), encoding="utf-8")
        if git_results["findings"]:
            with open(out2 / "raw-data" / "git-findings.csv", "w",
                      newline="", encoding="utf-8") as f:
                w = csv.DictWriter(f, fieldnames=[
                    "finding_id", "repo_name", "project", "file_path",
                    "line_number", "pattern_type", "matched_resource_name",
                    "severity", "is_hardcoded_secret", "confirmed_in_inventory",
                    "raw_match"])
                w.writeheader()
                w.writerows(git_results["findings"])
    else:
        combined["git_findings"]       = []
        combined["git_repo_summaries"] = []
        combined["git_repo_to_apps"]   = {}

    return combined

def build_dependency_map(inventory, tracker):
    tracker.start_phase("Building Dependency Map", 4)
    mapper  = DependencyMapper(inventory, tracker)
    dep_map = mapper.build_full_dependency_map()
    risks   = mapper.generate_risk_register()
    order   = mapper.generate_migration_order()

    # ── add git security risks to risk register ─────────────────────────────────
    counter_base = len(risks)
    for f in inventory.get("git_findings", []):
        if f.get("is_hardcoded_secret"):
            counter_base += 1
            risks.append({
                "risk_id":            f"RISK-GIT-{counter_base:03d}",
                "resource_name":      f["repo_name"],
                "resource_type":      "GitRepo",
                "resource_group":     f["project"],
                "risk_level":         "HIGH",
                "risk_category":      "Secret",
                "description":        (
                    f"Hardcoded secret in code: {f['pattern_type']} — "
                    f"{f['file_path']}:{f['line_number']}"
                ),
                "recommended_action": (
                    "Remove hardcoded credential from source code. "
                    "Move to Key Vault or environment variable. "
                    "Rotate the exposed credential immediately."
                ),
                "migration_phase":    "Before migration",
                "estimated_effort":   "Hours",
            })

    out = Path(inventory.get("_output_dir", "./migration-output"))
    (out / "dependency" / "dependency-map.json").write_text(
        json.dumps(dep_map, indent=2), encoding="utf-8")
    (out / "dependency" / "migration-risks.json").write_text(
        json.dumps(risks, indent=2), encoding="utf-8")
    (out / "dependency" / "migration-order.json").write_text(
        json.dumps(order, indent=2), encoding="utf-8")

    with open(out / "dependency" / "dependency-edges.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=[
            "edge_id", "source_node_id", "relationship", "target_node_id",
            "confidence", "migration_impact", "evidence_detail", "migration_note"])
        w.writeheader()
        w.writerows(dep_map["edges"])

    git_count = len(inventory.get("git_findings", []))
    tracker.complete_phase("Dependency Map",
        f"{len(dep_map['nodes'])} nodes, {len(dep_map['edges'])} edges, "
        f"{len(risks)} risks, {git_count} git findings")
    return dep_map, risks, order

def generate_html_report(inventory, dep_map, risks, order, args, tracker):
    tracker.start_phase("Generating HTML Report", 1)
    gen  = HTMLReportGenerator(inventory, dep_map, risks, order)
    path = gen.generate(args.output_dir)
    tracker.log_success(f"HTML report: {path}")

# ── Prompts 14+15+16: ExcelReportGenerator ─────────────────────────────────────
class ExcelReportGenerator:

    def __init__(self, inventory, dep_map, risks, order):
        self.inv   = inventory
        self.dep   = dep_map
        self.risks = risks
        self.order = order

    def generate(self, output_dir):
        import openpyxl
        from openpyxl.styles import PatternFill, Font, Alignment
        from openpyxl.utils import get_column_letter
        self._xl       = openpyxl
        self._fill     = PatternFill
        self._font     = Font
        self._align    = Alignment
        self._get_col  = get_column_letter
        self._wb       = openpyxl.Workbook()
        self._wb.remove(self._wb.active)

        self._add_summary_sheet()
        self._add_rg_sheet()
        self._add_web_apps_sheet()
        self._add_function_apps_sheet()
        self._add_sql_sheet()
        self._add_storage_sheet()
        self._add_keyvault_sheet()
        self._add_networking_sheet()
        self._add_app_gateway_sheet()
        self._add_lb_tm_sheet()
        self._add_monitoring_sheet()
        self._add_identity_sheet()
        self._add_dependency_sheet()
        self._add_risks_sheet()
        self._add_migration_order_sheet()
        self._add_checklist_sheet()

        path = Path(output_dir) / "reports" / "azure-migration-inventory.xlsx"
        self._wb.save(str(path))
        return str(path)

    # ── styling helpers ────────────────────────────────────────────────────────
    def _style_ws(self, ws, headers):
        hdr_fill = self._fill("solid", fgColor="0078D4")
        hdr_font = self._font(color="FFFFFF", bold=True, name="Arial", size=11)
        alt_fill = self._fill("solid", fgColor="EBF3FB")
        for col_idx, h in enumerate(headers, 1):
            cell = ws.cell(row=1, column=col_idx, value=h)
            cell.fill = hdr_fill
            cell.font = hdr_font
            col_letter = self._get_col(col_idx)
            ws.column_dimensions[col_letter].width = min(60, max(14, len(str(h)) + 4))
        ws.freeze_panes = "A2"
        ws.auto_filter.ref = ws.dimensions
        for row_idx, row in enumerate(ws.iter_rows(min_row=2), 2):
            if row_idx % 2 == 0:
                for cell in row:
                    if cell.value is not None:
                        cell.fill = alt_fill

    def _wr(self, ws, values, row_idx=None):
        ws.append([str(v) if v is not None else "" for v in values])

    def _safe_str(self, val, max_len=500):
        if val is None: return ""
        if isinstance(val, (list, dict)): return json.dumps(val)[:max_len]
        return str(val)[:max_len]

    def _deployment_group(self, res_name, res_type):
        for group in self.order.get("groups", []):
            for item in group.get("resources", []):
                if item.get("name") == res_name and item.get("type") == res_type:
                    return group["group"]
        return ""

    def _all_resources_flat(self, *res_types):
        for rg_name, rg_data in self.inv.get("resource_groups", {}).items():
            for rt in res_types:
                for res in rg_data.get("resources", {}).get(rt, []):
                    yield rg_name, res

    # ── sheets ────────────────────────────────────────────────────────────────
    def _add_summary_sheet(self):
        ws = self._wb.create_sheet("Summary")
        sub = self.inv.get("subscription", {})
        rgs = self.inv.get("resource_groups", {})
        counts = {}
        for rg_data in rgs.values():
            for rt, rl in rg_data.get("resources", {}).items():
                counts[rt] = counts.get(rt, 0) + len(rl)
        rows = [
            ["Generated",           datetime.datetime.now().strftime("%Y-%m-%d %H:%M")],
            ["Subscription Name",   sub.get("name", "")],
            ["Subscription ID",     sub.get("id", "")],
            ["Tenant ID",           sub.get("tenantId", "")],
            ["Total RGs",           len(rgs)],
            ["Empty RGs",           sum(1 for r in rgs.values() if r.get("is_empty"))],
            [], ["Resource Type", "Count"],
        ] + [[rt, cnt] for rt, cnt in sorted(counts.items()) if cnt] + [
            [], ["Risk Level", "Count"],
            ["HIGH",   sum(1 for r in self.risks if r["risk_level"] == "HIGH")],
            ["MEDIUM", sum(1 for r in self.risks if r["risk_level"] == "MEDIUM")],
            ["LOW",    sum(1 for r in self.risks if r["risk_level"] == "LOW")],
        ]
        for row in rows:
            ws.append([self._safe_str(c) for c in row])
        ws.column_dimensions["A"].width = 24
        ws.column_dimensions["B"].width = 40

    def _add_rg_sheet(self):
        ws = self._wb.create_sheet("Resource Groups")
        headers = ["RG Name", "Location", "Resource Count", "Is Empty", "Tags", "Provisioning State"]
        ws.append(headers)
        for rg_name, rg_data in sorted(self.inv.get("resource_groups", {}).items()):
            meta = rg_data.get("metadata", {})
            self._wr(ws, [
                rg_name, meta.get("location", ""),
                rg_data.get("resource_count", 0),
                "YES" if rg_data.get("is_empty") else "NO",
                json.dumps(meta.get("tags", {})),
                meta.get("provisioningState", ""),
            ])
        self._style_ws(ws, headers)

    def _add_web_apps_sheet(self):
        ws = self._wb.create_sheet("Web Apps")
        headers = ["RG", "Name", "Kind", "State", "Plan", "Runtime", "HTTPS Only",
                   "VNet Integration", "Identity Type", "Principal ID", "Slots",
                   "Setting Keys Count", "Sensitive Keys", "KV Refs", "Conn Strings",
                   "Custom Domains", "Deploy Group", "Migration Notes"]
        ws.append(headers)
        for rg_name, app in self._all_resources_flat("web_apps"):
            self._wr(ws, [
                rg_name, app.get("name"), app.get("kind"), app.get("state"),
                app.get("server_farm_name"), app.get("runtime"),
                app.get("httpsOnly"),
                json.dumps(app.get("vnet_integration", [])),
                app.get("identity_type"), app.get("principal_id"),
                ", ".join(app.get("slots_list", [])),
                len(app.get("app_setting_keys", [])),
                ", ".join(app.get("sensitive_keys", [])),
                json.dumps(app.get("kv_references", [])),
                json.dumps(app.get("conn_string_types", [])),
                ", ".join(app.get("custom_domains", [])),
                self._deployment_group(app.get("name"), "web_apps"),
                " | ".join(app.get("bicep_notes", [])),
            ])
        self._style_ws(ws, headers)

    def _add_function_apps_sheet(self):
        ws = self._wb.create_sheet("Function Apps")
        headers = ["RG", "Name", "Kind", "State", "Plan", "Runtime", "HTTPS Only",
                   "VNet Integration", "Identity Type", "Principal ID", "Slots",
                   "Setting Keys Count", "Sensitive Keys", "KV Refs",
                   "Has Job Storage", "Functions Runtime", "Functions Version",
                   "Has App Insights", "Deploy Group", "Migration Notes"]
        ws.append(headers)
        for rg_name, app in self._all_resources_flat("function_apps"):
            self._wr(ws, [
                rg_name, app.get("name"), app.get("kind"), app.get("state"),
                app.get("server_farm_name"), app.get("runtime"),
                app.get("httpsOnly"),
                json.dumps(app.get("vnet_integration", [])),
                app.get("identity_type"), app.get("principal_id"),
                ", ".join(app.get("slots_list", [])),
                len(app.get("app_setting_keys", [])),
                ", ".join(app.get("sensitive_keys", [])),
                json.dumps(app.get("kv_references", [])),
                "YES" if app.get("has_job_storage") else "NO",
                app.get("functions_runtime"), app.get("functions_version"),
                "YES" if app.get("has_app_insights") else "NO",
                self._deployment_group(app.get("name"), "function_apps"),
                " | ".join(app.get("bicep_notes", [])),
            ])
        self._style_ws(ws, headers)

    def _add_sql_sheet(self):
        ws = self._wb.create_sheet("SQL")
        srv_headers = ["RG", "Server", "FQDN", "Admin Login", "Version", "Min TLS",
                       "Public Network", "AAD Admin", "AAD Tenant ⚠", "FW Rule Count", "Public Access Warning"]
        ws.append(srv_headers)
        for rg_name, s in self._all_resources_flat("sql_servers"):
            pub_warn = any(fw.get("is_public_warning") for fw in s.get("firewall_rules", []))
            self._wr(ws, [
                rg_name, s.get("name"), s.get("fqdn"), s.get("admin_login"),
                s.get("version"), s.get("min_tls"), s.get("public_network_access"),
                s.get("ad_admin_login"), s.get("ad_admin_tenant"),
                len(s.get("firewall_rules", [])),
                "⚠ YES" if pub_warn else "No",
            ])
        self._style_ws(ws, srv_headers)

        ws.append([])
        ws.append(["── DATABASES ──"] + [""] * 10)
        db_headers = ["RG", "Server", "Database", "SKU", "Tier", "Max GB", "Collation",
                      "Status", "Zone Redundant", "TDE Status", "LTR Weekly", "STR Days"]
        ws.append(db_headers)
        for rg_name, db in self._all_resources_flat("sql_databases"):
            self._wr(ws, [
                rg_name, db.get("server_name"), db.get("name"),
                db.get("sku_name"), db.get("sku_tier"), db.get("max_size_gb"),
                db.get("collation"), db.get("status"), db.get("zone_redundant"),
                db.get("tde_status"), db.get("ltr_weekly"), db.get("str_days"),
            ])

        ws.append([])
        ws.append(["── FIREWALL RULES ──"] + [""] * 5)
        ws.append(["RG", "Server", "Rule Name", "Start IP", "End IP", "⚠ PUBLIC ACCESS"])
        for rg_name, s in self._all_resources_flat("sql_servers"):
            for fw in s.get("firewall_rules", []):
                self._wr(ws, [
                    rg_name, s.get("name"), fw.get("name"),
                    fw.get("start"), fw.get("end"),
                    "⚠ PUBLIC" if fw.get("is_public_warning") else "",
                ])

    def _add_storage_sheet(self):
        ws = self._wb.create_sheet("Storage")
        headers = ["RG", "Name", "Kind", "SKU", "Access Tier", "Min TLS", "HTTPS Only",
                   "Allow Public Blob", "Allow Shared Key", "HNS Enabled",
                   "Network Default", "Blob Versioning", "Soft Delete Days",
                   "Containers Count", "File Shares Count"]
        ws.append(headers)
        for rg_name, sa in self._all_resources_flat("storage_accounts"):
            self._wr(ws, [
                rg_name, sa.get("name"), sa.get("kind"), sa.get("sku_name"),
                sa.get("access_tier"), sa.get("min_tls"), sa.get("https_only"),
                sa.get("allow_blob_public"), sa.get("allow_shared_key"),
                sa.get("hns_enabled"), sa.get("net_default"),
                sa.get("blob_versioning"), sa.get("blob_soft_delete_days"),
                len(sa.get("containers_list", [])),
                len(sa.get("file_shares", [])),
            ])
        self._style_ws(ws, headers)

    def _add_keyvault_sheet(self):
        ws = self._wb.create_sheet("Key Vaults")
        kv_headers = ["RG", "Name", "SKU", "Vault URI", "Soft Delete", "Days",
                      "Purge Protect", "RBAC Auth", "Net Default", "Private EPs",
                      "Secrets Count", "Keys Count", "Certs Count", "Access Policies Count"]
        ws.append(kv_headers)
        for rg_name, kv in self._all_resources_flat("key_vaults"):
            self._wr(ws, [
                rg_name, kv.get("name"), kv.get("sku_name"), kv.get("vault_uri"),
                kv.get("enable_soft_delete"), kv.get("soft_delete_days"),
                kv.get("enable_purge_protect"), kv.get("enable_rbac"),
                kv.get("net_default"), kv.get("pe_count"),
                len(kv.get("secrets_list", [])),
                len(kv.get("keys_list", [])),
                len(kv.get("certs_list", [])),
                len(kv.get("access_policies", [])),
            ])
        self._style_ws(ws, kv_headers)

        ws.append([])
        ws.append(["── ACCESS POLICIES (⚠ ALL ARE MIGRATION REQUIRED) ──"] + [""] * 6)
        pol_headers = ["Vault", "Object ID", "Tenant ID", "Key Perms", "Secret Perms", "Cert Perms", "⚠ MIGRATION REQUIRED"]
        ws.append(pol_headers)
        from openpyxl.styles import PatternFill
        warn_fill = PatternFill("solid", fgColor="FFE4B3")
        for rg_name, kv in self._all_resources_flat("key_vaults"):
            for pol in kv.get("access_policies", []):
                self._wr(ws, [
                    kv.get("name"), pol.get("objectId"), pol.get("tenantId"),
                    ", ".join(pol.get("perms_keys", [])),
                    ", ".join(pol.get("perms_secrets", [])),
                    ", ".join(pol.get("perms_certs", [])),
                    "YES – must remap to new tenant objectId",
                ])
                for cell in ws[ws.max_row]:
                    cell.fill = warn_fill

    def _add_networking_sheet(self):
        ws = self._wb.create_sheet("Networking")

        ws.append(["── VNETs ──"])
        ws.append(["RG", "Name", "Location", "Address Prefixes", "DNS Servers", "DDoS", "Subnets Count", "Peerings Count"])
        for rg_name, v in self._all_resources_flat("virtual_networks"):
            self._wr(ws, [rg_name, v.get("name"), v.get("location"),
                ", ".join(v.get("address_prefixes", [])),
                ", ".join(v.get("dns_servers", [])),
                v.get("ddos_protection"),
                len(v.get("subnets", [])), len(v.get("peerings", []))])

        ws.append([])
        ws.append(["── NSGs ──"])
        ws.append(["RG", "Name", "Location", "Associated Subnets", "Custom Rules Count"])
        for rg_name, n in self._all_resources_flat("network_security_groups"):
            self._wr(ws, [rg_name, n.get("name"), n.get("location"),
                json.dumps(n.get("associated_subnets", [])),
                len(n.get("security_rules", []))])

        ws.append([])
        ws.append(["── Route Tables ──"])
        ws.append(["RG", "Name", "Location", "Disable BGP Propagation", "Routes Count"])
        for rg_name, t in self._all_resources_flat("route_tables"):
            self._wr(ws, [rg_name, t.get("name"), t.get("location"),
                t.get("disable_bgp"), len(t.get("routes", []))])

        ws.append([])
        ws.append(["── Public IPs ──"])
        ws.append(["RG", "Name", "Location", "SKU", "Allocation", "IP Address", "FQDN", "Associated"])
        for rg_name, p in self._all_resources_flat("public_ips"):
            self._wr(ws, [rg_name, p.get("name"), p.get("location"),
                p.get("sku_name"), p.get("allocation"), p.get("ip_address"),
                p.get("fqdn"), p.get("associated")])

        ws.append([])
        ws.append(["── Private Endpoints ──"])
        ws.append(["RG", "Name", "Location", "Subnet VNet", "Subnet Name", "Connections Count"])
        for rg_name, pe in self._all_resources_flat("private_endpoints"):
            subnet = pe.get("subnet", {})
            self._wr(ws, [rg_name, pe.get("name"), pe.get("location"),
                subnet.get("vnet_name", ""), subnet.get("subnet_name", ""),
                len(pe.get("connections", []))])

        ws.append([])
        ws.append(["── Private DNS Zones ──"])
        ws.append(["RG", "Name", "Record Sets", "VNet Links Count"])
        for rg_name, z in self._all_resources_flat("private_dns_zones"):
            self._wr(ws, [rg_name, z.get("name"), z.get("record_sets"), len(z.get("vnet_links", []))])

    def _add_app_gateway_sheet(self):
        ws = self._wb.create_sheet("App Gateways")
        agw_headers = ["RG", "Name", "SKU", "Tier", "Capacity", "Autoscale Min", "Autoscale Max",
                       "HTTP2", "Operational State", "Backend Pools", "Listeners", "Routing Rules", "WAF Policy"]
        ws.append(agw_headers)
        for rg_name, agw in self._all_resources_flat("application_gateways"):
            self._wr(ws, [
                rg_name, agw.get("name"), agw.get("sku_name"), agw.get("sku_tier"),
                agw.get("sku_capacity"), agw.get("autoscale_min"), agw.get("autoscale_max"),
                agw.get("enable_http2"), agw.get("operational_state"),
                len(agw.get("backend_pools", [])),
                len(agw.get("listeners", [])),
                len(agw.get("routing_rules", [])),
                parse_resource_name(agw.get("waf_policy_id") or ""),
            ])
        self._style_ws(ws, agw_headers)

        ws.append([])
        ws.append(["── WAF Policies ──"])
        ws.append(["RG", "Name", "Mode", "State", "Managed Rule Sets", "Custom Rules", "Exclusions"])
        for rg_name, pol in self._all_resources_flat("waf_policies"):
            self._wr(ws, [
                rg_name, pol.get("name"), pol.get("mode"), pol.get("state"),
                json.dumps(pol.get("managed_rule_sets", [])),
                pol.get("custom_rules_count"), pol.get("exclusions_count"),
            ])

    def _add_lb_tm_sheet(self):
        ws = self._wb.create_sheet("LB and Traffic Manager")
        lb_headers = ["RG", "Name", "SKU", "Tier", "Frontend IPs", "Backend Pools", "Rules Count", "Probes Count"]
        ws.append(lb_headers)
        for rg_name, lb in self._all_resources_flat("load_balancers"):
            self._wr(ws, [
                rg_name, lb.get("name"), lb.get("sku_name"), lb.get("sku_tier"),
                json.dumps(lb.get("frontend_ips", [])),
                ", ".join(lb.get("backend_pools", [])),
                len(lb.get("rules", [])), len(lb.get("probes", [])),
            ])
        self._style_ws(ws, lb_headers)

        ws.append([])
        ws.append(["── Traffic Manager ──"])
        tm_headers = ["RG", "Name", "Status", "Routing", "DNS Name", "DNS FQDN", "Monitor Protocol", "Endpoints Count"]
        ws.append(tm_headers)
        for rg_name, tm in self._all_resources_flat("traffic_managers"):
            self._wr(ws, [
                rg_name, tm.get("name"), tm.get("status"), tm.get("routing"),
                tm.get("dns_name"), tm.get("dns_fqdn"), tm.get("monitor_protocol"),
                len(tm.get("endpoints", [])),
            ])

    def _add_monitoring_sheet(self):
        ws = self._wb.create_sheet("Monitoring")
        ws.append(["── Log Analytics Workspaces ──"])
        ws.append(["RG", "Name", "Location", "SKU", "Retention Days", "Daily Quota GB", "Customer ID", "Public Ingestion"])
        for rg_name, ws_obj in self._all_resources_flat("log_analytics_workspaces"):
            self._wr(ws, [rg_name, ws_obj.get("name"), ws_obj.get("location"),
                ws_obj.get("sku"), ws_obj.get("retention_days"), ws_obj.get("daily_quota"),
                ws_obj.get("customer_id"), ws_obj.get("public_ingestion")])

        ws.append([])
        ws.append(["── Application Insights ──"])
        ws.append(["RG", "Name", "Location", "Kind", "App Type", "Retention", "Workspace",
                   "Ingestion Mode", "Disable Local Auth", "Sampling %", "Flow Type"])
        for rg_name, ai in self._all_resources_flat("app_insights"):
            self._wr(ws, [rg_name, ai.get("name"), ai.get("location"), ai.get("kind"),
                ai.get("application_type"), ai.get("retention_days"),
                ai.get("workspace_name"), ai.get("ingestion_mode"),
                ai.get("disable_local_auth"), ai.get("sampling_percentage"), ai.get("flow_type")])

        ws.append([])
        ws.append(["── Action Groups ──"])
        ws.append(["RG", "Name", "Location", "Short Name", "Enabled",
                   "Email Count", "SMS Count", "Webhook Count", "Logic App Count", "Azure Function Count", "ARM Role Count"])
        for rg_name, ag in self._all_resources_flat("action_groups"):
            self._wr(ws, [rg_name, ag.get("name"), ag.get("location"), ag.get("short_name"),
                ag.get("enabled"), ag.get("email_count"), ag.get("sms_count"),
                ag.get("webhook_count"), ag.get("logic_app_count"),
                ag.get("azure_function_count"), ag.get("arm_role_count")])

        ws.append([])
        ws.append(["── Metric Alert Rules ──"])
        ws.append(["RG", "Name", "Severity", "Enabled", "Description", "Evaluation Frequency", "Window Size", "Scopes"])
        for rg_name, a in self._all_resources_flat("alert_rules"):
            self._wr(ws, [rg_name, a.get("name"), a.get("severity"), a.get("enabled"),
                a.get("description"), a.get("evaluation_frequency"), a.get("window_size"),
                "; ".join(a.get("scopes") or [])])

        ws.append([])
        ws.append(["── Activity Log Alerts ──"])
        ws.append(["RG", "Name", "Enabled", "Description", "Scopes", "Conditions", "Action Groups"])
        for rg_name, a in self._all_resources_flat("activity_log_alerts"):
            conds = "; ".join(f"{c.get('field')}={c.get('equals')}" for c in (a.get("conditions") or []))
            self._wr(ws, [rg_name, a.get("name"), a.get("enabled"), a.get("description"),
                "; ".join(a.get("scopes") or []), conds,
                "; ".join(filter(None, a.get("action_group_ids") or []))])

        ws.append([])
        ws.append(["── Scheduled Query (Log Search) Alerts ──"])
        ws.append(["RG", "Name", "Severity", "Enabled", "Description", "Evaluation Frequency", "Window Duration", "Scopes"])
        for rg_name, a in self._all_resources_flat("scheduled_query_alerts"):
            self._wr(ws, [rg_name, a.get("name"), a.get("severity"), a.get("enabled"),
                a.get("description"), a.get("evaluation_frequency"), a.get("window_duration"),
                "; ".join(a.get("scopes") or [])])

        ws.append([])
        ws.append(["── Smart Detector Alert Rules ──"])
        ws.append(["RG", "Name", "Severity", "Enabled", "Description", "Frequency", "Detector ID"])
        for rg_name, a in self._all_resources_flat("smart_detector_alert_rules"):
            self._wr(ws, [rg_name, a.get("name"), a.get("severity"), a.get("enabled"),
                a.get("description"), a.get("frequency"), a.get("detector_id")])

        ws.append([])
        ws.append(["── Event Grid Topics ──"])
        ws.append(["RG", "Name", "Location", "Input Schema", "Endpoint", "Public Network Access",
                   "Provisioning State", "Event Subscriptions Count"])
        for rg_name, t in self._all_resources_flat("event_grid_topics"):
            self._wr(ws, [rg_name, t.get("name"), t.get("location"), t.get("input_schema"),
                t.get("endpoint"), t.get("public_network_access"), t.get("provisioning_state"),
                len(t.get("event_subscriptions") or [])])

        ws.append([])
        ws.append(["── Event Grid Domains ──"])
        ws.append(["RG", "Name", "Location", "Input Schema", "Endpoint", "Public Network Access",
                   "Provisioning State", "Domain Topics Count"])
        for rg_name, d in self._all_resources_flat("event_grid_domains"):
            self._wr(ws, [rg_name, d.get("name"), d.get("location"), d.get("input_schema"),
                d.get("endpoint"), d.get("public_network_access"), d.get("provisioning_state"),
                d.get("domain_topics_count", 0)])

    def _add_identity_sheet(self):
        ws = self._wb.create_sheet("Identities and RBAC")
        from openpyxl.styles import PatternFill, Font
        warn_fill = PatternFill("solid", fgColor="FFE4B3")

        mi_headers = ["RG", "Name", "Location", "Principal ID", "Client ID", "Tenant ID", "Role Assignments Count"]
        ws.append(mi_headers)
        for rg_name, mi in self._all_resources_flat("managed_identities"):
            self._wr(ws, [
                rg_name, mi.get("name"), mi.get("location"),
                mi.get("principal_id"), mi.get("client_id"), mi.get("tenant_id"),
                len(mi.get("role_assignments", [])),
            ])
        self._style_ws(ws, mi_headers)

        ws.append([])
        ws.append(["── ROLE ASSIGNMENTS (⚠ ALL MUST BE RECREATED) ──"])
        ra_headers = ["Identity Name", "RG", "Role", "Scope", "⚠ MUST RECREATE"]
        ws.append(ra_headers)
        for rg_name, mi in self._all_resources_flat("managed_identities"):
            for ra in mi.get("role_assignments", []):
                self._wr(ws, [mi.get("name"), rg_name, ra.get("role"), ra.get("scope"), "YES"])
                for cell in ws[ws.max_row]:
                    cell.fill = warn_fill

    def _add_dependency_sheet(self):
        ws = self._wb.create_sheet("Dependency Map")
        from openpyxl.styles import PatternFill
        nodes_by_id = {n["node_id"]: n for n in self.dep.get("nodes", [])}
        headers = ["Source RG", "Source", "Src Type", "Relationship", "Target RG",
                   "Target", "Tgt Type", "Confidence", "Impact", "Evidence", "Migration Note"]
        ws.append(headers)
        IMPACT_FILL = {
            "CRITICAL": PatternFill("solid", fgColor="FFB3B3"),
            "HIGH":     PatternFill("solid", fgColor="FFE4B3"),
        }
        for e in self.dep.get("edges", []):
            src = nodes_by_id.get(e["source_node_id"], {})
            tgt = nodes_by_id.get(e["target_node_id"], {})
            self._wr(ws, [
                src.get("resource_group", ""), src.get("display_name", ""),
                src.get("short_type", ""), e.get("relationship", ""),
                tgt.get("resource_group", ""), tgt.get("display_name", ""),
                tgt.get("short_type", ""), e.get("confidence", ""),
                e.get("migration_impact", ""), e.get("evidence_detail", ""),
                e.get("migration_note", ""),
            ])
            fill = IMPACT_FILL.get(e.get("migration_impact", ""))
            if fill:
                for cell in ws[ws.max_row]:
                    cell.fill = fill
        self._style_ws(ws, headers)

    def _add_risks_sheet(self):
        ws = self._wb.create_sheet("Risks")
        from openpyxl.styles import PatternFill
        LEVEL_FILL = {
            "HIGH":   PatternFill("solid", fgColor="FFB3B3"),
            "MEDIUM": PatternFill("solid", fgColor="FFF3B3"),
            "LOW":    PatternFill("solid", fgColor="C6EFCE"),
        }
        headers = ["Risk ID", "RG", "Resource", "Type", "Level", "Category",
                   "Description", "Recommended Action", "Phase", "Effort"]
        ws.append(headers)
        for r in sorted(self.risks, key=lambda x: {"HIGH": 0, "MEDIUM": 1, "LOW": 2}.get(x["risk_level"], 3)):
            self._wr(ws, [
                r["risk_id"], r["resource_group"], r["resource_name"],
                r["resource_type"], r["risk_level"], r["risk_category"],
                r["description"], r["recommended_action"],
                r["migration_phase"], r["estimated_effort"],
            ])
            fill = LEVEL_FILL.get(r["risk_level"])
            if fill:
                for cell in ws[ws.max_row]:
                    cell.fill = fill
        self._style_ws(ws, headers)

    def _add_migration_order_sheet(self):
        ws = self._wb.create_sheet("Migration Order")
        headers = ["Group", "Description", "RG", "Resource Name", "Resource Type", "Note"]
        ws.append(headers)
        for group in self.order.get("groups", []):
            for item in group.get("resources", []):
                self._wr(ws, [
                    group["group"], group["description"],
                    item.get("rg", ""), item.get("name", ""),
                    item.get("type", ""), item.get("note", ""),
                ])
        self._style_ws(ws, headers)

    def _add_checklist_sheet(self):
        ws = self._wb.create_sheet("Checklist")
        headers = ["Phase", "Task", "Owner", "Notes", "Done?"]
        ws.append(headers)
        tasks = [
            ("Pre-Migration", "Create new subscription & resource groups in target tenant", "Ops", ""),
            ("Pre-Migration", "Verify AAD tenant configuration and admin access", "Identity", ""),
            ("Pre-Migration", "Recreate all user-assigned managed identities", "Identity", "PrincipalIds will differ"),
            ("Pre-Migration", "Export all SQL databases (bacpac)", "DBA", ""),
            ("Pre-Migration", "Document all custom domain DNS records", "Ops", ""),
            ("Pre-Migration", "Audit all Key Vault access policy objectIds", "Security", ""),
            ("Pre-Migration", "Review all NSG rules for hardcoded external IPs", "Network", ""),
            ("Pre-Migration", "Recreate DevOps service connections for new subscription", "DevOps", ""),
            ("During Migration", "Deploy Group 1: Foundation (DNS Zones, Log Analytics, NSGs, Routes)", "Ops", ""),
            ("During Migration", "Deploy Group 2: Networking (VNets, Subnets, Public IPs)", "Network", ""),
            ("During Migration", "Deploy Group 3: Data+Security (Key Vaults, Storage, SQL Servers)", "DBA/Security", ""),
            ("During Migration", "Assign initial KV access policies using new tenant objectIds", "Security", ""),
            ("During Migration", "Deploy Group 4: Compute Prerequisites (Plans, SQL DBs, App Insights, PEs)", "Ops", ""),
            ("During Migration", "Deploy Group 5: Compute Services (Web Apps, Function Apps, App Gateways)", "DevOps", ""),
            ("During Migration", "Update all connection strings and app settings in new apps", "DevOps", ""),
            ("During Migration", "Deploy Group 6: Traffic+Monitoring (LB, TM, Diagnostics, Alerts)", "Ops", ""),
            ("Post-Migration", "Verify all apps start and respond (smoke test)", "QA", ""),
            ("Post-Migration", "Re-verify and rebind all custom domains and SSL certificates", "Ops", ""),
            ("Post-Migration", "Re-assign all RBAC role assignments for managed identities", "Security", ""),
            ("Post-Migration", "Validate Application Insights telemetry flowing", "Ops", ""),
            ("Post-Migration", "Coordinate and execute DNS cutover", "Network", ""),
            ("Validation", "Smoke test all public and internal endpoints", "QA", ""),
            ("Validation", "Verify SQL database connectivity from apps", "DBA", ""),
            ("Validation", "Validate Key Vault secret reads succeed", "Security", ""),
            ("Validation", "Check Function App triggers firing correctly", "DevOps", ""),
            ("Validation", "Confirm diagnostic logs streaming to Log Analytics", "Ops", ""),
            ("Validation", "Sign-off and decommission source environment", "All", ""),
        ]
        for phase, task, owner, notes in tasks:
            ws.append([phase, task, owner, notes, "☐"])
        self._style_ws(ws, headers)


def generate_excel_report(inventory, dep_map, risks, order, args, tracker):
    tracker.start_phase("Generating Excel Workbook", 1)
    gen  = ExcelReportGenerator(inventory, dep_map, risks, order)
    path = gen.generate(args.output_dir)
    tracker.log_success(f"Excel report: {path}")


def print_final_summary(inventory, dep_map, risks, order, start_time, output_dir):
    rgs       = inventory.get("resource_groups", {})
    total_rgs = len(rgs)
    empty_rgs = sum(1 for r in rgs.values() if r.get("is_empty"))
    total_res = sum(r.get("resource_count", 0) for r in rgs.values())
    total_edges = len(dep_map.get("edges", []))
    high   = sum(1 for r in risks if r["risk_level"] == "HIGH")
    medium = sum(1 for r in risks if r["risk_level"] == "MEDIUM")
    low    = sum(1 for r in risks if r["risk_level"] == "LOW")
    elapsed = int(time.time() - start_time)
    m, s   = divmod(elapsed, 60)
    out    = Path(output_dir)

    html_path  = str(out / "reports" / "azure-migration-inventory-report.html")[:48]
    excel_path = str(out / "reports" / "azure-migration-inventory.xlsx")[:48]
    raw_path   = str(out / "raw-data")[:48]
    dep_path   = str(out / "dependency")[:48]

    print(f"""
╔═══════════════════════════════════════════════════════╗
║  ✅  AZURE MIGRATION INVENTORY COMPLETE              ║
╠═══════════════════════════════════════════════════════╣
║  Resource Groups : {total_rgs:<34} ║
║  Empty RGs       : {empty_rgs:<34} ║
║  Total Resources : {total_res:<34} ║
║  Dependency Edges: {total_edges:<34} ║
║  🔴 HIGH  : {high:<42} ║
║  🟡 MEDIUM: {medium:<42} ║
║  🟢 LOW   : {low:<42} ║
╠═══════════════════════════════════════════════════════╣
║  📄 HTML : {html_path:<48} ║
║  📊 Excel: {excel_path:<48} ║
║  📁 Raw  : {raw_path:<48} ║
║  🔗 Deps : {dep_path:<48} ║
╠═══════════════════════════════════════════════════════╣
║  ⏱  Total: {m}m {s}s{' '*(42 - len(f'{m}m {s}s'))} ║
╚═══════════════════════════════════════════════════════╝""")

    high_risks = [r for r in risks if r["risk_level"] == "HIGH"][:5]
    if high_risks:
        print("\n⚠  TOP HIGH RISKS – Resolve before migration:")
        for r in high_risks:
            print(f"  [{r['risk_id']}] {r['resource_name']} ({r['resource_group']}): {r['description'][:80]}")

    g1 = next((g for g in order.get("groups", []) if g["group"] == 1), None)
    if g1 and g1.get("resources"):
        print("\n▶  START HERE – Group 1 foundation resources:")
        for res in g1["resources"][:10]:
            print(f"  • {res.get('name', '?')} ({res.get('type', '?')}) – {res.get('rg', '?')}")


# ── CLI + main ────────────────────────────────────────────────────────────────
def parse_args():
    """Load config.json first, then parse CLI args (CLI overrides config)."""
    cfg = load_config()

    p = argparse.ArgumentParser(
        description="Azure Migration Inventory Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="All options can also be set in config.json (CLI flags override config)."
    )
    p.add_argument("--config", default=None, dest="config_path",
                   help="Path to config.json (default: ./config.json)")
    p.add_argument("--subscription-id",
                   default="", dest="subscription_id",
                   help="(Optional) Single subscription GUID override — adds to subscription_ids from config.json")
    p.add_argument("--output-dir",
                   default=cfg.get("output_dir", "./migration-output"), dest="output_dir")
    p.add_argument("--parallel-workers", type=int,
                   default=cfg.get("parallel_workers", 8), dest="parallel_workers")
    p.add_argument("--skip-html",   action="store_true", dest="skip_html",
                   default=cfg.get("skip_html", False))
    p.add_argument("--skip-excel",  action="store_true", dest="skip_excel",
                   default=cfg.get("skip_excel", False))
    p.add_argument("--verbose",      action="store_true",
                   default=cfg.get("verbose", False))

    args = p.parse_args()

    # If --config was given, reload with that file and re-apply defaults
    if args.config_path:
        cfg = load_config(args.config_path)

    # ── Unpack nested azure_devops block into the flat devops_* keys the rest
    # of the script expects.  config.json stores it as:
    #   "azure_devops": { "organization": "...", "pat_token": "...",
    #                      "projects": [ {"project_name": ..., "repositories": [...]} ] }
    # We flatten it so devops_organization / devops_pat_token / devops_projects /
    # devops_repos can be read by the defaults loop below exactly like any other key.
    _PLACEHOLDER = lambda s: "YOUR_" in str(s).upper()
    _adv = cfg.get("azure_devops") or {}
    if _adv:
        cfg.setdefault("devops_organization", _adv.get("organization", ""))
        cfg.setdefault("devops_pat_token",    _adv.get("pat_token",    ""))
        _projs_raw = _adv.get("projects") or []
        # Flat project-name filter (skip placeholder names)
        if not cfg.get("devops_projects"):
            cfg["devops_projects"] = [
                p.get("project_name", "") for p in _projs_raw
                if p.get("project_name") and not _PLACEHOLDER(p["project_name"])
            ]
        # Flat repo-name filter + per-repo branch map
        _repo_names, _repo_branch_map = [], {}
        for _proj in _projs_raw:
            for _repo in (_proj.get("repositories") or []):
                # config.json uses 'repo_name'; accept 'name' as fallback for backward compat
                _rname  = _repo if isinstance(_repo, str) else (
                    _repo.get("repo_name", "") or _repo.get("name", ""))
                _branch = "" if isinstance(_repo, str) else _repo.get("branch", "")
                if _rname and not _PLACEHOLDER(_rname):
                    _repo_names.append(_rname)
                    if _branch:
                        _repo_branch_map[_rname.lower()] = _branch
        if _repo_names and not cfg.get("devops_repos"):
            cfg["devops_repos"] = _repo_names
        # Store the full per-repo branch map so GitRepoScanner can pick the right branch
        cfg.setdefault("devops_repo_branch_map", _repo_branch_map)
        # If azure_devops config has real org+pat, enable code scanning automatically
        if (cfg.get("devops_organization") and not _PLACEHOLDER(cfg["devops_organization"])
                and cfg.get("devops_pat_token") and not _PLACEHOLDER(cfg["devops_pat_token"])):
            cfg.setdefault("scan_code", True)

    # Attach all config values as attributes so the rest of the script can read them
    # (CLI args already override via argparse defaults above)
    defaults = {
        "subscription_ids":           [],
        "subscription_names":         [],
        "excluded_resource_groups":   [],
        "included_resource_groups":   [],
        "collect_web_apps":           True,
        "collect_function_apps":      True,
        "collect_app_service_plans":  True,
        "collect_sql":                True,
        "collect_storage":            True,
        "collect_key_vaults":         True,
        "collect_networking":         True,
        "collect_app_gateways":       True,
        "collect_load_balancers":     True,
        "collect_traffic_managers":   True,
        "collect_managed_identities": True,
        "collect_monitoring":         True,
        "collect_event_grid":          True,
        "collect_other_resources":    False,
        "https_proxy":                "",
        "no_proxy":                   "",
        "az_path":                    "",
        "auth_method":                "default",
        # git scanning
        "scan_code":                  False,
        "devops_organization":        "",
        "devops_pat_token":           "",
        "devops_projects":            [],
        "devops_repos":               [],
        "devops_branch":              "main",
        "devops_repo_branch_map":     {},   # {repo_name_lower: branch} per-repo override
        "git_clone_depth":            1,
        "git_clone_workers":          3,
        "git_max_file_kb":            512,
        "git_scan_extensions":        [".cs",".py",".js",".ts",".json",".yaml",
                                        ".yml",".xml",".config",".env"],
        "git_skip_dirs":              [".git","node_modules","bin","obj","dist",
                                        "build","__pycache__",".vs"],
    }
    for key, fallback in defaults.items():
        if not hasattr(args, key):
            setattr(args, key, cfg.get(key, fallback))

    # Inject a single --subscription-id CLI override into subscription_ids if provided
    placeholder = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
    single_id = getattr(args, "subscription_id", "").strip()
    if single_id and single_id != placeholder:
        ids = list(getattr(args, "subscription_ids", []))
        if single_id not in ids:
            ids.insert(0, single_id)
        args.subscription_ids = ids

    return args, cfg


def main():
    global _AZ_CMD, _AZ_EXE, _AZ_SHELL

    args, cfg = parse_args()

    # ── apply proxy settings ──────────────────────────────────────────────────
    if args.https_proxy:
        os.environ["HTTPS_PROXY"] = args.https_proxy
        os.environ["https_proxy"] = args.https_proxy
    if args.no_proxy:
        os.environ["NO_PROXY"]  = args.no_proxy
        os.environ["no_proxy"]  = args.no_proxy

    # ── apply custom az CLI path ──────────────────────────────────────────────
    if args.az_path:
        _AZ_EXE   = args.az_path
        _AZ_CMD   = [_AZ_EXE]
        _AZ_SHELL = _AZ_EXE.lower().endswith((".cmd", ".bat"))

    out = Path(args.output_dir)
    for sub_dir in ["raw-data", "dependency", "reports"]:
        (out / sub_dir).mkdir(parents=True, exist_ok=True)

    tracker = ProgressTracker()

    print("""
╔══════════════════════════════════════════╗
║  Azure Migration Inventory Tool v2.0     ║
╚══════════════════════════════════════════╝""")
    tracker.log_info("Mode    : READ-ONLY — no Azure resources will be created, modified, or deleted")
    tracker.log_info("Git     : READ-ONLY — only git clone (no push/commit/write)")
    tracker.log_info(f"Config  : {Path(__file__).parent / 'config.json'}")
    # Report what subscription filter was specified in config
    _ids   = getattr(args, 'subscription_ids',   [])
    _names = getattr(args, 'subscription_names', [])
    if _ids:
        tracker.log_info(f"Sub IDs : {', '.join(_ids)}")
    if _names:
        tracker.log_info(f"Sub names: {', '.join(_names)}")
    tracker.log_info(f"Output  : {args.output_dir}")
    tracker.log_info(f"Workers : {args.parallel_workers}")
    tracker.log_info(f"Reports : HTML={'off' if args.skip_html else 'on'}, Excel={'off' if args.skip_excel else 'on'}")
    if args.excluded_resource_groups:
        tracker.log_info(f"Excl RGs: {', '.join(args.excluded_resource_groups)}")
    if args.included_resource_groups:
        tracker.log_info(f"Incl RGs: {', '.join(args.included_resource_groups)}")

    # ── check az login ────────────────────────────────────────────────────────
    tracker.log_info(f"az CLI  : {' '.join(_AZ_CMD)}")
    sub_info = run_az(["account", "show"], verbose=True)
    if not sub_info:
        print("[ERROR] Azure CLI is installed but you are not logged in, "
              "or your login session has expired.")
        print("        Run:  az login")
        print("        For a service principal:")
        print("              az login --service-principal "
              "-u <APP_ID> -p <SECRET> --tenant <TENANT_ID>")
        sys.exit(1)
    tracker.log_info(f"Logged in as: {sub_info.get('name')} | Tenant: {sub_info.get('tenantId')}")

    start_time = time.time()
    inventory  = collect_inventory(args, tracker)
    dep_map, risks, order = build_dependency_map(inventory, tracker)

    if not args.skip_html:
        generate_html_report(inventory, dep_map, risks, order, args, tracker)
    if not args.skip_excel:
        generate_excel_report(inventory, dep_map, risks, order, args, tracker)

    print_final_summary(inventory, dep_map, risks, order, start_time, args.output_dir)


if __name__ == "__main__":
    main()
