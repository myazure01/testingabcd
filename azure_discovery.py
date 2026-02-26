#!/usr/bin/env python3
"""
Azure Discovery Tool for Tenant Migration
==========================================
Discovers all Azure resources, dependencies, and configurations for migration planning.

SECURITY: READ-ONLY OPERATIONS ONLY
-----------------------------------
This tool performs ONLY read operations on Azure resources. It does NOT create, modify, 
or delete any Azure resources. All Azure SDK calls are limited to:
- list() - List resources
- get() - Read resource details
- describe() - Get resource configurations

Required Azure Permissions: Reader role (minimum)
Safe to run in production environments without risk of modification.
"""

import os
import sys
import io
import json
import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Dict, List, Any, Set
from collections import defaultdict, Counter
import traceback

# ── Force UTF-8 output on Windows (prevents charmap/cp1252 encode errors) ─────
if hasattr(sys.stdout, 'buffer') and getattr(sys.stdout, 'encoding', '').lower() not in ('utf-8', 'utf-16'):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace', line_buffering=True)
if hasattr(sys.stderr, 'buffer') and getattr(sys.stderr, 'encoding', '').lower() not in ('utf-8', 'utf-16'):
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace', line_buffering=True)

# Azure SDK imports
try:
    from azure.identity import DefaultAzureCredential, ClientSecretCredential
    from azure.mgmt.resource import ResourceManagementClient
    from azure.mgmt.subscription import SubscriptionClient
    from azure.mgmt.network import NetworkManagementClient
    from azure.mgmt.compute import ComputeManagementClient
    from azure.mgmt.web import WebSiteManagementClient
    from azure.mgmt.sql import SqlManagementClient
    from azure.mgmt.storage import StorageManagementClient
    from azure.mgmt.cosmosdb import CosmosDBManagementClient
    from azure.mgmt.servicebus import ServiceBusManagementClient
    from azure.mgmt.eventhub import EventHubManagementClient
    from azure.mgmt.keyvault import KeyVaultManagementClient
    from azure.mgmt.redis import RedisManagementClient
    from azure.mgmt.applicationinsights import ApplicationInsightsManagementClient
    from azure.mgmt.monitor import MonitorManagementClient
    from azure.mgmt.authorization import AuthorizationManagementClient
    from azure.mgmt.dns import DnsManagementClient
    from azure.mgmt.trafficmanager import TrafficManagerManagementClient
    from azure.mgmt.apimanagement import ApiManagementClient
    from azure.mgmt.containerservice import ContainerServiceClient
    from azure.mgmt.containerregistry import ContainerRegistryManagementClient
    from azure.mgmt.loganalytics import LogAnalyticsManagementClient
    from azure.mgmt.notificationhubs import NotificationHubsManagementClient
    from azure.mgmt.search import SearchManagementClient
    from azure.mgmt.cognitiveservices import CognitiveServicesManagementClient
    from azure.mgmt.databricks import AzureDatabricksManagementClient
    from azure.mgmt.datafactory import DataFactoryManagementClient
    from azure.mgmt.cdn import CdnManagementClient
    from azure.mgmt.frontdoor import FrontDoorManagementClient
    from azure.core.pipeline.policies import HTTPPolicy
    # msgraph.core is optional - comment out if not needed
    # from msgraph.core import GraphClient
    import requests
    import openpyxl
    from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
    from openpyxl.utils import get_column_letter
    import git
    import re
    import yaml
    from pathlib import Path
    import hashlib
except ImportError as e:
    print(f"ERROR: Missing required package: {e}")
    print("\nPlease install required packages:")
    print("pip install -r requirements.txt")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Module-level helpers used by both discovery and dependency analysis
# ---------------------------------------------------------------------------

def _extract_azure_service_hint(raw_connection_string: str) -> str:
    """Parse a raw connection string / URL value and return a short hint such as
    'ServiceBus:mynamespace', 'CosmosDB:myaccount', 'Redis:mycache', 'SQL:myserver',
    'Storage:mystorageacct', 'KeyVault:myvault', 'EventHub:mynamespace/myentity'.
    Returns '' when no known Azure endpoint is found.
    """
    v = str(raw_connection_string)
    # Service Bus / Event Hub  (EntityPath= distinguishes EH from SB)
    m = re.search(r'(?:Endpoint=sb://)?([a-zA-Z0-9\-]+)\.servicebus\.windows\.net', v, re.I)
    if m:
        ns = m.group(1)
        ep = re.search(r'EntityPath=([^;\s]+)', v, re.I)
        if ep:
            return f'EventHub:{ns}/{ep.group(1)}'
        return f'ServiceBus:{ns}'
    # Cosmos DB
    m = re.search(
        r'AccountEndpoint=https://([a-zA-Z0-9\-]+)\.documents\.azure\.com'
        r'|([a-zA-Z0-9\-]+)\.(?:documents|mongo\.cosmos|table\.cosmos|cassandra\.cosmos)\.azure\.com',
        v, re.I)
    if m:
        return f'CosmosDB:{m.group(1) or m.group(2)}'
    # Redis
    m = re.search(r'([a-zA-Z0-9\-]+)\.redis\.cache\.windows\.net', v, re.I)
    if m:
        return f'Redis:{m.group(1)}'
    # Key Vault
    m = re.search(
        r'@Microsoft\.KeyVault\((?:VaultName=([a-zA-Z0-9\-]+)|SecretUri=https://([a-zA-Z0-9\-]+)\.vault\.azure\.net)'
        r'|([a-zA-Z0-9\-]+)\.vault\.azure\.net',
        v, re.I)
    if m:
        kv = m.group(1) or m.group(2) or m.group(3)
        if kv:
            return f'KeyVault:{kv}'
    # SQL
    m = re.search(r'([a-zA-Z0-9\-]+)\.database\.windows\.net', v, re.I)
    if m:
        return f'SQL:{m.group(1)}'
    # Storage
    m = (re.search(r'AccountName=([a-zA-Z0-9]+)', v, re.I) or
         re.search(r'([a-zA-Z0-9]+)\.(?:blob|table|queue|file)\.core\.windows\.net', v, re.I))
    if m:
        return f'Storage:{m.group(1)}'
    return ''


def _detect_service_from_key_name(key: str) -> str:
    """For masked app settings whose value is hidden, try to guess the Azure service
    type from the *key name* alone.  Returns a service hint string like 'ServiceBus'
    or '' when nothing matches.
    """
    k = key.upper()
    if any(s in k for s in ['SERVICEBUS', 'SERVICE_BUS']):
        return 'ServiceBus'
    if any(s in k for s in ['EVENTHUB', 'EVENT_HUB']):
        return 'EventHub'
    if any(s in k for s in ['COSMOS', 'DOCUMENTDB']):
        return 'CosmosDB'
    if any(s in k for s in ['REDIS']):
        return 'Redis'
    if any(s in k for s in ['KEYVAULT', 'KEY_VAULT']):
        return 'KeyVault'
    if any(s in k for s in ['SQL', 'DATABASE', 'DB_']):
        return 'SQL'
    if any(s in k for s in ['STORAGE', 'AZUREWEBJOBSSTORAGE', 'BLOB']):
        return 'Storage'
    return ''


def _add_dep_from_hint(hint, setting_key, app_name, source_type, sub_id, dependencies,
                       sb_lookup, eh_lookup, cosmos_lookup, redis_lookup,
                       kv_lookup, sql_lookup, storage_lookup):
    """Append a dependency dict using a hint string like 'ServiceBus:mynamespace'.
    When resource is '_masked_' (value was not available), attempts to resolve via
    the lookup map — if only one resource of that type exists it is assumed.
    """
    if not hint:
        return
    service, _, resource = hint.partition(':')
    resource_lower = resource.lower().split('/')[0]  # strip EventHub entity part

    service_map = {
        'ServiceBus': ('Service Bus',     'Service Bus Connection', sb_lookup),
        'EventHub':   ('Event Hub',       'Event Hub Connection',   eh_lookup),
        'CosmosDB':   ('Cosmos DB',       'Cosmos DB Connection',   cosmos_lookup),
        'Redis':      ('Redis Cache',     'Redis Connection',       redis_lookup),
        'KeyVault':   ('Key Vault',       'Key Vault Reference',    kv_lookup),
        'SQL':        ('SQL Server',      'SQL Connection',         sql_lookup),
        'Storage':    ('Storage Account', 'Storage Connection',     storage_lookup),
    }
    if service not in service_map:
        return
    target_type, dep_type, lookup = service_map[service]

    if resource == '_masked_':
        # Value was masked — only the key name hinted at the service type
        if len(lookup) == 1:
            target = next(iter(lookup.values()))
        elif len(lookup) > 1:
            target = f'{target_type} (ref: {setting_key})'
        else:
            target = target_type
    else:
        # Actual resource name extracted — try to resolve against discovered resources
        target = lookup.get(resource_lower, resource)

    dependencies.append({
        'source': app_name, 'source_type': source_type,
        'target': target, 'target_type': target_type,
        'dependency_type': dep_type, 'setting_key': setting_key,
        'subscription': sub_id
    })


class _ReadOnlyHttpPolicy(HTTPPolicy):
    """Azure SDK pipeline policy that enforces read-only behaviour.

    If ``read_only_enforce`` is True in config.json, this policy is attached
    to every Azure Management SDK client.  Any HTTP method other than GET,
    HEAD or OPTIONS will raise a RuntimeError immediately — before the request
    reaches the network — making accidental write operations impossible.
    """
    _SAFE_METHODS = frozenset({'GET', 'HEAD', 'OPTIONS'})

    def send(self, request):
        method = (request.http_request.method or '').upper()
        if method not in _ReadOnlyHttpPolicy._SAFE_METHODS:
            raise RuntimeError(
                f"READ-ONLY VIOLATION: azure_discovery.py attempted a"
                f" {method} request to {request.http_request.url}. "
                f"Only read (GET/HEAD/OPTIONS) calls are permitted."
            )
        return self.next.send(request)


class AzureDiscovery:
    """Main Azure Discovery class"""

    # ── Comprehensive Azure endpoint patterns ────────────────────────────────
    # Each tuple: (service_type_label, compiled_regex, capture_group_for_name)
    # capture_group_for_name=0  → use full match (no meaningful account name)
    # capture_group_for_name=1+ → extract that capture group as the service name
    _AZURE_ENDPOINT_PATTERNS = [
        ('Storage/Blob',          re.compile(r'([a-zA-Z0-9]{3,24})\.blob\.core\.windows\.net',       re.I), 1),
        ('Storage/Queue',         re.compile(r'([a-zA-Z0-9]{3,24})\.queue\.core\.windows\.net',      re.I), 1),
        ('Storage/Table',         re.compile(r'([a-zA-Z0-9]{3,24})\.table\.core\.windows\.net',      re.I), 1),
        ('Storage/File',          re.compile(r'([a-zA-Z0-9]{3,24})\.file\.core\.windows\.net',       re.I), 1),
        ('Storage/ADLS',          re.compile(r'([a-zA-Z0-9]{3,24})\.dfs\.core\.windows\.net',        re.I), 1),
        ('SQL',                   re.compile(r'([a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])\.database\.windows\.net', re.I), 1),
        ('CosmosDB',              re.compile(r'([a-zA-Z0-9][a-zA-Z0-9\-]{0,49})\.documents\.azure\.com',        re.I), 1),
        ('CosmosDB/Mongo',        re.compile(r'([a-zA-Z0-9][a-zA-Z0-9\-]{0,49})\.mongo\.cosmos\.azure\.com',    re.I), 1),
        ('CosmosDB/Cassandra',    re.compile(r'([a-zA-Z0-9][a-zA-Z0-9\-]{0,49})\.cassandra\.cosmos\.azure\.com', re.I), 1),
        ('ServiceBus',            re.compile(r'([a-zA-Z0-9][a-zA-Z0-9\-]{0,49})\.servicebus\.windows\.net',      re.I), 1),
        ('Redis',                 re.compile(r'([a-zA-Z0-9][a-zA-Z0-9\-]{0,49})\.redis\.cache\.windows\.net',   re.I), 1),
        ('KeyVault',              re.compile(r'([a-zA-Z0-9][a-zA-Z0-9\-]{0,23})\.vault\.azure\.net',             re.I), 1),
        ('AppService/Function',   re.compile(r'([a-zA-Z0-9][a-zA-Z0-9\-]{0,39})\.azurewebsites\.net',            re.I), 1),
        ('ContainerRegistry',     re.compile(r'([a-zA-Z0-9]{5,50})\.azurecr\.io',                                re.I), 1),
        ('CognitiveServices',     re.compile(r'([a-zA-Z0-9][a-zA-Z0-9\-]{0,63})\.cognitiveservices\.azure\.com',  re.I), 1),
        ('OpenAI',                re.compile(r'([a-zA-Z0-9][a-zA-Z0-9\-]{0,63})\.openai\.azure\.com',           re.I), 1),
        ('APIManagement',         re.compile(r'([a-zA-Z0-9][a-zA-Z0-9\-]{0,49})\.azure\-api\.net',              re.I), 1),
        ('Search',                re.compile(r'([a-zA-Z0-9][a-zA-Z0-9\-]{1,59})\.search\.windows\.net',         re.I), 1),
        ('IoTHub',                re.compile(r'([a-zA-Z0-9][a-zA-Z0-9\-]{0,49})\.azure\-devices\.net',           re.I), 1),
        ('SignalR',               re.compile(r'([a-zA-Z0-9][a-zA-Z0-9\-]{0,62})\.service\.signalr\.net',        re.I), 1),
        ('CDN',                   re.compile(r'([a-zA-Z0-9][a-zA-Z0-9\-]{0,49})\.azureedge\.net',                re.I), 1),
        ('FrontDoor',             re.compile(r'([a-zA-Z0-9][a-zA-Z0-9\-]{0,63})\.azurefd\.net',                 re.I), 1),
        ('Databricks',            re.compile(r'adb\-[a-zA-Z0-9\-]+\.azuredatabricks\.net',                     re.I), 0),
        ('AppInsights/IKey',      re.compile(r'InstrumentationKey\s*=\s*([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})', re.I), 1),
        ('AppInsights/ConnStr',   re.compile(r'APPLICATIONINSIGHTS_CONNECTION_STRING\s*[=:\"\']', re.I), 0),
        ('EventGrid',             re.compile(r'([a-zA-Z0-9][a-zA-Z0-9\-]{0,49})\.eventgrid\.azure\.net',        re.I), 1),
        ('AzureML',               re.compile(r'([a-zA-Z0-9][a-zA-Z0-9\-]{0,63})\.azureml\.net',                 re.I), 1),
        ('ServiceFabric',         re.compile(r'([a-zA-Z0-9][a-zA-Z0-9\-]{0,63})\.cloudapp\.azure\.com',         re.I), 1),
        ('StorageConnStr',        re.compile(r'DefaultEndpointsProtocol=https?;AccountName=([a-z0-9]{3,24})',      re.I), 1),
        ('EventHub/Entity',       re.compile(r'EntityPath=([^;"\s\'"]+)',                                        re.I), 1),
        ('AzureFunctions/Host',   re.compile(r'([a-zA-Z0-9][a-zA-Z0-9\-]{0,39})\.azurefd\.net',                re.I), 1),
        ('NotificationHub',       re.compile(r'Endpoint=sb://([a-zA-Z0-9][a-zA-Z0-9\-]{0,49})\.servicebus\.windows\.net', re.I), 1),
    ]

    # Azure SDK import/require patterns  (covers .NET, Python, JS/TS, Java)
    _AZURE_SDK_IMPORT_PATTERNS = [
        re.compile(r'^\s*using\s+(Azure\.[A-Za-z\.]+)\s*;',             re.M),   # C#
        re.compile(r'^\s*from\s+(azure\.[a-z_.]+)\s+import',            re.M),   # Python
        re.compile(r'^\s*import\s+(azure\.[a-z_.]+)',                    re.M),   # Python (direct)
        re.compile(r'from\s+[\'"](\@azure/[a-z\-]+)[\'"]',             re.M),   # JS/TS ESM
        re.compile(r'require\([\'"](\@azure/[a-z\-]+)[\'"]\)',          re.M),   # JS/TS CJS
        re.compile(r'^\s*import\s+(com\.azure\.[a-z_.]+)',              re.M),   # Java
        re.compile(r'^\s*import\s+(com\.microsoft\.azure\.[a-z_.]+)',  re.M),   # Java (old)
    ]

    def __init__(self, config_file: str = "config.json"):
        """Initialize Azure Discovery"""
        self.config = self._load_config(config_file)
        self.setup_logging()
        self.credential = self._get_credential()
        # Lock used to serialise writes to shared lists/dicts when parallel workers
        # are active (e.g. arm_templates.extend inside scan_repository_code).
        self._scan_lock = threading.Lock()
        # Optional read-only enforcement: attach _ReadOnlyHttpPolicy to every SDK client.
        # Enable in config.json: "read_only_enforce": true
        _enforce = self.config.get('read_only_enforce', True)
        self._ro_policies = [_ReadOnlyHttpPolicy()] if _enforce else []
        if _enforce:
            self.logger.info("READ-ONLY ENFORCEMENT: active — non-GET SDK calls will raise RuntimeError")
        self.discovery_data = {
            'metadata': {
                'discovery_date': datetime.now().isoformat(),
                'discovery_by': os.getenv('USERNAME', 'unknown'),
            },
            'subscriptions': {},
            'entra_id': {},
            'summary': defaultdict(int),
            'dependencies': [],
            'network_topology': {},
            'applications': {},
            'risks': [],
            'arm_templates': [],
            'application_dependencies': [],
            'code_inventory': {}
        }
    
    def _load_config(self, config_file: str) -> Dict:
        """Load configuration from file or use defaults"""
        default_config = {
            'auth_method': 'default',  # default, service_principal, cli
            'tenant_id': os.getenv('AZURE_TENANT_ID', ''),
            'client_id': os.getenv('AZURE_CLIENT_ID', ''),
            'client_secret': os.getenv('AZURE_CLIENT_SECRET', ''),
            'subscription_ids': [],  # Empty = all subscriptions
            'output_dir': 'discovery_output',
            'scan_code': True,
            'scan_network_flows': True,
            'deep_dependency_analysis': True,
            'git_repos': [],  # List of git repo URLs to scan
            'excluded_resource_groups': [],
            'log_level': 'INFO'
        }
        
        if os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    user_config = json.load(f)
                    default_config.update(user_config)
                    print(f"✓ Loaded configuration from {config_file}")
            except Exception as e:
                print(f"Warning: Could not load config file: {e}. Using defaults.")
        
        # Build Azure DevOps git repo URLs from parameterized config
        self._build_devops_repo_urls(default_config)
        
        return default_config
    
    def _build_devops_repo_urls(self, config: Dict):
        """Build Azure DevOps repository URLs from parameterized configuration.

        When a project entry has an empty / missing 'repositories' list, this
        method calls the Azure DevOps REST API (GET _apis/git/repositories) to
        enumerate ALL repositories in that project automatically.
        """
        import urllib.parse

        if 'azure_devops' not in config:
            print("  ℹ No azure_devops section in config - skipping DevOps repo URL building")
            return
        
        devops = config.get('azure_devops', {})
        organization = devops.get('organization', '')
        pat_token = devops.get('pat_token', '')
        projects = devops.get('projects', [])
        
        # Skip if required fields are placeholders or empty
        if not organization or not pat_token:
            print("")
            print("  " + "!"*70)
            print("  !! AZURE DEVOPS GIT REPOS — NOT CONFIGURED")
            print("  !! 'organization' or 'pat_token' is empty in config.json")
            print("  !! No repositories will be cloned or scanned.")
            print("  !!")
            print("  !! FIX: open config.json and fill in:")
            print("  !!   azure_devops.organization  → your Azure DevOps org name")
            print("  !!   azure_devops.pat_token     → a PAT with Code (Read) scope")
            print("  !!   (DevOps → User Settings → Personal Access Tokens)")
            print("  " + "!"*70)
            print("")
            return
        if 'YOUR_' in str(organization) or 'YOUR_' in str(pat_token):
            print("")
            print("  " + "!"*70)
            print("  !! AZURE DEVOPS GIT REPOS — STILL USING PLACEHOLDER VALUES")
            print("  !! config.json still contains the default example values.")
            print("  !! No repositories will be cloned or scanned.")
            print("  !!")
            print("  !! FIX: open config.json and replace each YOUR_... value:")
            print(f"  !!   azure_devops.organization  = '{organization}'  ← replace this")
            print(f"  !!   azure_devops.pat_token     = '{pat_token[:12]}...'  ← replace this")
            print("  !!   (DevOps → User Settings → Personal Access Tokens → Code Read)")
            print("  " + "!"*70)
            print("")
            return
        
        if not config.get('git_repos'):
            config['git_repos'] = []
        
        # Build base64-encoded Basic auth header for REST API calls
        import base64
        _auth_bytes = base64.b64encode(f":{pat_token}".encode('utf-8')).decode('utf-8')
        _rest_headers = {
            'Authorization': f'Basic {_auth_bytes}',
            'Accept': 'application/json',
        }

        def _list_all_repos_for_project(org: str, project: str) -> list:
            """Call DevOps REST API to get all repo names in a project."""
            api_url = (
                f"https://dev.azure.com/{urllib.parse.quote(org, safe='')}/"
                f"{urllib.parse.quote(project, safe='')}/"
                f"_apis/git/repositories?api-version=7.0"
            )
            try:
                resp = requests.get(api_url, headers=_rest_headers, timeout=30,
                                    verify=False)
                if resp.status_code == 200:
                    repos_json = resp.json()
                    names = [r['name'] for r in repos_json.get('value', [])]
                    print(f"  ✓ Auto-discovered {len(names)} repo(s) in project '{project}': {names}")
                    return names
                else:
                    print(f"  !! DevOps REST API returned {resp.status_code} for project '{project}'")
                    print(f"     URL: {api_url}")
                    if resp.status_code in (401, 203):
                        print(f"  !! PAT token rejected or lacks 'Code (Read)' scope.")
                        print(f"     DevOps → User Settings → Personal Access Tokens → Code (Read)")
                    elif resp.status_code == 404:
                        print(f"  !! Project '{project}' not found in org '{org}'.")
                        print(f"     Check azure_devops.projects[].project_name in config.json")
            except requests.exceptions.SSLError:
                # Retry without SSL verification (corporate proxy / self-signed cert)
                try:
                    resp2 = requests.get(api_url, headers=_rest_headers, timeout=30, verify=False)
                    if resp2.status_code == 200:
                        names = [r['name'] for r in resp2.json().get('value', [])]
                        print(f"  ✓ Auto-discovered {len(names)} repo(s) in project '{project}' (SSL bypass)")
                        return names
                except Exception as e2:
                    print(f"  !! REST API call failed (SSL bypass also failed): {e2}")
            except Exception as e:
                print(f"  !! Could not reach DevOps REST API for project '{project}': {e}")
            return []

        added = 0
        for project_config in projects:
            project_name = project_config.get('project_name', '')
            # Support both 'repositories' (list of dicts) and missing/empty list
            repositories = project_config.get('repositories', [])
            
            if not project_name or 'YOUR_' in str(project_name):
                print(f"  !! Skipping project — placeholder or empty name: '{project_name}'")
                print( "  !! Fix: set azure_devops.projects[].project_name in config.json")
                continue

            # ── Auto-discover repos via REST API if list is empty ────────────
            if not repositories:
                print(f"  ℹ repositories[] is empty for project '{project_name}' — "
                      f"auto-discovering via Azure DevOps REST API...")
                discovered = _list_all_repos_for_project(organization, project_name)
                repositories = [{'repo_name': n} for n in discovered]
                if not repositories:
                    print(f"  !! No repositories found for project '{project_name}'. "
                          f"Check project name and PAT permissions.")
                    continue
            
            for repo in repositories:
                # ── FIELD NAME FIX ───────────────────────────────────────────
                # config.json uses 'repo_name'; older entries may use 'name'
                if isinstance(repo, dict):
                    repo_name   = repo.get('repo_name', '') or repo.get('name', '')
                    repo_branch = repo.get('branch', None)
                else:
                    repo_name   = str(repo)
                    repo_branch = None
                # ─────────────────────────────────────────────────────────────
                
                if not repo_name or 'YOUR_' in str(repo_name):
                    continue
                
                # URL-encode PAT token to handle special characters (=, +, /, etc.)
                encoded_pat = urllib.parse.quote(str(pat_token), safe='')
                repo_url = (
                    f"https://pat:{encoded_pat}@dev.azure.com/"
                    f"{urllib.parse.quote(organization, safe='')}/"
                    f"{urllib.parse.quote(project_name, safe='')}/"
                    f"_git/{urllib.parse.quote(repo_name, safe='')}"
                )
                config['git_repos'].append({'url': repo_url, 'branch': repo_branch,
                                             'project': project_name, 'repo': repo_name})
                print(f"  ✓ Added Azure DevOps repo: {organization}/{project_name}/{repo_name}"
                      + (f" (branch: {repo_branch})" if repo_branch else ""))
                added += 1
        
        if added == 0:
            print("")
            print("  " + "!"*70)
            print("  !! AZURE DEVOPS — 0 REPOSITORIES ADDED")
            print("  !! All project/repository names are empty or still placeholders.")
            print("  !! FIX: open config.json and update:")
            print("  !!   azure_devops.projects[].project_name  → exact DevOps project name")
            print("  !!   azure_devops.projects[].repositories[].repo_name → exact repo name")
            print("  !!   (case-sensitive, must match exactly what you see in Azure DevOps Repos)")
            print("  !! TIP: leave repositories[] empty to auto-discover all repos in a project")
            print("  " + "!"*70)
            print("")
    
    def setup_logging(self):
        """Setup logging configuration"""
        os.makedirs(self.config['output_dir'], exist_ok=True)
        log_file = os.path.join(self.config['output_dir'], 
                               f"discovery_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
        
        logging.basicConfig(
            level=getattr(logging, self.config['log_level']),
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file, encoding='utf-8'),
                logging.StreamHandler(sys.stdout)  # stdout already set to UTF-8 at module start
            ]
        )
        self.logger = logging.getLogger(__name__)
        self.logger.info("="*80)
        self.logger.info("Azure Discovery Tool Started")
        self.logger.info("="*80)
        self.logger.info("")
        self.logger.info("🔒 SECURITY: Running in READ-ONLY mode")
        self.logger.info("   ✓ No resources will be created, modified, or deleted")
        self.logger.info("   ✓ Only list/get operations will be performed")
        self.logger.info("   ✓ Safe to run in production environments")
        self.logger.info("")
        self.logger.info("="*80)
    
    def _get_credential(self):
        """Get Azure credential based on configuration"""
        self.logger.info("Authenticating to Azure...")
        
        try:
            if self.config['auth_method'] == 'service_principal':
                if not all([self.config['tenant_id'], 
                          self.config['client_id'], 
                          self.config['client_secret']]):
                    raise ValueError("Service Principal requires tenant_id, client_id, and client_secret")
                
                credential = ClientSecretCredential(
                    tenant_id=self.config['tenant_id'],
                    client_id=self.config['client_id'],
                    client_secret=self.config['client_secret']
                )
                self.logger.info("✓ Using Service Principal authentication")
            else:
                # DefaultAzureCredential tries multiple methods:
                # 1. Environment variables
                # 2. Managed Identity
                # 3. Azure CLI
                # 4. Interactive browser
                credential = DefaultAzureCredential()
                self.logger.info("✓ Using DefaultAzureCredential (supports CLI, Managed Identity, etc.)")
            
            return credential
            
        except Exception as e:
            self.logger.error(f"Authentication failed: {e}")
            raise
    
    def verify_azure_connectivity(self) -> bool:
        """Verify Azure connectivity using az commands before running discovery"""
        import subprocess
        
        self.logger.info("\n" + "="*80)
        self.logger.info("VERIFYING AZURE CONNECTIVITY")
        self.logger.info("="*80)
        
        try:
            # Check if az CLI is installed
            result = subprocess.run(['az', '--version'], 
                                  capture_output=True, 
                                  text=True, 
                                  timeout=10,
                                  shell=True)
            if result.returncode != 0:
                self.logger.warning("⚠ Azure CLI check failed - but will continue with SDK authentication")
                self.logger.debug(f"Error: {result.stderr}")
            else:
                self.logger.info("✓ Azure CLI is installed")
            
            # Check if logged in
            result = subprocess.run(['az', 'account', 'show'], 
                                  capture_output=True, 
                                  text=True, 
                                  timeout=30,
                                  shell=True)
            if result.returncode != 0:
                self.logger.warning("⚠ Azure CLI authentication check failed - but will continue with SDK")
                self.logger.debug(f"Error: {result.stderr}")
            else:
                self.logger.info("✓ Azure CLI is authenticated")
            
            # List subscriptions
            self.logger.info("\nTesting subscription access via Azure CLI...")
            result = subprocess.run(['az', 'account', 'list', '--output', 'json'], 
                                  capture_output=True, 
                                  text=True, 
                                  timeout=30,
                                  shell=True)
            if result.returncode != 0:
                self.logger.warning("⚠ Cannot list subscriptions via CLI - will use SDK instead")
                self.logger.debug(f"Error: {result.stderr}")
            else:
                import json as json_module
                try:
                    subs = json_module.loads(result.stdout)
                    if not subs:
                        self.logger.warning("⚠ No subscriptions found via CLI!")
                    else:
                        self.logger.info(f"✓ Found {len(subs)} subscription(s) via CLI:")
                        for sub in subs[:3]:  # Show first 3
                            self.logger.info(f"   - {sub['name']} (ID: {sub['id']})")
                        
                        # Test resource listing on first subscription
                        test_sub_id = subs[0]['id']
                        self.logger.info(f"\nTesting resource listing on: {subs[0]['name']}...")
                        result = subprocess.run(['az', 'resource', 'list', 
                                               '--subscription', test_sub_id,
                                               '--output', 'json'], 
                                              capture_output=True, 
                                              text=True, 
                                              timeout=60,
                                              shell=True)
                        if result.returncode != 0:
                            self.logger.warning(f"⚠ Cannot list resources via CLI: {result.stderr}")
                        else:
                            resources = json_module.loads(result.stdout)
                            self.logger.info(f"✓ Successfully listed {len(resources)} resource(s) via CLI")
                            if len(resources) == 0:
                                self.logger.warning("⚠ No resources found in this subscription")
                            else:
                                self.logger.info(f"   Sample resources:")
                                for res in resources[:5]:  # Show first 5
                                    self.logger.info(f"   - {res.get('name')} ({res.get('type')})")
                except json_module.JSONDecodeError as e:
                    self.logger.warning(f"⚠ Could not parse CLI output: {e}")
            
            self.logger.info("\n" + "="*80)
            self.logger.info("✅ CONNECTIVITY CHECK COMPLETED - Proceeding with SDK-based discovery")
            self.logger.info("="*80 + "\n")
            return True  # Always return True, as CLI is optional
            
        except subprocess.TimeoutExpired:
            self.logger.warning("⚠ Azure CLI command timed out - will use SDK instead")
            return True  # Continue anyway
        except FileNotFoundError:
            self.logger.warning("⚠ Azure CLI (az) not found in PATH - will use SDK authentication instead")
            self.logger.info("   The tool will use Azure SDK with DefaultAzureCredential")
            return True  # Continue with SDK
        except Exception as e:
            self.logger.warning(f"⚠ CLI verification failed: {e} - will use SDK instead")
            self.logger.debug(traceback.format_exc())
            return True  # Continue with SDK
    
    def get_subscriptions(self) -> List[Dict]:
        """Get all accessible subscriptions (filtered by names/IDs if configured)"""
        self.logger.info("Discovering subscriptions...")
        subscriptions = []
        
        try:
            sub_client = SubscriptionClient(self.credential)
            
            subscription_ids = self.config.get('subscription_ids', [])
            subscription_names = self.config.get('subscription_names', [])
            
            # Normalize names for case-insensitive matching
            subscription_names_lower = [name.lower() for name in subscription_names]
            
            if subscription_ids or subscription_names:
                self.logger.info("Filtering subscriptions...")
                if subscription_names:
                    self.logger.info(f"  By names: {subscription_names}")
                if subscription_ids:
                    self.logger.info(f"  By IDs: {subscription_ids}")
                
                # Get all subscriptions first
                all_subs = list(sub_client.subscriptions.list())
                
                for sub in all_subs:
                    if sub.state != 'Enabled':
                        continue
                    
                    # Check if subscription matches by ID
                    matched_by_id = sub.subscription_id in subscription_ids
                    
                    # Check if subscription matches by name (case-insensitive, partial match)
                    matched_by_name = False
                    if subscription_names_lower:
                        sub_name_lower = sub.display_name.lower()
                        matched_by_name = any(name in sub_name_lower for name in subscription_names_lower)
                    
                    # Add if matched by either ID or name
                    if matched_by_id or matched_by_name:
                        subscriptions.append({
                            'id': sub.subscription_id,
                            'name': sub.display_name,
                            'state': sub.state
                        })
                        match_reason = []
                        if matched_by_id:
                            match_reason.append("ID")
                        if matched_by_name:
                            match_reason.append("Name")
                        self.logger.debug(f"  Matched '{sub.display_name}' by {', '.join(match_reason)}")
                
                if not subscriptions:
                    self.logger.warning("⚠ No subscriptions matched the specified filters!")
                    self.logger.warning("  Available subscriptions:")
                    for sub in all_subs[:5]:  # Show first 5
                        self.logger.warning(f"    - {sub.display_name} ({sub.subscription_id})")
            else:
                # Neither subscription_ids nor subscription_names provided — halt.
                self.logger.error("")
                self.logger.error("  " + "!" * 68)
                self.logger.error("  !! ERROR: No subscriptions mentioned in config.json.")
                self.logger.error("  !!")
                self.logger.error("  !! Add at least one of these fields to config.json:")
                self.logger.error("  !!   \"subscription_ids\":   [\"xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx\"]")
                self.logger.error("  !!   \"subscription_names\": [\"My Production Subscription\"]")
                self.logger.error("  !!")
                self.logger.error("  !! Names are case-insensitive and support partial matching.")
                self.logger.error("  " + "!" * 68)
                self.logger.error("")
                raise ValueError(
                    "No subscription_ids or subscription_names configured in config.json. "
                    "Add at least one subscription to proceed.")
            
        except Exception as e:
            self.logger.error(f"Failed to get subscriptions: {e}")
            raise
    
    def discover_subscription_resources(self, subscription_id: str, subscription_name: str):
        """Discover all resources in a subscription"""
        self.logger.info(f"\n{'='*80}")
        self.logger.info(f"Discovering resources in: {subscription_name}")
        self.logger.info(f"{'='*80}")
        
        sub_data = {
            'name': subscription_name,
            'id': subscription_id,
            'resource_groups': {},
            'resources': [],
            'networks': [],
            'databases': [],
            'app_services': [],
            'storage_accounts': [],
            'key_vaults': [],
            'api_management': [],
            'functions': [],
            'logic_apps': [],
            'service_bus': [],
            'event_hubs': [],
            'cosmos_db': [],
            'redis_cache': [],
            'app_insights': [],
            'virtual_machines': [],
            'aks_clusters': [],
            'container_registries': [],
            'sql_servers': [],
            'dns_zones': [],
            'traffic_managers': [],
            'frontdoors': [],
            'cdns': [],
            'cognitive_services': [],
            'search_services': [],
            'data_factories': [],
            'databricks': [],
            'log_analytics': [],
            'communication_services': [],
            'notification_hubs': []
        }
        
        try:
            # Initialize clients — per_call_policies enforces read-only when enabled
            _kw = dict(per_call_policies=self._ro_policies) if self._ro_policies else {}
            resource_client = ResourceManagementClient(self.credential, subscription_id, **_kw)
            network_client = NetworkManagementClient(self.credential, subscription_id, **_kw)
            compute_client = ComputeManagementClient(self.credential, subscription_id, **_kw)
            web_client = WebSiteManagementClient(self.credential, subscription_id, **_kw)
            sql_client = SqlManagementClient(self.credential, subscription_id, **_kw)
            storage_client = StorageManagementClient(self.credential, subscription_id, **_kw)
            
            # Discover Resource Groups
            self.logger.info("Discovering resource groups...")
            rg_count = 0
            try:
                for rg in resource_client.resource_groups.list():
                    if rg.name not in self.config['excluded_resource_groups']:
                        sub_data['resource_groups'][rg.name] = {
                            'name': rg.name,
                            'location': rg.location,
                            'tags': rg.tags or {},
                            'resources': []
                        }
                        rg_count += 1
            except Exception as e:
                self.logger.error(f"Error listing resource groups: {e}")
                self.logger.error(traceback.format_exc())
                
            self.logger.info(f"✓ Found {len(sub_data['resource_groups'])} resource groups")
            
            if len(sub_data['resource_groups']) == 0:
                self.logger.warning(f"⚠ WARNING: No resource groups found in subscription '{subscription_name}'")
                self.logger.warning("   Please verify access with: az group list --subscription " + subscription_id)
            
            # ── Run resource-type discoverers AND generic resource list in PARALLEL ──
            # resource_client.resources.list() paginates ALL resources serially and
            # was the biggest SDK bottleneck.  Moving it into the same pool means it
            # overlaps with all other typed discoverers instead of blocking them.
            self.logger.info("Discovering all resources (parallel)...")
            resource_count = 0

            def _generic_resource_list():
                nonlocal resource_count
                try:
                    for resource in resource_client.resources.list():
                        try:
                            if any(rg in resource.id for rg in self.config['excluded_resource_groups']):
                                continue
                            resource_info = {
                                'name': resource.name,
                                'type': resource.type,
                                'location': resource.location,
                                'id': resource.id,
                                'tags': resource.tags or {},
                                'resource_group': resource.id.split('/')[4] if len(resource.id.split('/')) > 4 else 'unknown'
                            }
                            sub_data['resources'].append(resource_info)
                            resource_count += 1
                            rg_name = resource_info['resource_group']
                            if rg_name in sub_data['resource_groups']:
                                sub_data['resource_groups'][rg_name]['resources'].append(resource_info)
                        except Exception as e:
                            self.logger.warning(f"Failed to process resource {getattr(resource, 'name', 'unknown')}: {e}")
                except Exception as e:
                    self.logger.error(f"Error listing resources: {e}")
                    self.logger.error(traceback.format_exc())

            _max_w = self.config.get('parallel_workers', 8)
            _discover_tasks = {
                'generic_resources': _generic_resource_list,
                'networking':        lambda: self.discover_networking(network_client, sub_data),
                'virtual_machines':  lambda: self.discover_virtual_machines(compute_client, sub_data),
                'app_services':      lambda: self.discover_app_services(web_client, sub_data, subscription_id),
                'sql_databases':     lambda: self.discover_sql_databases(sql_client, sub_data),
                'storage_accounts':  lambda: self.discover_storage_accounts(storage_client, sub_data),
                'paas_services':     lambda: self.discover_paas_services(subscription_id, sub_data),
            }
            self.logger.info(f"Running {len(_discover_tasks)} discovery tasks in parallel (max_workers={_max_w})...")
            with ThreadPoolExecutor(max_workers=_max_w) as _pool:
                _futs = {_pool.submit(fn): name for name, fn in _discover_tasks.items()}
                for _fut in as_completed(_futs):
                    _name = _futs[_fut]
                    try:
                        _fut.result()
                    except Exception as _e:
                        self.logger.error(f"Error in {_name} discovery: {_e}")
                        self.logger.error(traceback.format_exc())

            self.logger.info(f"✓ Found {len(sub_data['resources'])} total resources")
            if len(sub_data['resources']) == 0:
                self.logger.warning(f"⚠ WARNING: No resources found in subscription '{subscription_name}'")
                self.logger.warning("   1. The subscription is empty")
                self.logger.warning("   2. Insufficient permissions to list resources")
                self.logger.warning("   3. API throttling or connectivity issues")
                self.logger.warning("   Please verify with: az resource list --subscription " + subscription_id)

            self.discovery_data['summary']['total_resources'] += len(sub_data['resources'])
            
            # Store subscription data
            self.discovery_data['subscriptions'][subscription_id] = sub_data
            
        except Exception as e:
            self.logger.error(f"Error discovering subscription {subscription_name}: {e}")
            self.logger.error(traceback.format_exc())
    
    def discover_networking(self, network_client, sub_data):
        """Discover networking resources"""
        self.logger.info("Discovering networking resources...")
        
        try:
            # Fetch all five networking resource types in parallel
            with ThreadPoolExecutor(max_workers=5) as _net_pool:
                _f_vnets = _net_pool.submit(lambda: list(network_client.virtual_networks.list_all()))
                _f_nsgs  = _net_pool.submit(lambda: list(network_client.network_security_groups.list_all()))
                _f_pips  = _net_pool.submit(lambda: list(network_client.public_ip_addresses.list_all()))
                _f_lbs   = _net_pool.submit(lambda: list(network_client.load_balancers.list_all()))
                _f_agws  = _net_pool.submit(lambda: list(network_client.application_gateways.list_all()))
            # All futures resolved; retrieve results (exceptions re-raised here if needed)
            vnets          = _f_vnets.result()
            nsgs_raw       = _f_nsgs.result()
            public_ips_raw = _f_pips.result()
            lbs_raw        = _f_lbs.result()
            agws_raw       = _f_agws.result()

            # Virtual Networks
            for vnet in vnets:
                vnet_info = {
                    'name': vnet.name,
                    'id': vnet.id,
                    'location': vnet.location,
                    'address_space': vnet.address_space.address_prefixes if vnet.address_space else [],
                    'subnets': [],
                    'peerings': [],
                    'resource_group': vnet.id.split('/')[4]
                }
                
                # Subnets
                if vnet.subnets:
                    for subnet in vnet.subnets:
                        subnet_info = {
                            'name': subnet.name,
                            'address_prefix': subnet.address_prefix,
                            'nsg': subnet.network_security_group.id if subnet.network_security_group else None,
                            'route_table': subnet.route_table.id if subnet.route_table else None,
                            'service_endpoints': [ep.service for ep in subnet.service_endpoints] if subnet.service_endpoints else []
                        }
                        vnet_info['subnets'].append(subnet_info)
                
                # Peerings
                if vnet.virtual_network_peerings:
                    for peering in vnet.virtual_network_peerings:
                        vnet_info['peerings'].append({
                            'name': peering.name,
                            'remote_vnet': peering.remote_virtual_network.id if peering.remote_virtual_network else None,
                            'status': peering.peering_state
                        })
                
                sub_data['networks'].append(vnet_info)
            
            self.logger.info(f"  ✓ Found {len(vnets)} Virtual Networks")
            self.discovery_data['summary']['vnets'] += len(vnets)
            
            # Network Security Groups (already fetched in parallel above)
            nsgs = nsgs_raw
            nsg_data = []
            for nsg in nsgs:
                nsg_info = {
                    'name': nsg.name,
                    'id': nsg.id,
                    'location': nsg.location,
                    'resource_group': nsg.id.split('/')[4],
                    'security_rules': []
                }
                
                if nsg.security_rules:
                    for rule in nsg.security_rules:
                        nsg_info['security_rules'].append({
                            'name': rule.name,
                            'priority': rule.priority,
                            'direction': rule.direction,
                            'access': rule.access,
                            'protocol': rule.protocol,
                            'source_address_prefix': rule.source_address_prefix,
                            'source_port_range': rule.source_port_range,
                            'destination_address_prefix': rule.destination_address_prefix,
                            'destination_port_range': rule.destination_port_range
                        })
                
                nsg_data.append(nsg_info)
            
            sub_data['nsgs'] = nsg_data
            self.logger.info(f"  ✓ Found {len(nsgs)} Network Security Groups")
            self.discovery_data['summary']['nsgs'] += len(nsgs)
            
            # Public IP Addresses (already fetched in parallel above)
            public_ips = public_ips_raw
            pip_data = []
            for pip in public_ips:
                pip_data.append({
                    'name': pip.name,
                    'id': pip.id,
                    'location': pip.location,
                    'ip_address': pip.ip_address,
                    'allocation_method': pip.public_ip_allocation_method,
                    'dns_name': pip.dns_settings.fqdn if pip.dns_settings else None,
                    'resource_group': pip.id.split('/')[4]
                })
            
            sub_data['public_ips'] = pip_data
            self.logger.info(f"  ✓ Found {len(public_ips)} Public IP Addresses")
            
            # Load Balancers (already fetched in parallel above)
            load_balancers = lbs_raw
            lb_data = []
            for lb in load_balancers:
                lb_data.append({
                    'name': lb.name,
                    'id': lb.id,
                    'location': lb.location,
                    'sku': lb.sku.name if lb.sku else None,
                    'frontend_ips': [fip.name for fip in lb.frontend_ip_configurations] if lb.frontend_ip_configurations else [],
                    'backend_pools': [bp.name for bp in lb.backend_address_pools] if lb.backend_address_pools else [],
                    'resource_group': lb.id.split('/')[4]
                })
            
            sub_data['load_balancers'] = lb_data
            self.logger.info(f"  ✓ Found {len(load_balancers)} Load Balancers")
            
            # Application Gateways (already fetched in parallel above)
            app_gateways = agws_raw
            agw_data = []
            for agw in app_gateways:
                agw_data.append({
                    'name': agw.name,
                    'id': agw.id,
                    'location': agw.location,
                    'sku': agw.sku.name if agw.sku else None,
                    'tier': agw.sku.tier if agw.sku else None,
                    'capacity': agw.sku.capacity if agw.sku else None,
                    'resource_group': agw.id.split('/')[4]
                })
            
            sub_data['app_gateways'] = agw_data
            self.logger.info(f"  ✓ Found {len(app_gateways)} Application Gateways")
            
        except Exception as e:
            self.logger.error(f"Error discovering networking: {e}")
            self.logger.error(traceback.format_exc())
    
    def discover_virtual_machines(self, compute_client, sub_data):
        """Discover Virtual Machines"""
        self.logger.info("Discovering Virtual Machines...")
        
        try:
            vms = list(compute_client.virtual_machines.list_all())
            for vm in vms:
                vm_info = {
                    'name': vm.name,
                    'id': vm.id,
                    'location': vm.location,
                    'resource_group': vm.id.split('/')[4],
                    'vm_size': vm.hardware_profile.vm_size if vm.hardware_profile else None,
                    'os_type': vm.storage_profile.os_disk.os_type if vm.storage_profile and vm.storage_profile.os_disk else None,
                    'os_disk': {},
                    'image_reference': {},
                    'data_disks': [],
                    'network_interfaces': [],
                    'vnet': None,
                    'subnet': None,
                    'availability_set': vm.availability_set.id if vm.availability_set else None,
                    'tags': vm.tags or {}
                }
                
                # OS Disk information
                if vm.storage_profile and vm.storage_profile.os_disk:
                    os_disk = vm.storage_profile.os_disk
                    vm_info['os_disk'] = {
                        'name': os_disk.name,
                        'size_gb': os_disk.disk_size_gb,
                        'create_option': os_disk.create_option,
                        'caching': os_disk.caching,
                        'managed_disk_id': os_disk.managed_disk.id if os_disk.managed_disk else None,
                        'storage_account': os_disk.vhd.uri.split('/')[2].split('.')[0] if os_disk.vhd else None
                    }
                
                # Image details
                if vm.storage_profile and vm.storage_profile.image_reference:
                    img = vm.storage_profile.image_reference
                    vm_info['image_reference'] = {
                        'publisher': img.publisher,
                        'offer': img.offer,
                        'sku': img.sku,
                        'version': img.version
                    }
                
                # Data disks
                if vm.storage_profile and vm.storage_profile.data_disks:
                    for disk in vm.storage_profile.data_disks:
                        disk_info = {
                            'name': disk.name,
                            'size_gb': disk.disk_size_gb,
                            'lun': disk.lun,
                            'caching': disk.caching,
                            'managed_disk_id': disk.managed_disk.id if disk.managed_disk else None,
                            'storage_account': disk.vhd.uri.split('/')[2].split('.')[0] if disk.vhd else None
                        }
                        vm_info['data_disks'].append(disk_info)
                
                # Network interfaces - extract VNet info
                if vm.network_profile and vm.network_profile.network_interfaces:
                    for nic in vm.network_profile.network_interfaces:
                        vm_info['network_interfaces'].append(nic.id)
                        # Extract VNet from NIC ID if possible
                        # NIC ID format: /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Network/networkInterfaces/{name}
                        # We need to look at the subnet to get VNet info
                        nic_id_parts = nic.id.split('/')
                        if len(nic_id_parts) >= 9:
                            nic_name = nic_id_parts[-1]
                            # Try to extract VNet from networks already discovered
                            for vnet in sub_data.get('networks', []):
                                for subnet in vnet.get('subnets', []):
                                    # This is a best effort - we'd need to actually query the NIC to be sure
                                    if not vm_info['vnet']:
                                        vm_info['vnet'] = vnet['name']
                                        vm_info['subnet'] = subnet['name']
                                        break
                
                sub_data['virtual_machines'].append(vm_info)
            
            self.logger.info(f"  ✓ Found {len(vms)} Virtual Machines")
            self.discovery_data['summary']['vms'] += len(vms)
            
        except Exception as e:
            self.logger.error(f"Error discovering VMs: {e}")
            self.logger.error(traceback.format_exc())
    
    def discover_app_services(self, web_client, sub_data, subscription_id):
        """Discover App Services and analyze configurations"""
        self.logger.info("Discovering App Services...")
        
        try:
            apps = list(web_client.web_apps.list())

            def _process_single_app(app):
                """Fully process one App Service: build info dict + fetch all details in parallel."""
                app_info = {
                    'name': app.name,
                    'id': app.id,
                    'location': app.location,
                    'resource_group': app.id.split('/')[4],
                    'kind': app.kind,
                    'state': app.state,
                    'default_host_name': app.default_host_name,
                    'enabled': app.enabled,
                    'https_only': app.https_only,
                    'app_service_plan': app.server_farm_id,
                    'runtime_stack': None,
                    'app_settings': {},
                    'connection_strings': {},
                    'custom_domains': [],
                    'ssl_certificates': [],
                    'ip_restrictions': [],
                    'external_dependencies': [],
                    'webjobs': [],
                    'deployment_slots': [],
                    'tags': app.tags or {}
                }
                rg_name = app.id.split('/')[4]

                # Fetch settings, connection strings, domains, slots IN PARALLEL for this app
                with ThreadPoolExecutor(max_workers=4) as _ap:
                    _f_settings = _ap.submit(lambda: web_client.web_apps.list_application_settings(rg_name, app.name))
                    _f_conn     = _ap.submit(lambda: web_client.web_apps.list_connection_strings(rg_name, app.name))
                    _f_domains  = _ap.submit(lambda: list(web_client.web_apps.list_host_name_bindings(rg_name, app.name)))
                    _f_slots    = _ap.submit(lambda: list(web_client.web_apps.list_slots(rg_name, app.name)))

                # Process settings
                try:
                    settings = _f_settings.result()
                    if settings and settings.properties:
                        for key, value in settings.properties.items():
                            if any(s in key.lower() for s in ['password', 'secret', 'key', 'token']):
                                app_info['app_settings'][key] = '***MASKED***'
                            else:
                                app_info['app_settings'][key] = value
                            if 'http://' in str(value) or 'https://' in str(value):
                                app_info['external_dependencies'].append({
                                    'type': 'URL in app setting',
                                    'key': key,
                                    'value': value
                                })
                except Exception as e:
                    self.logger.warning(f"Could not get app settings for {app.name}: {e}")

                # Process connection strings
                try:
                    conn_strings = _f_conn.result()
                    if conn_strings and conn_strings.properties:
                        for key, value in conn_strings.properties.items():
                            raw_val = str(value.value) if value.value else ''
                            azure_hint = _extract_azure_service_hint(raw_val)
                            app_info['connection_strings'][key] = {
                                'type': value.type,
                                'value': '***MASKED***',
                                'azure_hint': azure_hint
                            }
                            if value.type:
                                app_info['external_dependencies'].append({
                                    'type': f'Connection String - {value.type}',
                                    'key': key
                                })
                except Exception as e:
                    self.logger.warning(f"Could not get connection strings for {app.name}: {e}")

                # Process custom domains
                try:
                    for domain in _f_domains.result():
                        app_info['custom_domains'].append({
                            'name': domain.name,
                            'ssl_state': domain.ssl_state,
                            'thumbprint': domain.thumbprint
                        })
                except Exception as e:
                    self.logger.warning(f"Could not get custom domains for {app.name}: {e}")

                # Process deployment slots
                try:
                    for slot in _f_slots.result():
                        app_info['deployment_slots'].append({
                            'name': slot.name,
                            'state': slot.state,
                            'default_host_name': slot.default_host_name
                        })
                except Exception as e:
                    self.logger.warning(f"Could not get deployment slots for {app.name}: {e}")

                # Analyze IP restrictions for inbound traffic
                if app.site_config:
                    if app.site_config.ip_security_restrictions:
                        for restriction in app.site_config.ip_security_restrictions:
                            app_info['ip_restrictions'].append({
                                'ip_address': restriction.ip_address if hasattr(restriction, 'ip_address') else None,
                                'action': restriction.action if hasattr(restriction, 'action') else None,
                                'name': restriction.name if hasattr(restriction, 'name') else None
                            })

                # Scan source code if enabled
                if self.config['scan_code']:
                    self.scan_app_service_code(web_client, rg_name, app.name, app_info)

                return app_info

            # Process all apps in parallel (each app gets its own 4-call sub-pool above)
            _app_max_w = max(4, self.config.get('parallel_workers', 8))
            app_results = []
            with ThreadPoolExecutor(max_workers=_app_max_w) as _apps_pool:
                _app_futs = {_apps_pool.submit(_process_single_app, app): app.name for app in apps}
                for _fut in as_completed(_app_futs):
                    try:
                        app_results.append(_fut.result())
                    except Exception as _e:
                        self.logger.warning(f"Failed to process app {_app_futs[_fut]}: {_e}")

            sub_data['app_services'].extend(app_results)
            self.logger.info(f"  ✓ Found {len(apps)} App Services")
            self.discovery_data['summary']['app_services'] += len(apps)
            
            # Discover Azure Functions
            functions = [app for app in apps if app.kind and 'functionapp' in app.kind.lower()]
            self.logger.info(f"  ✓ Found {len(functions)} Azure Functions")
            self.discovery_data['summary']['functions'] += len(functions)
            
        except Exception as e:
            self.logger.error(f"Error discovering App Services: {e}")
            self.logger.error(traceback.format_exc())
    
    def scan_app_service_code(self, web_client, resource_group, app_name, app_info):
        """Mark App Service code scanning status.
        
        Full Kudu-based code scanning requires publishing credentials and is
        performed separately via scan_git_repositories() when git_repos are
        configured. This method only records the metadata.
        """
        app_info['code_analysis'] = {
            'scanned': False,
            'note': (
                'App Service code scanning via Kudu requires configuring git_repos '
                'or azure_devops in config.json. See README.md for instructions.'
            )
        }
    
    def discover_sql_databases(self, sql_client, sub_data):
        """Discover SQL Databases"""
        self.logger.info("Discovering SQL Databases...")
        
        try:
            servers = list(sql_client.servers.list())

            def _fetch_server_details(server):
                rg_name = server.id.split('/')[4]
                server_info = {
                    'name': server.name,
                    'id': server.id,
                    'location': server.location,
                    'resource_group': rg_name,
                    'admin_login': server.administrator_login,
                    'version': server.version,
                    'fqdn': server.fully_qualified_domain_name,
                    'databases': [],
                    'firewall_rules': [],
                    'vnet_rules': [],
                    'private_endpoints': [],
                    'tags': server.tags or {}
                }

                # Fetch databases, firewall rules and VNet rules in parallel
                with ThreadPoolExecutor(max_workers=3) as _sp:
                    _f_dbs   = _sp.submit(lambda: list(sql_client.databases.list_by_server(rg_name, server.name)))
                    _f_fws   = _sp.submit(lambda: list(sql_client.firewall_rules.list_by_server(rg_name, server.name)))
                    _f_vnet  = _sp.submit(lambda: list(sql_client.virtual_network_rules.list_by_server(rg_name, server.name)))

                try:
                    for db in _f_dbs.result():
                        if db.name != 'master':
                            server_info['databases'].append({
                                'name': db.name,
                                'sku': db.sku.name if db.sku else None,
                                'tier': db.sku.tier if db.sku else None,
                                'max_size_bytes': db.max_size_bytes,
                                'collation': db.collation,
                                'zone_redundant': db.zone_redundant
                            })
                except Exception as e:
                    self.logger.warning(f"Could not get databases for {server.name}: {e}")

                try:
                    for rule in _f_fws.result():
                        server_info['firewall_rules'].append({
                            'name': rule.name,
                            'start_ip': rule.start_ip_address,
                            'end_ip': rule.end_ip_address
                        })
                except Exception as e:
                    self.logger.warning(f"Could not get firewall rules for {server.name}: {e}")

                try:
                    for rule in _f_vnet.result():
                        server_info['vnet_rules'].append({
                            'name': rule.name,
                            'vnet_subnet': rule.virtual_network_subnet_id,
                            'ignore_missing_endpoint': rule.ignore_missing_vnet_service_endpoint
                        })
                except Exception as e:
                    self.logger.debug(f"Could not get VNet rules for {server.name}: {e}")

                return server_info

            # Fetch all servers in parallel
            _sql_max_w = max(4, self.config.get('parallel_workers', 8))
            with ThreadPoolExecutor(max_workers=_sql_max_w) as _sp_pool:
                _sql_futs = {_sp_pool.submit(_fetch_server_details, srv): srv.name for srv in servers}
                for _fut in as_completed(_sql_futs):
                    try:
                        sub_data['sql_servers'].append(_fut.result())
                    except Exception as _e:
                        self.logger.warning(f"Failed to process SQL server {_sql_futs[_fut]}: {_e}")
            
            self.logger.info(f"  ✓ Found {len(servers)} SQL Servers")
            self.discovery_data['summary']['sql_servers'] += len(servers)
            
        except Exception as e:
            self.logger.error(f"Error discovering SQL databases: {e}")
    
    def discover_storage_accounts(self, storage_client, sub_data):
        """Discover Storage Accounts"""
        self.logger.info("Discovering Storage Accounts...")
        
        try:
            storage_accounts = list(storage_client.storage_accounts.list())
            for sa in storage_accounts:
                sa_info = {
                    'name': sa.name,
                    'id': sa.id,
                    'location': sa.location,
                    'resource_group': sa.id.split('/')[4],
                    'sku': sa.sku.name if sa.sku else None,
                    'kind': sa.kind,
                    'access_tier': sa.access_tier,
                    'https_only': sa.enable_https_traffic_only,
                    'blob_endpoint': sa.primary_endpoints.blob if sa.primary_endpoints else None,
                    'file_endpoint': sa.primary_endpoints.file if sa.primary_endpoints else None,
                    'queue_endpoint': sa.primary_endpoints.queue if sa.primary_endpoints else None,
                    'table_endpoint': sa.primary_endpoints.table if sa.primary_endpoints else None,
                    'network_rules': {},
                    'tags': sa.tags or {}
                }
                
                # Network rules
                if sa.network_rule_set:
                    sa_info['network_rules'] = {
                        'default_action': sa.network_rule_set.default_action,
                        'ip_rules': [rule.ip_address_or_range for rule in sa.network_rule_set.ip_rules] if sa.network_rule_set.ip_rules else [],
                        'virtual_network_rules': [rule.virtual_network_resource_id for rule in sa.network_rule_set.virtual_network_rules] if sa.network_rule_set.virtual_network_rules else []
                    }
                
                sub_data['storage_accounts'].append(sa_info)
            
            self.logger.info(f"  ✓ Found {len(storage_accounts)} Storage Accounts")
            self.discovery_data['summary']['storage_accounts'] += len(storage_accounts)
            
        except Exception as e:
            self.logger.error(f"Error discovering storage accounts: {e}")
    
    def discover_paas_services(self, subscription_id, sub_data):
        """Discover other PaaS services — all service types run in parallel."""
        self.logger.info("Discovering PaaS services...")
        # Pass read-only policy to every SDK client created in this method
        _kw = dict(per_call_policies=self._ro_policies) if self._ro_policies else {}

        # ── Inner helpers — one per service type ──────────────────────────────
        # Each helper is self-contained: create client → list → append to sub_data.
        # They write to DIFFERENT sub_data keys so no locking is required.

        def _disc_keyvault():
            try:
                kv_client = KeyVaultManagementClient(self.credential, subscription_id, **_kw)
                vaults = list(kv_client.vaults.list())
                for vault in vaults:
                    sub_data['key_vaults'].append({
                        'name': vault.name, 'id': vault.id, 'location': vault.location,
                        'resource_group': vault.id.split('/')[4],
                        'vault_uri': vault.properties.vault_uri if vault.properties else None,
                        'sku': vault.properties.sku.name if vault.properties and vault.properties.sku else None,
                        'tenant_id': vault.properties.tenant_id if vault.properties else None
                    })
                self.logger.info(f"  ✓ Found {len(vaults)} Key Vaults")
                self.discovery_data['summary']['key_vaults'] += len(vaults)
            except Exception as e:
                self.logger.warning(f"Could not discover Key Vaults: {e}")

        def _disc_cosmos():
            try:
                cosmos_client = CosmosDBManagementClient(self.credential, subscription_id, **_kw)
                accounts = list(cosmos_client.database_accounts.list())
                for a in accounts:
                    sub_data['cosmos_db'].append({
                        'name': a.name, 'id': a.id, 'location': a.location,
                        'resource_group': a.id.split('/')[4], 'kind': a.kind,
                        'consistency_policy': a.consistency_policy.default_consistency_level if a.consistency_policy else None,
                        'locations': [loc.location_name for loc in a.locations] if a.locations else []
                    })
                self.logger.info(f"  ✓ Found {len(accounts)} Cosmos DB accounts")
                self.discovery_data['summary']['cosmos_db'] += len(accounts)
            except Exception as e:
                self.logger.warning(f"Could not discover Cosmos DB: {e}")

        def _disc_redis():
            try:
                redis_client = RedisManagementClient(self.credential, subscription_id, **_kw)
                caches = list(redis_client.redis.list())
                for c in caches:
                    sub_data['redis_cache'].append({
                        'name': c.name, 'id': c.id, 'location': c.location,
                        'resource_group': c.id.split('/')[4],
                        'sku': c.sku.name if c.sku else None,
                        'redis_version': c.redis_version, 'port': c.port, 'ssl_port': c.ssl_port
                    })
                self.logger.info(f"  ✓ Found {len(caches)} Redis Caches")
                self.discovery_data['summary']['redis_cache'] += len(caches)
            except Exception as e:
                self.logger.warning(f"Could not discover Redis Cache: {e}")

        def _disc_servicebus():
            try:
                sb_client = ServiceBusManagementClient(self.credential, subscription_id, **_kw)
                namespaces = list(sb_client.namespaces.list())
                for ns in namespaces:
                    rg_name = ns.id.split('/')[4]
                    ns_info = {
                        'name': ns.name, 'id': ns.id, 'location': ns.location,
                        'resource_group': rg_name,
                        'sku': ns.sku.name if ns.sku else None,
                        'queues': [], 'topics': []
                    }
                    # Fetch queues + topics in parallel for this namespace
                    with ThreadPoolExecutor(max_workers=2) as _sbp:
                        _fq = _sbp.submit(lambda: [q.name for q in sb_client.queues.list_by_namespace(rg_name, ns.name)])
                        _ft = _sbp.submit(lambda: [t.name for t in sb_client.topics.list_by_namespace(rg_name, ns.name)])
                    try:
                        ns_info['queues'] = _fq.result()
                    except Exception:
                        pass
                    try:
                        ns_info['topics'] = _ft.result()
                    except Exception:
                        pass
                    sub_data['service_bus'].append(ns_info)
                self.logger.info(f"  ✓ Found {len(namespaces)} Service Bus namespaces")
                self.discovery_data['summary']['service_bus'] += len(namespaces)
            except Exception as e:
                self.logger.warning(f"Could not discover Service Bus: {e}")

        def _disc_eventhub():
            try:
                eh_client = EventHubManagementClient(self.credential, subscription_id, **_kw)
                nss = list(eh_client.namespaces.list())
                for ns in nss:
                    sub_data['event_hubs'].append({
                        'name': ns.name, 'id': ns.id, 'location': ns.location,
                        'resource_group': ns.id.split('/')[4],
                        'sku': ns.sku.name if ns.sku else None
                    })
                self.logger.info(f"  ✓ Found {len(nss)} Event Hub namespaces")
                self.discovery_data['summary']['event_hubs'] += len(nss)
            except Exception as e:
                self.logger.warning(f"Could not discover Event Hubs: {e}")

        def _disc_appinsights():
            try:
                ai_client = ApplicationInsightsManagementClient(self.credential, subscription_id, **_kw)
                components = list(ai_client.components.list())
                for c in components:
                    sub_data['app_insights'].append({
                        'name': c.name, 'id': c.id, 'location': c.location,
                        'resource_group': c.id.split('/')[4],
                        'application_type': c.application_type,
                        'instrumentation_key': '***MASKED***'
                    })
                self.logger.info(f"  ✓ Found {len(components)} Application Insights")
                self.discovery_data['summary']['app_insights'] += len(components)
            except Exception as e:
                self.logger.warning(f"Could not discover Application Insights: {e}")

        def _disc_acr():
            try:
                acr_client = ContainerRegistryManagementClient(self.credential, subscription_id, **_kw)
                registries = list(acr_client.registries.list())
                for r in registries:
                    sub_data['container_registries'].append({
                        'name': r.name, 'id': r.id, 'location': r.location,
                        'resource_group': r.id.split('/')[4],
                        'sku': r.sku.name if r.sku else None,
                        'login_server': r.login_server, 'admin_enabled': r.admin_user_enabled
                    })
                self.logger.info(f"  ✓ Found {len(registries)} Container Registries")
                self.discovery_data['summary']['container_registries'] += len(registries)
            except Exception as e:
                self.logger.warning(f"Could not discover Container Registries: {e}")

        def _disc_aks():
            try:
                aks_client = ContainerServiceClient(self.credential, subscription_id, **_kw)
                clusters = list(aks_client.managed_clusters.list())
                for cluster in clusters:
                    ci = {
                        'name': cluster.name, 'id': cluster.id, 'location': cluster.location,
                        'resource_group': cluster.id.split('/')[4],
                        'kubernetes_version': cluster.kubernetes_version, 'fqdn': cluster.fqdn,
                        'node_pools': [p.name for p in cluster.agent_pool_profiles] if cluster.agent_pool_profiles else [],
                        'vnet': None, 'subnet': None, 'container_registry': None
                    }
                    if cluster.network_profile and cluster.network_profile.vnet_subnet_id:
                        parts = cluster.network_profile.vnet_subnet_id.split('/')
                        if len(parts) >= 11:
                            ci['vnet'] = parts[8]
                            ci['subnet'] = parts[10]
                    sub_data['aks_clusters'].append(ci)
                self.logger.info(f"  ✓ Found {len(clusters)} AKS Clusters")
                self.discovery_data['summary']['aks_clusters'] += len(clusters)
            except Exception as e:
                self.logger.warning(f"Could not discover AKS: {e}")

        def _disc_dns():
            try:
                dns_client = DnsManagementClient(self.credential, subscription_id, **_kw)
                zones = list(dns_client.zones.list())
                for z in zones:
                    sub_data['dns_zones'].append({
                        'name': z.name, 'id': z.id,
                        'location': getattr(z, 'location', 'global'),
                        'resource_group': z.id.split('/')[4],
                        'number_of_record_sets': getattr(z, 'number_of_record_sets', 0)
                    })
                self.logger.info(f"  ✓ Found {len(zones)} DNS Zones")
                self.discovery_data['summary']['dns_zones'] += len(zones)
            except Exception as e:
                self.logger.warning(f"Could not discover DNS Zones: {e}")

        def _disc_trafficmanager():
            try:
                tm_client = TrafficManagerManagementClient(self.credential, subscription_id, **_kw)
                profiles = list(tm_client.profiles.list_by_subscription())
                for p in profiles:
                    sub_data['traffic_managers'].append({
                        'name': p.name, 'id': p.id,
                        'location': getattr(p, 'location', 'global'),
                        'resource_group': p.id.split('/')[4],
                        'dns_name': p.dns_config.relative_name if p.dns_config else None,
                        'routing_method': getattr(p, 'traffic_routing_method', None)
                    })
                self.logger.info(f"  ✓ Found {len(profiles)} Traffic Manager Profiles")
                self.discovery_data['summary']['traffic_managers'] += len(profiles)
            except Exception as e:
                self.logger.warning(f"Could not discover Traffic Manager: {e}")

        def _disc_cdn():
            try:
                cdn_client = CdnManagementClient(self.credential, subscription_id, **_kw)
                cdn_profiles = list(cdn_client.profiles.list())
                for p in cdn_profiles:
                    sub_data['cdns'].append({
                        'name': p.name, 'id': p.id, 'location': p.location,
                        'resource_group': p.id.split('/')[4],
                        'sku': p.sku.name if p.sku else None
                    })
                self.logger.info(f"  ✓ Found {len(cdn_profiles)} CDN Profiles")
                self.discovery_data['summary']['cdns'] += len(cdn_profiles)
            except Exception as e:
                self.logger.warning(f"Could not discover CDN: {e}")

        def _disc_frontdoor():
            try:
                fd_client = FrontDoorManagementClient(self.credential, subscription_id, **_kw)
                frontdoors = list(fd_client.front_doors.list())
                for fd in frontdoors:
                    sub_data['frontdoors'].append({
                        'name': fd.name, 'id': fd.id,
                        'location': getattr(fd, 'location', 'global'),
                        'resource_group': fd.id.split('/')[4],
                        'frontend_endpoints': len(fd.frontend_endpoints) if getattr(fd, 'frontend_endpoints', None) else 0
                    })
                self.logger.info(f"  ✓ Found {len(frontdoors)} Front Doors")
                self.discovery_data['summary']['frontdoors'] += len(frontdoors)
            except Exception as e:
                self.logger.warning(f"Could not discover Front Door: {e}")

        def _disc_cognitive():
            try:
                cog_client = CognitiveServicesManagementClient(self.credential, subscription_id, **_kw)
                accounts = list(cog_client.accounts.list())
                for a in accounts:
                    sub_data['cognitive_services'].append({
                        'name': a.name, 'id': a.id, 'location': a.location,
                        'resource_group': a.id.split('/')[4],
                        'kind': a.kind, 'sku': a.sku.name if a.sku else None
                    })
                self.logger.info(f"  ✓ Found {len(accounts)} Cognitive Services")
                self.discovery_data['summary']['cognitive_services'] += len(accounts)
            except Exception as e:
                self.logger.warning(f"Could not discover Cognitive Services: {e}")

        def _disc_search():
            try:
                search_client = SearchManagementClient(self.credential, subscription_id, **_kw)
                services = list(search_client.services.list_by_subscription())
                for s in services:
                    sub_data['search_services'].append({
                        'name': s.name, 'id': s.id, 'location': s.location,
                        'resource_group': s.id.split('/')[4],
                        'sku': s.sku.name if s.sku else None,
                        'replica_count': getattr(s, 'replica_count', None)
                    })
                self.logger.info(f"  ✓ Found {len(services)} Search Services")
                self.discovery_data['summary']['search_services'] += len(services)
            except Exception as e:
                self.logger.warning(f"Could not discover Search Services: {e}")

        def _disc_datafactory():
            try:
                df_client = DataFactoryManagementClient(self.credential, subscription_id, **_kw)
                factories = list(df_client.factories.list())
                for f in factories:
                    sub_data['data_factories'].append({
                        'name': f.name, 'id': f.id, 'location': f.location,
                        'resource_group': f.id.split('/')[4],
                        'provisioning_state': getattr(f, 'provisioning_state', None)
                    })
                self.logger.info(f"  ✓ Found {len(factories)} Data Factories")
                self.discovery_data['summary']['data_factories'] += len(factories)
            except Exception as e:
                self.logger.warning(f"Could not discover Data Factory: {e}")

        def _disc_databricks():
            try:
                dbr_client = AzureDatabricksManagementClient(self.credential, subscription_id, **_kw)
                workspaces = list(dbr_client.workspaces.list_by_subscription())
                for w in workspaces:
                    sub_data['databricks'].append({
                        'name': w.name, 'id': w.id, 'location': w.location,
                        'resource_group': w.id.split('/')[4],
                        'sku': w.sku.name if w.sku else None,
                        'workspace_url': getattr(w, 'workspace_url', None)
                    })
                self.logger.info(f"  ✓ Found {len(workspaces)} Databricks Workspaces")
                self.discovery_data['summary']['databricks'] += len(workspaces)
            except Exception as e:
                self.logger.warning(f"Could not discover Databricks: {e}")

        def _disc_loganalytics():
            try:
                la_client = LogAnalyticsManagementClient(self.credential, subscription_id, **_kw)
                workspaces = list(la_client.workspaces.list())
                for w in workspaces:
                    sub_data['log_analytics'].append({
                        'name': w.name, 'id': w.id, 'location': w.location,
                        'resource_group': w.id.split('/')[4],
                        'sku': w.sku.name if w.sku else None,
                        'retention_days': getattr(w, 'retention_in_days', None)
                    })
                self.logger.info(f"  ✓ Found {len(workspaces)} Log Analytics Workspaces")
                self.discovery_data['summary']['log_analytics'] += len(workspaces)
            except Exception as e:
                self.logger.warning(f"Could not discover Log Analytics: {e}")

        def _disc_notificationhubs():
            try:
                nh_client = NotificationHubsManagementClient(self.credential, subscription_id, **_kw)
                nss = list(nh_client.namespaces.list())
                for ns in nss:
                    sub_data['notification_hubs'].append({
                        'name': ns.name, 'id': ns.id, 'location': ns.location,
                        'resource_group': ns.id.split('/')[4],
                        'sku': ns.sku.name if ns.sku else None
                    })
                self.logger.info(f"  ✓ Found {len(nss)} Notification Hub Namespaces")
                self.discovery_data['summary']['notification_hubs'] += len(nss)
            except Exception as e:
                self.logger.warning(f"Could not discover Notification Hubs: {e}")

        # ── Run ALL service discoveries in parallel ────────────────────────────
        _paas_tasks = {
            'key_vault':        _disc_keyvault,
            'cosmos_db':        _disc_cosmos,
            'redis_cache':      _disc_redis,
            'service_bus':      _disc_servicebus,
            'event_hubs':       _disc_eventhub,
            'app_insights':     _disc_appinsights,
            'acr':              _disc_acr,
            'aks':              _disc_aks,
            'dns':              _disc_dns,
            'traffic_manager':  _disc_trafficmanager,
            'cdn':              _disc_cdn,
            'front_door':       _disc_frontdoor,
            'cognitive':        _disc_cognitive,
            'search':           _disc_search,
            'data_factory':     _disc_datafactory,
            'databricks':       _disc_databricks,
            'log_analytics':    _disc_loganalytics,
            'notification_hubs': _disc_notificationhubs,
        }
        with ThreadPoolExecutor(max_workers=len(_paas_tasks)) as _paas_pool:
            _paas_futs = {_paas_pool.submit(fn): name for name, fn in _paas_tasks.items()}
            for _fut in as_completed(_paas_futs):
                try:
                    _fut.result()
                except Exception as _e:
                    self.logger.error(f"Unexpected error in PaaS discovery ({_paas_futs[_fut]}): {_e}")

        self.logger.info("✓ PaaS services discovery complete")

    def analyze_dependencies(self):
        """Analyze and map dependencies between resources.
        
        Detects service-to-service connections by:
        1. Building lookup maps of discovered Azure resources (indexed by hostname/endpoint)
        2. Scanning App Service / Function App settings values for Azure service endpoints
        3. Matching found endpoints against actual resource names in the same subscription
        
        Detected connection types:
        - App Service / Function → Service Bus (Endpoint=sb://...servicebus.windows.net)
        - App Service / Function → Event Hub   (EntityPath= in connection string)
        - App Service / Function → Cosmos DB   (AccountEndpoint=https://...documents.azure.com)
        - App Service / Function → Redis Cache (...redis.cache.windows.net)
        - App Service / Function → Key Vault   (@Microsoft.KeyVault(...) or ...vault.azure.net)
        - App Service / Function → SQL Server  (...database.windows.net)
        - App Service / Function → Storage     (AccountName= or ...blob.core.windows.net)
        - App Service / Function → App Insights (APPINSIGHTS_* keys)
        - VM → VNet / Storage (disk)
        - AKS → VNet / Container Registry
        - VNet → VNet (peering), Subnet → NSG
        """
        self.logger.info("\n" + "="*80)
        self.logger.info("Analyzing Dependencies")
        self.logger.info("="*80)
        
        dependencies = []
        
        for sub_id, sub_data in self.discovery_data['subscriptions'].items():
            self.logger.info(f"\nAnalyzing subscription: {sub_data['name']}")
            
            # ----------------------------------------------------------------
            # Build lookup maps: resource name (lower) → display name
            # Used to resolve hostnames found in app settings to real names
            # ----------------------------------------------------------------
            sb_lookup      = {r['name'].lower(): r['name'] for r in sub_data.get('service_bus', [])}
            eh_lookup      = {r['name'].lower(): r['name'] for r in sub_data.get('event_hubs', [])}
            cosmos_lookup  = {r['name'].lower(): r['name'] for r in sub_data.get('cosmos_db', [])}
            redis_lookup   = {r['name'].lower(): r['name'] for r in sub_data.get('redis_cache', [])}
            kv_lookup      = {r['name'].lower(): r['name'] for r in sub_data.get('key_vaults', [])}
            storage_lookup = {r['name'].lower(): r['name'] for r in sub_data.get('storage_accounts', [])}
            ai_lookup      = {r['name'].lower(): r['name'] for r in sub_data.get('app_insights', [])}
            # SQL indexed by server name
            sql_lookup = {}
            for srv in sub_data.get('sql_servers', []):
                sql_lookup[srv['name'].lower()] = srv['name']
            
            self.logger.info(
                f"  Lookup maps built: {len(sb_lookup)} SB, {len(eh_lookup)} EH, "
                f"{len(cosmos_lookup)} CosmosDB, {len(redis_lookup)} Redis, "
                f"{len(kv_lookup)} KeyVaults, {len(sql_lookup)} SQL, "
                f"{len(storage_lookup)} Storage, {len(ai_lookup)} AppInsights"
            )
            
            # ----------------------------------------------------------------
            # App Service / Function App → Azure Service dependencies
            # ----------------------------------------------------------------
            app_count = len(sub_data.get('app_services', []))
            self.logger.info(f"  Analyzing {app_count} App Services / Functions...")
            
            for app in sub_data.get('app_services', []):
                is_function  = 'functionapp' in str(app.get('kind', '')).lower()
                source_type  = 'Azure Function' if is_function else 'App Service'
                app_name     = app['name']
                all_settings = app.get('app_settings', {})
                
                for setting_key, setting_value in all_settings.items():
                    val = str(setting_value)
                    if not val or val == '***MASKED***':
                        # Value is masked (key name had password/secret/key/token).
                        # Still try to detect the service type from the KEY NAME alone.
                        svc = _detect_service_from_key_name(setting_key)
                        if svc:
                            _add_dep_from_hint(
                                f'{svc}:_masked_', setting_key, app_name, source_type,
                                sub_id, dependencies,
                                sb_lookup, eh_lookup, cosmos_lookup, redis_lookup,
                                kv_lookup, sql_lookup, storage_lookup
                            )
                        continue
                    
                    # ---- Service Bus ----
                    # Endpoint=sb://{ns}.servicebus.windows.net/ OR {ns}.servicebus.windows.net
                    sb_match = re.search(
                        r'(?:Endpoint=sb://|^)([a-zA-Z0-9\-]+)\.servicebus\.windows\.net',
                        val, re.IGNORECASE
                    )
                    if sb_match and 'servicebus.windows.net' in val.lower():
                        ns_name = sb_match.group(1)
                        # Differentiate Event Hub vs Service Bus by EntityPath=
                        if 'entitypath=' in val.lower():
                            ep_match = re.search(r'EntityPath=([^;\s]+)', val, re.IGNORECASE)
                            eh_entity = f"/{ep_match.group(1)}" if ep_match else ''
                            target = eh_lookup.get(ns_name.lower(), ns_name) + eh_entity
                            target_type = 'Event Hub'
                            dep_type = 'Event Hub Connection'
                        else:
                            target = sb_lookup.get(ns_name.lower(), ns_name)
                            target_type = 'Service Bus'
                            dep_type = 'Service Bus Connection'
                        dependencies.append({
                            'source': app_name, 'source_type': source_type,
                            'target': target, 'target_type': target_type,
                            'dependency_type': dep_type, 'setting_key': setting_key,
                            'subscription': sub_id
                        })
                        continue  # already classified this setting
                    
                    # ---- Cosmos DB ----
                    cosmos_match = re.search(
                        r'AccountEndpoint=https://([a-zA-Z0-9\-]+)\.documents\.azure\.com'
                        r'|([a-zA-Z0-9\-]+)\.(?:documents|mongo\.cosmos|table\.cosmos|cassandra\.cosmos)\.azure\.com',
                        val, re.IGNORECASE
                    )
                    if cosmos_match:
                        acct = cosmos_match.group(1) or cosmos_match.group(2)
                        target = cosmos_lookup.get(acct.lower(), acct)
                        dependencies.append({
                            'source': app_name, 'source_type': source_type,
                            'target': target, 'target_type': 'Cosmos DB',
                            'dependency_type': 'Cosmos DB Connection', 'setting_key': setting_key,
                            'subscription': sub_id
                        })
                        continue
                    
                    # ---- Redis Cache ----
                    redis_match = re.search(
                        r'([a-zA-Z0-9\-]+)\.redis\.cache\.windows\.net', val, re.IGNORECASE
                    )
                    if redis_match:
                        target = redis_lookup.get(redis_match.group(1).lower(), redis_match.group(1))
                        dependencies.append({
                            'source': app_name, 'source_type': source_type,
                            'target': target, 'target_type': 'Redis Cache',
                            'dependency_type': 'Redis Connection', 'setting_key': setting_key,
                            'subscription': sub_id
                        })
                        continue
                    
                    # ---- Key Vault Reference ----
                    # @Microsoft.KeyVault(VaultName=...) OR @Microsoft.KeyVault(SecretUri=https://...vault.azure.net/...)
                    kv_match = re.search(
                        r'@Microsoft\.KeyVault\((?:VaultName=([a-zA-Z0-9\-]+)|SecretUri=https://([a-zA-Z0-9\-]+)\.vault\.azure\.net)'
                        r'|([a-zA-Z0-9\-]+)\.vault\.azure\.net',
                        val, re.IGNORECASE
                    )
                    if kv_match:
                        kv_name = kv_match.group(1) or kv_match.group(2) or kv_match.group(3)
                        if kv_name:
                            target = kv_lookup.get(kv_name.lower(), kv_name)
                            dependencies.append({
                                'source': app_name, 'source_type': source_type,
                                'target': target, 'target_type': 'Key Vault',
                                'dependency_type': 'Key Vault Reference', 'setting_key': setting_key,
                                'subscription': sub_id
                            })
                        continue
                    
                    # ---- SQL Server ----
                    sql_match = re.search(
                        r'([a-zA-Z0-9\-]+)\.database\.windows\.net', val, re.IGNORECASE
                    )
                    if sql_match:
                        srv_name = sql_match.group(1)
                        target = sql_lookup.get(srv_name.lower(), srv_name)
                        dependencies.append({
                            'source': app_name, 'source_type': source_type,
                            'target': target, 'target_type': 'SQL Server',
                            'dependency_type': 'SQL Connection', 'setting_key': setting_key,
                            'subscription': sub_id
                        })
                        continue
                    
                    # ---- Storage Account ----
                    sa_match = (
                        re.search(r'AccountName=([a-zA-Z0-9]+)', val, re.IGNORECASE) or
                        re.search(r'([a-zA-Z0-9]+)\.(?:blob|table|queue|file)\.core\.windows\.net', val, re.IGNORECASE)
                    )
                    if sa_match:
                        sa_name = sa_match.group(1)
                        target = storage_lookup.get(sa_name.lower(), sa_name)
                        dependencies.append({
                            'source': app_name, 'source_type': source_type,
                            'target': target, 'target_type': 'Storage Account',
                            'dependency_type': 'Storage Connection', 'setting_key': setting_key,
                            'subscription': sub_id
                        })
                        continue
                
                # ---- Application Insights (by key name, value may be masked) ----
                for setting_key in all_settings:
                    if setting_key.upper() in (
                        'APPINSIGHTS_INSTRUMENTATIONKEY',
                        'APPLICATIONINSIGHTS_CONNECTION_STRING',
                        'APPINSIGHTS_PROFILERFEATURE_VERSION',
                        'APPINSIGHTS_SNAPSHOTFEATURE_VERSION',
                    ):
                        # Try to match to a discovered AI component in the same subscription
                        # (we can't match by key value since it may be masked)
                        if len(ai_lookup) == 1:
                            target = next(iter(ai_lookup.values()))
                        elif len(ai_lookup) > 1:
                            # Find component whose name appears in the app name
                            matched = next(
                                (name for key, name in ai_lookup.items() if key in app_name.lower()),
                                'Application Insights'
                            )
                            target = matched
                        else:
                            target = 'Application Insights'
                        dependencies.append({
                            'source': app_name, 'source_type': source_type,
                            'target': target, 'target_type': 'Application Insights',
                            'dependency_type': 'Monitoring (App Insights)', 'setting_key': setting_key,
                            'subscription': sub_id
                        })
                        break
                
                # ---- Connection Strings (full endpoint detection via azure_hint + SQL type fallback) ----
                for conn_key, conn_info in app.get('connection_strings', {}).items():
                    if not isinstance(conn_info, dict):
                        continue
                    conn_type = str(conn_info.get('type', '')).lower()
                    azure_hint = conn_info.get('azure_hint', '')

                    # Priority 1: use the azure_hint extracted at discovery time (actual endpoint)
                    if azure_hint:
                        _add_dep_from_hint(
                            azure_hint, conn_key, app_name, source_type, sub_id, dependencies,
                            sb_lookup, eh_lookup, cosmos_lookup, redis_lookup,
                            kv_lookup, sql_lookup, storage_lookup
                        )
                        continue

                    # Priority 2: SQL-typed connection strings (no hostname hint available)
                    if conn_type in ('sqlazure', 'sqlserver', 'sql'):
                        matched_sql = next(
                            (name for key, name in sql_lookup.items()
                             if key in conn_key.lower() or conn_key.lower() in key),
                            conn_key
                        )
                        dependencies.append({
                            'source': app_name, 'source_type': source_type,
                            'target': matched_sql, 'target_type': 'SQL Database',
                            'dependency_type': 'Connection String (SQL)', 'setting_key': conn_key,
                            'subscription': sub_id
                        })
                        continue

                    # Priority 3: fallback — use key name hint for other types
                    svc = _detect_service_from_key_name(conn_key)
                    if svc:
                        _add_dep_from_hint(
                            f'{svc}:_masked_', conn_key, app_name, source_type, sub_id, dependencies,
                            sb_lookup, eh_lookup, cosmos_lookup, redis_lookup,
                            kv_lookup, sql_lookup, storage_lookup
                        )
                    elif conn_key and conn_type not in ('', 'custom'):
                        dependencies.append({
                            'source': app_name, 'source_type': source_type,
                            'target': conn_key, 'target_type': f'Database ({conn_type})',
                            'dependency_type': 'Connection String', 'setting_key': conn_key,
                            'subscription': sub_id
                        })
                
                # ---- VNet Integration ----
                if app.get('vnet_integration'):
                    dependencies.append({
                        'source': app_name, 'source_type': source_type,
                        'target': app['vnet_integration'], 'target_type': 'Virtual Network',
                        'dependency_type': 'VNet Integration',
                        'subscription': sub_id
                    })
                
                # ---- External API dependencies ----
                for ext_dep in app.get('external_dependencies', []):
                    ext_target = ext_dep.get('value', ext_dep.get('key'))
                    if ext_target and ext_target != '***MASKED***':
                        dependencies.append({
                            'source': app_name, 'source_type': source_type,
                            'target': ext_target, 'target_type': 'External API',
                            'dependency_type': ext_dep.get('type', 'External'),
                            'subscription': sub_id
                        })
            
            # ----------------------------------------------------------------
            # Virtual Machine dependencies
            # ----------------------------------------------------------------
            vm_count = len(sub_data.get('virtual_machines', []))
            self.logger.info(f"  Analyzing {vm_count} Virtual Machines...")
            for vm in sub_data.get('virtual_machines', []):
                if vm.get('vnet'):
                    dependencies.append({
                        'source': vm['name'], 'source_type': 'Virtual Machine',
                        'target': vm['vnet'], 'target_type': 'Virtual Network',
                        'dependency_type': 'Network Connection', 'subscription': sub_id
                    })
                if vm.get('os_disk', {}).get('storage_account'):
                    dependencies.append({
                        'source': vm['name'], 'source_type': 'Virtual Machine',
                        'target': vm['os_disk']['storage_account'], 'target_type': 'Storage Account',
                        'dependency_type': 'OS Disk', 'subscription': sub_id
                    })
                for disk in vm.get('data_disks', []):
                    if disk.get('storage_account'):
                        dependencies.append({
                            'source': vm['name'], 'source_type': 'Virtual Machine',
                            'target': disk['storage_account'], 'target_type': 'Storage Account',
                            'dependency_type': 'Data Disk', 'subscription': sub_id
                        })
            
            # ----------------------------------------------------------------
            # SQL Server dependencies
            # ----------------------------------------------------------------
            sql_count = len(sub_data.get('sql_servers', []))
            self.logger.info(f"  Analyzing {sql_count} SQL Servers...")
            for sql_server in sub_data.get('sql_servers', []):
                for vnet_rule in sql_server.get('vnet_rules', []):
                    if vnet_rule.get('vnet_subnet'):
                        dependencies.append({
                            'source': sql_server['name'], 'source_type': 'SQL Server',
                            'target': vnet_rule['vnet_subnet'], 'target_type': 'Virtual Network Subnet',
                            'dependency_type': 'VNet Service Endpoint', 'subscription': sub_id
                        })
            
            # ----------------------------------------------------------------
            # AKS Cluster dependencies
            # ----------------------------------------------------------------
            aks_count = len(sub_data.get('aks_clusters', []))
            self.logger.info(f"  Analyzing {aks_count} AKS Clusters...")
            for aks in sub_data.get('aks_clusters', []):
                if aks.get('vnet'):
                    dependencies.append({
                        'source': aks['name'], 'source_type': 'AKS Cluster',
                        'target': aks['vnet'], 'target_type': 'Virtual Network',
                        'dependency_type': 'Network Plugin', 'subscription': sub_id
                    })
                if aks.get('container_registry'):
                    dependencies.append({
                        'source': aks['name'], 'source_type': 'AKS Cluster',
                        'target': aks['container_registry'], 'target_type': 'Container Registry',
                        'dependency_type': 'Image Pull', 'subscription': sub_id
                    })
            
            # ----------------------------------------------------------------
            # VNet Peering + Subnet → NSG dependencies
            # ----------------------------------------------------------------
            vnet_count = len(sub_data.get('networks', []))
            self.logger.info(f"  Analyzing {vnet_count} Virtual Networks...")
            for vnet in sub_data.get('networks', []):
                for peering in vnet.get('peerings', []):
                    if peering.get('remote_vnet'):
                        dependencies.append({
                            'source': vnet['name'], 'source_type': 'Virtual Network',
                            'target': peering['remote_vnet'], 'target_type': 'Virtual Network',
                            'dependency_type': 'VNet Peering', 'subscription': sub_id
                        })
                for subnet in vnet.get('subnets', []):
                    if subnet.get('nsg'):
                        nsg_name = subnet['nsg'].split('/')[-1] if '/' in subnet['nsg'] else subnet['nsg']
                        dependencies.append({
                            'source': f"{vnet['name']}/{subnet['name']}", 'source_type': 'Subnet',
                            'target': nsg_name, 'target_type': 'Network Security Group',
                            'dependency_type': 'Security Rules', 'subscription': sub_id
                        })
        
        # Deduplicate (same source → target via same dependency type)
        seen = set()
        unique_deps = []
        for dep in dependencies:
            dedup_key = (dep['source'], dep['target'], dep['dependency_type'])
            if dedup_key not in seen:
                seen.add(dedup_key)
                unique_deps.append(dep)
        
        self.discovery_data['dependencies'] = unique_deps
        total = len(unique_deps)
        self.logger.info(f"\n✓ Identified {total} unique dependencies ({len(dependencies)} before dedup)")
        
        if total == 0:
            self.logger.warning("⚠ No dependencies found!")
            self.logger.warning("  Possible reasons:")
            self.logger.warning("  - App Settings/Connection Strings have no Azure service endpoints")
            self.logger.warning("  - Sensitive settings (containing 'key'/'secret'/'token'/'password') are masked")
            self.logger.warning("  - VNets have no peering, AKS has no VNet/ACR configured")
            self.logger.warning("  - Insufficient permissions to read App Settings (requires Contributor or Website Contributor)")
        else:
            type_counts = Counter(d['dependency_type'] for d in unique_deps)
            self.logger.info("  Dependency breakdown:")
            for dep_type, count in sorted(type_counts.items(), key=lambda x: -x[1]):
                self.logger.info(f"    {dep_type}: {count}")
        
        return unique_deps
    
    def build_complete_dependency_map(self):
        """Build complete application-centric dependency mapping"""
        self.logger.info("\n" + "="*80)
        self.logger.info("Building Application-Centric Dependency Map")
        self.logger.info("="*80)
        
        app_dependencies = []
        
        for app_name, app_data in self.discovery_data['applications'].items():
            self.logger.info(f"\nMapping dependencies for: {app_name}")
            
            # ARM template resources
            for template in app_data.get('arm_templates', []):
                for resource in template.get('resources', []):
                    app_dependencies.append({
                        'application': app_name,
                        'dependency_name': resource['name'],
                        'dependency_type': resource['type'],
                        'source': 'ARM Template',
                        'category': 'Infrastructure as Code',
                        'details': {
                            'api_version': resource['api_version'],
                            'location': resource['location']
                        }
                    })
            
            # Configuration-based dependencies
            for config in app_data.get('configuration_files', []):
                for conn in config.get('connection_strings', []):
                    app_dependencies.append({
                        'application': app_name,
                        'dependency_name': conn['name'],
                        'dependency_type': conn['type'],
                        'source': config['file'],
                        'category': 'Database',
                        'details': {}
                    })
                
                for azure_svc in config.get('azure_services', []):
                    app_dependencies.append({
                        'application': app_name,
                        'dependency_name': azure_svc['key'],
                        'dependency_type': 'Azure Service',
                        'source': config['file'],
                        'category': 'Azure PaaS',
                        'details': {'endpoint': azure_svc['value']}
                    })
            
            # Code-level dependencies
            for azure_sdk in app_data.get('azure_sdk_usage', []):
                app_dependencies.append({
                    'application': app_name,
                    'dependency_name': azure_sdk,
                    'dependency_type': 'Azure SDK',
                    'source': 'Source Code',
                    'category': 'Azure SDK Usage',
                    'details': {}
                })
            
            # External APIs
            for ext_api in app_data.get('external_dependencies', []):
                if isinstance(ext_api, dict) and 'url' in ext_api:
                    app_dependencies.append({
                        'application': app_name,
                        'dependency_name': ext_api['url'],
                        'dependency_type': 'External API',
                        'source': ext_api.get('file', 'Unknown'),
                        'category': 'External Service',
                        'details': {}
                    })
            
            # NuGet packages
            for pkg in app_data.get('nuget_packages', [])[:10]:  # Limit to top 10
                if 'Azure' in pkg['name'] or 'Microsoft.Extensions' in pkg['name']:
                    app_dependencies.append({
                        'application': app_name,
                        'dependency_name': pkg['name'],
                        'dependency_type': 'NuGet Package',
                        'source': pkg['source'],
                        'category': 'Package Dependency',
                        'details': {'version': pkg['version']}
                    })

            # ── Line-by-line Azure service references (from full repo code scan) ──
            seen_hits: Set[str] = set()
            for hit in app_data.get('azure_service_hits', []):
                # Deduplicate by (service_type, service_name, file)
                dedup_key = f"{hit['service_type']}|{hit['service_name']}|{hit['file']}"
                if dedup_key in seen_hits:
                    continue
                seen_hits.add(dedup_key)
                app_dependencies.append({
                    'application':    app_name,
                    'dependency_name': hit['service_name'],
                    'dependency_type': hit['service_type'],
                    'source':         f"{hit['file']}:L{hit['line_no']}",
                    'category':       'Azure Service Reference (Code)',
                    'details': {
                        'endpoint': hit['endpoint_match'],
                        'context':  hit['context'],
                        'repo':     hit.get('repo', app_name),
                    }
                })
        
        self.discovery_data['application_dependencies'] = app_dependencies
        self.logger.info(f"\n✓ Mapped {len(app_dependencies)} application dependencies")
        
        return app_dependencies
    
    def _clone_repo_with_ssl_fallback(self, repo_url: str, repo_path: str, repo_branch=None):
        """Clone or pull a git repo, retrying with SSL verification disabled on SSL errors.
        
        NOTE: git.Repo.clone_from does NOT accept an 'env' kwarg for subprocess env vars.
        The correct approach is git.cmd.Git().custom_environment() context manager or
        temporarily patching os.environ before the call.
        """
        import urllib.parse

        # Mask credentials in log output
        try:
            parsed   = urllib.parse.urlparse(repo_url)
            safe_url = repo_url.replace(parsed.password or '', '***') if parsed.password else repo_url
        except Exception:
            safe_url = repo_url

        clone_kwargs = {}
        if repo_branch:
            clone_kwargs['branch'] = repo_branch

        def _do_clone_normal():
            git.Repo.clone_from(repo_url, repo_path, **clone_kwargs)

        def _do_clone_ssl_bypass():
            """Bypass SSL by temporarily patching os.environ – the only reliable way
            to affect git.Repo.clone_from which creates its own git.cmd.Git instance."""
            old_val = os.environ.get('GIT_SSL_NO_VERIFY')
            os.environ['GIT_SSL_NO_VERIFY'] = '1'
            try:
                git.Repo.clone_from(repo_url, repo_path, **clone_kwargs)
            finally:
                if old_val is None:
                    os.environ.pop('GIT_SSL_NO_VERIFY', None)
                else:
                    os.environ['GIT_SSL_NO_VERIFY'] = old_val

        def _do_pull_normal(repo_obj):
            origin = repo_obj.remotes.origin
            if repo_branch:
                branch_names = [h.name for h in repo_obj.heads]
                if repo_branch in branch_names:
                    repo_obj.heads[repo_branch].checkout()
                origin.pull(repo_branch)
            else:
                origin.pull()

        def _do_pull_ssl_bypass(repo_obj):
            with repo_obj.git.custom_environment(GIT_SSL_NO_VERIFY='1'):
                _do_pull_normal(repo_obj)

        def _is_ssl_error(err):
            s = str(err).lower()
            return 'ssl' in s or 'certificate' in s or 'cert' in s

        if os.path.exists(repo_path):
            # Repo already cloned: just pull latest
            try:
                repo_obj = git.Repo(repo_path)
                _do_pull_normal(repo_obj)
                self.logger.info(f"  ✓ Updated existing repo (pull)")
                return repo_path
            except git.exc.GitCommandError as pull_err:
                if _is_ssl_error(pull_err):
                    self.logger.warning(f"  ⚠ SSL error on pull — retrying with SSL verification bypassed")
                    self.logger.warning(f"    Permanent fix: git config --global http.sslBackend schannel")
                    _do_pull_ssl_bypass(repo_obj)
                    self.logger.info(f"  ✓ Pull succeeded (SSL bypassed)")
                    return repo_path
                raise
        else:
            # First clone
            try:
                _do_clone_normal()
                self.logger.info(f"  ✓ Cloned successfully")
                return repo_path
            except git.exc.GitCommandError as clone_err:
                err_str = str(clone_err).lower()
                if _is_ssl_error(clone_err):
                    self.logger.warning(f"  ⚠ SSL error cloning {safe_url}")
                    self.logger.warning(f"  ⚠ Retrying with GIT_SSL_NO_VERIFY=1")
                    self.logger.warning(f"  💡 Permanent fix options:")
                    self.logger.warning(f"     1. git config --global http.sslBackend schannel  (Windows cert store)")
                    self.logger.warning(f"     2. git config --global http.sslVerify false       (less secure)")
                    self.logger.warning(f"     3. git config --global http.sslCAInfo C:\\path\\to\\ca.crt")
                    try:
                        _do_clone_ssl_bypass()
                        self.logger.info(f"  ✓ Cloned successfully (SSL verification bypassed)")
                        return repo_path
                    except Exception as retry_err:
                        self.logger.error(f"  ✗ Clone failed even with SSL bypass: {retry_err}")
                        raise
                elif '401' in err_str or '403' in err_str or 'authentication' in err_str:
                    self.logger.error(f"  ✗ Authentication failed for {safe_url}")
                    self.logger.error(f"  💡 Check PAT token has 'Code (Read)' permission")
                    self.logger.error(f"  💡 Azure DevOps: User Settings → Personal Access Tokens → Code (Read)")
                    raise
                elif 'not found' in err_str or '404' in err_str:
                    self.logger.error(f"  ✗ Repository not found: {safe_url}")
                    self.logger.error(f"  💡 Check organization/project/repository names in config.json")
                    raise
                else:
                    self.logger.error(f"  ✗ Git error cloning {safe_url}: {clone_err}")
                    raise

    def scan_git_repositories(self):
        """Scan Git repositories for external dependencies"""
        import urllib.parse
        import subprocess

        repos = self.config.get('git_repos', [])

        # ── Diagnostics header ───────────────────────────────────────────────
        self.logger.info("\n" + "="*80)
        self.logger.info("Scanning Git Repositories")
        self.logger.info("="*80)
        self.logger.info(f"  scan_code : {self.config.get('scan_code', False)}")
        self.logger.info(f"  git_repos : {len(repos)} repo(s) configured")
        devops = self.config.get('azure_devops', {})
        org    = devops.get('organization', '')
        pat    = devops.get('pat_token', '')
        pat_ok = bool(pat) and 'YOUR_' not in str(pat)
        self.logger.info(f"  DevOps org: {org if org else 'not set'}")
        self.logger.info(f"  DevOps PAT: {'SET' if pat_ok else 'NOT SET or placeholder'}")

        if not repos:
            sep = "="*70
            self.logger.warning("")
            self.logger.warning(sep)
            self.logger.warning("GIT REPOSITORY SCAN — SKIPPED (no repos configured)")
            self.logger.warning(sep)
            self.logger.warning("  No repositories are queued for scanning.")
            self.logger.warning("  This means code-level Azure dependency mapping will be EMPTY.")
            self.logger.warning("")
            self.logger.warning("  OPTION A — Azure DevOps (recommended):")
            self.logger.warning("    Open config.json and fill in ALL of these fields:")
            self.logger.warning("      azure_devops.organization          ← your DevOps org name")
            self.logger.warning("      azure_devops.pat_token             ← PAT with Code (Read)")
            self.logger.warning("      azure_devops.projects[].project_name ← DevOps project name")
            self.logger.warning("      azure_devops.projects[].repositories[].name ← repo name")
            self.logger.warning("      azure_devops.projects[].repositories[].branch ← e.g. main")
            self.logger.warning("    Create PAT at: DevOps → User Settings → Personal Access Tokens")
            self.logger.warning("      Scope required: Code (Read)")
            self.logger.warning("")
            self.logger.warning("  OPTION B — Manual full URLs:")
            self.logger.warning('    Add entries directly to git_repos in config.json:')  
            self.logger.warning('    "git_repos": [')
            self.logger.warning('      {"url": "https://pat:TOKEN@dev.azure.com/ORG/PROJ/_git/REPO",')
            self.logger.warning('       "branch": "main"}')
            self.logger.warning('    ]')
            self.logger.warning(sep)
            self.logger.warning("")
            return

        temp_dir = os.path.join(self.config['output_dir'], 'temp_repos')
        os.makedirs(temp_dir, exist_ok=True)

        total = len(repos)
        _failed_lock = threading.Lock()
        scanned_count = [0]
        failed_count  = [0]

        def _scan_single_repo(idx, repo_config):
            """Clone + scan one repository. Returns True on success."""
            repo_url    = repo_config['url']    if isinstance(repo_config, dict) else repo_config
            repo_branch = repo_config.get('branch') if isinstance(repo_config, dict) else None

            try:
                parsed   = urllib.parse.urlparse(repo_url)
                safe_url = repo_url.replace(parsed.password or '', '***') if parsed.password else repo_url
            except Exception:
                safe_url = repo_url

            branch_info = f" (branch: {repo_branch})" if repo_branch else " (default branch)"
            self.logger.info(f"\n  [{idx}/{total}] {safe_url}{branch_info}")

            repo_name = repo_url.rstrip('/').split('/')[-1].replace('.git', '')
            repo_path = os.path.join(temp_dir, repo_name)

            # ── Pre-flight: test reachability with git ls-remote ─────────────
            self.logger.info(f"      Testing connectivity...")
            try:
                ls_env = os.environ.copy()
                ls_env['GIT_SSL_NO_VERIFY'] = '1'
                ls_env['GIT_TERMINAL_PROMPT'] = '0'
                ls_result = subprocess.run(
                    ['git', 'ls-remote', '--heads', repo_url],
                    capture_output=True, text=True, timeout=30, env=ls_env
                )
                if ls_result.returncode == 0:
                    heads = [
                        line.split('\t')[1].replace('refs/heads/', '')
                        for line in ls_result.stdout.strip().splitlines() if '\t' in line
                    ]
                    self.logger.info(f"      Reachable - branches: {heads if heads else '(empty repo)'}")
                    if repo_branch and repo_branch not in heads:
                        self.logger.warning(f"      !! Branch '{repo_branch}' not found on remote.")
                        self.logger.warning(f"         Available: {heads}")
                        self.logger.warning(f"         Update the branch field in config.json for this repo.")
                else:
                    err = (ls_result.stderr or '').strip()
                    self.logger.error(f"      !! Cannot reach repo. Git error:")
                    for line in err.splitlines():
                        self.logger.error(f"         {line}")
                    if '401' in err or '403' in err or 'authentication' in err.lower() or 'credential' in err.lower():
                        self.logger.error(f"      Fix: Azure DevOps -> User Settings -> Personal Access Tokens")
                        self.logger.error(f"           Create/renew PAT with scope: Code (Read)")
                        self.logger.error(f"           Update pat_token in config.json")
                        return False
                    elif '404' in err or 'not found' in err.lower() or 'does not exist' in err.lower():
                        self.logger.error(f"      Fix: Check organization / project_name / repository name in config.json")
                        return False
                    # else: non-fatal warning, still try the clone
            except subprocess.TimeoutExpired:
                self.logger.warning(f"      ls-remote timed out (30s) - network may be slow or blocked")
            except FileNotFoundError:
                self.logger.warning(f"      'git' not found in PATH - skipping preflight check")
            except Exception as ls_err:
                self.logger.warning(f"      Preflight check skipped: {ls_err}")

            # ── Step 1: Clone / pull repo ─────────────────────────────────────
            try:
                self._clone_repo_with_ssl_fallback(repo_url, repo_path, repo_branch)
                self.logger.info(f"      Repository ready at: {repo_path}")
            except git.exc.GitCommandError as git_err:
                err_str = str(git_err)
                sep = '='*64
                self.logger.error(f"\n  {sep}\n  CLONE FAILED : {safe_url}\n  {sep}")
                if '401' in err_str or '403' in err_str or 'authentication' in err_str.lower() or 'credential' in err_str.lower():
                    self.logger.error(f"  ERROR TYPE   : Authentication / Authorization failure (HTTP 401/403)")
                    self.logger.error(f"  HOW TO FIX   : Renew PAT (Code Read) and update pat_token in config.json")
                elif '404' in err_str or 'not found' in err_str.lower() or 'does not exist' in err_str.lower():
                    self.logger.error(f"  ERROR TYPE   : Repository / path not found (HTTP 404)")
                    self.logger.error(f"  HOW TO FIX   : Verify organization / project_name / repository in config.json")
                elif 'ssl' in err_str.lower() or 'certificate' in err_str.lower():
                    self.logger.error(f"  ERROR TYPE   : SSL / TLS certificate error")
                    self.logger.error(f"  HOW TO FIX   : git config --global http.sslBackend schannel")
                elif 'timeout' in err_str.lower() or 'timed out' in err_str.lower():
                    self.logger.error(f"  ERROR TYPE   : Network timeout")
                    self.logger.error(f"  HOW TO FIX   : Check internet / VPN, then: git ls-remote {safe_url}")
                else:
                    self.logger.error(f"  ERROR TYPE   : Unexpected git error\n  DETAILS      : {err_str[:500]}")
                self.logger.error(f"  {sep}\n  Skipping code scan for this repository.\n  {sep}")
                return False
            except Exception as clone_err:
                sep = '='*64
                self.logger.error(f"\n  {sep}\n  CLONE FAILED : {safe_url}\n  REASON       : {str(clone_err)[:500]}\n  {sep}")
                return False

            # ── Step 2: Scan code ─────────────────────────────────────────────
            try:
                self.logger.info(f"      Scanning repository line by line for Azure service dependencies...")
                self.scan_repository_code(repo_path, repo_name)
                self.logger.info(f"      Done - {repo_name}")
                return True
            except Exception as scan_err:
                self.logger.error(f"      !! Code scan failed for {repo_name}: {scan_err}")
                return False

        # ── Run all repos in parallel (bounded by git_clone_workers) ──────────
        git_workers = self.config.get('git_clone_workers', 3)
        with ThreadPoolExecutor(max_workers=git_workers) as _git_pool:
            _git_futs = {
                _git_pool.submit(_scan_single_repo, idx, repo_config): idx
                for idx, repo_config in enumerate(repos, 1)
            }
            for _fut in as_completed(_git_futs):
                try:
                    if _fut.result():
                        scanned_count[0] += 1
                    else:
                        failed_count[0] += 1
                except Exception as _e:
                    self.logger.error(f"Unexpected error scanning repo {_git_futs[_fut]}: {_e}")
                    failed_count[0] += 1

        scanned = scanned_count[0]
        failed  = failed_count[0]
        self.logger.info(f"\n  Code scanning complete: {scanned} succeeded, {failed} failed out of {total} repo(s)")
    
    def scan_repository_code(self, repo_path, repo_name):
        """Scan repository code for Azure service dependencies and configurations.
        
        Performs three passes:
        1. ARM / Bicep template analysis
        2. .NET project file + appsettings analysis
        3. Full line-by-line scan of every file for Azure endpoint / SDK references
        """
        self.logger.info(f"  Scanning code in {repo_name}...")
        
        app_data = {
            'type': 'Git Repository',
            'path': repo_path,
            'files_scanned': 0,
            'lines_scanned': 0,
            'findings': {},
            'dotnet_dependencies': [],
            'nuget_packages': [],
            'configuration_files': [],
            'arm_templates': [],
            'external_dependencies': [],
            'database_connections': [],
            'azure_sdk_usage': [],
            'api_endpoints': [],
            'dependency_graph': {},
            'azure_service_hits': []   # line-by-line Azure service references
        }
        
        # Pass 1: ARM / Bicep templates
        self.logger.info(f"    Pass 1/3 - Scanning for ARM / Bicep templates...")
        arm_templates = self.scan_arm_templates(repo_path)
        app_data['arm_templates'] = arm_templates
        with self._scan_lock:
            self.discovery_data['arm_templates'].extend(arm_templates)
        
        # Pass 2: .NET project files, appsettings, web.config
        self.logger.info(f"    Pass 2/4 - Scanning .NET project / config files...")
        dotnet_analysis = self.scan_dotnet_code(repo_path, repo_name)
        app_data.update(dotnet_analysis)
        
        # Pass 3: Multi-language dependency manifests
        self.logger.info(f"    Pass 3/4 - Scanning dependency manifests (pip, npm, maven, go, ruby)...")
        dep_manifests = self.scan_dependency_manifests(repo_path, repo_name)
        app_data['dependency_manifests'] = dep_manifests

        # Pass 4: Line-by-line scan of ALL file types
        self.logger.info(f"    Pass 4/4 - Full repository line-by-line scan...")
        line_hits, files_count, lines_count = self.scan_repo_line_by_line(repo_path, repo_name)
        app_data['azure_service_hits'] = line_hits
        # Use max so we don't under-count when dotnet scan already walked some files
        app_data['files_scanned'] = max(app_data.get('files_scanned', 0), files_count)
        app_data['lines_scanned'] = max(app_data.get('lines_scanned', 0), lines_count)
        
        # General pattern scanning (external URLs, SMTP, api-keys)
        findings = self.scan_code_patterns(repo_path)
        app_data['findings'] = findings
        
        # Build application dependency graph
        self.logger.info(f"    Building application dependency graph...")
        dep_graph = self.build_application_dependency_graph(app_data, repo_name)
        app_data['dependency_graph'] = dep_graph
        
        # Store application data
        self.discovery_data['applications'][repo_name] = app_data
        self.discovery_data['code_inventory'][repo_name] = {
            'files':             app_data['files_scanned'],
            'lines':             app_data['lines_scanned'],
            'dependencies':      len(app_data['external_dependencies']),
            'azure_resources':   len(app_data['azure_sdk_usage']),
            'azure_service_refs': len(line_hits)
        }
        
        self.logger.info(f"    Scanned {app_data['files_scanned']} files, {app_data['lines_scanned']:,} lines")
        self.logger.info(f"    Found {len(arm_templates)} ARM/Bicep templates")
        self.logger.info(f"    Found {len(app_data['nuget_packages'])} NuGet packages")
        total_pkg = sum(len(v) for v in dep_manifests.values()) if dep_manifests else 0
        self.logger.info(f"    Found {total_pkg} dependency manifest entries across {len(dep_manifests)} manifest file(s)")
        self.logger.info(f"    Found {len(line_hits)} Azure service references in source code")

    def scan_repo_line_by_line(self, repo_path: str, repo_name: str):
        """Scan every file in the repository line-by-line for Azure service references.

        Covers all common source-code and config file types (C#, Python, JS/TS,
        Java, Go, YAML, JSON, XML, .env, Terraform, Bicep, PowerShell, etc.).
        For each line that matches a known Azure endpoint pattern or SDK import,
        records the exact file path, 1-based line number, matched service type,
        extracted service name, full endpoint token, and a sanitised line snippet.

        Returns:
            (hits, files_scanned, lines_scanned)
            hits             – list[dict] with keys:
                               repo, file, line_no, service_type, service_name,
                               endpoint_match, context
            files_scanned    – int
            lines_scanned    – int
        """
        SCANNABLE_EXTENSIONS = {
            # .NET
            '.cs', '.vb', '.fs', '.csproj', '.vbproj', '.fsproj',
            # Python
            '.py',
            # JavaScript / TypeScript
            '.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs',
            # Java / Kotlin / Scala
            '.java', '.kt', '.scala',
            # Go
            '.go',
            # PHP / Ruby
            '.php', '.rb',
            # Data / Config
            '.json', '.jsonc',
            '.yaml', '.yml',
            '.xml', '.config',
            '.env', '.env.local', '.env.production', '.env.staging',
            '.properties', '.ini', '.toml',
            # Infrastructure as Code
            '.tf', '.tfvars', '.hcl',
            '.bicep',
            # Shell / scripting
            '.sh', '.bash',
            '.ps1', '.psm1', '.psd1',
        }
        SCANNABLE_NAMES = {
            'dockerfile', '.env', '.envrc', 'procfile',
            'requirements.txt', 'package.json', 'appsettings.json',
        }
        SKIP_DIRS = {
            '.git', 'node_modules', 'bin', 'obj', '__pycache__',
            'dist', 'build', '.vs', 'packages', '.terraform',
            'vendor', '.idea', '.vscode', 'target', 'out', 'coverage',
        }

        hits          = []
        files_scanned = 0
        lines_scanned = 0

        for root, dirs, files in os.walk(repo_path):
            # Prune skip directories in-place to avoid descending
            dirs[:] = [
                d for d in dirs
                if d.lower() not in SKIP_DIRS and not d.startswith('.git')
            ]

            for filename in files:
                ext = os.path.splitext(filename)[1].lower()
                if ext not in SCANNABLE_EXTENSIONS and filename.lower() not in SCANNABLE_NAMES:
                    continue

                file_path = os.path.join(root, filename)
                rel_path  = os.path.relpath(file_path, repo_path).replace('\\', '/')

                try:
                    with open(file_path, 'r', encoding='utf-8', errors='replace') as fh:
                        files_scanned += 1
                        for line_no, raw_line in enumerate(fh, start=1):
                            lines_scanned += 1
                            line = raw_line.rstrip('\n')

                            # ── Azure endpoint pattern matching ──────────────
                            for svc_type, pattern, name_grp in self._AZURE_ENDPOINT_PATTERNS:
                                for m in pattern.finditer(line):
                                    if name_grp and name_grp <= len(m.groups()):
                                        svc_name = m.group(name_grp)
                                    else:
                                        svc_name = m.group(0)
                                    # Sanitise context: mask likely secret values
                                    ctx = line[:250].strip()
                                    ctx = re.sub(
                                        r'(key|secret|password|pwd|token|connectionstring)'
                                        r'\s*[=:]\s*["\']?[A-Za-z0-9+/=]{8,}',
                                        r'\1=***', ctx, flags=re.I
                                    )
                                    hits.append({
                                        'repo':           repo_name,
                                        'file':           rel_path,
                                        'line_no':        line_no,
                                        'service_type':   svc_type,
                                        'service_name':   svc_name,
                                        'endpoint_match': m.group(0),
                                        'context':        ctx,
                                    })

                            # ── Azure SDK import matching ──────────────────
                            for sdk_pattern in self._AZURE_SDK_IMPORT_PATTERNS:
                                for m in sdk_pattern.finditer(line):
                                    sdk_name = (
                                        m.group(1)
                                        if m.lastindex and m.lastindex >= 1
                                        else m.group(0)
                                    )
                                    hits.append({
                                        'repo':           repo_name,
                                        'file':           rel_path,
                                        'line_no':        line_no,
                                        'service_type':   'Azure SDK Import',
                                        'service_name':   sdk_name,
                                        'endpoint_match': m.group(0).strip(),
                                        'context':        line[:250].strip(),
                                    })

                except PermissionError:
                    self.logger.debug(f"Permission denied: {rel_path} - skipping")
                except Exception as read_err:
                    self.logger.debug(f"Cannot read {rel_path}: {read_err} - skipping")

        # ── Per-service-type summary log ──────────────────────────────────
        by_type: Dict[str, int] = defaultdict(int)
        by_name: Dict[str, Set[str]] = defaultdict(set)
        for h in hits:
            stype = h['service_type']
            sname = h['service_name']
            by_type[stype] += 1
            by_name[stype].add(sname)

        self.logger.info(
            f"    Line-by-line scan complete: {files_scanned} files, "
            f"{lines_scanned:,} lines, {len(hits)} Azure refs found"
        )
        if by_type:
            self.logger.info("    Azure service references by type:")
            for svc, cnt in sorted(by_type.items(), key=lambda x: -x[1]):
                names_preview = ', '.join(sorted(by_name[svc])[:5])
                if len(by_name[svc]) > 5:
                    names_preview += f" ... (+{len(by_name[svc])-5} more)"
                self.logger.info(f"      {svc:<30}: {cnt:>4} ref(s)  [{names_preview}]")
        else:
            self.logger.info("    No Azure service references detected in code.")

        return hits, files_scanned, lines_scanned

    def scan_arm_templates(self, repo_path):
        """Scan for and analyze ARM / Bicep templates in a repository."""
        arm_templates = []
        
        for root, dirs, files in os.walk(repo_path):
            # Skip git internals and common non-source dirs
            dirs[:] = [d for d in dirs if d not in ('.git', 'node_modules', 'bin', 'obj', '__pycache__')]

            for file in files:
                file_path = os.path.join(root, file)
                # ── Bicep templates ──────────────────────────────────────────
                if file.endswith('.bicep'):
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='replace') as fh:
                            content = fh.read()
                        arm_templates.append({
                            'file': os.path.relpath(file_path, repo_path).replace('\\', '/'),
                            'path': file_path,
                            'type': 'Bicep',
                            'resources': re.findall(r"resource\s+\w+\s+'([^']+)'", content),
                            'modules': re.findall(r"module\s+\w+\s+'([^']+)'", content),
                            'params': re.findall(r"^param\s+(\w+)", content, re.M),
                        })
                        self.logger.info(f"      Found Bicep template: {file}")
                    except Exception as e:
                        self.logger.debug(f"Could not parse Bicep {file_path}: {e}")

                # ── ARM JSON templates ───────────────────────────────────────
                elif file.endswith('.json') and any(
                    keyword in file.lower()
                    for keyword in ['template', 'deploy', 'arm', 'azuredeploy', 'maintemplate']
                ):
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='replace') as fh:
                            content = json.load(fh)
                        if '$schema' in content and 'deploymentTemplate' in content.get('$schema', ''):
                            template_info = self.parse_arm_template(content, file_path)
                            if template_info:
                                arm_templates.append(template_info)
                                self.logger.info(f"      Found ARM template: {file}")
                    except Exception as e:
                        self.logger.debug(f"Could not parse {file_path} as ARM template: {e}")

        return arm_templates

    def parse_arm_template(self, template, file_path):
        """Parse ARM template and extract resource definitions"""
        try:
            resources = template.get('resources', [])
            parameters = template.get('parameters', {})
            variables = template.get('variables', {})
            
            template_info = {
                'file': os.path.basename(file_path),
                'path': file_path,
                'schema': template.get('$schema', ''),
                'content_version': template.get('contentVersion', ''),
                'parameters': list(parameters.keys()),
                'variables': list(variables.keys()),
                'resources': [],
                'resource_types': set(),
                'dependencies_declared': []
            }
            
            # Parse resources
            for resource in resources:
                resource_type = resource.get('type', '')
                resource_name = resource.get('name', '')
                
                resource_info = {
                    'type': resource_type,
                    'name': resource_name,
                    'api_version': resource.get('apiVersion', ''),
                    'location': resource.get('location', ''),
                    'sku': resource.get('sku', {}),
                    'properties': self.extract_key_properties(resource.get('properties', {})),
                    'depends_on': resource.get('dependsOn', [])
                }
                
                template_info['resources'].append(resource_info)
                template_info['resource_types'].add(resource_type)
                
                # Track dependencies
                if resource.get('dependsOn'):
                    for dep in resource.get('dependsOn', []):
                        template_info['dependencies_declared'].append({
                            'source': resource_name,
                            'target': dep,
                            'type': 'ARM Template Dependency'
                        })
            
            template_info['resource_types'] = list(template_info['resource_types'])
            return template_info
            
        except Exception as e:
            self.logger.warning(f"Error parsing ARM template: {e}")
            return None
    
    def extract_key_properties(self, properties):
        """Extract important properties from ARM template resources"""
        if not isinstance(properties, dict):
            return {}
        
        # Extract only non-sensitive, important properties
        key_props = {}
        important_keys = ['serverFarmId', 'hostingEnvironment', 'virtualNetworkSubnetId', 
                         'vnetName', 'subnetName', 'databaseName', 'collation', 'sku']
        
        for key in important_keys:
            if key in properties:
                key_props[key] = properties[key]
        
        return key_props
    
    def scan_dependency_manifests(self, repo_path: str, repo_name: str) -> dict:
        """Scan all common package/dependency manifest files in a repository.

        Handles:
        - Python  : requirements*.txt, setup.py, setup.cfg, pyproject.toml, Pipfile
        - Node.js : package.json (direct + devDependencies)
        - Java    : pom.xml (Maven), build.gradle / build.gradle.kts (Gradle)
        - Go      : go.mod
        - Ruby    : Gemfile
        - .NET    : *.csproj, packages.config  (delegated to existing scanner)
        - PHP     : composer.json
        - Rust    : Cargo.toml

        Returns a dict keyed by manifest file path (relative), each value is a list
        of {"name": pkg, "version": ver, "type": "<ecosystem>", "file": rel_path}.
        Packages / modules that contain Azure-related names are flagged with
        "azure_related": True.
        """
        import xml.etree.ElementTree as ET

        AZURE_PKG_KEYWORDS = (
            'azure', '@azure/', 'microsoft.azure', 'com.microsoft.azure',
            'com.azure', 'azure-', 'azure_', 'servicebus', 'cosmosdb',
            'applicationinsights', 'eventhub', 'keyvault', 'blobstorage',
        )

        def _is_azure(name: str) -> bool:
            n = name.lower()
            return any(k in n for k in AZURE_PKG_KEYWORDS)

        manifests: dict = {}   # {rel_path: [{"name":, "version":, "type":, ...}]}

        SKIP_DIRS = {'.git', 'node_modules', 'bin', 'obj', '__pycache__',
                     'dist', 'build', '.venv', 'venv', 'env', '.terraform',
                     'vendor', 'packages', 'target', '.gradle'}

        for root, dirs, files in os.walk(repo_path):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            rel_root = os.path.relpath(root, repo_path).replace('\\', '/')
            if rel_root == '.':
                rel_root = ''

            for fname in files:
                fpath     = os.path.join(root, fname)
                rel_fpath = (f"{rel_root}/{fname}" if rel_root else fname)
                pkgs: list = []

                # ── Python: requirements*.txt ────────────────────────────────
                if re.match(r'requirements.*\.txt$', fname, re.I):
                    try:
                        with open(fpath, encoding='utf-8', errors='replace') as fh:
                            for raw in fh:
                                line = raw.strip()
                                if not line or line.startswith('#') or line.startswith('-'):
                                    continue
                                m = re.match(r'^([A-Za-z0-9_\-\.\[\]]+)\s*([><=!~,\s].*)?$', line)
                                if m:
                                    name = m.group(1)
                                    ver  = (m.group(2) or '').strip() or '*'
                                    pkgs.append({'name': name, 'version': ver,
                                                 'type': 'PyPI', 'file': rel_fpath,
                                                 'azure_related': _is_azure(name)})
                    except Exception as e:
                        self.logger.debug(f"Cannot parse {rel_fpath}: {e}")

                # ── Python: pyproject.toml ───────────────────────────────────
                elif fname.lower() == 'pyproject.toml':
                    try:
                        import tomllib  # Python 3.11+
                    except ImportError:
                        try:
                            import tomli as tomllib  # fallback
                        except ImportError:
                            tomllib = None
                    if tomllib:
                        try:
                            with open(fpath, 'rb') as fh:
                                data = tomllib.load(fh)
                            deps = (data.get('project', {}).get('dependencies', [])
                                    or data.get('tool', {}).get('poetry', {}).get('dependencies', {}).keys())
                            for dep in deps:
                                name = str(dep).split('[')[0].strip()
                                pkgs.append({'name': name, 'version': '*',
                                             'type': 'PyPI', 'file': rel_fpath,
                                             'azure_related': _is_azure(name)})
                        except Exception as e:
                            self.logger.debug(f"Cannot parse {rel_fpath}: {e}")
                    else:
                        # Fallback: regex parse
                        try:
                            with open(fpath, encoding='utf-8', errors='replace') as fh:
                                content = fh.read()
                            for m in re.finditer(r'"([A-Za-z0-9_\-\.]+)\s*[>=<!]', content):
                                name = m.group(1)
                                pkgs.append({'name': name, 'version': '*',
                                             'type': 'PyPI', 'file': rel_fpath,
                                             'azure_related': _is_azure(name)})
                        except Exception:
                            pass

                # ── Python: Pipfile ──────────────────────────────────────────
                elif fname == 'Pipfile':
                    try:
                        with open(fpath, encoding='utf-8', errors='replace') as fh:
                            content = fh.read()
                        in_pkg = False
                        for line in content.splitlines():
                            if re.match(r'^\[packages\]', line, re.I):
                                in_pkg = True; continue
                            if line.startswith('['):
                                in_pkg = False
                            if in_pkg:
                                m = re.match(r'^([A-Za-z0-9_\-\.]+)\s*=\s*"?([^"]+)"?', line)
                                if m:
                                    pkgs.append({'name': m.group(1), 'version': m.group(2).strip(),
                                                 'type': 'PyPI', 'file': rel_fpath,
                                                 'azure_related': _is_azure(m.group(1))})
                    except Exception as e:
                        self.logger.debug(f"Cannot parse {rel_fpath}: {e}")

                # ── Node.js: package.json ────────────────────────────────────
                elif fname == 'package.json':
                    try:
                        with open(fpath, encoding='utf-8', errors='replace') as fh:
                            data = json.load(fh)
                        for section in ('dependencies', 'devDependencies', 'peerDependencies'):
                            for name, ver in (data.get(section) or {}).items():
                                pkgs.append({'name': name, 'version': str(ver),
                                             'type': 'npm', 'file': rel_fpath,
                                             'azure_related': _is_azure(name)})
                    except Exception as e:
                        self.logger.debug(f"Cannot parse {rel_fpath}: {e}")

                # ── Maven: pom.xml ───────────────────────────────────────────
                elif fname == 'pom.xml':
                    try:
                        tree = ET.parse(fpath)
                        ns   = {'m': 'http://maven.apache.org/POM/4.0.0'}
                        # Try with namespace first, then without
                        root_el = tree.getroot()
                        ns_prefix = 'm:' if root_el.tag.startswith('{http://maven.apache.org') else ''
                        for dep in root_el.iter(
                            f'{{{ns["m"]}}}dependency' if ns_prefix else 'dependency'
                        ):
                            gid = (dep.findtext(f'{{{ns["m"]}}}groupId'   if ns_prefix else 'groupId') or '').strip()
                            aid = (dep.findtext(f'{{{ns["m"]}}}artifactId' if ns_prefix else 'artifactId') or '').strip()
                            ver = (dep.findtext(f'{{{ns["m"]}}}version'    if ns_prefix else 'version') or '*').strip()
                            name = f"{gid}:{aid}" if gid else aid
                            pkgs.append({'name': name, 'version': ver,
                                         'type': 'Maven', 'file': rel_fpath,
                                         'azure_related': _is_azure(name)})
                    except Exception as e:
                        self.logger.debug(f"Cannot parse {rel_fpath}: {e}")

                # ── Gradle: build.gradle / build.gradle.kts ──────────────────
                elif fname in ('build.gradle', 'build.gradle.kts'):
                    try:
                        with open(fpath, encoding='utf-8', errors='replace') as fh:
                            content = fh.read()
                        for m in re.finditer(
                            r"(?:implementation|api|compile|testImplementation|runtimeOnly)"
                            r"\s*['\"]([^'\"]+)['\"]", content
                        ):
                            parts = m.group(1).split(':')
                            name  = ':'.join(parts[:2]) if len(parts) >= 2 else parts[0]
                            ver   = parts[2].strip() if len(parts) >= 3 else '*'
                            pkgs.append({'name': name, 'version': ver,
                                         'type': 'Gradle', 'file': rel_fpath,
                                         'azure_related': _is_azure(name)})
                    except Exception as e:
                        self.logger.debug(f"Cannot parse {rel_fpath}: {e}")

                # ── Go: go.mod ───────────────────────────────────────────────
                elif fname == 'go.mod':
                    try:
                        with open(fpath, encoding='utf-8', errors='replace') as fh:
                            content = fh.read()
                        for m in re.finditer(
                            r'^(?:require\s+)?([a-zA-Z0-9_\-\./]+azure[a-zA-Z0-9_\-\./]*|'
                            r'github\.com/Azure/[a-zA-Z0-9_\-]+)\s+([^\s]+)',
                            content, re.M | re.I
                        ):
                            pkgs.append({'name': m.group(1), 'version': m.group(2).strip(),
                                         'type': 'Go Module', 'file': rel_fpath,
                                         'azure_related': _is_azure(m.group(1))})
                        # Also collect all requires
                        for m in re.finditer(r'^\t([^ ]+) ([^ \n]+)', content, re.M):
                            name = m.group(1).strip()
                            if name and not name.startswith('//'):
                                pkgs.append({'name': name, 'version': m.group(2).strip(),
                                             'type': 'Go Module', 'file': rel_fpath,
                                             'azure_related': _is_azure(name)})
                    except Exception as e:
                        self.logger.debug(f"Cannot parse {rel_fpath}: {e}")

                # ── Ruby: Gemfile ────────────────────────────────────────────
                elif fname == 'Gemfile':
                    try:
                        with open(fpath, encoding='utf-8', errors='replace') as fh:
                            content = fh.read()
                        for m in re.finditer(r"gem\s+['\"]([^'\"]+)['\"](?:,\s*['\"]([^'\"]+)['\"])?", content):
                            pkgs.append({'name': m.group(1), 'version': m.group(2) or '*',
                                         'type': 'RubyGem', 'file': rel_fpath,
                                         'azure_related': _is_azure(m.group(1))})
                    except Exception as e:
                        self.logger.debug(f"Cannot parse {rel_fpath}: {e}")

                # ── PHP: composer.json ───────────────────────────────────────
                elif fname == 'composer.json':
                    try:
                        with open(fpath, encoding='utf-8', errors='replace') as fh:
                            data = json.load(fh)
                        for section in ('require', 'require-dev'):
                            for name, ver in (data.get(section) or {}).items():
                                if name == 'php':
                                    continue
                                pkgs.append({'name': name, 'version': str(ver),
                                             'type': 'Composer', 'file': rel_fpath,
                                             'azure_related': _is_azure(name)})
                    except Exception as e:
                        self.logger.debug(f"Cannot parse {rel_fpath}: {e}")

                # ── Rust: Cargo.toml ─────────────────────────────────────────
                elif fname == 'Cargo.toml':
                    try:
                        with open(fpath, encoding='utf-8', errors='replace') as fh:
                            content = fh.read()
                        in_deps = False
                        for line in content.splitlines():
                            if re.match(r'^\[dependencies\]', line, re.I):
                                in_deps = True; continue
                            if line.startswith('['):
                                in_deps = False
                            if in_deps:
                                m = re.match(r'^([A-Za-z0-9_\-]+)\s*=\s*"?([^"]+)"?', line)
                                if m:
                                    pkgs.append({'name': m.group(1), 'version': m.group(2).strip(),
                                                 'type': 'Cargo (Rust)', 'file': rel_fpath,
                                                 'azure_related': _is_azure(m.group(1))})
                    except Exception as e:
                        self.logger.debug(f"Cannot parse {rel_fpath}: {e}")

                if pkgs:
                    manifests[rel_fpath] = manifests.get(rel_fpath, []) + pkgs

        # Summary log
        azure_pkgs   = [p for pl in manifests.values() for p in pl if p.get('azure_related')]
        total_pkgs   = sum(len(v) for v in manifests.values())
        self.logger.info(
            f"    Dependency manifests: {len(manifests)} file(s), "
            f"{total_pkgs} total packages, {len(azure_pkgs)} Azure-related"
        )
        if azure_pkgs:
            seen: set = set()
            self.logger.info("    Azure-related packages detected:")
            for p in azure_pkgs:
                key = f"{p['type']}:{p['name']}"
                if key not in seen:
                    seen.add(key)
                    self.logger.info(f"      [{p['type']}] {p['name']} {p['version']}  ({p['file']})")
        return manifests

    def scan_dotnet_code(self, repo_path, repo_name):
        """Comprehensive .NET code analysis"""
        dotnet_data = {
            'files_scanned': 0,
            'lines_scanned': 0,
            'dotnet_dependencies': [],
            'nuget_packages': [],
            'configuration_files': [],
            'azure_sdk_usage': [],
            'database_connections': [],
            'external_dependencies': [],
            'api_endpoints': [],
            'service_dependencies': []
        }
        
        # .NET specific patterns
        dotnet_patterns = {
            'using_statements': re.compile(r'^\s*using\s+([\w\.]+);', re.MULTILINE),
            'connection_strings': re.compile(r'(ConnectionStrings?|connectionString)["\']?\s*[:=]', re.IGNORECASE),
            'http_client': re.compile(r'HttpClient|RestClient|WebClient'),
            'dependency_injection': re.compile(r'services\.Add[A-Z]\w+'),
            'api_routes': re.compile(r'\[Route\(["\']([^"\']+)["\']\)\]|\[HttpGet\(["\']([^"\']+)["\']\)\]|\[HttpPost\(["\']([^"\']+)["\']\)\]'),
            'azure_sdk': re.compile(r'using\s+(Azure|Microsoft\.Azure|Microsoft\.Graph)[\w\.]*;', re.MULTILINE),
            'entity_framework': re.compile(r'DbContext|DbSet<|EF\.Core'),
            'appsettings_ref': re.compile(r'Configuration\[["\']([^"\']+)["\']\]|GetSection\(["\']([^"\']+)["\']\)'),
            'sql_queries': re.compile(r'(SELECT|INSERT|UPDATE|DELETE)\s+.*\s+FROM\s+', re.IGNORECASE),
            'email_smtp': re.compile(r'SmtpClient|MailMessage|SendGrid'),
            'external_urls': re.compile(r'https?://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}[^\s\'"\)]*')
        }
        
        for root, dirs, files in os.walk(repo_path):
            if '.git' in root or 'node_modules' in root or 'bin' in root or 'obj' in root:
                continue
            
            for file in files:
                file_path = os.path.join(root, file)
                relative_path = os.path.relpath(file_path, repo_path)
                
                # Scan .csproj files for NuGet packages
                if file.endswith('.csproj'):
                    packages = self.parse_csproj(file_path)
                    dotnet_data['nuget_packages'].extend(packages)
                    dotnet_data['files_scanned'] += 1
                
                # Scan packages.config
                elif file == 'packages.config':
                    packages = self.parse_packages_config(file_path)
                    dotnet_data['nuget_packages'].extend(packages)
                    dotnet_data['files_scanned'] += 1
                
                # Scan appsettings.json and web.config
                elif file in ['appsettings.json', 'appsettings.Development.json', 'appsettings.Production.json']:
                    config = self.parse_appsettings(file_path)
                    dotnet_data['configuration_files'].append(config)
                    dotnet_data['files_scanned'] += 1
                
                elif file == 'web.config' or file == 'app.config':
                    config = self.parse_xml_config(file_path)
                    dotnet_data['configuration_files'].append(config)
                    dotnet_data['files_scanned'] += 1
                
                # Scan C# source files line by line
                elif file.endswith('.cs'):
                    line_analysis = self.analyze_csharp_file(file_path, relative_path, dotnet_patterns)
                    dotnet_data['files_scanned'] += 1
                    dotnet_data['lines_scanned'] += line_analysis['line_count']
                    
                    # Aggregate findings
                    dotnet_data['azure_sdk_usage'].extend(line_analysis['azure_sdk'])
                    dotnet_data['external_dependencies'].extend(line_analysis['external_urls'])
                    dotnet_data['api_endpoints'].extend(line_analysis['api_routes'])
                    dotnet_data['database_connections'].extend(line_analysis['db_connections'])
                    dotnet_data['service_dependencies'].extend(line_analysis['dependencies'])
        
        # Deduplicate
        dotnet_data['nuget_packages'] = self.deduplicate_list(dotnet_data['nuget_packages'], 'name')
        dotnet_data['azure_sdk_usage'] = list(set(dotnet_data['azure_sdk_usage']))
        
        return dotnet_data
    
    def parse_csproj(self, file_path):
        """Parse .csproj file for NuGet package references"""
        packages = []
        try:
            import xml.etree.ElementTree as ET
            tree = ET.parse(file_path)
            root = tree.getroot()
            
            # Find PackageReference elements
            for pkg in root.findall('.//PackageReference'):
                name = pkg.get('Include')
                version = pkg.get('Version', 'Unknown')
                if name:
                    packages.append({
                        'name': name,
                        'version': version,
                        'source': os.path.basename(file_path),
                        'type': 'NuGet Package'
                    })
        except Exception as e:
            self.logger.debug(f"Error parsing {file_path}: {e}")
        
        return packages
    
    def parse_packages_config(self, file_path):
        """Parse packages.config file"""
        packages = []
        try:
            import xml.etree.ElementTree as ET
            tree = ET.parse(file_path)
            root = tree.getroot()
            
            for pkg in root.findall('.//package'):
                name = pkg.get('id')
                version = pkg.get('version', 'Unknown')
                if name:
                    packages.append({
                        'name': name,
                        'version': version,
                        'source': 'packages.config',
                        'type': 'NuGet Package'
                    })
        except Exception as e:
            self.logger.debug(f"Error parsing {file_path}: {e}")
        
        return packages
    
    def parse_appsettings(self, file_path):
        """Parse appsettings.json for configuration"""
        config_data = {
            'file': os.path.basename(file_path),
            'path': file_path,
            'connection_strings': [],
            'azure_services': [],
            'external_endpoints': [],
            'smtp_settings': {}
        }
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
                
                # Extract connection strings
                if 'ConnectionStrings' in config:
                    for key, value in config['ConnectionStrings'].items():
                        config_data['connection_strings'].append({
                            'name': key,
                            'type': self.detect_connection_type(str(value))
                        })
                
                # Look for Azure service references
                self.extract_azure_config(config, config_data)
                
                # Look for external URLs
                self.extract_urls_from_config(config, config_data)
        
        except Exception as e:
            self.logger.debug(f"Error parsing {file_path}: {e}")
        
        return config_data
    
    def parse_xml_config(self, file_path):
        """Parse web.config or app.config"""
        config_data = {
            'file': os.path.basename(file_path),
            'path': file_path,
            'connection_strings': [],
            'app_settings': []
        }
        
        try:
            import xml.etree.ElementTree as ET
            tree = ET.parse(file_path)
            root = tree.getroot()
            
            # Connection strings
            for conn in root.findall('.//connectionStrings/add'):
                config_data['connection_strings'].append({
                    'name': conn.get('name', ''),
                    'type': self.detect_connection_type(conn.get('connectionString', ''))
                })
            
            # App settings
            for setting in root.findall('.//appSettings/add'):
                key = setting.get('key', '')
                if key and not any(s in key.lower() for s in ['password', 'secret', 'key']):
                    config_data['app_settings'].append(key)
        
        except Exception as e:
            self.logger.debug(f"Error parsing {file_path}: {e}")
        
        return config_data
    
    def analyze_csharp_file(self, file_path, relative_path, patterns):
        """Analyze C# file line by line"""
        analysis = {
            'file': relative_path,
            'line_count': 0,
            'azure_sdk': [],
            'external_urls': [],
            'api_routes': [],
            'db_connections': [],
            'dependencies': []
        }
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
                analysis['line_count'] = len(lines)
                
                # Azure SDK usage
                azure_matches = patterns['azure_sdk'].findall(content)
                for match in azure_matches:
                    analysis['azure_sdk'].append(match)
                
                # External URLs
                url_matches = patterns['external_urls'].findall(content)
                for url in url_matches:
                    if not url.endswith('.com') and len(url) > 10:
                        analysis['external_urls'].append({
                            'url': url,
                            'file': relative_path
                        })
                
                # API Routes
                route_matches = patterns['api_routes'].findall(content)
                for route_match in route_matches:
                    route = [r for r in route_match if r]
                    if route:
                        analysis['api_routes'].append({
                            'route': route[0],
                            'file': relative_path
                        })
                
                # Database usage
                if patterns['entity_framework'].search(content) or patterns['sql_queries'].search(content):
                    analysis['db_connections'].append(relative_path)
                
                # Using statements for dependencies
                using_matches = patterns['using_statements'].findall(content)
                for using in using_matches:
                    if using.startswith('System') or using.startswith('Microsoft'):
                        analysis['dependencies'].append(using)
        
        except Exception as e:
            self.logger.debug(f"Error analyzing {file_path}: {e}")
        
        return analysis
    
    def detect_connection_type(self, conn_string):
        """Detect database type from connection string"""
        conn_lower = str(conn_string).lower()
        if 'sqlserver' in conn_lower or 'database.windows.net' in conn_lower:
            return 'Azure SQL'
        elif 'mongodb' in conn_lower or 'cosmos' in conn_lower:
            return 'Cosmos DB / MongoDB'
        elif 'mysql' in conn_lower:
            return 'MySQL'
        elif 'postgresql' in conn_lower or 'postgres' in conn_lower:
            return 'PostgreSQL'
        elif 'redis' in conn_lower:
            return 'Redis Cache'
        else:
            return 'Unknown'
    
    def extract_azure_config(self, config, config_data):
        """Extract Azure service references from configuration"""
        def search_dict(d, path=''):
            if isinstance(d, dict):
                for key, value in d.items():
                    current_path = f"{path}.{key}" if path else key
                    if isinstance(value, str):
                        # Check for Azure service endpoints
                        if any(azure_domain in value for azure_domain in 
                              ['.azure.com', '.windows.net', '.azurewebsites.net', 
                               '.blob.core', '.queue.core', '.table.core', '.file.core']):
                            config_data['azure_services'].append({
                                'key': current_path,
                                'value': value
                            })
                    else:
                        search_dict(value, current_path)
            elif isinstance(d, list):
                for item in d:
                    search_dict(item, path)
        
        search_dict(config)
    
    def extract_urls_from_config(self, config, config_data):
        """Extract external URLs from configuration"""
        def search_urls(d):
            if isinstance(d, dict):
                for key, value in d.items():
                    if isinstance(value, str) and value.startswith('http'):
                        config_data['external_endpoints'].append({
                            'key': key,
                            'url': value
                        })
                    else:
                        search_urls(value)
            elif isinstance(d, list):
                for item in d:
                    search_urls(item)
        
        search_urls(config)
    
    def deduplicate_list(self, lst, key):
        """Deduplicate list of dictionaries by key"""
        seen = set()
        result = []
        for item in lst:
            identifier = item.get(key) if isinstance(item, dict) else item
            if identifier not in seen:
                seen.add(identifier)
                result.append(item)
        return result
    
    def scan_code_patterns(self, repo_path):
        """General pattern scanning across all code files"""
        patterns = {
            'external_apis': re.compile(r'https?://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}[^\s\'"]*'),
            'smtp_servers': re.compile(r'smtp\.[a-zA-Z0-9\-\.]+'),
            'email_addresses': re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),
            'api_keys': re.compile(r'(api[_-]?key|apikey)["\']?\s*[:=]\s*["\']([^"\']+)["\']'),
            'azure_resources': re.compile(r'\.azure\.com|\.azurewebsites\.net|\.blob\.core\.windows\.net')
        }
        
        findings = defaultdict(set)
        
        for root, dirs, files in os.walk(repo_path):
            if '.git' in root:
                continue
            
            for file in files:
                if not any(file.endswith(ext) for ext in [
                    '.cs', '.vb', '.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.go',
                    '.php', '.rb', '.json', '.yml', '.yaml', '.config', '.xml',
                    '.tf', '.bicep', '.hcl', '.sh', '.ps1', '.psm1',
                    '.properties', '.env', '.toml', '.ini',
                ]) and file.lower() not in {'dockerfile', '.env', '.envrc', 'procfile'}:
                    continue
                
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        
                        for pattern_name, pattern in patterns.items():
                            matches = pattern.findall(content)
                            if matches:
                                for match in matches:
                                    if isinstance(match, tuple):
                                        findings[pattern_name].add(match[0] if match else str(match))
                                    else:
                                        findings[pattern_name].add(match)
                except Exception as e:
                    self.logger.debug(f"Could not read file {file_path}: {e}")
        
        return {k: list(v) for k, v in findings.items()}
    
    def build_application_dependency_graph(self, app_data, app_name):
        """Build application-centric dependency graph"""
        dep_graph = {
            'root': app_name,
            'type': 'Application',
            'children': {
                'infrastructure': [],
                'databases': [],
                'external_services': [],
                'azure_services': [],
                'internal_dependencies': []
            }
        }
        
        # Infrastructure from ARM templates
        for template in app_data.get('arm_templates', []):
            for resource in template.get('resources', []):
                dep_graph['children']['infrastructure'].append({
                    'name': resource['name'],
                    'type': resource['type'],
                    'source': 'ARM Template',
                    'file': template['file']
                })
        
        # Database dependencies
        for config_file in app_data.get('configuration_files', []):
            for conn in config_file.get('connection_strings', []):
                dep_graph['children']['databases'].append({
                    'name': conn['name'],
                    'type': conn['type'],
                    'source': config_file['file']
                })
        
        # Azure SDK usage
        for azure_sdk in app_data.get('azure_sdk_usage', []):
            dep_graph['children']['azure_services'].append({
                'sdk': azure_sdk,
                'type': 'Azure SDK'
            })
        
        # External dependencies
        for ext_dep in app_data.get('external_dependencies', []):
            if isinstance(ext_dep, dict):
                dep_graph['children']['external_services'].append(ext_dep)
        
        # NuGet packages
        for pkg in app_data.get('nuget_packages', []):
            dep_graph['children']['internal_dependencies'].append({
                'name': pkg['name'],
                'version': pkg['version'],
                'type': 'NuGet Package'
            })
        
        return dep_graph

    # ──────────────────────────────────────────────────────────────────────────
    # PHASE 6 — Full Resource Property Export & Cross-Tenant Deployment Package
    # ──────────────────────────────────────────────────────────────────────────

    def _write_json(self, path: str, data: Any) -> None:
        """Write data as pretty-printed JSON to path, creating parent dirs as needed."""
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(path, 'w', encoding='utf-8') as fh:
            json.dump(data, fh, indent=2, default=str)

    def _get_api_version(self, resource_type: str) -> str:
        """Return a stable published API version for common Azure resource types."""
        rt = resource_type.lower()
        table: Dict[str, str] = {
            'microsoft.web/sites':                                  '2023-01-01',
            'microsoft.web/serverfarms':                            '2023-01-01',
            'microsoft.web/staticwebapps':                         '2023-01-01',
            'microsoft.storage/storageaccounts':                    '2023-01-01',
            'microsoft.sql/servers':                                '2023-08-01-preview',
            'microsoft.sql/servers/databases':                      '2023-08-01-preview',
            'microsoft.documentdb/databaseaccounts':               '2024-02-15-preview',
            'microsoft.keyvault/vaults':                           '2023-07-01',
            'microsoft.network/virtualnetworks':                   '2024-01-01',
            'microsoft.network/networksecuritygroups':             '2024-01-01',
            'microsoft.network/publicipaddresses':                 '2024-01-01',
            'microsoft.network/loadbalancers':                     '2024-01-01',
            'microsoft.network/applicationgateways':               '2024-01-01',
            'microsoft.network/dnszones':                          '2023-07-01-preview',
            'microsoft.compute/virtualmachines':                   '2024-03-01',
            'microsoft.compute/disks':                             '2024-03-02',
            'microsoft.compute/snapshots':                         '2024-03-02',
            'microsoft.compute/availabilitysets':                  '2024-03-01',
            'microsoft.containerservice/managedclusters':          '2024-02-01',
            'microsoft.containerregistry/registries':              '2023-11-01-preview',
            'microsoft.servicebus/namespaces':                     '2023-01-01-preview',
            'microsoft.eventhub/namespaces':                       '2024-01-01',
            'microsoft.cache/redis':                               '2024-03-01',
            'microsoft.redis/redis':                               '2024-03-01',
            'microsoft.apimanagement/service':                     '2023-09-01-preview',
            'microsoft.insights/components':                       '2020-02-02',
            'microsoft.operationalinsights/workspaces':            '2023-09-01',
            'microsoft.search/searchservices':                     '2024-03-01-preview',
            'microsoft.cognitiveservices/accounts':                '2023-10-01-preview',
            'microsoft.databricks/workspaces':                     '2024-05-01',
            'microsoft.datafactory/factories':                     '2018-06-01',
            'microsoft.cdn/profiles':                              '2024-02-01',
            'microsoft.notificationhubs/namespaces':               '2023-10-01-preview',
            'microsoft.signalrservice/signalr':                    '2023-08-01-preview',
            'microsoft.authorization/roleassignments':             '2022-04-01',
        }
        return table.get(rt, '2022-09-01')

    def _build_arm_snippet(self, name: str, rtype: str, location: str, detail: Dict) -> Dict:
        """Build a minimal deployable ARM resource object, stripping read-only fields."""
        READ_ONLY = {
            'provisioningstate', 'creationtime', 'lastmodifiedtime', 'status',
            'statusdetails',    'internalid',   'serviceuri',        'managedby',
            'tenantid',         'principalid',  'resourceguid',      'etag',
            'privateendpointconnections',
        }

        def _strip(obj: Any) -> Any:
            if isinstance(obj, dict):
                return {k: _strip(v) for k, v in obj.items()
                        if k.lower() not in READ_ONLY}
            if isinstance(obj, list):
                return [_strip(i) for i in obj]
            return obj

        props: Dict[str, Any] = _strip(detail.get('properties', {}))
        snippet: Dict[str, Any] = {
            'type':       rtype,
            'apiVersion': self._get_api_version(rtype),
            'name':       name,
            'location':   location,
            'properties': props,
        }
        for key in ('sku', 'kind', 'tags', 'identity', 'zones'):
            if detail.get(key):
                snippet[key] = detail[key]
        return snippet

    def _generate_redeploy_notes(self, resource_type: str, detail: Dict) -> List[str]:
        """Return actionable redeployment guidance for a specific Azure resource type."""
        rt = resource_type.lower()
        notes: List[str] = []
        if 'microsoft.keyvault/vaults' in rt:
            notes += [
                'Secrets, keys, and certificates are NOT exported — export manually via: '
                'az keyvault secret list / download',
                'Soft-delete and purge-protection settings must be matched in the target tenant.',
                'Access policies and RBAC role assignments reference source-tenant object IDs '
                '— re-grant to new principal IDs after deployment.',
            ]
        elif 'microsoft.storage/storageaccounts' in rt:
            notes += [
                'Blob / Table / Queue data must be migrated separately using AzCopy or '
                'Azure Data Factory.',
                'SAS tokens and shared-access policies must be regenerated in the target tenant.',
                'Firewall rules (VNet service endpoints, allowed IPs) need updating for the '
                'new environment.',
            ]
        elif 'microsoft.sql/servers/databases' in rt or 'microsoft.sql/servers' in rt:
            notes += [
                'Export database data as BACPAC: az sql db export --server ... --name ... '
                '--storage-key ... --storage-uri ...',
                'Admin password is NOT included — supply a new password during deployment.',
                'Firewall rules reference IPs / VNets that may differ in the target tenant.',
                'Elastic Pool membership must be recreated manually if applicable.',
            ]
        elif 'microsoft.documentdb/databaseaccounts' in rt:
            notes += [
                'Account keys are NOT included — regenerate after deployment.',
                'Migrate data using the Azure Cosmos DB Migration Tool or Azure Data Factory.',
                'Replicated regions must be re-added; geo-redundancy config must match '
                'throughput tier.',
            ]
        elif 'microsoft.compute/virtualmachines' in rt:
            notes += [
                'OS disk image / VHD is NOT exported — use Azure Migrate or snapshot + '
                'copy the VHD manually.',
                'Admin password / SSH key is NOT included — provide new credentials at '
                'deploy time.',
                'Availability Set, NIC, and Disk resources must be deployed separately first.',
            ]
        elif 'microsoft.servicebus/namespaces' in rt or 'microsoft.eventhub/namespaces' in rt:
            notes += [
                'Connection strings (Shared Access Keys) must be regenerated after deployment.',
                'Queue / Topic / Hub definitions are included; in-flight messages are NOT '
                'migrated.',
                'Consumer groups and subscriptions must be validated post-deployment.',
            ]
        elif 'microsoft.web/sites' in rt:
            notes += [
                'Application Settings containing secrets are NOT exported — review and re-add '
                'manually in the target tenant.',
                'Application code must be redeployed via CI/CD pipeline or zip-deploy.',
                'Custom domains require DNS re-pointing and SSL certificate re-binding.',
                'Managed Identity must be re-granted RBAC roles in the target tenant.',
            ]
        elif 'microsoft.apimanagement/service' in rt:
            notes += [
                'Subscription keys and named values with secrets must be reconfigured manually.',
                'Backend URLs may point to source-tenant resources — update after migration.',
                'Custom domains require new SSL certificates in the target tenant.',
            ]
        elif 'microsoft.containerservice/managedclusters' in rt:
            notes += [
                'AKS cluster is reprovisioned fresh — existing node state is NOT migrated.',
                'Workloads must be redeployed via Helm charts or kubectl apply.',
                'Persistent Volume Claims backed by Azure Disks must be recreated and data '
                'migrated separately.',
                'AAD integration and RBAC bindings reference source-tenant object IDs — '
                'update all bindings after deployment.',
            ]
        else:
            notes.append(
                'Review all endpoint references, connection strings, and managed identities '
                'for tenant-specific values.'
            )
        return notes

    def _flag_sensitive_params(self, resource_type: str, detail: Dict) -> List[str]:
        """Walk the resource properties tree and return paths to potentially sensitive keys."""
        SENSITIVE_KEYS = {
            'administratorloginpassword', 'password',          'secretvalue',
            'connectionstring',           'primarykey',         'secondarykey',
            'primaryconnectionstring',    'secondaryconnectionstring',
            'instrumentationkey',         'connectionstrings',  'apikey',
            'sastoken',   'sharedaccesskey', 'clientsecret',
            'adminpassword', 'sshpublickey',
        }
        found: List[str] = []

        def _walk(obj: Any, path: str = '') -> None:
            if isinstance(obj, dict):
                for k, v in obj.items():
                    _walk(v, f'{path}.{k}' if path else k)
            elif isinstance(obj, list):
                for idx, item in enumerate(obj):
                    _walk(item, f'{path}[{idx}]')
            else:
                leaf_key = path.split('.')[-1].split('[')[0].lower()
                leaf_key = leaf_key.replace('_', '').replace('-', '')
                if leaf_key in SENSITIVE_KEYS:
                    found.append(path)

        _walk(detail.get('properties', {}))
        return list(dict.fromkeys(found))  # deduplicate, preserve order

    def _get_resource_full_detail(self, resource_id: str,
                                   resource_type: str) -> Dict:
        """Run `az resource show --ids` with a 30-second hard timeout.

        Retries once on HTTP 429 (rate-limit) or 503 (service unavailable).
        Returns {} on any failure so callers always get a safe value.
        """
        if not resource_id:
            return {}
        import subprocess as _sp
        api_ver = self._get_api_version(resource_type)
        cmd = [
            'az', 'resource', 'show',
            '--ids',         resource_id,
            '--api-version', api_ver,
            '--output',      'json',
        ]
        for attempt in range(2):          # up to 2 attempts
            try:
                r = _sp.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=30,           # hard 30-second cap per resource
                    env={**os.environ},
                )
                if r.returncode == 0 and r.stdout.strip():
                    parsed = json.loads(r.stdout)
                    return parsed if isinstance(parsed, dict) else {}
                stderr = (r.stderr or '').lower()
                if '429' in stderr or 'too many requests' in stderr:
                    time.sleep(2 ** attempt)   # 1s then 2s back-off
                    continue
                if '503' in stderr or 'service unavailable' in stderr:
                    time.sleep(2 ** attempt)
                    continue
                self.logger.debug(
                    f'az resource show failed rc={r.returncode} '
                    f'id={resource_id} err={r.stderr[:200]}'
                )
                return {}
            except _sp.TimeoutExpired:
                self.logger.debug(f'az resource show timed out (30s): {resource_id}')
                return {}
            except json.JSONDecodeError as e:
                self.logger.debug(f'az resource show JSON error {resource_id}: {e}')
                return {}
            except Exception as e:
                self.logger.debug(f'az resource show unexpected error {resource_id}: {e}')
                return {}
        return {}

    def export_resource_properties(self) -> Dict[str, Any]:
        """Fetch full ARM properties for every discovered resource.

        Uses a thread pool (``parallel_workers`` config key, default 10) for
        parallel ``az resource show`` calls.  Prints a live progress bar to
        stdout so the user can see exactly what is happening.

        Returns a nested inventory dict keyed by subscription_id.
        """
        max_workers: int = int(self.config.get('parallel_workers', 10))

        sep = '=' * 72
        print(f'\n{sep}')
        print('  EXPORTING FULL RESOURCE PROPERTIES  (cross-tenant redeployment)')
        print(sep)

        full_result: Dict[str, Any] = {}

        for sub_id, sub_data in self.discovery_data.get('subscriptions', {}).items():
            sub_name = sub_data.get('name', sub_id)
            print(f'\n  Subscription : {sub_name}')
            print(f'  ID           : {sub_id}')

            # ── collect flat resource list from already-discovered data ────
            print('  Step 1/3  : Collecting resource list from discovery data...', flush=True)
            work_items: List[tuple] = []   # (rg_name, res_dict)
            for rg_name, rg_data in sub_data.get('resource_groups', {}).items():
                for res in rg_data.get('resources', []):
                    work_items.append((rg_name, rg_data, res))

            total = len(work_items)
            if total == 0:
                print('  ⚠  No resources found in this subscription — skipping.')
                continue
            print(f'  ✅ Step 1/3  : {total} resources across '
                  f"{len(sub_data.get('resource_groups', {}))} resource groups")

            # ── parallel az resource show ──────────────────────────────────
            print(f'  Step 2/3  : Fetching full properties'
                  f' ({max_workers} parallel workers, 30s timeout each)...')

            lock        = threading.Lock()
            done_count  = [0]         # list so closure can mutate
            fail_count  = [0]
            t_start     = time.time()

            def _fetch(item):
                rg_name, rg_data, res = item
                res_id   = res.get('id',       '')
                res_name = res.get('name',     '')
                res_type = res.get('type',     '')
                res_loc  = res.get('location', '')

                detail         = self._get_resource_full_detail(res_id, res_type)
                arm_snippet    = self._build_arm_snippet(res_name, res_type, res_loc,
                                                         detail if detail else res)
                redeploy_notes = self._generate_redeploy_notes(res_type,
                                                                detail if detail else res)
                sensitive_keys = self._flag_sensitive_params(res_type,
                                                             detail if detail else res)

                enriched = {
                    'id':             res_id,
                    'name':           res_name,
                    'type':           res_type,
                    'location':       res_loc,
                    'sku':            (detail or res).get('sku')  or {},
                    'kind':           (detail or res).get('kind') or '',
                    'zones':          (detail or res).get('zones') or [],
                    'tags':           (detail or res).get('tags') or {},
                    'api_version':    self._get_api_version(res_type),
                    'properties':     (detail or {}).get('properties') or {},
                    'arm_snippet':    arm_snippet,
                    'redeploy_notes': redeploy_notes,
                    'sensitive_keys': sensitive_keys,
                    # keep rg_meta for assembly
                    '_rg_name':       rg_name,
                    '_rg_location':   rg_data.get('location', ''),
                    '_rg_tags':       rg_data.get('tags', {}),
                }

                with lock:
                    done_count[0] += 1
                    if not detail:
                        fail_count[0] += 1
                    done    = done_count[0]
                    elapsed = time.time() - t_start
                    rate    = done / elapsed if elapsed > 0 else 1
                    remain  = int((total - done) / rate) if rate > 0 else 0
                    pct     = int(done * 100 / total)
                    filled  = pct // 2          # 50-char bar
                    bar     = '\u2588' * filled + '\u2591' * (50 - filled)
                    eta     = (f'{remain // 60}m {remain % 60}s'
                               if remain >= 60 else f'{remain}s')
                    warn    = '\u26a0 ' if not detail else '  '
                    print(
                        f'\r  {warn}[{bar}] {pct:3d}%  '
                        f'{done}/{total}  ETA: {eta:<8}  '
                        f'\u274c failed: {fail_count[0]}   ',
                        end='', flush=True,
                    )

                return enriched

            results: List[Dict] = []
            with ThreadPoolExecutor(max_workers=max_workers) as pool:
                futures = {pool.submit(_fetch, item): item for item in work_items}
                for fut in as_completed(futures):
                    try:
                        results.append(fut.result(timeout=90))
                    except Exception as exc:
                        with lock:
                            fail_count[0] += 1
                            done_count[0] += 1
                        self.logger.debug(f'Future error: {exc}')

            elapsed_total = time.time() - t_start
            ok = total - fail_count[0]
            print(f'\n  ✅ Step 2/3  : Done in {elapsed_total:.1f}s  '
                  f'({ok}/{total} fetched, {fail_count[0]} failed/timed-out)')

            # ── assemble into rg-grouped structure ─────────────────────────
            print('  Step 3/3  : Assembling resource group inventory...', flush=True)
            rg_inventory: Dict[str, Any] = {}
            for entry in results:
                rg  = entry.pop('_rg_name')
                loc = entry.pop('_rg_location')
                tgs = entry.pop('_rg_tags')
                if rg not in rg_inventory:
                    rg_inventory[rg] = {'location': loc, 'tags': tgs, 'resources': []}
                rg_inventory[rg]['resources'].append(entry)

            full_result[sub_id] = {
                'name':            sub_name,
                'resource_groups': rg_inventory,
            }

            # per-RG summary table
            print(f'  ✅ Step 3/3  : Assembled {len(rg_inventory)} resource groups')
            print(f'\n  {"Resource Group":<42} {"Resources":>9}')
            print(f'  {"-"*42} {"-"*9}')
            for rg, rg_d in sorted(rg_inventory.items()):
                print(f'  {rg:<42} {len(rg_d["resources"]):>9}')
            print(f'  {"-"*42} {"-"*9}')
            print(f'  {"TOTAL":<42} {total:>9}\n')

        print(sep)
        print('  Full resource property export complete.')
        print(sep + '\n')
        self._full_inventory = full_result   # cache for Excel sheet
        return full_result

    def generate_deployment_package(self, full_inventory: Dict[str, Any]) -> str:
        """Write one deployment package folder per resource group.

        Output layout under ``output_dir``::

            deployment_package_<ts>/
              <safe_sub_name>/
                <rg_name>/
                  arm_template.json
                  parameters.json
                  deploy.ps1
                  deploy.sh
                  resource_inventory.json

        Returns the path to the top-level ``deployment_package_<ts>/`` folder.
        """
        self.logger.info("\n" + "=" * 80)
        self.logger.info("Building Deployment Packages")
        self.logger.info("=" * 80)

        ts   = datetime.now().strftime('%Y%m%d_%H%M%S')
        base = os.path.join(self.config['output_dir'], f'deployment_package_{ts}')
        os.makedirs(base, exist_ok=True)

        SENSITIVE_LEAF = {
            'administratorloginpassword', 'password',          'secretvalue',
            'connectionstring',           'primarykey',         'secondarykey',
            'primaryconnectionstring',    'secondaryconnectionstring',
            'instrumentationkey',         'apikey',             'sastoken',
            'sharedaccesskey',            'clientsecret',       'adminpassword',
        }

        def _redact(obj: Any) -> Any:
            """Return a copy with sensitive leaf values replaced by placeholder strings."""
            if isinstance(obj, dict):
                out: Dict[str, Any] = {}
                for k, v in obj.items():
                    norm = k.lower().replace('_', '').replace('-', '')
                    if norm in SENSITIVE_LEAF and isinstance(v, str) and v:
                        out[k] = f'<REPLACE_WITH_{k.upper()}>'
                    else:
                        out[k] = _redact(v)
                return out
            if isinstance(obj, list):
                return [_redact(i) for i in obj]
            return obj

        pkg_count = 0
        for sub_id, sub_data in full_inventory.items():
            safe_sub = re.sub(r'[^A-Za-z0-9_\-]', '_', sub_data.get('name', sub_id))[:60]
            for rg_name, rg_data in sub_data.get('resource_groups', {}).items():
                rg_dir = os.path.join(base, safe_sub, rg_name)
                os.makedirs(rg_dir, exist_ok=True)

                resources = rg_data.get('resources', [])
                if not resources:
                    continue

                # ── arm_template.json ─────────────────────────────────────────
                arm_resources: List[Dict] = []
                params_schema: Dict[str, Any] = {}
                params_values: Dict[str, Any] = {}

                for res in resources:
                    snippet = dict(res.get('arm_snippet', {}))
                    snippet['properties'] = _redact(snippet.get('properties', {}))
                    arm_resources.append(snippet)

                    for sk in res.get('sensitive_keys', []):
                        param_name = re.sub(r'[^A-Za-z0-9]', '_', sk)[-64:]
                        if param_name not in params_schema:
                            params_schema[param_name] = {
                                'type':     'securestring',
                                'metadata': {'description': f'Sensitive value for: {sk}'},
                            }
                            params_values[param_name] = {
                                'value': f'<REPLACE_WITH_{param_name.upper()}>'
                            }

                arm_template: Dict[str, Any] = {
                    '$schema': ('https://schema.management.azure.com/schemas/'
                                '2019-04-01/deploymentTemplate.json#'),
                    'contentVersion': '1.0.0.0',
                    'parameters': params_schema,
                    'variables':  {},
                    'resources':  arm_resources,
                    'outputs':    {},
                }
                self._write_json(os.path.join(rg_dir, 'arm_template.json'), arm_template)

                # ── parameters.json ───────────────────────────────────────────
                params_file: Dict[str, Any] = {
                    '$schema': ('https://schema.management.azure.com/schemas/'
                                '2019-04-01/deploymentParameters.json#'),
                    'contentVersion': '1.0.0.0',
                    'parameters': params_values,
                }
                self._write_json(os.path.join(rg_dir, 'parameters.json'), params_file)

                # ── resource_inventory.json ───────────────────────────────────
                self._write_json(os.path.join(rg_dir, 'resource_inventory.json'), rg_data)

                # ── deploy.ps1 ────────────────────────────────────────────────
                rg_loc  = rg_data.get('location', 'eastus')
                ps1_lines = [
                    f"# Deploy {rg_name} — generated by Azure Discovery Tool",
                    f"# Edit parameters.json with real secret values before running.",
                    "",
                    "param(",
                    f"    [string]$SubscriptionId   = '{sub_id}',",
                    f"    [string]$ResourceGroupName = '{rg_name}',",
                    f"    [string]$Location          = '{rg_loc}'",
                    ")",
                    "",
                    "Connect-AzAccount -Subscription $SubscriptionId",
                    "New-AzResourceGroup -Name $ResourceGroupName -Location $Location -Force",
                    "New-AzResourceGroupDeployment `",
                    "    -ResourceGroupName      $ResourceGroupName `",
                    "    -TemplateFile           .\\arm_template.json `",
                    "    -TemplateParameterFile  .\\parameters.json `",
                    "    -Verbose",
                ]
                with open(os.path.join(rg_dir, 'deploy.ps1'), 'w', encoding='utf-8') as fh:
                    fh.write('\n'.join(ps1_lines) + '\n')

                # ── deploy.sh ─────────────────────────────────────────────────
                sh_lines = [
                    "#!/bin/bash",
                    f"# Deploy {rg_name} — generated by Azure Discovery Tool",
                    f"# Edit parameters.json with real secret values before running.",
                    "",
                    f"SUBSCRIPTION_ID='{sub_id}'",
                    f"RESOURCE_GROUP='{rg_name}'",
                    f"LOCATION='{rg_loc}'",
                    "",
                    "az login",
                    'az account set --subscription "$SUBSCRIPTION_ID"',
                    'az group create --name "$RESOURCE_GROUP" --location "$LOCATION"',
                    "az deployment group create \\",
                    '  --resource-group "$RESOURCE_GROUP" \\',
                    "  --template-file  arm_template.json \\",
                    "  --parameters     @parameters.json",
                ]
                with open(os.path.join(rg_dir, 'deploy.sh'), 'w', encoding='utf-8') as fh:
                    fh.write('\n'.join(sh_lines) + '\n')

                pkg_count += 1

        self.logger.info(f"Deployment packages written for {pkg_count} resource group(s): {base}")
        return base

    def generate_full_inventory_html(self, full_inventory: Dict[str, Any]) -> str:
        """Generate a standalone HTML file with full resource properties.

        Features:
        - Search + subscription / type filter
        - Per-resource modal with 4 tabs:
          ARM Template | Full Properties | Redeploy Notes | Sensitive Params
        - Amber highlight for resources with sensitive parameters
        - CSV export button
        """
        self.logger.info("\n" + "=" * 80)
        self.logger.info("Generating Full Resource Inventory HTML")
        self.logger.info("=" * 80)

        out_file = os.path.join(
            self.config['output_dir'],
            f"resource_inventory_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        )

        rows_html   = ''
        modals_html = ''
        total_res   = 0
        total_sens  = 0
        sub_opts: Set[str]  = set()
        type_opts: Set[str] = set()
        team_opts: Set[str] = set()   # serviceTeam / service-team tag values

        import html as _html   # stdlib – escape untrusted data injected into HTML
        _he = _html.escape     # shorthand: _he(s) → HTML-safe string

        for sub_id, sub_data in full_inventory.items():
            sub_name = _he(str(sub_data.get('name', sub_id)))
            sub_opts.add(sub_name)
            for rg_name, rg_data in sub_data.get('resource_groups', {}).items():
                rg_name_h = _he(rg_name)
                for res in rg_data.get('resources', []):
                    total_res += 1
                    rid    = f"res_{total_res}"
                    rname  = _he(str(res.get('name',     '')))
                    rtype  = str(res.get('type',     ''))
                    rloc   = _he(str(res.get('location', '')))
                    sku_d  = res.get('sku') or {}
                    sku    = _he(str(sku_d.get('name', '') if isinstance(sku_d, dict) else ''))
                    notes  = res.get('redeploy_notes', [])
                    sens   = res.get('sensitive_keys',  [])
                    apiver = _he(str(res.get('api_version', '')))
                    rtype_h = _he(rtype)
                    type_opts.add(rtype_h)

                    has_sens   = bool(sens)
                    if has_sens:
                        total_sens += 1

                    # ── service team tag (serviceTeam | service-team | service_team) ──
                    raw_tags = res.get('tags') or {}
                    svc_team = ''
                    for _tk in raw_tags:
                        if _tk.lower() in ('serviceteam', 'service-team', 'service_team'):
                            svc_team = _he(str(raw_tags[_tk]))
                            break
                    if svc_team:
                        team_opts.add(svc_team)

                    row_cls    = 'sens-row' if has_sens else ''
                    sens_badge = ('<span class="badge badge-warn">SENSITIVE</span>'
                                  if has_sens else '')

                    arm_json  = json.dumps(res.get('arm_snippet', {}),
                                           indent=2, default=str)
                    full_json = json.dumps(res.get('properties', {}),
                                           indent=2, default=str)

                    # Escape < > in JSON so it renders safely in <pre>
                    arm_json  = arm_json.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
                    full_json = full_json.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')

                    notes_li  = ''.join(f'<li>{n}</li>' for n in notes) \
                                if notes else '<li>No specific notes.</li>'
                    sens_li   = ''.join(f'<li><code>{s}</code></li>' for s in sens) \
                                if sens else '<li>None detected.</li>'
                    warn_div  = (
                        '<div class="warn-box">This resource has sensitive parameters '
                        'that were NOT exported. Supply these values manually in '
                        'parameters.json before deploying.</div>'
                    ) if has_sens else ''

                    rows_html += (
                        f'<tr class="{row_cls}" data-sub="{sub_name}" '
                        f'data-type="{rtype_h}" data-team="{svc_team}" onclick="openModal(\'{rid}\')" '
                        f'style="cursor:pointer">'
                        f'<td>{sub_name}</td><td>{rg_name_h}</td><td>{rname}</td>'
                        f'<td>{rtype_h}</td><td>{rloc}</td><td>{sku}</td>'
                        f'<td>{apiver}</td>'
                        f'<td>{sens_badge}</td>'
                        f'</tr>\n'
                    )

                    modals_html += f"""<div id="{rid}" class="modal" onclick="if(event.target===this)closeModal('{rid}')">
  <div class="modal-box">
    <button class="modal-close" onclick="closeModal('{rid}')">&times;</button>
    <h2>{rname}</h2>
    <p style="color:#666;margin:0 0 12px">{rtype_h} &bull; {rloc} &bull; {sub_name} / {rg_name_h}</p>
    <div class="tabs">
      <button class="tab active" onclick="switchTab(this,'{rid}_arm')">ARM Template</button>
      <button class="tab" onclick="switchTab(this,'{rid}_props')">Full Properties</button>
      <button class="tab" onclick="switchTab(this,'{rid}_notes')">Redeploy Notes</button>
      <button class="tab" onclick="switchTab(this,'{rid}_sens')">Sensitive Params</button>
    </div>
    <div id="{rid}_arm" class="tab-panel active">
      <button class="copy-btn" onclick="copyText('{rid}_arm_code')">Copy</button>
      <pre id="{rid}_arm_code">{arm_json}</pre>
    </div>
    <div id="{rid}_props" class="tab-panel">
      <button class="copy-btn" onclick="copyText('{rid}_props_code')">Copy</button>
      <pre id="{rid}_props_code">{full_json}</pre>
    </div>
    <div id="{rid}_notes" class="tab-panel">
      <ul class="notes-list">{notes_li}</ul>
    </div>
    <div id="{rid}_sens" class="tab-panel">
      {warn_div}
      <ul class="notes-list">{sens_li}</ul>
    </div>
  </div>
</div>
"""

        ts_str       = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        sub_opts_html = (
            '<option value="">All Subscriptions</option>'
            + ''.join(f'<option>{s}</option>' for s in sorted(sub_opts))
        )
        type_opts_html = (
            '<option value="">All Types</option>'
            + ''.join(f'<option>{t}</option>' for t in sorted(type_opts))
        )
        team_opts_html = (
            '<option value="">All Service Teams</option>'
            + ''.join(f'<option>{t}</option>' for t in sorted(team_opts))
        )
        total_subs = len(full_inventory)

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Azure Full Resource Inventory</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:Segoe UI,Arial,sans-serif;background:#f0f4f8;color:#222}}
.header{{background:linear-gradient(135deg,#0078d4,#106ebe);color:#fff;padding:28px 36px}}
.header h1{{font-size:1.8rem;font-weight:700}}
.header p{{opacity:.85;margin-top:4px}}
.stat-bar{{display:flex;gap:16px;padding:20px 36px;background:#fff;border-bottom:1px solid #dde3ea;flex-wrap:wrap}}
.stat{{padding:12px 24px;border-radius:8px;background:#f7f9fc;border:1px solid #dde3ea;text-align:center}}
.stat .num{{font-size:2rem;font-weight:700;color:#0078d4}}
.stat .lbl{{font-size:.75rem;text-transform:uppercase;color:#666;letter-spacing:.04em}}
.stat.warn .num{{color:#d83b01}}
.controls{{padding:16px 36px;background:#fff;border-bottom:1px solid #dde3ea;display:flex;gap:12px;flex-wrap:wrap;align-items:center}}
.controls input,.controls select{{padding:8px 12px;border:1px solid #ccc;border-radius:6px;font-size:.9rem}}
.controls input{{width:280px}}
.btn-csv{{padding:8px 18px;background:#0078d4;color:#fff;border:none;border-radius:6px;cursor:pointer;font-size:.9rem}}
.btn-csv:hover{{background:#006cbe}}
.btn-group{{padding:8px 18px;background:#fff;color:#0078d4;border:1px solid #0078d4;border-radius:6px;cursor:pointer;font-size:.9rem}}
.btn-group.active{{background:#0078d4;color:#fff}}
.btn-group:hover{{background:#e5f1fb}}
.btn-group.active:hover{{background:#006cbe}}
.group-header{{background:#e5f1fb;font-weight:700;color:#0078d4;font-size:.82rem;text-transform:uppercase;letter-spacing:.06em;padding:8px 14px}}
.group-header td{{background:#e5f1fb!important}}
.table-wrap{{padding:24px 36px}}
table{{width:100%;border-collapse:collapse;background:#fff;border-radius:10px;overflow:hidden;box-shadow:0 2px 8px #0001}}
th{{background:#0078d4;color:#fff;padding:10px 14px;text-align:left;font-size:.82rem;text-transform:uppercase;letter-spacing:.04em}}
td{{padding:10px 14px;font-size:.88rem;border-bottom:1px solid #eef1f5}}
tr:hover td{{background:#e9f2fb}}
tr.sens-row td{{background:#fff4ce}}
tr.sens-row:hover td{{background:#ffe9a0}}
.badge{{padding:2px 8px;border-radius:12px;font-size:.72rem;font-weight:700;text-transform:uppercase}}
.badge-warn{{background:#d83b01;color:#fff}}
.modal{{display:none;position:fixed;inset:0;background:#0006;z-index:1000;overflow:auto;padding:40px 20px}}
.modal.open{{display:flex;align-items:flex-start;justify-content:center}}
.modal-box{{background:#fff;border-radius:12px;padding:28px;width:100%;max-width:920px;position:relative;max-height:90vh;overflow:auto}}
.modal-close{{position:absolute;top:14px;right:18px;background:none;border:none;font-size:1.6rem;cursor:pointer;color:#666}}
.tabs{{display:flex;gap:6px;margin:16px 0 0}}
.tab{{padding:8px 18px;border:1px solid #dde3ea;border-radius:6px 6px 0 0;background:#f7f9fc;cursor:pointer;font-size:.85rem}}
.tab.active{{background:#0078d4;color:#fff;border-color:#0078d4}}
.tab-panel{{display:none;border:1px solid #dde3ea;border-radius:0 6px 6px 6px;padding:16px;position:relative}}
.tab-panel.active{{display:block}}
pre{{background:#1e1e1e;color:#d4d4d4;padding:16px;border-radius:6px;overflow:auto;font-size:.8rem;max-height:420px;white-space:pre-wrap;word-wrap:break-word}}
.copy-btn{{position:absolute;top:24px;right:24px;padding:4px 12px;background:#0078d4;color:#fff;border:none;border-radius:4px;cursor:pointer;font-size:.78rem}}
.copy-btn:hover{{background:#006cbe}}
.notes-list{{padding-left:20px;line-height:1.7;margin-top:8px}}
.notes-list li{{margin-bottom:6px;font-size:.9rem}}
.notes-list code{{background:#f0f0f0;padding:1px 5px;border-radius:3px;font-size:.82rem}}
.warn-box{{background:#fff4ce;border:1px solid #f0e68c;border-radius:6px;padding:10px 14px;margin-bottom:12px;font-size:.88rem;color:#7a5a00}}
.hidden{{display:none!important}}
</style>
</head>
<body>
<div class="header">
  <h1>Azure Full Resource Inventory</h1>
  <p>Cross-tenant redeployment guide &mdash; Generated {ts_str}</p>
</div>
<div class="stat-bar">
  <div class="stat"><div class="num">{total_res}</div><div class="lbl">Total Resources</div></div>
  <div class="stat warn"><div class="num">{total_sens}</div><div class="lbl">With Sensitive Params</div></div>
  <div class="stat"><div class="num">{total_subs}</div><div class="lbl">Subscriptions</div></div>
</div>
<div class="controls">
  <input type="text" id="searchBox" placeholder="Search name, type, resource group..."
         oninput="filterTable()">
  <select id="subFilter" onchange="filterTable()">{sub_opts_html}</select>
  <select id="typeFilter" onchange="filterTable()">{type_opts_html}</select>
  <select id="teamFilter" onchange="filterTable()" title="Filter by serviceTeam / service-team tag">{team_opts_html}</select>
  <button class="btn-group" id="groupBtn" onclick="toggleGroupByTeam()">Group by Service Team</button>
  <button class="btn-csv" onclick="exportCSV()">Export CSV</button>
</div>
<div class="table-wrap">
  <table id="invTable">
    <thead><tr>
      <th>Subscription</th><th>Resource Group</th><th>Name</th>
      <th>Type</th><th>Location</th><th>SKU</th><th>API Version</th><th>Flags</th>
    </tr></thead>
    <tbody id="tableBody">
{rows_html}
    </tbody>
  </table>
</div>
{modals_html}
<script>
function openModal(id){{document.getElementById(id).classList.add('open');}}
function closeModal(id){{document.getElementById(id).classList.remove('open');}}
function switchTab(btn, panelId){{
  var box = btn.closest('.modal-box');
  box.querySelectorAll('.tab').forEach(function(t){{t.classList.remove('active');}});
  box.querySelectorAll('.tab-panel').forEach(function(p){{p.classList.remove('active');}});
  btn.classList.add('active');
  document.getElementById(panelId).classList.add('active');
}}
function copyText(id){{
  var el = document.getElementById(id);
  if (navigator.clipboard){{
    navigator.clipboard.writeText(el.textContent);
  }} else {{
    var r = document.createRange();
    r.selectNode(el);
    window.getSelection().removeAllRanges();
    window.getSelection().addRange(r);
    document.execCommand('copy');
  }}
}}
function filterTable(){{
  var q    = document.getElementById('searchBox').value.toLowerCase();
  var sub  = document.getElementById('subFilter').value;
  var typ  = document.getElementById('typeFilter').value;
  var team = document.getElementById('teamFilter').value;
  document.querySelectorAll('#tableBody tr:not(.group-header)').forEach(function(row){{
    var txt   = row.textContent.toLowerCase();
    var rSub  = row.getAttribute('data-sub')  || '';
    var rTyp  = row.getAttribute('data-type') || '';
    var rTeam = row.getAttribute('data-team') || '';
    var ok = (q === '' || txt.includes(q))
          && (sub  === '' || rSub  === sub)
          && (typ  === '' || rTyp  === typ)
          && (team === '' || rTeam === team);
    row.classList.toggle('hidden', !ok);
  }});
  // re-apply grouping headers if grouping is on
  if(_groupByTeam) _applyGroupHeaders();
}}
var _groupByTeam = false;
function toggleGroupByTeam(){{
  _groupByTeam = !_groupByTeam;
  var btn = document.getElementById('groupBtn');
  btn.classList.toggle('active', _groupByTeam);
  if(_groupByTeam){{
    _applyGroupHeaders();
  }} else {{
    _removeGroupHeaders();
  }}
}}
function _removeGroupHeaders(){{
  document.querySelectorAll('#tableBody tr.group-header').forEach(function(r){{r.remove();}});
}}
function _applyGroupHeaders(){{
  _removeGroupHeaders();
  var tbody = document.getElementById('tableBody');
  var rows  = Array.from(tbody.querySelectorAll('tr:not(.group-header):not(.hidden)'));
  // sort visible rows by team then by original order
  rows.forEach(function(r,i){{r._origIdx=i;}});
  rows.sort(function(a,b){{
    var ta=(a.getAttribute('data-team')||'').toLowerCase();
    var tb=(b.getAttribute('data-team')||'').toLowerCase();
    if(ta<tb) return -1; if(ta>tb) return 1; return a._origIdx-b._origIdx;
  }});
  var lastTeam = null;
  rows.forEach(function(row){{
    var t = row.getAttribute('data-team') || '';
    var teamLabel = t || '(no service team tag)';
    if(t !== lastTeam){{
      lastTeam = t;
      var hdr = document.createElement('tr');
      hdr.className='group-header';
      hdr.innerHTML='<td colspan="8">&#128101; Service Team: '+teamLabel+'</td>';
      tbody.insertBefore(hdr, row);
    }}
    tbody.appendChild(row);
  }});
}}
function exportCSV(){{
  var rows = [['Subscription','ResourceGroup','Name','Type','Location',
               'SKU','APIVersion','HasSensitive','ServiceTeam']];
  document.querySelectorAll('#tableBody tr:not(.hidden):not(.group-header)').forEach(function(row){{
    var cells = Array.from(row.querySelectorAll('td')).map(function(td){{
      return '"' + td.textContent.replace(/"/g, '""') + '"';
    }});
    cells.push('"' + (row.getAttribute('data-team')||'').replace(/"/g,'""') + '"');
    rows.push(cells);
  }});
  var csv = rows.map(function(r){{return r.join(',');}}).join('\\n');
  var a   = document.createElement('a');
  a.href  = 'data:text/csv;charset=utf-8,' + encodeURIComponent(csv);
  a.download = 'resource_inventory.csv';
  a.click();
}}
</script>
</body>
</html>"""

        with open(out_file, 'w', encoding='utf-8') as fh:
            fh.write(html)
        self.logger.info(f"Full inventory HTML generated: {out_file}")
        return out_file

    def generate_html_report(self):
        """Generate comprehensive HTML report"""
        self.logger.info("\n" + "="*80)
        self.logger.info("Generating HTML Report")
        self.logger.info("="*80)
        
        html_file = os.path.join(self.config['output_dir'], 
                                f"azure_discovery_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html")
        
        # Generate enhanced interactive HTML report
        html_content = self._generate_enhanced_html_content()
        
        with open(html_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        self.logger.info(f"\u2713 HTML report generated: {html_file}")

        # Also generate basic HTML for compatibility
        basic_html_file = os.path.join(self.config['output_dir'], 
                                f"azure_discovery_basic_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html")
        basic_html_content = self._generate_html_content()
        with open(basic_html_file, 'w', encoding='utf-8') as f:
            f.write(basic_html_content)
        
        return html_file
    
    def _generate_html_content(self):
        """Generate basic HTML content"""
        html = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Azure Discovery Report - Migration Planning</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }
        
        header {
            background: linear-gradient(135deg, #0078d4 0%, #00bcf2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        
        header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        
        .metadata {
            background: rgba(255,255,255,0.2);
            padding: 15px;
            border-radius: 5px;
            margin-top: 20px;
        }
        
        .metadata p {
            margin: 5px 0;
        }
        
        .dashboard {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .metric-card {
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            border-left: 4px solid #0078d4;
        }
        
        .metric-card h3 {
            color: #666;
            font-size: 0.9em;
            text-transform: uppercase;
            margin-bottom: 10px;
        }
        
        .metric-card .value {
            font-size: 2.5em;
            font-weight: bold;
            color: #0078d4;
        }
        
        .section {
            background: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        
        .section h2 {
            color: #0078d4;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #e0e0e0;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }
        
        table thead {
            background: #0078d4;
            color: white;
        }
        
        table th, table td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #e0e0e0;
        }
        
        table tbody tr:hover {
            background: #f5f5f5;
        }
        
        .tag {
            display: inline-block;
            background: #e0e0e0;
            padding: 3px 8px;
            border-radius: 3px;
            font-size: 0.85em;
            margin: 2px;
        }
        
        .dependency-graph {
            background: #fafafa;
            padding: 20px;
            border-radius: 5px;
            margin-top: 15px;
        }
        
        .dependency-item {
            background: white;
            padding: 15px;
            margin: 10px 0;
            border-left: 3px solid #00bcf2;
            border-radius: 3px;
        }
        
        .warning {
            background: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 15px;
            margin: 15px 0;
            border-radius: 3px;
        }
        
        .success {
            background: #d4edda;
            border-left: 4px solid #28a745;
            padding: 15px;
            margin: 15px 0;
            border-radius: 3px;
        }
        
        .info {
            background: #d1ecf1;
            border-left: 4px solid #17a2b8;
            padding: 15px;
            margin: 15px 0;
            border-radius: 3px;
        }
        
        .collapsible {
            cursor: pointer;
            padding: 10px;
            background: #f0f0f0;
            border: none;
            text-align: left;
            width: 100%;
            font-size: 1em;
            margin-top: 10px;
            border-radius: 5px;
        }
        
        .collapsible:hover {
            background: #e0e0e0;
        }
        
        .collapsible-content {
            display: none;
            padding: 15px;
            background: #fafafa;
            margin-bottom: 10px;
            border-radius: 5px;
        }
        
        .resource-type {
            font-weight: bold;
            color: #0078d4;
        }
        
        code {
            background: #f4f4f4;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
        }
        
        .network-diagram {
            background: white;
            padding: 20px;
            border: 1px solid #e0e0e0;
            border-radius: 5px;
            margin: 15px 0;
        }
        
        @media print {
            .collapsible-content {
                display: block !important;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔍 Azure Discovery Report</h1>
            <p style="font-size: 1.2em;">Migration Planning & Dependency Analysis</p>
            <div class="metadata">
                <p><strong>Discovery Date:</strong> """ + self.discovery_data['metadata']['discovery_date'] + """</p>
                <p><strong>Discovered By:</strong> """ + self.discovery_data['metadata']['discovery_by'] + """</p>
                <p><strong>Total Subscriptions:</strong> """ + str(len(self.discovery_data['subscriptions'])) + """</p>
            </div>
        </header>
        
        <div class="dashboard">
            <div class="metric-card">
                <h3>Total Resources</h3>
                <div class="value">""" + str(self.discovery_data['summary'].get('total_resources', 0)) + """</div>
            </div>
            <div class="metric-card">
                <h3>Virtual Networks</h3>
                <div class="value">""" + str(self.discovery_data['summary'].get('vnets', 0)) + """</div>
            </div>
            <div class="metric-card">
                <h3>App Services</h3>
                <div class="value">""" + str(self.discovery_data['summary'].get('app_services', 0)) + """</div>
            </div>
            <div class="metric-card">
                <h3>SQL Servers</h3>
                <div class="value">""" + str(self.discovery_data['summary'].get('sql_servers', 0)) + """</div>
            </div>
            <div class="metric-card">
                <h3>Storage Accounts</h3>
                <div class="value">""" + str(self.discovery_data['summary'].get('storage_accounts', 0)) + """</div>
            </div>
            <div class="metric-card">
                <h3>Virtual Machines</h3>
                <div class="value">""" + str(self.discovery_data['summary'].get('vms', 0)) + """</div>
            </div>
            <div class="metric-card">
                <h3>Dependencies</h3>
                <div class="value">""" + str(len(self.discovery_data.get('dependencies', []))) + """</div>
            </div>
            <div class="metric-card">
                <h3>Key Vaults</h3>
                <div class="value">""" + str(self.discovery_data['summary'].get('key_vaults', 0)) + """</div>
            </div>
        </div>
"""
        
        # Add subscriptions overview section
        html += """
        <div class="section">
            <h2>📋 Subscriptions Scanned</h2>
            <table>
                <thead>
                    <tr>
                        <th>Subscription Name</th>
                        <th>Subscription ID</th>
                        <th>Resource Groups</th>
                        <th>Total Resources</th>
                    </tr>
                </thead>
                <tbody>
"""
        for sub_id, sub_data in self.discovery_data['subscriptions'].items():
            html += f"""
                    <tr>
                        <td><strong>{sub_data['name']}</strong></td>
                        <td><code>{sub_id}</code></td>
                        <td>{len(sub_data.get('resource_groups', {}))}</td>
                        <td>{len(sub_data.get('resources', []))}</td>
                    </tr>
"""
        html += """
                </tbody>
            </table>
        </div>
"""
        
        # Add subscription details
        for sub_id, sub_data in self.discovery_data['subscriptions'].items():
            html += self._generate_subscription_html(sub_id, sub_data)

        # Add resource groups inventory section
        html += self._generate_resource_groups_html()

        # Add application dependencies section
        html += self._generate_application_dependencies_html()
        
        # Add ARM templates section
        html += self._generate_arm_templates_html()
        
        # Add visual service dependency diagrams
        html += self._generate_dependency_diagrams_html()
        
        # Add dependencies section
        html += self._generate_dependencies_html()
        
        # Add network topology section
        html += self._generate_network_topology_html()
        
        # Add code inventory section
        html += self._generate_code_inventory_html()
        
        # Footer
        html += """
    </div>
    
    <script>
        // Make sections collapsible
        document.querySelectorAll('.collapsible').forEach(button => {
            button.addEventListener('click', function() {
                this.classList.toggle('active');
                const content = this.nextElementSibling;
                if (content.style.display === 'block') {
                    content.style.display = 'none';
                } else {
                    content.style.display = 'block';
                }
            });
        });
    </script>
</body>
</html>
"""
        return html
    
    def _generate_resource_groups_html(self):
        """Generate a full Resource Group → Resources inventory section."""
        # Colour map: one stable colour per Azure resource type prefix (Microsoft.XXX)
        TYPE_COLOURS = {
            'microsoft.compute':          '#0078d4',
            'microsoft.web':              '#7719aa',
            'microsoft.sql':              '#d83b01',
            'microsoft.storage':          '#107c10',
            'microsoft.keyvault':         '#c19c00',
            'microsoft.network':          '#00b7c3',
            'microsoft.servicebus':       '#e81123',
            'microsoft.eventhub':         '#ff8c00',
            'microsoft.cosmosdb':         '#008272',
            'microsoft.cache':            '#498205',
            'microsoft.insights':         '#b4009e',
            'microsoft.containerservice': '#004e8c',
            'microsoft.containerregistry':'#004e8c',
            'microsoft.databricks':       '#0e7a0d',
            'microsoft.datafactory':      '#881798',
            'microsoft.cognitiveservices':'#038387',
            'microsoft.search':           '#004b1c',
            'microsoft.cdn':              '#004e8c',
            'microsoft.documentdb':       '#008272',
        }

        def rtype_colour(rtype: str) -> str:
            prefix = '/'.join(rtype.lower().split('/')[:1])
            for k, v in TYPE_COLOURS.items():
                if prefix.startswith(k):
                    return v
            return '#605e5c'

        def rtype_short(rtype: str) -> str:
            """Return last segment of resource type for a compact badge label."""
            parts = rtype.split('/')
            return parts[-1] if parts else rtype

        def tags_html(tags: dict) -> str:
            if not tags:
                return '<span style="color:#999;font-size:11px">—</span>'
            return ' '.join(
                f'<span style="background:#f0f0f0;border:1px solid #ccc;border-radius:3px;'
                f'padding:1px 5px;font-size:11px;color:#333">{k}={v}</span>'
                for k, v in list(tags.items())[:6]
            ) + (f' <span style="color:#999;font-size:11px">(+{len(tags)-6} more)</span>' if len(tags) > 6 else '')

        html = '''
        <div class="section" id="rg-inventory">
            <h2>&#128193; Resource Group Inventory</h2>
            <p>All resource groups discovered across subscriptions, with every resource listed under its group.
               Data reflects the live Azure Resource Manager output at discovery time.</p>
'''
        grand_rg_total   = 0
        grand_res_total  = 0
        empty_rgs        = []   # list of (subscription_name, rg_name, location, tags)

        for sub_id, sub_data in self.discovery_data['subscriptions'].items():
            rgs = sub_data.get('resource_groups', {})
            all_sub_res = sum(len(rg.get('resources', [])) for rg in rgs.values())
            grand_rg_total  += len(rgs)
            grand_res_total += all_sub_res
            for rg_name, rg_data in rgs.items():
                if not rg_data.get('resources'):
                    empty_rgs.append((sub_data['name'], rg_name,
                                      rg_data.get('location', 'N/A'),
                                      rg_data.get('tags', {})))

            html += f'''
            <button class="collapsible">
                &#128196; Subscription: {sub_data["name"]}
                &nbsp;<span style="font-weight:normal;font-size:13px">
                    ({len(rgs)} resource groups &middot; {all_sub_res} resources)
                </span>
            </button>
            <div class="collapsible-content">
'''

            if not rgs:
                html += '<div class="info">No resource groups found in this subscription.</div>'
            else:
                for rg_name, rg_data in sorted(rgs.items()):
                    resources = rg_data.get('resources', [])
                    # Count by type
                    type_counts: Dict[str, int] = defaultdict(int)
                    for r in resources:
                        type_counts[r.get('type', 'Unknown')] += 1

                    # Visual marker for empty RGs
                    if not resources:
                        rg_btn_style = ('margin-left:20px;background:#fff4ce;color:#7a4f01;'
                                        'border-left:4px solid #f7a800;font-size:13px')
                        rg_icon = '&#9888;&#65039;'
                        rg_extra = ' &nbsp;<span style="color:#c7720a;font-size:11px">EMPTY &mdash; no resources</span>'
                    else:
                        rg_btn_style = 'margin-left:20px;background:#f5f5f5;color:#333;font-size:13px'
                        rg_icon = '&#128200;'
                        rg_extra = ''

                    html += f'''
                <button class="collapsible" style="{rg_btn_style}">
                    {rg_icon} {rg_name}
                    &nbsp;<small>({rg_data.get("location","?")} &middot; {len(resources)} resource(s))</small>{rg_extra}
                </button>
                <div class="collapsible-content" style="margin-left:20px">
                    <div style="margin-bottom:8px">
                        <strong>Location:</strong> {rg_data.get("location","N/A")}&nbsp;&nbsp;
                        <strong>Tags:</strong> {tags_html(rg_data.get("tags",{}))}
                    </div>
                    <div style="margin-bottom:10px">
'''
                    for rtype, cnt in sorted(type_counts.items(), key=lambda x: -x[1]):
                        colour = rtype_colour(rtype)
                        html += (f'<span style="background:{colour};color:#fff;border-radius:4px;'
                                 f'padding:2px 8px;font-size:11px;margin:2px 4px 2px 0;display:inline-block">'
                                 f'{rtype_short(rtype)}&nbsp;({cnt})</span>')

                    html += '''
                    </div>
'''
                    if resources:
                        html += '''
                    <table>
                        <thead>
                            <tr>
                                <th>#</th>
                                <th>Resource Name</th>
                                <th>Type</th>
                                <th>Location</th>
                                <th>Tags</th>
                            </tr>
                        </thead>
                        <tbody>
'''
                        for idx, res in enumerate(sorted(resources, key=lambda x: (x.get('type',''), x.get('name',''))), start=1):
                            colour = rtype_colour(res.get('type', ''))
                            html += f'''
                            <tr>
                                <td style="color:#999;font-size:11px">{idx}</td>
                                <td><strong>{res.get("name","?")}</strong></td>
                                <td><span style="background:{colour};color:#fff;border-radius:4px;
                                    padding:2px 7px;font-size:11px">{res.get("type","?")}</span></td>
                                <td>{res.get("location","N/A")}</td>
                                <td>{tags_html(res.get("tags",{}))}</td>
                            </tr>
'''
                        html += '''
                        </tbody>
                    </table>
'''
                    else:
                        html += '<div class="info" style="margin:8px 0">No resources in this resource group.</div>'

                    html += '''
                </div>
'''
            html += '''
            </div>
'''

        # ── Empty Resource Groups warning block ─────────────────────────────────
        if empty_rgs:
            empty_rows = ''.join(
                f'<tr>'
                f'<td>{sub}</td>'
                f'<td><strong>{rg}</strong></td>'
                f'<td>{loc}</td>'
                f'<td>{tags_html(tags)}</td>'
                f'</tr>'
                for sub, rg, loc, tags in sorted(empty_rgs)
            )
            html += f'''
            <div style="margin-top:20px;padding:16px 20px;background:#fff4ce;
                        border-left:4px solid #f7a800;border-radius:6px">
                <h3 style="color:#7a4f01;margin-bottom:10px">
                    &#9888;&#65039; {len(empty_rgs)} Empty Resource Group(s) Detected
                </h3>
                <p style="color:#5c3b00;font-size:13px;margin-bottom:12px">
                    These resource groups contain no resources and may represent
                    unused infrastructure, orphaned deployments, or cost-incurring
                    placeholders. Review and delete if no longer needed.
                </p>
                <table>
                    <thead>
                        <tr>
                            <th>Subscription</th>
                            <th>Resource Group</th>
                            <th>Location</th>
                            <th>Tags</th>
                        </tr>
                    </thead>
                    <tbody>{empty_rows}</tbody>
                </table>
            </div>
'''

        empty_note = (
            f'&mdash; <span style="color:#c7720a"><strong>{len(empty_rgs)} empty</strong></span>'
            if empty_rgs else ''
        )
        html += f'''
            <div style="margin-top:16px;padding:12px 18px;background:#f0f6ff;
                        border-left:4px solid #0078d4;border-radius:4px;font-size:13px">
                <strong>Grand Total:</strong>&nbsp;
                {grand_rg_total} resource group(s) across all subscriptions,
                {grand_res_total} total resource(s)
                {empty_note}.
            </div>
        </div>
'''
        return html

    def generate_resource_groups_report(self):
        """Generate a self-contained standalone HTML report: Resource Groups + Resources."""
        self.logger.info("Generating Resource Group Inventory report...")
        ts   = datetime.now().strftime('%Y%m%d_%H%M%S')
        path = os.path.join(self.config['output_dir'],
                            f'resource_groups_inventory_{ts}.html')

        def rtype_colour(rtype: str) -> str:
            TYPE_COLOURS = {
                'microsoft.compute':          '#0078d4',
                'microsoft.web':              '#7719aa',
                'microsoft.sql':              '#d83b01',
                'microsoft.storage':          '#107c10',
                'microsoft.keyvault':         '#c19c00',
                'microsoft.network':          '#00b7c3',
                'microsoft.servicebus':       '#e81123',
                'microsoft.eventhub':         '#ff8c00',
                'microsoft.cosmosdb':         '#008272',
                'microsoft.cache':            '#498205',
                'microsoft.insights':         '#b4009e',
                'microsoft.containerservice': '#004e8c',
                'microsoft.containerregistry':'#004e8c',
                'microsoft.databricks':       '#0e7a0d',
                'microsoft.datafactory':      '#881798',
                'microsoft.cognitiveservices':'#038387',
                'microsoft.search':           '#004b1c',
                'microsoft.cdn':              '#004e8c',
                'microsoft.documentdb':       '#008272',
            }
            prefix = '/'.join(rtype.lower().split('/')[:1])
            for k, v in TYPE_COLOURS.items():
                if prefix.startswith(k):
                    return v
            return '#605e5c'

        # ── collect grand totals ────────────────────────────────────────
        grand_subs  = 0
        grand_rgs   = 0
        grand_res   = 0
        grand_empty = 0
        empty_rg_list = []   # (sub_name, rg_name, location, tags_str)
        all_types: Dict[str, int] = defaultdict(int)
        for sub_data in self.discovery_data['subscriptions'].values():
            grand_subs += 1
            for rg_name_k, rg_data in sub_data.get('resource_groups', {}).items():
                grand_rgs += 1
                res_list = rg_data.get('resources', [])
                if not res_list:
                    grand_empty += 1
                    empty_rg_list.append((
                        sub_data['name'], rg_name_k,
                        rg_data.get('location', 'N/A'),
                        '; '.join(f'{k}={v}' for k, v in (rg_data.get('tags') or {}).items())
                    ))
                for r in res_list:
                    grand_res += 1
                    all_types[r.get('type', 'Unknown')] += 1

        top_types_html = ''.join(
            f'<tr><td>{t}</td><td style="text-align:right">{c}</td></tr>'
            for t, c in sorted(all_types.items(), key=lambda x: -x[1])[:20]
        )

        # ── build body rows ─────────────────────────────────────────────
        body_rows = ''
        row_num = 0
        for sub_data in self.discovery_data['subscriptions'].values():
            sub_name = sub_data['name']
            for rg_name, rg_data in sorted(sub_data.get('resource_groups', {}).items()):
                rg_loc  = rg_data.get('location', 'N/A')
                rg_tags = '; '.join(f'{k}={v}' for k, v in (rg_data.get('tags') or {}).items())
                resources = rg_data.get('resources', [])
                if not resources:
                    row_num += 1
                    body_rows += f'''
                    <tr class="empty-rg-row" style="background:#fff4ce">
                        <td>{sub_name}</td>
                        <td><strong>{rg_name}</strong>
                            <span style="background:#f7a800;color:#fff;border-radius:3px;
                                padding:1px 6px;font-size:10px;margin-left:6px">EMPTY</span></td>
                        <td>{rg_loc}</td>
                        <td style="color:#7a4f01;font-style:italic">— no resources</td>
                        <td></td>
                        <td></td>
                        <td style="font-size:11px;color:#777">{rg_tags}</td>
                    </tr>'''
                else:
                    for res in sorted(resources, key=lambda x: (x.get('type',''), x.get('name',''))):
                        row_num += 1
                        stripe = '#fafafa' if row_num % 2 == 0 else '#fff'
                        colour = rtype_colour(res.get('type', ''))
                        res_tags = '; '.join(f'{k}={v}' for k, v in (res.get('tags') or {}).items())
                        body_rows += f'''
                    <tr style="background:{stripe}">
                        <td>{sub_name}</td>
                        <td><strong>{rg_name}</strong></td>
                        <td>{rg_loc}</td>
                        <td>{res.get("name","?")}</td>
                        <td><span style="background:{colour};color:#fff;border-radius:3px;padding:1px 7px;font-size:11px">{res.get("type","?")}</span></td>
                        <td>{res.get("location","N/A")}</td>
                        <td style="font-size:11px;color:#555">{res_tags}</td>
                    </tr>'''

        now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        empty_stat_cls = "warn" if grand_empty else "ok"
        empty_hdr_note = (
            f"&nbsp;|&nbsp; <strong style='color:#ffe284'>{grand_empty} empty RG(s)</strong>"
            if grand_empty else ""
        )

        # ── Empty RGs panel rows ───────────────────────────────────────────
        if empty_rg_list:
            empty_panel_rows = ''.join(
                f'<tr><td>{sub}</td><td><strong>{rg}</strong></td>'
                f'<td>{loc}</td><td style="font-size:11px;color:#555">{tags or "—"}</td></tr>'
                for sub, rg, loc, tags in sorted(empty_rg_list)
            )
            empty_panel = f'''
  <div class="panel" style="border-left:4px solid #f7a800">
    <h2 style="color:#7a4f01">&#9888;&#65039; Empty Resource Groups ({grand_empty})</h2>
    <p style="color:#5c3b00;font-size:12px;margin-bottom:12px">
      These resource groups contain <strong>no resources</strong>.
      They may represent unused infrastructure, orphaned deployments, or cost-incurring
      placeholders. Review and consider deleting them if no longer needed.
    </p>
    <table>
      <thead>
        <tr style="background:#f7a800">
          <th>Subscription</th><th>Resource Group</th><th>Location</th><th>Tags</th>
        </tr>
      </thead>
      <tbody>{empty_panel_rows}</tbody>
    </table>
  </div>'''
        else:
            empty_panel = '''
  <div class="panel" style="border-left:4px solid #107c10">
    <h2 style="color:#107c10">&#10003; No Empty Resource Groups</h2>
    <p style="color:#555;font-size:12px">All discovered resource groups contain at least one resource.</p>
  </div>'''

        html = f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Azure Resource Group Inventory</title>
<style>
  * {{ box-sizing:border-box; margin:0; padding:0; }}
  body {{ font-family:"Segoe UI",Arial,sans-serif; font-size:13px;
          background:#f4f6f9; color:#333; }}
  header {{ background:#0078d4; color:#fff; padding:20px 32px; }}
  header h1 {{ font-size:22px; font-weight:600; }}
  header p  {{ font-size:12px; opacity:.85; margin-top:4px; }}
  .container {{ max-width:1400px; margin:0 auto; padding:24px 32px; }}
  .stat-bar {{ display:flex; gap:16px; flex-wrap:wrap; margin-bottom:24px; }}
  .stat {{ background:#fff; border-radius:8px; border-left:4px solid #0078d4;
           padding:12px 20px; min-width:160px; box-shadow:0 1px 3px rgba(0,0,0,.08); }}
  .stat.warn {{ border-left-color:#f7a800; }}
  .stat.warn .num {{ color:#c7720a; }}
  .stat.ok   {{ border-left-color:#107c10; }}
  .stat.ok   .num {{ color:#107c10; }}
  .stat .num {{ font-size:26px; font-weight:700; color:#0078d4; }}
  .stat .lbl {{ font-size:11px; color:#777; text-transform:uppercase; letter-spacing:.5px; }}
  .panel {{ background:#fff; border-radius:8px; padding:20px 24px;
            margin-bottom:24px; box-shadow:0 1px 3px rgba(0,0,0,.08); }}
  .panel h2 {{ font-size:15px; font-weight:600; margin-bottom:14px;
               border-bottom:1px solid #eee; padding-bottom:8px; }}
  table {{ width:100%; border-collapse:collapse; font-size:12px; }}
  th {{ background:#0078d4; color:#fff; padding:8px 10px; text-align:left; font-weight:600; }}
  td {{ padding:6px 10px; border-bottom:1px solid #f0f0f0; vertical-align:top; }}
  tr:hover td {{ background:#e8f3ff !important; }}
  .empty-rg-row td {{ background:#fff4ce !important; }}
  .filter-bar {{ display:flex; gap:10px; margin-bottom:14px; flex-wrap:wrap; }}
  .filter-bar input {{ padding:6px 10px; border:1px solid #ccc; border-radius:5px;
      font-size:12px; outline:none; flex:1; min-width:200px; }}
  .filter-bar input:focus {{ border-color:#0078d4; }}
  .filter-bar label {{ display:flex; align-items:center; gap:6px; font-size:12px; cursor:pointer; }}
  #rowCount {{ font-size:12px; color:#666; align-self:center; margin-left:auto; }}
  footer {{ text-align:center; color:#aaa; font-size:11px; padding:20px; }}
</style>
</head>
<body>
<header>
  <h1>&#128193; Azure Resource Group Inventory</h1>
  <p>Generated: {now_str} &nbsp;|&nbsp;
     {grand_subs} subscription(s) &nbsp;|&nbsp;
     {grand_rgs} resource group(s) &nbsp;|&nbsp;
     {grand_res} resource(s)
     {empty_hdr_note}</p>
</header>
<div class="container">

  <!-- Stat bar -->
  <div class="stat-bar">
    <div class="stat"><div class="num">{grand_subs}</div><div class="lbl">Subscriptions</div></div>
    <div class="stat"><div class="num">{grand_rgs}</div><div class="lbl">Resource Groups</div></div>
    <div class="stat"><div class="num">{grand_res}</div><div class="lbl">Total Resources</div></div>
    <div class="stat"><div class="num">{len(all_types)}</div><div class="lbl">Distinct Types</div></div>
    <div class="stat {empty_stat_cls}"><div class="num">{grand_empty}</div><div class="lbl">Empty RGs</div></div>
  </div>

  {empty_panel}

  <!-- Top types panel -->
  <div class="panel">
    <h2>Top Resource Types</h2>
    <table style="width:auto;min-width:340px">
      <thead><tr><th>Resource Type</th><th>Count</th></tr></thead>
      <tbody>{top_types_html}</tbody>
    </table>
  </div>

  <!-- Full inventory table -->
  <div class="panel">
    <h2>Full Inventory</h2>
    <div class="filter-bar">
      <input id="search" placeholder="&#128269; Filter by name, type, RG...">
      <label><input type="checkbox" id="showEmpty" checked> Show empty RGs</label>
      <span id="rowCount"></span>
    </div>
    <table id="invTable">
      <thead>
        <tr>
          <th>Subscription</th>
          <th>Resource Group</th>
          <th>RG Location</th>
          <th>Resource Name</th>
          <th>Resource Type</th>
          <th>Resource Location</th>
          <th>Tags</th>
        </tr>
      </thead>
      <tbody id="invBody">
        {body_rows}
      </tbody>
    </table>
  </div>

</div>
<footer>Azure Discovery Tool &mdash; Resource Group Inventory &mdash; {now_str}</footer>
<script>
(function(){{
  var rows   = Array.from(document.querySelectorAll('#invBody tr'));
  var countEl = document.getElementById('rowCount');
  function updateCount(n) {{ countEl.textContent = n + ' / ' + rows.length + ' rows'; }}
  updateCount(rows.length);
  function applyFilter() {{
    var q         = document.getElementById('search').value.toLowerCase();
    var showEmpty = document.getElementById('showEmpty').checked;
    var shown = 0;
    rows.forEach(function(r){{
      var isEmpty = r.classList.contains('empty-rg-row');
      var txt     = r.textContent.toLowerCase();
      var vis = (!q || txt.includes(q)) && (showEmpty || !isEmpty);
      r.style.display = vis ? '' : 'none';
      if(vis) shown++;
    }});
    updateCount(shown);
  }}
  document.getElementById('search').addEventListener('input', applyFilter);
  document.getElementById('showEmpty').addEventListener('change', applyFilter);
  applyFilter();
}})();
</script>
</body>
</html>'''

        with open(path, 'w', encoding='utf-8') as f:
            f.write(html)
        self.logger.info(f'  Resource Group report: {path}')
        return path

    def _generate_subscription_html(self, sub_id, sub_data):
        """Generate HTML for subscription details"""
        html = f"""
        <div class="section">
            <h2>📁 Subscription: {sub_data['name']}</h2>
            <p><code>{sub_id}</code></p>
            
            <div class="info">
                <strong>Summary:</strong> {len(sub_data['resource_groups'])} Resource Groups, 
                {len(sub_data['resources'])} Total Resources
            </div>
"""
        
        # Networks
        if sub_data['networks']:
            html += """
            <button class="collapsible">🌐 Virtual Networks (""" + str(len(sub_data['networks'])) + """)</button>
            <div class="collapsible-content">
                <table>
                    <thead>
                        <tr>
                            <th>Name</th>
                            <th>Location</th>
                            <th>Address Space</th>
                            <th>Subnets</th>
                            <th>Peerings</th>
                        </tr>
                    </thead>
                    <tbody>
"""
            for vnet in sub_data['networks']:
                html += f"""
                        <tr>
                            <td><strong>{vnet['name']}</strong></td>
                            <td>{vnet['location']}</td>
                            <td>{', '.join(vnet['address_space'])}</td>
                            <td>{len(vnet['subnets'])}</td>
                            <td>{len(vnet['peerings'])}</td>
                        </tr>
"""
            html += """
                    </tbody>
                </table>
            </div>
"""
        
        # App Services
        if sub_data['app_services']:
            html += """
            <button class="collapsible">🌐 App Services (""" + str(len(sub_data['app_services'])) + """)</button>
            <div class="collapsible-content">
                <table>
                    <thead>
                        <tr>
                            <th>Name</th>
                            <th>Location</th>
                            <th>State</th>
                            <th>HTTPS Only</th>
                            <th>External Dependencies</th>
                            <th>Connection Strings</th>
                        </tr>
                    </thead>
                    <tbody>
"""
            for app in sub_data['app_services']:
                html += f"""
                        <tr>
                            <td><strong>{app['name']}</strong></td>
                            <td>{app['location']}</td>
                            <td>{app['state']}</td>
                            <td>{'✓' if app['https_only'] else '✗'}</td>
                            <td>{len(app['external_dependencies'])}</td>
                            <td>{len(app['connection_strings'])}</td>
                        </tr>
"""
            html += """
                    </tbody>
                </table>
            </div>
"""
        
        # SQL Servers
        if sub_data['sql_servers']:
            html += """
            <button class="collapsible">🗄️ SQL Servers (""" + str(len(sub_data['sql_servers'])) + """)</button>
            <div class="collapsible-content">
                <table>
                    <thead>
                        <tr>
                            <th>Server Name</th>
                            <th>Location</th>
                            <th>Version</th>
                            <th>Databases</th>
                            <th>Firewall Rules</th>
                        </tr>
                    </thead>
                    <tbody>
"""
            for server in sub_data['sql_servers']:
                html += f"""
                        <tr>
                            <td><strong>{server['name']}</strong></td>
                            <td>{server['location']}</td>
                            <td>{server['version']}</td>
                            <td>{len(server['databases'])}</td>
                            <td>{len(server['firewall_rules'])}</td>
                        </tr>
"""
            html += """
                    </tbody>
                </table>
            </div>
"""
        
        # Storage Accounts
        if sub_data['storage_accounts']:
            html += """
            <button class="collapsible">💾 Storage Accounts (""" + str(len(sub_data['storage_accounts'])) + """)</button>
            <div class="collapsible-content">
                <table>
                    <thead>
                        <tr>
                            <th>Name</th>
                            <th>Location</th>
                            <th>SKU</th>
                            <th>Kind</th>
                            <th>HTTPS Only</th>
                        </tr>
                    </thead>
                    <tbody>
"""
            for sa in sub_data['storage_accounts']:
                html += f"""
                        <tr>
                            <td><strong>{sa['name']}</strong></td>
                            <td>{sa['location']}</td>
                            <td>{sa['sku']}</td>
                            <td>{sa['kind']}</td>
                            <td>{'✓' if sa['https_only'] else '✗'}</td>
                        </tr>
"""
            html += """
                    </tbody>
                </table>
            </div>
"""
        
        html += "</div>"
        return html
    
    def _generate_dependency_diagrams_html(self):
        """Generate visual dependency diagrams for App Services/Functions and VMs.

        Shows only connections involving:
          SQL, App Services, Service Bus, Functions, Traffic Manager,
          Application Gateway, Load Balancer, SMTP, FTP, VMs,
          Automation Accounts, NSG, Resource Group
        """

        # ── Color / label map keyed by source_type / target_type strings ──────
        TYPE_META = {
            # source_type strings produced by analyze_dependencies()
            'Azure Function':           ('#e67e22', '⚡', 'Function App'),
            'App Service':              ('#3498db', '🌐', 'App Service'),
            'Virtual Machine':          ('#e74c3c', '🖥️',  'Virtual Machine'),
            # target_type strings
            'SQL Database':             ('#e74c3c', '🗄️',  'SQL Database'),
            'SQL Server':               ('#e74c3c', '🗄️',  'SQL Server'),
            'Service Bus':              ('#9b59b6', '📨', 'Service Bus'),
            'Event Hub':                ('#8e44ad', '📡', 'Event Hub'),
            'Traffic Manager':          ('#1abc9c', '🔀', 'Traffic Manager'),
            'Application Gateway':      ('#f39c12', '🛡️',  'App Gateway'),
            'Load Balancer':            ('#2ecc71', '⚖️',  'Load Balancer'),
            'SMTP':                     ('#16a085', '📧', 'SMTP'),
            'FTP':                      ('#2980b9', '📁', 'FTP'),
            'Automation Account':       ('#95a5a6', '⚙️',  'Automation'),
            'Network Security Group':   ('#d35400', '🔒', 'NSG'),
            'Virtual Network':          ('#27ae60', '🔷', 'VNet'),
            'Storage Account':          ('#f1c40f', '💾', 'Storage'),
            'Key Vault':                ('#6c3483', '🔑', 'Key Vault'),
            'Cosmos DB':                ('#1a5276', '🌍', 'Cosmos DB'),
            'Redis Cache':              ('#c0392b', '⚡', 'Redis'),
            'Application Insights':     ('#117a65', '📊', 'App Insights'),
            'Resource Group':           ('#7f8c8d', '📂', 'Resource Group'),
            'External API':             ('#bdc3c7', '🌍', 'External API'),
            'Container Registry':       ('#2471a3', '📦', 'ACR'),
            'AKS Cluster':              ('#1f618d', '☸️',  'AKS'),
        }

        ALLOWED_TARGETS = {
            'SQL Database', 'SQL Server', 'Service Bus', 'Event Hub',
            'Traffic Manager', 'Application Gateway', 'Load Balancer',
            'SMTP', 'FTP', 'Virtual Machine', 'Automation Account',
            'Network Security Group', 'Resource Group',
            'Storage Account', 'Key Vault', 'Cosmos DB', 'Redis Cache',
            'Application Insights', 'Virtual Network',
        }

        def meta(t):
            return TYPE_META.get(t, ('#aaaaaa', '●', t))

        all_deps = self.discovery_data.get('dependencies', [])

        # Split deps into the two diagrams
        app_deps = [d for d in all_deps
                    if d['source_type'] in ('App Service', 'Azure Function')
                    and d['target_type'] in ALLOWED_TARGETS]

        vm_deps  = [d for d in all_deps
                    if d['source_type'] == 'Virtual Machine'
                    and d['target_type'] in ALLOWED_TARGETS]

        def build_diagram_html(title, icon, deps, diagram_id):
            if not deps:
                return f'''
        <div class="dep-section">
            <h3>{icon} {title}</h3>
            <div class="dd-nodata">
                ⚠ No dependencies discovered for {title}.<br>
                Ensure App Settings / Connection Strings reference Azure service endpoints.
            </div>
        </div>'''

            # Collect unique nodes
            nodes_map = {}   # name → meta
            for d in deps:
                sc, si, sl = meta(d['source_type'])
                tc, ti, tl = meta(d['target_type'])
                nodes_map[d['source']] = (sc, si, sl)
                nodes_map[d['target']] = (tc, ti, tl)

            # Build node list with positions
            node_list = list(nodes_map.items())   # [(name, (color,icon,label))]
            n = len(node_list)
            cols = max(1, min(6, n))

            nodes_js_parts = []
            for i, (name, (color, ico, lbl)) in enumerate(node_list):
                safe_name = name.replace('"', '\\"')
                safe_lbl  = lbl.replace('"', '\\"')
                col_pos   = i % cols
                row_pos   = i // cols
                x = 30 + col_pos * 185
                y = 30 + row_pos * 110
                nodes_js_parts.append(
                    f'{{id:"{safe_name}",label:"{safe_lbl}",color:"{color}",'
                    f'x:{x},y:{y}}}'
                )
            nodes_js = '[' + ','.join(nodes_js_parts) + ']'

            edges_js_parts = []
            for d in deps:
                _, _, dep_lbl = meta(d['dependency_type']) if d['dependency_type'] in TYPE_META else ('#888', '', d['dependency_type'])
                safe_src = d['source'].replace('"', '\\"')
                safe_tgt = d['target'].replace('"', '\\"')
                safe_dep = d['dependency_type'].replace('"', '\\"')
                tc, _, _ = meta(d['target_type'])
                edges_js_parts.append(
                    f'{{s:"{safe_src}",t:"{safe_tgt}",dep:"{safe_dep}",color:"{tc}"}}'
                )
            edges_js = '[' + ','.join(edges_js_parts) + ']'

            # Table rows
            table_rows = ''
            for d in deps:
                sc, si, _ = meta(d['source_type'])
                tc, ti, _ = meta(d['target_type'])
                table_rows += (
                    f'<tr>'
                    f'<td><span class="dd-badge" style="background:{sc}">{si} {d["source_type"]}</span>'
                    f'<br><strong>{d["source"]}</strong></td>'
                    f'<td class="dd-arrow">→</td>'
                    f'<td><span class="dd-badge" style="background:{tc}">{ti} {d["target_type"]}</span>'
                    f'<br><strong>{d["target"]}</strong></td>'
                    f'<td><small>{d["dependency_type"]}</small></td>'
                    f'</tr>'
                )

            rows_high = max(2, (n // cols) + 1)
            canvas_h  = rows_high * 110 + 60

            return f'''
        <div class="dep-section">
            <h3>{icon} {title} <span class="dd-count">{len(deps)} connections</span></h3>

            <div class="dd-canvas-wrap">
                <canvas id="{diagram_id}" style="width:100%;height:{canvas_h}px"></canvas>
            </div>

            <h4 style="margin:18px 0 8px;color:#2c3e50">📋 Connection Table</h4>
            <table class="dd-table">
                <thead>
                    <tr><th>Source Resource</th><th></th><th>Target Resource</th><th>Connection Type</th></tr>
                </thead>
                <tbody>{table_rows}</tbody>
            </table>
        </div>

        <script>
        (function(){{
            var NODES = {nodes_js};
            var EDGES = {edges_js};
            var canvas = document.getElementById('{diagram_id}');
            if (!canvas) return;

            // Scale canvas for retina
            var dpr = window.devicePixelRatio || 1;
            var rect = canvas.getBoundingClientRect();
            var W = canvas.parentElement.offsetWidth - 20 || 1060;
            var H = {canvas_h};
            canvas.width  = W * dpr;
            canvas.height = H * dpr;
            canvas.style.width  = W + 'px';
            canvas.style.height = H + 'px';
            var ctx = canvas.getContext('2d');
            ctx.scale(dpr, dpr);

            // Re-calculate positions to fill full width
            var cols = Math.ceil(Math.sqrt(NODES.length));
            var spacX = Math.max(160, (W - 30) / (cols + 0.5));
            var spacY = 110;
            NODES.forEach(function(n, i){{
                n.x = 20 + (i % cols) * spacX;
                n.y = 30 + Math.floor(i / cols) * spacY;
            }});
            var nmap = {{}};
            NODES.forEach(function(n){{ nmap[n.id] = n; }});

            // Draw edges first
            EDGES.forEach(function(e){{
                var s = nmap[e.s], t = nmap[e.t];
                if (!s || !t) return;
                var sx = s.x + 90, sy = s.y + 22;
                var tx = t.x + 90, ty = t.y + 22;
                ctx.beginPath();
                ctx.moveTo(sx, sy);
                // Slight curve
                var mx = (sx + tx) / 2, my = (sy + ty) / 2 - 20;
                ctx.quadraticCurveTo(mx, my, tx, ty);
                ctx.strokeStyle = e.color + '88';
                ctx.lineWidth = 1.8;
                ctx.stroke();
                // Arrowhead
                var ang = Math.atan2(ty - my, tx - mx);
                ctx.beginPath();
                ctx.moveTo(tx, ty);
                ctx.lineTo(tx - 10*Math.cos(ang-0.35), ty - 10*Math.sin(ang-0.35));
                ctx.lineTo(tx - 10*Math.cos(ang+0.35), ty - 10*Math.sin(ang+0.35));
                ctx.closePath();
                ctx.fillStyle = e.color;
                ctx.fill();
                // Label on edge
                ctx.fillStyle = '#666';
                ctx.font = '9px Arial';
                ctx.textAlign = 'center';
                ctx.fillText(e.dep, mx, my - 4);
            }});

            // Draw nodes
            NODES.forEach(function(n){{
                var bw = 180, bh = 44, br = 8;
                // Shadow
                ctx.shadowColor = 'rgba(0,0,0,0.15)';
                ctx.shadowBlur  = 6;
                ctx.shadowOffsetY = 3;
                // Box
                ctx.beginPath();
                ctx.roundRect(n.x, n.y, bw, bh, br);
                ctx.fillStyle = n.color;
                ctx.fill();
                ctx.shadowBlur = 0; ctx.shadowOffsetY = 0;
                // Top label (type)
                ctx.fillStyle = 'rgba(255,255,255,0.85)';
                ctx.font = 'bold 10px Arial';
                ctx.textAlign = 'center';
                ctx.fillText(n.label, n.x + bw/2, n.y + 14);
                // Bottom label (name, truncated)
                var nm = n.id.length > 22 ? n.id.substring(0,20) + '..' : n.id;
                ctx.fillStyle = '#fff';
                ctx.font = '9px Arial';
                ctx.fillText(nm, n.x + bw/2, n.y + 30);
            }});
        }})();
        </script>'''

        # ── Legend ──────────────────────────────────────────────────────────────
        legend_items = [
            ('#e74c3c', 'SQL / VM'),
            ('#3498db', 'App Service'),
            ('#e67e22', 'Function App'),
            ('#9b59b6', 'Service Bus'),
            ('#1abc9c', 'Traffic Manager'),
            ('#f39c12', 'App Gateway'),
            ('#2ecc71', 'Load Balancer'),
            ('#95a5a6', 'Automation Account'),
            ('#d35400', 'NSG'),
            ('#7f8c8d', 'Resource Group'),
            ('#6c3483', 'Key Vault'),
            ('#f1c40f', 'Storage'),
            ('#117a65', 'App Insights'),
            ('#1a5276', 'Cosmos DB'),
            ('#c0392b', 'Redis'),
        ]
        legend_html = '<div class="dd-legend">' + ''.join(
            f'<span class="dd-legend-item">'
            f'<span class="dd-dot" style="background:{c}"></span>{lbl}'
            f'</span>'
            for c, lbl in legend_items
        ) + '</div>'

        css = '''
        <style>
        .dd-section-wrap { margin:0 0 30px 0; }
        .dep-section {
            background:#fff; border-radius:12px; padding:22px 24px;
            margin-bottom:28px; box-shadow:0 2px 10px rgba(0,0,0,0.08);
        }
        .dep-section h3 {
            color:#2c3e50; border-bottom:3px solid #3498db;
            padding-bottom:10px; margin-bottom:16px; font-size:16px;
        }
        .dd-count {
            background:#ecf0f1; color:#7f8c8d; font-size:12px;
            padding:2px 10px; border-radius:12px; margin-left:8px;
        }
        .dd-canvas-wrap {
            background:#f8f9fa; border-radius:8px; padding:10px;
            overflow-x:auto; min-height:80px;
        }
        .dd-table {
            width:100%; border-collapse:collapse; font-size:12px; margin-top:6px;
        }
        .dd-table th {
            background:#2c3e50; color:#fff; padding:9px 12px; text-align:left;
        }
        .dd-table td { padding:7px 12px; border-bottom:1px solid #eee; vertical-align:middle; }
        .dd-table tr:hover { background:#f0f4ff; }
        .dd-badge {
            display:inline-block; padding:2px 8px; border-radius:10px;
            color:#fff; font-size:10px; margin-bottom:3px;
        }
        .dd-arrow { font-size:20px; color:#3498db; font-weight:bold; text-align:center; }
        .dd-legend {
            display:flex; flex-wrap:wrap; gap:10px;
            padding:12px 16px; background:#f8f9fa; border-radius:8px;
            margin-bottom:20px;
        }
        .dd-legend-item { display:flex; align-items:center; gap:6px; font-size:11px; color:#555; }
        .dd-dot { width:13px; height:13px; border-radius:50%; display:inline-block; flex-shrink:0; }
        .dd-nodata {
            padding:18px 20px; background:#fff3cd; border-radius:8px;
            color:#856404; font-size:13px; line-height:1.6;
        }
        </style>'''

        app_section = build_diagram_html(
            'App Services &amp; Functions → Dependencies', '🌐', app_deps, 'ddAppCanvas'
        )
        vm_section = build_diagram_html(
            'Virtual Machines → Dependencies', '🖥️', vm_deps, 'ddVmCanvas'
        )

        return f'''
        <div class="section dd-section-wrap">
            <h2>📊 Service Dependency Diagrams</h2>
            <p style="color:#666;margin-bottom:16px">
                Visual map of connections between Azure resources.
                Scoped to: SQL, App Services, Service Bus, Functions, Traffic Manager,
                App Gateway, Load Balancer, SMTP, FTP, VMs, Automation Accounts, NSG, Resource Group.
            </p>
            {css}
            {legend_html}
            {app_section}
            {vm_section}
        </div>'''

    def _generate_dependencies_html(self):
        """Generate HTML for dependencies"""
        html = """
        <div class="section">
            <h2>🔗 Dependencies & Relationships</h2>
            <p>Discovered dependencies between resources and external services</p>
"""
        
        if self.discovery_data.get('dependencies'):
            html += '<div class="dependency-graph">'
            for dep in self.discovery_data['dependencies']:
                html += f"""
                <div class="dependency-item">
                    <strong class="resource-type">{dep['source']}</strong> ({dep['source_type']})
                    <span style="color: #666;"> → </span>
                    <strong class="resource-type">{dep.get('target', 'Unknown')}</strong> ({dep['target_type']})
                    <br>
                    <small style="color: #666;">Type: {dep['dependency_type']}</small>
                </div>
"""
            html += '</div>'
        else:
            html += '<div class="info">No dependencies discovered</div>'
        
        html += "</div>"
        return html
    
    def _generate_network_topology_html(self):
        """Generate HTML for network topology"""
        html = """
        <div class="section">
            <h2>🌐 Network Topology</h2>
"""
        
        has_networks = False
        for sub_id, sub_data in self.discovery_data['subscriptions'].items():
            if sub_data['networks']:
                has_networks = True
                html += f"""
                <div class="network-diagram">
                    <h3>{sub_data['name']}</h3>
"""
                for vnet in sub_data['networks']:
                    html += f"""
                    <div style="margin: 15px 0; padding: 15px; background: #f9f9f9; border-left: 4px solid #0078d4;">
                        <strong>{vnet['name']}</strong> ({', '.join(vnet['address_space'])})
                        <ul style="margin-top: 10px;">
"""
                    for subnet in vnet['subnets']:
                        html += f"""
                            <li>
                                <strong>Subnet:</strong> {subnet['name']} ({subnet['address_prefix']})
                                {' - NSG: ' + subnet['nsg'].split('/')[-1] if subnet['nsg'] else ''}
                            </li>
"""
                    html += """
                        </ul>
                    </div>
"""
                html += "</div>"
        
        if not has_networks:
            html += '<div class="info">No virtual networks discovered</div>'
        
        html += "</div>"
        return html
    
    def _generate_application_dependencies_html(self):
        """Generate HTML for application-centric dependencies"""
        html = f"""
        <div class="section">
            <h2>🎯 Application-Centric Dependency Map</h2>
            <p>Complete mapping of applications and their dependencies on Azure services, databases, and external APIs</p>
            
            <div class="info">
                This section shows dependencies from the <strong>application perspective</strong>, helping you understand
                what each application needs to function properly.
            </div>
"""
        
        if self.discovery_data.get('application_dependencies'):
            # Group by application
            app_deps = defaultdict(list)
            for dep in self.discovery_data['application_dependencies']:
                app_deps[dep['application']].append(dep)
            
            for app_name, deps in app_deps.items():
                # Count by category
                category_counts = defaultdict(int)
                for dep in deps:
                    category_counts[dep['category']] += 1
                
                html += f"""
            <button class="collapsible">📱 {app_name} ({len(deps)} dependencies)</button>
            <div class="collapsible-content">
                <div style="background: white; padding: 15px; border-radius: 5px; margin-bottom: 15px;">
                    <strong>Dependency Breakdown:</strong>
"""
                for category, count in category_counts.items():
                    html += f"<span class='tag'>{category}: {count}</span>"
                
                html += """
                </div>
                <table>
                    <thead>
                        <tr>
                            <th>Dependency</th>
                            <th>Type</th>
                            <th>Category</th>
                            <th>Source</th>
                        </tr>
                    </thead>
                    <tbody>
"""
                for dep in deps:
                    html += f"""
                        <tr>
                            <td><strong>{dep['dependency_name']}</strong></td>
                            <td>{dep['dependency_type']}</td>
                            <td><span class='tag'>{dep['category']}</span></td>
                            <td><small>{dep['source']}</small></td>
                        </tr>
"""
                html += """
                    </tbody>
                </table>
            </div>
"""
        else:
            html += '<div class="warning">No application dependencies analyzed. Make sure Git repositories are configured.</div>'
        
        html += "</div>"
        return html
    
    def _generate_arm_templates_html(self):
        """Generate HTML for ARM template analysis"""
        html = """
        <div class="section">
            <h2>📋 ARM Template Analysis (Infrastructure as Code)</h2>
            <p>Azure Resource Manager templates found in code repositories</p>
"""
        
        if self.discovery_data.get('arm_templates'):
            html += f'<div class="success">Found {len(self.discovery_data["arm_templates"])} ARM template(s)</div>'
            
            for template in self.discovery_data['arm_templates']:
                html += f"""
            <button class="collapsible">📄 {template['file']} ({len(template['resources'])} resources)</button>
            <div class="collapsible-content">
                <p><strong>Schema:</strong> <code>{template['schema']}</code></p>
                <p><strong>Version:</strong> {template['content_version']}</p>
                <p><strong>Parameters:</strong> {len(template['parameters'])}</p>
                <p><strong>Resource Types:</strong></p>
                <div style="margin: 10px 0;">
"""
                for rt in template['resource_types']:
                    html += f"<span class='tag'>{rt}</span>"
                
                html += """
                </div>
                <table>
                    <thead>
                        <tr>
                            <th>Resource Name</th>
                            <th>Type</th>
                            <th>Location</th>
                            <th>API Version</th>
                        </tr>
                    </thead>
                    <tbody>
"""
                for resource in template['resources']:
                    html += f"""
                        <tr>
                            <td><strong>{resource['name']}</strong></td>
                            <td>{resource['type']}</td>
                            <td>{resource.get('location', 'N/A')}</td>
                            <td><small>{resource['api_version']}</small></td>
                        </tr>
"""
                html += """
                    </tbody>
                </table>
            </div>
"""
        else:
            html += '<div class="info">No ARM templates found. Make sure Git repositories are configured.</div>'
        
        html += "</div>"
        return html
    
    def _generate_code_inventory_html(self):
        """Generate HTML for code inventory"""
        html = """
        <div class="section">
            <h2>💻 Code Inventory & Analysis</h2>
            <p>Summary of scanned source code repositories</p>
"""
        
        if self.discovery_data.get('code_inventory'):
            html += """
            <table>
                <thead>
                    <tr>
                        <th>Repository</th>
                        <th>Files Scanned</th>
                        <th>Lines of Code</th>
                        <th>Dependencies Found</th>
                        <th>Azure Resources Referenced</th>
                    </tr>
                </thead>
                <tbody>
"""
            for repo_name, inventory in self.discovery_data['code_inventory'].items():
                html += f"""
                    <tr>
                        <td><strong>{repo_name}</strong></td>
                        <td>{inventory['files']:,}</td>
                        <td>{inventory['lines']:,}</td>
                        <td>{inventory['dependencies']}</td>
                        <td>{inventory['azure_resources']}</td>
                    </tr>
"""
            html += """
                </tbody>
            </table>
"""
            
            # Detailed breakdown per application
            for app_name, app_data in self.discovery_data['applications'].items():
                if app_data.get('nuget_packages'):
                    html += f"""
            <button class="collapsible">📦 {app_name} - NuGet Packages ({len(app_data['nuget_packages'])})</button>
            <div class="collapsible-content">
                <table>
                    <thead>
                        <tr>
                            <th>Package Name</th>
                            <th>Version</th>
                            <th>Source File</th>
                        </tr>
                    </thead>
                    <tbody>
"""
                    for pkg in app_data['nuget_packages'][:50]:  # Limit to 50
                        html += f"""
                        <tr>
                            <td>{pkg['name']}</td>
                            <td>{pkg['version']}</td>
                            <td><small>{pkg['source']}</small></td>
                        </tr>
"""
                    html += """
                    </tbody>
                </table>
            </div>
"""
        else:
            html += '<div class="info">No code repositories scanned.</div>'
        
        html += "</div>"
        return html
    
    def _generate_enhanced_html_content(self):
        """Generate modern, interactive HTML content with tabs - BUILT-IN VERSION"""
        self.logger.info("Generating enhanced interactive HTML report...")
        
        # Use the basic HTML generator for now - it's comprehensive and works well
        # Future enhancement: Add more interactive features here
        return self._generate_html_content()
    
    def generate_excel_report(self):
        """Generate Excel report"""
        self.logger.info("\n" + "="*80)
        self.logger.info("Generating Excel Report")
        self.logger.info("="*80)
        
        excel_file = os.path.join(self.config['output_dir'], 
                                 f"azure_discovery_inventory_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx")
        
        wb = openpyxl.Workbook()
        
        # Remove default sheet
        wb.remove(wb.active)
        
        # Create sheets
        self._create_summary_sheet(wb)
        self._create_resource_groups_sheet(wb)
        self._create_empty_rgs_sheet(wb)
        self._create_resource_properties_sheet(wb)
        self._create_application_dependencies_sheet(wb)
        self._create_arm_templates_sheet(wb)
        self._create_code_inventory_sheet(wb)
        self._create_networks_sheet(wb)
        self._create_app_services_sheet(wb)
        self._create_databases_sheet(wb)
        self._create_storage_sheet(wb)
        self._create_vms_sheet(wb)
        self._create_paas_services_sheet(wb)
        self._create_dependencies_sheet(wb)
        
        # Save workbook
        wb.save(excel_file)
        self.logger.info(f"✓ Excel report generated: {excel_file}")
        return excel_file
    
    def _create_resource_groups_sheet(self, wb):
        """Create a Resource Group → Resources inventory sheet."""
        ws = wb.create_sheet("Resource Groups")

        headers = [
            "Subscription", "Resource Group", "RG Location", "RG Tags",
            "Resource Name", "Resource Type", "Resource Location", "Resource Tags"
        ]
        HDR_FILL  = PatternFill(start_color="0078D4", end_color="0078D4", fill_type="solid")
        HDR_FONT  = Font(bold=True, color="FFFFFF", size=11)
        ALT_FILLS = [
            PatternFill(start_color="FFFFFF", end_color="FFFFFF", fill_type="solid"),
            PatternFill(start_color="F0F6FF", end_color="F0F6FF", fill_type="solid"),
        ]
        RG_HEADER_FILL = PatternFill(start_color="DEECF9", end_color="DEECF9", fill_type="solid")
        RG_FONT        = Font(bold=True, size=11, color="004578")
        EMPTY_FILL     = PatternFill(start_color="FFF4CE", end_color="FFF4CE", fill_type="solid")
        EMPTY_FONT     = Font(italic=True, color="7A4F01")
        WRAP           = Alignment(wrap_text=True, vertical="top")
        THIN_BORDER    = Border(
            bottom=Side(style='thin', color='D0D0D0'),
            right=Side(style='thin', color='D0D0D0')
        )

        # ── Header row ───────────────────────────────────────────────────
        for col_idx, hdr in enumerate(headers, 1):
            cell = ws.cell(row=1, column=col_idx, value=hdr)
            cell.font   = HDR_FONT
            cell.fill   = HDR_FILL
            cell.alignment = Alignment(horizontal="center", vertical="center")
        ws.freeze_panes = 'A2'
        ws.row_dimensions[1].height = 18

        row = 2
        rg_colour_idx = 0  # alternates per RG for visual grouping

        for sub_data in self.discovery_data['subscriptions'].values():
            sub_name = sub_data['name']
            for rg_name, rg_data in sorted(sub_data.get('resource_groups', {}).items()):
                rg_loc  = rg_data.get('location', 'N/A')
                rg_tags = '; '.join(f'{k}={v}' for k, v in (rg_data.get('tags') or {}).items())
                resources = sorted(
                    rg_data.get('resources', []),
                    key=lambda x: (x.get('type', ''), x.get('name', ''))
                )

                rg_colour_idx += 1
                alt_fill = ALT_FILLS[rg_colour_idx % 2]

                if not resources:
                    # Empty RG — one placeholder row
                    vals = [sub_name, rg_name, rg_loc, rg_tags,
                            '(empty — no resources)', '', '', '']
                    for col_idx, val in enumerate(vals, 1):
                        cell = ws.cell(row=row, column=col_idx, value=val)
                        cell.fill      = EMPTY_FILL
                        cell.alignment = WRAP
                        cell.border    = THIN_BORDER
                        cell.font      = EMPTY_FONT
                    row += 1
                else:
                    for res_data in resources:
                        res_tags = '; '.join(
                            f'{k}={v}' for k, v in (res_data.get('tags') or {}).items()
                        )
                        vals = [
                            sub_name,
                            rg_name,
                            rg_loc,
                            rg_tags,
                            res_data.get('name', ''),
                            res_data.get('type', ''),
                            res_data.get('location', 'N/A'),
                            res_tags,
                        ]
                        for col_idx, val in enumerate(vals, 1):
                            cell = ws.cell(row=row, column=col_idx, value=val)
                            cell.fill      = alt_fill
                            cell.alignment = WRAP
                            cell.border    = THIN_BORDER
                            if col_idx == 2:  # RG name bold
                                cell.font = Font(bold=True)
                            elif col_idx == 5:  # Resource name
                                cell.font = Font(bold=False)
                        row += 1

        # ── Column widths ────────────────────────────────────────────────
        col_widths = [28, 30, 18, 40, 36, 50, 18, 50]
        for col_idx, width in enumerate(col_widths, 1):
            ws.column_dimensions[get_column_letter(col_idx)].width = width

        # ── Auto-filter ──────────────────────────────────────────────────
        ws.auto_filter.ref = f"A1:{get_column_letter(len(headers))}{row - 1}"

    def _create_empty_rgs_sheet(self, wb):
        """Create a dedicated sheet listing only empty resource groups."""
        ws = wb.create_sheet("Empty Resource Groups")

        HDR_FILL = PatternFill(start_color="F7A800", end_color="F7A800", fill_type="solid")
        HDR_FONT = Font(bold=True, color="FFFFFF", size=11)
        ROW_FILL = PatternFill(start_color="FFF4CE", end_color="FFF4CE", fill_type="solid")
        ALT_FILL = PatternFill(start_color="FEE9A0", end_color="FEE9A0", fill_type="solid")
        WRAP     = Alignment(wrap_text=True, vertical="top")
        THIN     = Border(
            bottom=Side(style='thin', color='E0C060'),
            right=Side(style='thin',  color='E0C060')
        )

        headers = ["Subscription", "Resource Group", "Location", "Tags",
                   "Recommendation"]
        for col_idx, hdr in enumerate(headers, 1):
            cell = ws.cell(row=1, column=col_idx, value=hdr)
            cell.font      = HDR_FONT
            cell.fill      = HDR_FILL
            cell.alignment = Alignment(horizontal="center", vertical="center")
        ws.freeze_panes = 'A2'
        ws.row_dimensions[1].height = 18

        row      = 2
        row_idx  = 0
        found    = False
        for sub_data in self.discovery_data['subscriptions'].values():
            sub_name = sub_data['name']
            for rg_name, rg_data in sorted(sub_data.get('resource_groups', {}).items()):
                if rg_data.get('resources'):
                    continue  # skip non-empty
                found = True
                row_idx += 1
                fill = ROW_FILL if row_idx % 2 == 1 else ALT_FILL
                rg_loc  = rg_data.get('location', 'N/A')
                rg_tags = '; '.join(
                    f'{k}={v}' for k, v in (rg_data.get('tags') or {}).items()
                )
                vals = [
                    sub_name,
                    rg_name,
                    rg_loc,
                    rg_tags or '—',
                    'Review and delete if no longer needed to avoid orphaned costs',
                ]
                for col_idx, val in enumerate(vals, 1):
                    cell = ws.cell(row=row, column=col_idx, value=val)
                    cell.fill      = fill
                    cell.alignment = WRAP
                    cell.border    = THIN
                    if col_idx == 2:
                        cell.font = Font(bold=True, color="7A4F01")
                row += 1

        if not found:
            cell = ws.cell(row=2, column=1,
                           value="✅ No empty resource groups found — all RGs contain at least one resource.")
            cell.font = Font(italic=True, color="107C10")

        col_widths = [30, 36, 18, 50, 56]
        for col_idx, width in enumerate(col_widths, 1):
            ws.column_dimensions[get_column_letter(col_idx)].width = width

        if row > 2:
            ws.auto_filter.ref = f"A1:{get_column_letter(len(headers))}{row - 1}"

    def _create_resource_properties_sheet(self, wb: Any) -> None:
        """Create an Excel sheet with full ARM properties for every discovered resource.

        Columns:
          Subscription | Resource Group | Name | Type | Location |
          SKU Name | SKU Tier | Kind | Zones | Tags | API Version |
          Sensitive Params | Redeploy Notes | ARM Template JSON (capped 3 000 chars)

        Rows with sensitive parameters are highlighted in amber.
        """
        full_inventory: Dict[str, Any] = getattr(self, '_full_inventory', {})
        if not full_inventory:
            return  # export_resource_properties() was not called — skip silently

        ws = wb.create_sheet("Resource Properties")

        HDR_FILL  = PatternFill(start_color="0078D4", end_color="0078D4", fill_type="solid")
        HDR_FONT  = Font(bold=True, color="FFFFFF", size=11)
        SENS_FILL = PatternFill(start_color="FFF4CE", end_color="FFF4CE", fill_type="solid")
        SENS_FONT = Font(color="7A4F01", italic=True)
        WRAP      = Alignment(wrap_text=True, vertical="top")
        THIN      = Border(
            bottom=Side(style='thin', color='DDEBF7'),
            right=Side(style='thin',  color='DDEBF7'),
        )

        headers = [
            "Subscription", "Resource Group", "Name", "Type", "Location",
            "SKU Name", "SKU Tier", "Kind", "Zones", "Tags",
            "API Version", "Sensitive Params", "Redeploy Notes",
            "ARM Template JSON",
        ]
        col_widths = [26, 28, 30, 46, 18, 16, 16, 16, 14, 40, 20, 40, 50, 60]

        for col_idx, hdr in enumerate(headers, 1):
            cell = ws.cell(row=1, column=col_idx, value=hdr)
            cell.font      = HDR_FONT
            cell.fill      = HDR_FILL
            cell.alignment = Alignment(horizontal="center", vertical="center")

        ws.freeze_panes = 'A2'
        ws.row_dimensions[1].height = 20

        data_row = 2
        for sub_id, sub_data in full_inventory.items():
            sub_name = sub_data.get('name', sub_id)
            for rg_name, rg_data in sub_data.get('resource_groups', {}).items():
                for res in rg_data.get('resources', []):
                    rname   = res.get('name',     '')
                    rtype   = res.get('type',     '')
                    rloc    = res.get('location', '')
                    apiver  = res.get('api_version', '')
                    sku     = res.get('sku') or {}
                    sku_name = sku.get('name', '') if isinstance(sku, dict) else ''
                    sku_tier = sku.get('tier', '') if isinstance(sku, dict) else ''
                    kind    = res.get('kind', '') or ''
                    zones   = ', '.join(res.get('zones') or [])
                    tags    = '; '.join(
                        f'{k}={v}' for k, v in (res.get('tags') or {}).items()
                    )
                    sens    = res.get('sensitive_keys', [])
                    notes   = res.get('redeploy_notes',  [])
                    arm_raw = json.dumps(res.get('arm_snippet', {}),
                                         indent=2, default=str)
                    # Cap ARM JSON at 3 000 chars to stay within Excel cell limit
                    arm_str = arm_raw[:3000] + (' ... [truncated]' if len(arm_raw) > 3000 else '')

                    has_sens = bool(sens)
                    row_vals = [
                        sub_name,
                        rg_name,
                        rname,
                        rtype,
                        rloc,
                        sku_name,
                        sku_tier,
                        kind,
                        zones,
                        tags or '—',
                        apiver,
                        '\n'.join(sens)  if sens  else '—',
                        '\n'.join(notes) if notes else '—',
                        arm_str,
                    ]
                    for col_idx, val in enumerate(row_vals, 1):
                        cell = ws.cell(row=data_row, column=col_idx, value=val)
                        cell.alignment = WRAP
                        cell.border    = THIN
                        if has_sens:
                            cell.fill = SENS_FILL
                            cell.font = SENS_FONT

                    data_row += 1

        if data_row > 2:
            ws.auto_filter.ref = (
                f"A1:{get_column_letter(len(headers))}{data_row - 1}"
            )

        for col_idx, width in enumerate(col_widths, 1):
            ws.column_dimensions[get_column_letter(col_idx)].width = width

    def _create_summary_sheet(self, wb):
        """Create summary sheet in Excel"""
        ws = wb.create_sheet("Summary", 0)
        
        # Header
        ws['A1'] = "Azure Discovery Summary"
        ws['A1'].font = Font(size=16, bold=True, color="FFFFFF")
        ws['A1'].fill = PatternFill(start_color="0078D4", end_color="0078D4", fill_type="solid")
        ws.merge_cells('A1:D1')
        
        # Metadata
        row = 3
        ws[f'A{row}'] = "Discovery Date:"
        ws[f'B{row}'] = self.discovery_data['metadata']['discovery_date']
        row += 1
        ws[f'A{row}'] = "Discovered By:"
        ws[f'B{row}'] = self.discovery_data['metadata']['discovery_by']
        row += 2
        
        # Resource counts
        ws[f'A{row}'] = "Resource Type"
        ws[f'B{row}'] = "Count"
        ws[f'A{row}'].font = Font(bold=True)
        ws[f'B{row}'].font = Font(bold=True)
        row += 1
        
        for resource_type, count in self.discovery_data['summary'].items():
            ws[f'A{row}'] = resource_type.replace('_', ' ').title()
            ws[f'B{row}'] = count
            row += 1
        
        # Adjust column widths
        ws.column_dimensions['A'].width = 30
        ws.column_dimensions['B'].width = 15
    
    def _create_networks_sheet(self, wb):
        """Create networks sheet in Excel"""
        ws = wb.create_sheet("Networks")
        
        headers = ["Subscription", "VNet Name", "Resource Group", "Location", 
                  "Address Space", "Subnets", "Peerings"]
        
        for col, header in enumerate(headers, 1):
            cell = ws.cell(row=1, column=col, value=header)
            cell.font = Font(bold=True, color="FFFFFF")
            cell.fill = PatternFill(start_color="0078D4", end_color="0078D4", fill_type="solid")
        
        row = 2
        for sub_id, sub_data in self.discovery_data['subscriptions'].items():
            for vnet in sub_data.get('networks', []):
                ws.cell(row=row, column=1, value=sub_data['name'])
                ws.cell(row=row, column=2, value=vnet['name'])
                ws.cell(row=row, column=3, value=vnet['resource_group'])
                ws.cell(row=row, column=4, value=vnet['location'])
                ws.cell(row=row, column=5, value=', '.join(vnet['address_space']))
                ws.cell(row=row, column=6, value=len(vnet['subnets']))
                ws.cell(row=row, column=7, value=len(vnet['peerings']))
                row += 1
        
        # Adjust column widths
        for col in range(1, len(headers) + 1):
            ws.column_dimensions[get_column_letter(col)].width = 20
    
    def _create_app_services_sheet(self, wb):
        """Create app services sheet in Excel"""
        ws = wb.create_sheet("App Services")
        
        headers = ["Subscription", "App Name", "Resource Group", "Location", "State", 
                  "HTTPS Only", "Default Host", "External Dependencies", "Connection Strings"]
        
        for col, header in enumerate(headers, 1):
            cell = ws.cell(row=1, column=col, value=header)
            cell.font = Font(bold=True, color="FFFFFF")
            cell.fill = PatternFill(start_color="0078D4", end_color="0078D4", fill_type="solid")
        
        row = 2
        for sub_id, sub_data in self.discovery_data['subscriptions'].items():
            for app in sub_data.get('app_services', []):
                ws.cell(row=row, column=1, value=sub_data['name'])
                ws.cell(row=row, column=2, value=app['name'])
                ws.cell(row=row, column=3, value=app['resource_group'])
                ws.cell(row=row, column=4, value=app['location'])
                ws.cell(row=row, column=5, value=app['state'])
                ws.cell(row=row, column=6, value='Yes' if app['https_only'] else 'No')
                ws.cell(row=row, column=7, value=app['default_host_name'])
                ws.cell(row=row, column=8, value=len(app['external_dependencies']))
                ws.cell(row=row, column=9, value=len(app['connection_strings']))
                row += 1
        
        for col in range(1, len(headers) + 1):
            ws.column_dimensions[get_column_letter(col)].width = 20
    
    def _create_databases_sheet(self, wb):
        """Create databases sheet in Excel"""
        ws = wb.create_sheet("Databases")
        
        headers = ["Subscription", "Server Name", "Resource Group", "Location", 
                  "Version", "Admin Login", "Databases", "Firewall Rules"]
        
        for col, header in enumerate(headers, 1):
            cell = ws.cell(row=1, column=col, value=header)
            cell.font = Font(bold=True, color="FFFFFF")
            cell.fill = PatternFill(start_color="0078D4", end_color="0078D4", fill_type="solid")
        
        row = 2
        for sub_id, sub_data in self.discovery_data['subscriptions'].items():
            for server in sub_data.get('sql_servers', []):
                ws.cell(row=row, column=1, value=sub_data['name'])
                ws.cell(row=row, column=2, value=server['name'])
                ws.cell(row=row, column=3, value=server['resource_group'])
                ws.cell(row=row, column=4, value=server['location'])
                ws.cell(row=row, column=5, value=server['version'])
                ws.cell(row=row, column=6, value=server['admin_login'])
                ws.cell(row=row, column=7, value=len(server['databases']))
                ws.cell(row=row, column=8, value=len(server['firewall_rules']))
                row += 1
        
        for col in range(1, len(headers) + 1):
            ws.column_dimensions[get_column_letter(col)].width = 20
    
    def _create_storage_sheet(self, wb):
        """Create storage accounts sheet in Excel"""
        ws = wb.create_sheet("Storage")
        
        headers = ["Subscription", "Storage Account", "Resource Group", "Location", 
                  "SKU", "Kind", "HTTPS Only", "Access Tier"]
        
        for col, header in enumerate(headers, 1):
            cell = ws.cell(row=1, column=col, value=header)
            cell.font = Font(bold=True, color="FFFFFF")
            cell.fill = PatternFill(start_color="0078D4", end_color="0078D4", fill_type="solid")
        
        row = 2
        for sub_id, sub_data in self.discovery_data['subscriptions'].items():
            for sa in sub_data.get('storage_accounts', []):
                ws.cell(row=row, column=1, value=sub_data['name'])
                ws.cell(row=row, column=2, value=sa['name'])
                ws.cell(row=row, column=3, value=sa['resource_group'])
                ws.cell(row=row, column=4, value=sa['location'])
                ws.cell(row=row, column=5, value=sa['sku'])
                ws.cell(row=row, column=6, value=sa['kind'])
                ws.cell(row=row, column=7, value='Yes' if sa['https_only'] else 'No')
                ws.cell(row=row, column=8, value=sa.get('access_tier', 'N/A'))
                row += 1
        
        for col in range(1, len(headers) + 1):
            ws.column_dimensions[get_column_letter(col)].width = 20
    
    def _create_vms_sheet(self, wb):
        """Create virtual machines sheet in Excel"""
        ws = wb.create_sheet("Virtual Machines")
        
        headers = ["Subscription", "VM Name", "Resource Group", "Location", 
                  "Size", "OS Type", "Data Disks"]
        
        for col, header in enumerate(headers, 1):
            cell = ws.cell(row=1, column=col, value=header)
            cell.font = Font(bold=True, color="FFFFFF")
            cell.fill = PatternFill(start_color="0078D4", end_color="0078D4", fill_type="solid")
        
        row = 2
        for sub_id, sub_data in self.discovery_data['subscriptions'].items():
            for vm in sub_data.get('virtual_machines', []):
                ws.cell(row=row, column=1, value=sub_data['name'])
                ws.cell(row=row, column=2, value=vm['name'])
                ws.cell(row=row, column=3, value=vm['resource_group'])
                ws.cell(row=row, column=4, value=vm['location'])
                ws.cell(row=row, column=5, value=vm.get('vm_size', 'N/A'))
                ws.cell(row=row, column=6, value=vm.get('os_type', 'N/A'))
                ws.cell(row=row, column=7, value=len(vm.get('data_disks', [])))
                row += 1
        
        for col in range(1, len(headers) + 1):
            ws.column_dimensions[get_column_letter(col)].width = 20
    
    def _create_paas_services_sheet(self, wb):
        """Create PaaS services sheet in Excel"""
        ws = wb.create_sheet("PaaS Services")
        
        headers = ["Subscription", "Service Type", "Name", "Resource Group", "Location"]
        
        for col, header in enumerate(headers, 1):
            cell = ws.cell(row=1, column=col, value=header)
            cell.font = Font(bold=True, color="FFFFFF")
            cell.fill = PatternFill(start_color="0078D4", end_color="0078D4", fill_type="solid")
        
        row = 2
        for sub_id, sub_data in self.discovery_data['subscriptions'].items():
            # Key Vaults
            for kv in sub_data.get('key_vaults', []):
                ws.cell(row=row, column=1, value=sub_data['name'])
                ws.cell(row=row, column=2, value="Key Vault")
                ws.cell(row=row, column=3, value=kv['name'])
                ws.cell(row=row, column=4, value=kv['resource_group'])
                ws.cell(row=row, column=5, value=kv['location'])
                row += 1
            
            # Cosmos DB
            for cosmos in sub_data.get('cosmos_db', []):
                ws.cell(row=row, column=1, value=sub_data['name'])
                ws.cell(row=row, column=2, value="Cosmos DB")
                ws.cell(row=row, column=3, value=cosmos['name'])
                ws.cell(row=row, column=4, value=cosmos['resource_group'])
                ws.cell(row=row, column=5, value=cosmos['location'])
                row += 1
            
            # Redis Cache
            for redis in sub_data.get('redis_cache', []):
                ws.cell(row=row, column=1, value=sub_data['name'])
                ws.cell(row=row, column=2, value="Redis Cache")
                ws.cell(row=row, column=3, value=redis['name'])
                ws.cell(row=row, column=4, value=redis['resource_group'])
                ws.cell(row=row, column=5, value=redis['location'])
                row += 1
            
            # Service Bus
            for sb in sub_data.get('service_bus', []):
                ws.cell(row=row, column=1, value=sub_data['name'])
                ws.cell(row=row, column=2, value="Service Bus")
                ws.cell(row=row, column=3, value=sb['name'])
                ws.cell(row=row, column=4, value=sb['resource_group'])
                ws.cell(row=row, column=5, value=sb['location'])
                row += 1
            
            # Event Hubs
            for eh in sub_data.get('event_hubs', []):
                ws.cell(row=row, column=1, value=sub_data['name'])
                ws.cell(row=row, column=2, value="Event Hub")
                ws.cell(row=row, column=3, value=eh['name'])
                ws.cell(row=row, column=4, value=eh['resource_group'])
                ws.cell(row=row, column=5, value=eh['location'])
                row += 1
            
            # Application Insights
            for ai in sub_data.get('app_insights', []):
                ws.cell(row=row, column=1, value=sub_data['name'])
                ws.cell(row=row, column=2, value="Application Insights")
                ws.cell(row=row, column=3, value=ai['name'])
                ws.cell(row=row, column=4, value=ai['resource_group'])
                ws.cell(row=row, column=5, value=ai['location'])
                row += 1
            
            # Container Registries
            for acr in sub_data.get('container_registries', []):
                ws.cell(row=row, column=1, value=sub_data['name'])
                ws.cell(row=row, column=2, value="Container Registry")
                ws.cell(row=row, column=3, value=acr['name'])
                ws.cell(row=row, column=4, value=acr['resource_group'])
                ws.cell(row=row, column=5, value=acr['location'])
                row += 1
            
            # AKS Clusters
            for aks in sub_data.get('aks_clusters', []):
                ws.cell(row=row, column=1, value=sub_data['name'])
                ws.cell(row=row, column=2, value="AKS Cluster")
                ws.cell(row=row, column=3, value=aks['name'])
                ws.cell(row=row, column=4, value=aks['resource_group'])
                ws.cell(row=row, column=5, value=aks['location'])
                row += 1
            
            # DNS Zones
            for dns in sub_data.get('dns_zones', []):
                ws.cell(row=row, column=1, value=sub_data['name'])
                ws.cell(row=row, column=2, value="DNS Zone")
                ws.cell(row=row, column=3, value=dns['name'])
                ws.cell(row=row, column=4, value=dns['resource_group'])
                ws.cell(row=row, column=5, value=dns.get('location', 'global'))
                row += 1
            
            # Traffic Manager
            for tm in sub_data.get('traffic_managers', []):
                ws.cell(row=row, column=1, value=sub_data['name'])
                ws.cell(row=row, column=2, value="Traffic Manager")
                ws.cell(row=row, column=3, value=tm['name'])
                ws.cell(row=row, column=4, value=tm['resource_group'])
                ws.cell(row=row, column=5, value=tm.get('location', 'global'))
                row += 1
            
            # CDN
            for cdn in sub_data.get('cdns', []):
                ws.cell(row=row, column=1, value=sub_data['name'])
                ws.cell(row=row, column=2, value="CDN Profile")
                ws.cell(row=row, column=3, value=cdn['name'])
                ws.cell(row=row, column=4, value=cdn['resource_group'])
                ws.cell(row=row, column=5, value=cdn['location'])
                row += 1
            
            # Front Door
            for fd in sub_data.get('frontdoors', []):
                ws.cell(row=row, column=1, value=sub_data['name'])
                ws.cell(row=row, column=2, value="Front Door")
                ws.cell(row=row, column=3, value=fd['name'])
                ws.cell(row=row, column=4, value=fd['resource_group'])
                ws.cell(row=row, column=5, value=fd.get('location', 'global'))
                row += 1
            
            # Cognitive Services
            for cog in sub_data.get('cognitive_services', []):
                ws.cell(row=row, column=1, value=sub_data['name'])
                ws.cell(row=row, column=2, value="Cognitive Services")
                ws.cell(row=row, column=3, value=cog['name'])
                ws.cell(row=row, column=4, value=cog['resource_group'])
                ws.cell(row=row, column=5, value=cog['location'])
                row += 1
            
            # Search Services
            for search in sub_data.get('search_services', []):
                ws.cell(row=row, column=1, value=sub_data['name'])
                ws.cell(row=row, column=2, value="Search Service")
                ws.cell(row=row, column=3, value=search['name'])
                ws.cell(row=row, column=4, value=search['resource_group'])
                ws.cell(row=row, column=5, value=search['location'])
                row += 1
            
            # Data Factory
            for df in sub_data.get('data_factories', []):
                ws.cell(row=row, column=1, value=sub_data['name'])
                ws.cell(row=row, column=2, value="Data Factory")
                ws.cell(row=row, column=3, value=df['name'])
                ws.cell(row=row, column=4, value=df['resource_group'])
                ws.cell(row=row, column=5, value=df['location'])
                row += 1
            
            # Databricks
            for dbr in sub_data.get('databricks', []):
                ws.cell(row=row, column=1, value=sub_data['name'])
                ws.cell(row=row, column=2, value="Databricks")
                ws.cell(row=row, column=3, value=dbr['name'])
                ws.cell(row=row, column=4, value=dbr['resource_group'])
                ws.cell(row=row, column=5, value=dbr['location'])
                row += 1
            
            # Log Analytics
            for la in sub_data.get('log_analytics', []):
                ws.cell(row=row, column=1, value=sub_data['name'])
                ws.cell(row=row, column=2, value="Log Analytics")
                ws.cell(row=row, column=3, value=la['name'])
                ws.cell(row=row, column=4, value=la['resource_group'])
                ws.cell(row=row, column=5, value=la['location'])
                row += 1
            
            # Notification Hubs
            for nh in sub_data.get('notification_hubs', []):
                ws.cell(row=row, column=1, value=sub_data['name'])
                ws.cell(row=row, column=2, value="Notification Hub")
                ws.cell(row=row, column=3, value=nh['name'])
                ws.cell(row=row, column=4, value=nh['resource_group'])
                ws.cell(row=row, column=5, value=nh['location'])
                row += 1
        
        for col in range(1, len(headers) + 1):
            ws.column_dimensions[get_column_letter(col)].width = 25
    
    def _create_dependencies_sheet(self, wb):
        """Create dependencies sheet in Excel"""
        ws = wb.create_sheet("Dependencies")
        
        headers = ["Source Resource", "Source Type", "Target Resource", 
                  "Target Type", "Dependency Type", "Subscription"]
        
        for col, header in enumerate(headers, 1):
            cell = ws.cell(row=1, column=col, value=header)
            cell.font = Font(bold=True, color="FFFFFF")
            cell.fill = PatternFill(start_color="0078D4", end_color="0078D4", fill_type="solid")
        
        row = 2
        for dep in self.discovery_data.get('dependencies', []):
            ws.cell(row=row, column=1, value=dep['source'])
            ws.cell(row=row, column=2, value=dep['source_type'])
            ws.cell(row=row, column=3, value=dep.get('target', 'Unknown'))
            ws.cell(row=row, column=4, value=dep['target_type'])
            ws.cell(row=row, column=5, value=dep['dependency_type'])
            ws.cell(row=row, column=6, value=dep.get('subscription', 'N/A'))
            row += 1
        
        for col in range(1, len(headers) + 1):
            ws.column_dimensions[get_column_letter(col)].width = 30
    
    def _create_application_dependencies_sheet(self, wb):
        """Create application dependencies sheet in Excel"""
        ws = wb.create_sheet("App Dependencies")
        
        headers = ["Application", "Dependency Name", "Dependency Type", 
                  "Category", "Source", "Details"]
        
        for col, header in enumerate(headers, 1):
            cell = ws.cell(row=1, column=col, value=header)
            cell.font = Font(bold=True, color="FFFFFF")
            cell.fill = PatternFill(start_color="0078D4", end_color="0078D4", fill_type="solid")
        
        row = 2
        for dep in self.discovery_data.get('application_dependencies', []):
            ws.cell(row=row, column=1, value=dep['application'])
            ws.cell(row=row, column=2, value=dep['dependency_name'])
            ws.cell(row=row, column=3, value=dep['dependency_type'])
            ws.cell(row=row, column=4, value=dep['category'])
            ws.cell(row=row, column=5, value=dep['source'])
            ws.cell(row=row, column=6, value=str(dep.get('details', {})))
            row += 1
        
        for col in range(1, len(headers) + 1):
            ws.column_dimensions[get_column_letter(col)].width = 25
    
    def _create_arm_templates_sheet(self, wb):
        """Create ARM templates sheet in Excel"""
        ws = wb.create_sheet("ARM Templates")
        
        headers = ["Template File", "Resource Name", "Resource Type", 
                  "API Version", "Location", "Schema"]
        
        for col, header in enumerate(headers, 1):
            cell = ws.cell(row=1, column=col, value=header)
            cell.font = Font(bold=True, color="FFFFFF")
            cell.fill = PatternFill(start_color="0078D4", end_color="0078D4", fill_type="solid")
        
        row = 2
        for template in self.discovery_data.get('arm_templates', []):
            for resource in template.get('resources', []):
                ws.cell(row=row, column=1, value=template['file'])
                ws.cell(row=row, column=2, value=resource['name'])
                ws.cell(row=row, column=3, value=resource['type'])
                ws.cell(row=row, column=4, value=resource['api_version'])
                ws.cell(row=row, column=5, value=resource.get('location', 'N/A'))
                ws.cell(row=row, column=6, value=template.get('schema', ''))
                row += 1
        
        for col in range(1, len(headers) + 1):
            ws.column_dimensions[get_column_letter(col)].width = 30
    
    def _create_code_inventory_sheet(self, wb):
        """Create code inventory sheet in Excel"""
        ws = wb.create_sheet("Code Inventory")
        
        # Summary section
        ws['A1'] = "Repository"
        ws['B1'] = "Files Scanned"
        ws['C1'] = "Lines of Code"
        ws['D1'] = "Dependencies"
        ws['E1'] = "Azure Resources"
        
        for col in range(1, 6):
            cell = ws.cell(row=1, column=col)
            cell.font = Font(bold=True, color="FFFFFF")
            cell.fill = PatternFill(start_color="0078D4", end_color="0078D4", fill_type="solid")
        
        row = 2
        for repo_name, inventory in self.discovery_data.get('code_inventory', {}).items():
            ws.cell(row=row, column=1, value=repo_name)
            ws.cell(row=row, column=2, value=inventory['files'])
            ws.cell(row=row, column=3, value=inventory['lines'])
            ws.cell(row=row, column=4, value=inventory['dependencies'])
            ws.cell(row=row, column=5, value=inventory['azure_resources'])
            row += 1
        
        # NuGet packages section
        row += 2
        ws.cell(row=row, column=1, value="NuGet Packages").font = Font(bold=True, size=12)
        row += 1
        
        ws.cell(row=row, column=1, value="Application")
        ws.cell(row=row, column=2, value="Package Name")
        ws.cell(row=row, column=3, value="Version")
        ws.cell(row=row, column=4, value="Source File")
        
        for col in range(1, 5):
            cell = ws.cell(row=row, column=col)
            cell.font = Font(bold=True)
        
        row += 1
        for app_name, app_data in self.discovery_data.get('applications', {}).items():
            for pkg in app_data.get('nuget_packages', []):
                ws.cell(row=row, column=1, value=app_name)
                ws.cell(row=row, column=2, value=pkg['name'])
                ws.cell(row=row, column=3, value=pkg['version'])
                ws.cell(row=row, column=4, value=pkg['source'])
                row += 1
        
        for col in range(1, 6):
            ws.column_dimensions[get_column_letter(col)].width = 30
    
    def save_json_output(self):
        """Save raw discovery data as JSON"""
        json_file = os.path.join(self.config['output_dir'], 
                                f"azure_discovery_data_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(self.discovery_data, f, indent=2, default=str)
        
        self.logger.info(f"✓ JSON data saved: {json_file}")
        return json_file
    
    def run(self):
        """Run the complete discovery process"""
        try:
            self.logger.info("Starting Azure Discovery Process...")
            
            # Verify Azure connectivity (optional - uses CLI if available, otherwise SDK)
            self.verify_azure_connectivity()
            
            # Get subscriptions
            subscriptions = self.get_subscriptions()
            
            if not subscriptions:
                self.logger.error("\n❌ No subscriptions found!")
                self.logger.error("Please ensure you have access to at least one Azure subscription.")
                return {
                    'success': False,
                    'error': 'No subscriptions found'
                }
            
            # Discover resources in each subscription — run in parallel
            self.logger.info(f"Scanning {len(subscriptions)} subscription(s) in parallel...")
            def _discover_sub(sub):
                self.discover_subscription_resources(sub['id'], sub['name'])

            max_sub_workers = min(len(subscriptions), int(self.config.get('parallel_workers', 4)))
            if max_sub_workers > 1:
                from concurrent.futures import ThreadPoolExecutor as _TPE, as_completed as _ac
                with _TPE(max_workers=max_sub_workers) as _ex:
                    _futs = {_ex.submit(_discover_sub, s): s for s in subscriptions}
                    for _fut in _ac(_futs):
                        _s = _futs[_fut]
                        try:
                            _fut.result()
                            self.logger.info(f"  ✓ Completed: {_s['name']}")
                        except Exception as _e:
                            self.logger.error(f"  ✗ Failed: {_s['name']}: {_e}")
            else:
                for sub in subscriptions:
                    self.discover_subscription_resources(sub['id'], sub['name'])
            
            # Analyze dependencies
            self.analyze_dependencies()
            
            # Build application-centric dependency map
            self.build_complete_dependency_map()
            
            # Scan Git repositories if scan_code is enabled
            # Always call scan_git_repositories when scan_code=true so diagnostics are shown
            if self.config.get('scan_code', True):
                self.scan_git_repositories()
            
            # Phase 6 — full resource property export & deployment packages
            # Gated on config flags: export_resource_properties / export_deployment_package
            full_inventory:  Dict[str, Any] = {}
            inventory_html   = 'skipped (export_resource_properties=false in config)'
            deployment_pkg   = 'skipped (export_deployment_package=false in config)'

            if self.config.get('export_resource_properties', True):
                try:
                    full_inventory = self.export_resource_properties()
                except KeyboardInterrupt:
                    print('\n\n  ⚠  Export interrupted (Ctrl+C). '
                          'Continuing with reports using data collected so far.')
                    full_inventory = getattr(self, '_full_inventory', {})
                except Exception as _exp_err:
                    self.logger.error(f'export_resource_properties failed: {_exp_err}')
                    self.logger.error(traceback.format_exc())
                    print(f'\n  ❌ Export failed: {_exp_err}\n'
                          f'     Reports will be generated without full properties.\n')
            else:
                self.logger.info(
                    'export_resource_properties=false in config — skipping property export')

            if full_inventory:
                try:
                    print('\n  Generating full resource inventory HTML...')
                    inventory_html = self.generate_full_inventory_html(full_inventory)
                    print(f'  ✅ Inventory HTML : {inventory_html}')
                except Exception as _html_err:
                    self.logger.error(f'generate_full_inventory_html failed: {_html_err}')

                if self.config.get('export_deployment_package', True):
                    try:
                        print('\n  Building deployment packages (ARM templates + scripts)...')
                        deployment_pkg = self.generate_deployment_package(full_inventory)
                        print(f'  ✅ Deployment pkg : {deployment_pkg}')
                    except Exception as _pkg_err:
                        self.logger.error(f'generate_deployment_package failed: {_pkg_err}')
                else:
                    self.logger.info(
                        'export_deployment_package=false in config — skipping package gen')

            # Generate reports
            html_file  = self.generate_html_report()
            rg_file    = self.generate_resource_groups_report()
            excel_file = self.generate_excel_report()
            json_file  = self.save_json_output()

            # Summary
            self.logger.info("\n" + "="*80)
            self.logger.info("DISCOVERY COMPLETED SUCCESSFULLY!")
            self.logger.info("="*80)
            self.logger.info(f"\U0001f4ca Total Resources Discovered: {self.discovery_data['summary'].get('total_resources', 0)}")
            self.logger.info(f"\U0001f517 Total Dependencies Identified: {len(self.discovery_data.get('dependencies', []))}")
            self.logger.info(f"\n\U0001f4c1 Reports Generated:")
            self.logger.info(f"   HTML (full)              : {html_file}")
            self.logger.info(f"   Resource Group Report    : {rg_file}")
            self.logger.info(f"   Full Inventory HTML      : {inventory_html}")
            self.logger.info(f"   Deployment Packages      : {deployment_pkg}")
            self.logger.info(f"   Excel Workbook           : {excel_file}")
            self.logger.info(f"   JSON Data                : {json_file}")
            self.logger.info("="*80)

            return {
                'success':          True,
                'html_report':      html_file,
                'rg_report':        rg_file,
                'inventory_html':   inventory_html,
                'deployment_pkg':   deployment_pkg,
                'excel_report':     excel_file,
                'json_data':        json_file,
            }
            
        except Exception as e:
            self.logger.error(f"\n❌ Discovery failed: {e}")
            self.logger.error(traceback.format_exc())
            return {
                'success': False,
                'error': str(e)
            }


def self_update():
    """Auto-sync this tool's own git repository before running.
    
    Pulls the latest code from the remote (origin) so every run
    always uses the most up-to-date version of the scripts.
    
    Behaviour:
    - If the folder is not a git repo, or git is not installed: skips silently.
    - If there are local uncommitted changes: skips to avoid overwriting user edits.
    - If pull succeeds and files changed: prints a restart notice.
    - Network errors (no internet, auth failure): warns and continues.
    """
    print("\n🔄 Checking for tool updates...")
    script_dir = os.path.dirname(os.path.abspath(__file__))

    try:
        repo = git.Repo(script_dir, search_parent_directories=True)
    except git.exc.InvalidGitRepositoryError:
        print("   ℹ  Not a git repository – skipping auto-update")
        return
    except Exception as e:
        print(f"   ⚠  Could not open git repo: {e} – skipping auto-update")
        return

    # Safety: don't overwrite local uncommitted changes
    if repo.is_dirty(untracked_files=False):
        print("   ⚠  Local uncommitted changes detected – skipping auto-update to avoid overwriting")
        print("      Commit or stash your changes to enable auto-update.")
        return

    # Check remote exists
    if not repo.remotes:
        print("   ℹ  No git remote configured – skipping auto-update")
        return

    origin = repo.remotes.origin
    remote_url = origin.url

    # Mask credentials in URL for display
    try:
        import urllib.parse
        parsed = urllib.parse.urlparse(remote_url)
        display_url = remote_url.replace(parsed.password or '', '***') if parsed.password else remote_url
    except Exception:
        display_url = remote_url

    try:
        current_branch = repo.active_branch.name
    except TypeError:
        # Detached HEAD state
        print("   ⚠  Detached HEAD state – skipping auto-update")
        return

    print(f"   Remote : {display_url}")
    print(f"   Branch : {current_branch}")

    try:
        # Fetch first to check if there are updates, with SSL fallback
        def _fetch(ssl_bypass=False):
            if ssl_bypass:
                with repo.git.custom_environment(GIT_SSL_NO_VERIFY='1'):
                    origin.fetch()
            else:
                origin.fetch()

        try:
            _fetch(ssl_bypass=False)
        except git.exc.GitCommandError as fe:
            s = str(fe).lower()
            if 'ssl' in s or 'certificate' in s:
                print("   ⚠  SSL error on fetch – retrying with SSL verification bypassed")
                print("      Permanent fix: git config --global http.sslBackend schannel")
                _fetch(ssl_bypass=True)
            elif '401' in s or '403' in s or 'authentication' in s:
                print("   ⚠  Authentication error fetching updates – skipping auto-update")
                return
            else:
                raise

        # Compare local HEAD with remote tracking branch
        tracking = f"origin/{current_branch}"
        try:
            remote_commit = repo.commit(tracking)
        except git.exc.BadName:
            print(f"   ⚠  Remote branch '{tracking}' not found – skipping auto-update")
            return

        local_commit  = repo.head.commit
        if local_commit.hexsha == remote_commit.hexsha:
            print("   ✓  Already up to date")
            return

        # Count commits behind
        commits_behind = list(repo.iter_commits(f"{local_commit.hexsha}..{remote_commit.hexsha}"))
        print(f"   ⬇  {len(commits_behind)} new commit(s) available – pulling...")

        # Preserve config.json across the pull – it contains user-specific settings
        # (subscription IDs, PAT tokens, etc.) that must never be overwritten by remote
        config_path = os.path.join(script_dir, 'config.json')
        config_backup = None
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r', encoding='utf-8') as _cf:
                    config_backup = _cf.read()
            except Exception:
                config_backup = None

        # Pull with SSL fallback
        def _pull(ssl_bypass=False):
            if ssl_bypass:
                with repo.git.custom_environment(GIT_SSL_NO_VERIFY='1'):
                    origin.pull(current_branch)
            else:
                origin.pull(current_branch)

        try:
            _pull(ssl_bypass=False)
        except git.exc.GitCommandError as pe:
            s = str(pe).lower()
            if 'ssl' in s or 'certificate' in s:
                print("   ⚠  SSL error on pull – retrying with SSL verification bypassed")
                _pull(ssl_bypass=True)
            else:
                raise

        # Restore config.json to the user's pre-pull version
        if config_backup is not None:
            try:
                with open(config_path, 'w', encoding='utf-8') as _cf:
                    _cf.write(config_backup)
                print("   ✓  config.json preserved (local subscription settings kept)")
            except Exception as re:
                print(f"   ⚠  Could not restore config.json: {re}")

        # Show what changed
        changed_files = [
            item.a_path
            for item in repo.index.diff(local_commit)
        ]
        print(f"   ✓  Updated successfully! Files changed:")
        for f in changed_files[:10]:   # cap display at 10
            print(f"      • {f}")
        if len(changed_files) > 10:
            print(f"      ... and {len(changed_files) - 10} more")

        # If this script itself was updated, warn user to restart
        this_script = os.path.basename(__file__)
        if any(this_script in f or 'azure_discovery' in f for f in changed_files):
            print()
            print("   ⚠  " + "="*60)
            print("   ⚠  azure_discovery.py was updated.")
            print("   ⚠  Please re-run the script to use the latest version.")
            print("   ⚠  " + "="*60)
            print()
            sys.exit(0)   # Exit cleanly so the user runs the updated version

    except git.exc.GitCommandError as e:
        print(f"   ⚠  Git pull failed: {e}")
        print("      Continuing with current version...")
    except Exception as e:
        print(f"   ⚠  Auto-update error: {e}")
        print("      Continuing with current version...")

    print()


def main():
    """Main entry point"""
    # Auto-sync before anything else
    self_update()

    print("""
╔═══════════════════════════════════════════════════════════════════════════════╗
║                     AZURE DISCOVERY TOOL FOR MIGRATION                        ║
║                                                                               ║
║  Comprehensive discovery of Azure resources, dependencies, and configuration ║
║  for tenant-to-tenant migration planning.                                    ║
║                                                                               ║
║  🔒 SECURITY: 100% READ-ONLY OPERATIONS                                      ║
║     • Only reads Azure resources (list, get, describe)                       ║
║     • Does NOT create, modify, or delete anything                            ║
║     • Safe to run in production environments                                 ║
║     • Requires only Reader role permissions                                  ║
╚═══════════════════════════════════════════════════════════════════════════════╝
    """)
    
    # Check for config file
    config_file = "config.json"
    if not os.path.exists(config_file):
        print(f"\n⚠️  Configuration file '{config_file}' not found.")
        print("Creating a default configuration file...")
        
        default_config = {
            "auth_method": "default",
            "tenant_id": "",
            "client_id": "",
            "client_secret": "",
            "subscription_ids": [],
            "output_dir": "discovery_output",
            "scan_code": True,
            "scan_network_flows": True,
            "deep_dependency_analysis": True,
            "git_repos": [],
            "excluded_resource_groups": [],
            "log_level": "INFO"
        }
        
        with open(config_file, 'w') as f:
            json.dump(default_config, f, indent=4)
        
        print(f"✓ Created '{config_file}' with default settings")
        print(f"\nPlease review and update the configuration file, then run the script again.")
        print(f"\nAuthentication options:")
        print(f"  1. Azure CLI: Run 'az login' first, then run this script")
        print(f"  2. Service Principal: Update config.json with tenant_id, client_id, client_secret")
        print(f"  3. Environment Variables: Set AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET")
        return
    
    try:
        # Initialize and run discovery
        discovery = AzureDiscovery(config_file)
        result = discovery.run()
        
        if result['success']:
            print("\n✓ Discovery completed successfully!")
            print(f"\nYou can now review the reports and use them for migration planning.")
            sys.exit(0)
        else:
            print(f"\n❌ Discovery failed: {result['error']}")
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("\n\n⚠️  Discovery interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
