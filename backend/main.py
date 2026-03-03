#!/usr/bin/env python3
"""
HackInterface - Interface Web pour Pentest Automatisé
Point d'entrée principal de l'API FastAPI
"""

import os
import asyncio
import contextvars
import re
import uuid
from pathlib import Path
from typing import Dict, Any
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, UploadFile, File, HTTPException, BackgroundTasks, Body, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, HTMLResponse, Response, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import uvicorn

from core.config import settings
from core.vpn import vpn_manager
from core.executor import CommandExecutor, escape_shell_arg, validate_target
from core.websocket_manager import ConnectionManager
from models.schemas import (
    TargetCreate, TargetResponse, ActionRequest, WorkflowRequest,
    PingRequest, VPNStatus, ActionResult
)
from modules.recon import ReconModule
from modules.web_enum import WebEnumModule
from modules.vuln_scan import VulnScanModule
from modules.exploitation import ExploitationModule
from modules.password_attacks import PasswordAttacksModule
from modules.metasploit import MetasploitModule
from modules.network import NetworkModule
from modules.osint import OSINTModule
from modules.web_advanced import WebAdvancedModule
from modules.netexec import NetExecModule
from modules.impacket import ImpacketModule
from modules.bloodhound import BloodHoundModule
from modules.kerbrute import KerbruteModule
from modules.evilwinrm import EvilWinRMModule
from modules.peas import PEASModule
from workflows.engine import WorkflowEngine
from reports.generator import ReportGenerator
from core.database import db

SESSION_KEY_PATTERN = re.compile(r'^[a-zA-Z0-9_-]{1,64}$')
_current_client_session_key: contextvars.ContextVar[str] = contextvars.ContextVar(
    "current_client_session_key",
    default="default"
)


def _new_session_state() -> Dict[str, Any]:
    """Crée un nouvel état de session isolé"""
    return {
        "id": None,
        "targets": [],
        "results": {},
        "workflow_status": None
    }


def _resolve_session_key(
    header_value: str | None = None,
    query_value: str | None = None,
    cookie_value: str | None = None
) -> str:
    """Détermine une clé de session valide"""
    for candidate in (header_value, query_value, cookie_value):
        if isinstance(candidate, str):
            normalized = candidate.strip()
            if SESSION_KEY_PATTERN.match(normalized):
                return normalized
    return "default"


class SessionStateProxy:
    """Proxy dictionnaire vers un store de session isolé par client"""

    def __init__(self):
        self._store: Dict[str, Dict[str, Any]] = {"default": _new_session_state()}

    def _get_state(self) -> Dict[str, Any]:
        key = _current_client_session_key.get()
        if key not in self._store:
            self._store[key] = _new_session_state()
        return self._store[key]

    def __getitem__(self, item):
        return self._get_state()[item]

    def __setitem__(self, key, value):
        self._get_state()[key] = value

    def __contains__(self, item):
        return item in self._get_state()

    def get(self, key, default=None):
        return self._get_state().get(key, default)

    def pop(self, key, default=None):
        return self._get_state().pop(key, default)

    def clear(self):
        self._store[_current_client_session_key.get()] = _new_session_state()

    def items(self):
        return self._get_state().items()

    def keys(self):
        return self._get_state().keys()

    def values(self):
        return self._get_state().values()

# Gestionnaire de connexions WebSocket
ws_manager = ConnectionManager()

# Modules de pentest
recon_module = ReconModule()
web_enum_module = WebEnumModule()
vuln_scan_module = VulnScanModule()
exploit_module = ExploitationModule()
password_module = PasswordAttacksModule()
metasploit_module = MetasploitModule()
network_module = NetworkModule()
osint_module = OSINTModule()
web_advanced_module = WebAdvancedModule()
netexec_module = NetExecModule()
impacket_module = ImpacketModule()
bloodhound_module = BloodHoundModule()
kerbrute_module = KerbruteModule()
evilwinrm_module = EvilWinRMModule()
peas_module = PEASModule()
workflow_engine = WorkflowEngine()
report_generator = ReportGenerator()

# Stockage des tâches de workflow actives pour permettre l'annulation
active_workflow_tasks: dict[str, asyncio.Task] = {}

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Gestion du cycle de vie de l'application"""
    # Startup
    os.makedirs(settings.DATA_DIR, exist_ok=True)
    os.makedirs(settings.UPLOAD_DIR, exist_ok=True)
    os.makedirs(settings.REPORTS_DIR, exist_ok=True)
    os.makedirs(settings.SCREENSHOTS_DIR, exist_ok=True)
    print(f"[+] HackInterface démarré sur http://127.0.0.1:{settings.PORT}")
    yield
    # Shutdown
    if vpn_manager.is_connected():
        await vpn_manager.disconnect()
    print("[+] HackInterface arrêté")

app = FastAPI(
    title="HackInterface",
    description="Interface Web pour automatisation de pentest",
    version="1.0.0",
    lifespan=lifespan
)


def _extract_bearer_token(auth_header: str | None) -> str:
    """Extrait le token Bearer depuis l'en-tête Authorization"""
    if not auth_header:
        return ""
    if not auth_header.lower().startswith("bearer "):
        return ""
    return auth_header[7:].strip()


def _is_valid_api_token(headers: Dict[str, str], query_token: str | None = None) -> bool:
    """Vérifie la validité du token API"""
    expected = settings.API_TOKEN
    if not expected:
        return True

    bearer_token = _extract_bearer_token(headers.get("authorization"))
    header_token = headers.get("x-api-key", "").strip()
    query_value = (query_token or "").strip()

    return expected in {bearer_token, header_token, query_value}


@app.middleware("http")
async def api_auth_middleware(request: Request, call_next):
    """Protège /api et attache un contexte de session mémoire isolé"""
    session_key = _resolve_session_key(
        header_value=request.headers.get("x-session-key"),
        query_value=request.query_params.get("session_key"),
        cookie_value=request.cookies.get("hackinterface_session")
    )
    context_token = _current_client_session_key.set(session_key)

    try:
        if settings.REQUIRE_API_AUTH and request.url.path.startswith("/api"):
            query_token = request.query_params.get("token") or request.query_params.get("api_token")
            if not _is_valid_api_token(dict(request.headers), query_token):
                return JSONResponse(
                    status_code=401,
                    content={
                        "detail": "Authentification requise. Fournissez un token via Authorization: Bearer <token> ou X-API-Key."
                    }
                )

        response = await call_next(request)
        response.headers["X-Session-Key"] = session_key
        return response
    finally:
        _current_client_session_key.reset(context_token)

# CORS pour usage local
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Servir les fichiers statiques du frontend
app.mount("/static", StaticFiles(directory="frontend/static"), name="static")

# ============================================================================
# ROUTES - Interface principale et PWA
# ============================================================================

@app.get("/", response_class=HTMLResponse)
async def root():
    """Page principale de l'interface"""
    return FileResponse("frontend/index.html")

@app.get("/manifest.json")
async def get_manifest():
    """Manifest PWA"""
    return FileResponse("frontend/manifest.json", media_type="application/manifest+json")

@app.get("/sw.js")
async def get_service_worker():
    """Service Worker PWA"""
    return FileResponse(
        "frontend/sw.js", 
        media_type="application/javascript",
        headers={"Service-Worker-Allowed": "/"}
    )

# ============================================================================
# ROUTES - Gestion VPN
# ============================================================================

@app.post("/api/vpn/upload")
async def upload_vpn(file: UploadFile = File(...)):
    """Upload d'un fichier .ovpn"""
    if not file.filename.endswith('.ovpn'):
        raise HTTPException(status_code=400, detail="Le fichier doit être un .ovpn")
    
    filepath = os.path.join(settings.UPLOAD_DIR, "current.ovpn")
    content = await file.read()
    with open(filepath, "wb") as f:
        f.write(content)
    
    return {"status": "success", "message": f"Fichier {file.filename} uploadé"}

@app.post("/api/vpn/connect")
async def connect_vpn():
    """Connexion au VPN"""
    result = await vpn_manager.connect()
    return result

@app.post("/api/vpn/disconnect")
async def disconnect_vpn():
    """Déconnexion du VPN"""
    result = await vpn_manager.disconnect()
    return result

@app.get("/api/vpn/status", response_model=VPNStatus)
async def vpn_status():
    """Statut de la connexion VPN"""
    return vpn_manager.get_status()

@app.post("/api/vpn/ping")
async def ping_target(request: PingRequest):
    """Test de connectivité vers une IP"""
    validation = validate_target(request.target)
    if not validation.valid or validation.target_type not in {"ipv4", "ipv6", "fqdn", "domain"}:
        raise HTTPException(status_code=400, detail="Cible invalide pour ping")

    executor = CommandExecutor()
    target_safe = escape_shell_arg(validation.normalized)
    result = await executor.run(f"ping -c 3 {target_safe}")
    success = result.return_code == 0
    return {
        "success": success,
        "target": validation.normalized,
        "output": result.stdout if success else result.stderr
    }

# ============================================================================
# ROUTES - Validation des cibles
# ============================================================================

@app.post("/api/validate/target")
async def validate_target_endpoint(request: dict):
    """Valide une cible et retourne des informations détaillées"""
    from core.executor import validate_target
    
    target = request.get("target", "")
    result = validate_target(target)
    
    return {
        "valid": result.valid,
        "target_type": result.target_type,
        "normalized": result.normalized,
        "message": result.message,
        "details": result.details
    }

@app.post("/api/validate/targets")
async def validate_multiple_targets(request: dict):
    """Valide plusieurs cibles en une fois"""
    from core.executor import validate_target
    
    targets = request.get("targets", [])
    results = []
    
    for target in targets:
        result = validate_target(target)
        results.append({
            "target": target,
            "valid": result.valid,
            "target_type": result.target_type,
            "normalized": result.normalized,
            "message": result.message
        })
    
    valid_count = sum(1 for r in results if r["valid"])
    
    return {
        "results": results,
        "summary": {
            "total": len(targets),
            "valid": valid_count,
            "invalid": len(targets) - valid_count
        }
    }

# ============================================================================
# ROUTES - Gestion des cibles
# ============================================================================

# Stockage en mémoire isolé par client (clé session via header/query/cookie)
current_session = SessionStateProxy()

@app.post("/api/targets", response_model=TargetResponse)
async def add_target(target: TargetCreate):
    """Ajouter une cible"""
    target_id = len(current_session["targets"]) + 1
    target_data = {
        "id": target_id,
        "type": target.type,
        "value": target.value,
        "description": target.description
    }
    current_session["targets"].append(target_data)
    current_session["results"][target_id] = {}
    
    # Sauvegarder en DB si session active
    if current_session["id"]:
        db.add_target(current_session["id"], target.type, target.value, 
                      name=target.description)
    
    return TargetResponse(**target_data)

@app.get("/api/targets")
async def list_targets():
    """Lister toutes les cibles"""
    return current_session["targets"]

@app.delete("/api/targets/{target_id}")
async def delete_target(target_id: int):
    """Supprimer une cible"""
    current_session["targets"] = [t for t in current_session["targets"] if t["id"] != target_id]
    if target_id in current_session["results"]:
        del current_session["results"][target_id]
    return {"status": "success"}

@app.delete("/api/targets")
async def clear_targets():
    """Supprimer toutes les cibles"""
    current_session["targets"] = []
    current_session["results"] = {}
    return {"status": "success"}

# ============================================================================
# ROUTES - Actions individuelles
# ============================================================================

@app.post("/api/actions/run")
async def run_action(request: ActionRequest):
    """Exécuter une action spécifique sur une cible"""
    target = next((t for t in current_session["targets"] if t["id"] == request.target_id), None)
    if not target:
        raise HTTPException(status_code=404, detail="Cible non trouvée")
    
    module_map = {
        # Recon
        "nmap_quick": recon_module.nmap_quick,
        "nmap_full": recon_module.nmap_full,
        "nmap_vuln": recon_module.nmap_vuln,
        "whois": recon_module.whois_lookup,
        "dns_enum": recon_module.dns_enumeration,
        "subdomain_enum": recon_module.subdomain_enumeration,
        # Web Enum
        "gobuster": web_enum_module.gobuster,
        "nikto": web_enum_module.nikto,
        "whatweb": web_enum_module.whatweb,
        "wpscan": web_enum_module.wpscan,
        # Vuln Scan
        "nuclei": vuln_scan_module.nuclei_scan,
        "searchsploit": vuln_scan_module.searchsploit,
        # Password Attacks
        "hydra_ssh": password_module.hydra_ssh,
        "hydra_ftp": password_module.hydra_ftp,
        "hydra_smb": password_module.hydra_smb,
        "hydra_rdp": password_module.hydra_rdp,
        "hydra_http": password_module.hydra_http_post,
        "cewl": password_module.cewl,
        # Metasploit
        "msf_smb_version": metasploit_module.smb_version,
        "msf_smb_ms17_010": metasploit_module.smb_ms17_010,
        "msf_ssh_version": metasploit_module.ssh_version,
        "msf_ftp_version": metasploit_module.ftp_version,
        "msf_http_version": metasploit_module.http_version,
        # Network
        "masscan": network_module.masscan,
        "sslscan": network_module.sslscan,
        "arp_scan": network_module.arp_scan,
        # OSINT
        "theharvester": osint_module.theharvester,
        "amass": osint_module.amass_enum,
        "sherlock": osint_module.sherlock,
        "wafw00f": osint_module.wafw00f,
        "subfinder": osint_module.subfinder,
        "httpx": osint_module.httpx_probe,
        "subfinder_httpx": osint_module.subfinder_httpx,
        # Web Advanced
        "sqlmap": web_advanced_module.sqlmap_url,
        "ffuf": web_advanced_module.ffuf_dir,
        "feroxbuster": web_advanced_module.feroxbuster,
        "commix": web_advanced_module.commix,
        "xsser": web_advanced_module.xsser,
        "joomscan": web_advanced_module.joomscan,
        # Exploitation
        "enum4linux": exploit_module.run_enum4linux,
        "smbclient": exploit_module.run_smbclient,
        "ldapsearch": exploit_module.run_ldapsearch,
        # NetExec (ex-CrackMapExec)
        "nxc_smb": netexec_module.smb_enum,
        "nxc_smb_shares": netexec_module.smb_shares,
        "nxc_smb_users": netexec_module.smb_users,
        "nxc_spray": netexec_module.smb_pass_spray,
        "nxc_winrm": netexec_module.winrm_enum,
        "nxc_winrm_exec": netexec_module.winrm_exec,
        "nxc_ssh": netexec_module.ssh_enum,
        "nxc_ldap": netexec_module.ldap_enum,
        "nxc_mssql": netexec_module.mssql_enum,
        "nxc_rdp": netexec_module.rdp_enum,
        "nxc_sam": netexec_module.dump_sam,
        "nxc_lsa": netexec_module.dump_lsa,
        # Impacket
        "secretsdump": impacket_module.secretsdump,
        "kerberoasting": impacket_module.getuserspns,
        "asreproasting": impacket_module.getnpusers,
        "psexec": impacket_module.psexec,
        "wmiexec": impacket_module.wmiexec,
        "smbexec": impacket_module.smbexec,
        "dcomexec": impacket_module.dcomexec,
        "atexec": impacket_module.atexec,
        "lookupsid": impacket_module.lookupsid,
        "getTGT": impacket_module.gettgt,
        "getST": impacket_module.getst,
        # BloodHound
        "bloodhound": bloodhound_module.bloodhound_python,
        "bloodhound_dns": bloodhound_module.bloodhound_dns,
        "sharphound": bloodhound_module.sharphound_run,
        # Kerbrute
        "kerbrute_userenum": kerbrute_module.userenum,
        "kerbrute_spray": kerbrute_module.passwordspray,
        "kerbrute_brute": kerbrute_module.bruteforce,
        # Evil-WinRM
        "evilwinrm_check": evilwinrm_module.check_access,
        "evilwinrm_exec": evilwinrm_module.execute_command,
        "evilwinrm_upload": evilwinrm_module.upload_file,
        "evilwinrm_download": evilwinrm_module.download_file,
        "evilwinrm_mimikatz": evilwinrm_module.run_mimikatz,
        "evilwinrm_amsi": evilwinrm_module.bypass_amsi,
        # PEAS (LinPEAS / WinPEAS)
        "linpeas": peas_module.linpeas_local,
        "linpeas_remote": peas_module.linpeas_remote,
        "winpeas": peas_module.winpeas_via_evilwinrm,
        "winpeas_cmd": peas_module.winpeas_generate_command,
        "lse": peas_module.lse,
        "pspy": peas_module.pspy,
        "suid_search": peas_module.suid_search,
        "creds_search": peas_module.creds_search,
    }
    
    if request.action not in module_map:
        raise HTTPException(status_code=400, detail=f"Action inconnue: {request.action}")
    
    action_func = module_map[request.action]
    result = await action_func(target["value"], request.options or {})
    
    # Stocker le résultat en mémoire
    if request.target_id not in current_session["results"]:
        current_session["results"][request.target_id] = {}
    current_session["results"][request.target_id][request.action] = result
    
    # Sauvegarder en DB si session active
    if current_session["id"]:
        db.save_result(current_session["id"], request.target_id, request.action, result)
    
    return result

@app.get("/api/actions/available")
async def get_available_actions():
    """Liste des actions disponibles par catégorie"""
    return {
        "recon": [
            {"id": "nmap_quick", "name": "Nmap Quick Scan", "description": "Scan rapide des ports courants"},
            {"id": "nmap_full", "name": "Nmap Full Scan", "description": "Scan complet de tous les ports"},
            {"id": "nmap_vuln", "name": "Nmap Vuln Scan", "description": "Scan avec scripts de vulnérabilités"},
            {"id": "masscan", "name": "Masscan", "description": "Scan de ports ultra-rapide"},
            {"id": "whois", "name": "Whois Lookup", "description": "Informations WHOIS"},
            {"id": "dns_enum", "name": "DNS Enumeration", "description": "Énumération DNS complète"},
            {"id": "subdomain_enum", "name": "Subdomain Enum", "description": "Recherche de sous-domaines"},
        ],
        "osint": [
            {"id": "theharvester", "name": "theHarvester", "description": "Collecte emails, sous-domaines (OSINT)"},
            {"id": "amass", "name": "Amass", "description": "Énumération sous-domaines avancée"},
            {"id": "sherlock", "name": "Sherlock", "description": "Recherche comptes réseaux sociaux"},
            {"id": "wafw00f", "name": "WAFw00f", "description": "Détection de WAF"},
            {"id": "subfinder", "name": "Subfinder", "description": "Énumération sous-domaines rapide (ProjectDiscovery)"},
            {"id": "httpx", "name": "httpx", "description": "Probe HTTP, détection technos et status codes"},
            {"id": "subfinder_httpx", "name": "Subfinder → httpx", "description": "Pipeline: sous-domaines + probe HTTP"},
        ],
        "web_enum": [
            {"id": "gobuster", "name": "Gobuster", "description": "Brute-force répertoires/fichiers"},
            {"id": "ffuf", "name": "FFUF", "description": "Fuzzing web ultra-rapide"},
            {"id": "feroxbuster", "name": "Feroxbuster", "description": "Brute-force récursif rapide"},
            {"id": "nikto", "name": "Nikto", "description": "Scanner vulnérabilités web"},
            {"id": "whatweb", "name": "WhatWeb", "description": "Identification technologies"},
            {"id": "wpscan", "name": "WPScan", "description": "Scanner WordPress"},
            {"id": "joomscan", "name": "JoomScan", "description": "Scanner Joomla"},
        ],
        "vuln_scan": [
            {"id": "nuclei", "name": "Nuclei", "description": "Scan vulnérabilités avec templates"},
            {"id": "sqlmap", "name": "SQLMap", "description": "Détection/exploitation injection SQL"},
            {"id": "xsser", "name": "XSSer", "description": "Détection vulnérabilités XSS"},
            {"id": "commix", "name": "Commix", "description": "Injection de commandes"},
            {"id": "sslscan", "name": "SSLScan", "description": "Analyse SSL/TLS"},
            {"id": "searchsploit", "name": "SearchSploit", "description": "Recherche d'exploits"},
        ],
        "password_attacks": [
            {"id": "hydra_ssh", "name": "Hydra SSH", "description": "Brute-force SSH"},
            {"id": "hydra_ftp", "name": "Hydra FTP", "description": "Brute-force FTP"},
            {"id": "hydra_smb", "name": "Hydra SMB", "description": "Brute-force SMB"},
            {"id": "hydra_rdp", "name": "Hydra RDP", "description": "Brute-force RDP"},
            {"id": "hydra_http", "name": "Hydra HTTP", "description": "Brute-force formulaire web"},
            {"id": "cewl", "name": "CeWL", "description": "Générer wordlist depuis site web"},
        ],
        "metasploit": [
            {"id": "msf_smb_version", "name": "MSF SMB Version", "description": "Scanner versions SMB"},
            {"id": "msf_smb_ms17_010", "name": "MSF EternalBlue", "description": "Check MS17-010 (EternalBlue)"},
            {"id": "msf_ssh_version", "name": "MSF SSH Version", "description": "Scanner versions SSH"},
            {"id": "msf_ftp_version", "name": "MSF FTP Version", "description": "Scanner versions FTP"},
            {"id": "msf_http_version", "name": "MSF HTTP Version", "description": "Scanner serveurs web"},
        ],
        "netexec": [
            {"id": "nxc_smb", "name": "NXC SMB Enum", "description": "Énumération SMB (OS, signing, domaine)"},
            {"id": "nxc_smb_shares", "name": "NXC Shares", "description": "Énumération partages SMB"},
            {"id": "nxc_smb_users", "name": "NXC Users", "description": "Énumération utilisateurs SMB"},
            {"id": "nxc_spray", "name": "NXC Password Spray", "description": "Password spray SMB"},
            {"id": "nxc_winrm", "name": "NXC WinRM", "description": "Test connexion WinRM"},
            {"id": "nxc_winrm_exec", "name": "NXC WinRM Exec", "description": "Exécution commande WinRM"},
            {"id": "nxc_ssh", "name": "NXC SSH", "description": "Brute-force/test SSH"},
            {"id": "nxc_ldap", "name": "NXC LDAP", "description": "Énumération LDAP/AD"},
            {"id": "nxc_mssql", "name": "NXC MSSQL", "description": "Test connexion MSSQL"},
            {"id": "nxc_rdp", "name": "NXC RDP", "description": "Test connexion RDP"},
            {"id": "nxc_sam", "name": "NXC Dump SAM", "description": "Dump hashes SAM (admin requis)"},
            {"id": "nxc_lsa", "name": "NXC Dump LSA", "description": "Dump secrets LSA (admin requis)"},
        ],
        "impacket": [
            {"id": "secretsdump", "name": "SecretsDump", "description": "Dump SAM/LSA/NTDS hashes"},
            {"id": "kerberoasting", "name": "Kerberoasting", "description": "GetUserSPNs - TGS tickets"},
            {"id": "asreproasting", "name": "AS-REP Roasting", "description": "GetNPUsers - sans preauth"},
            {"id": "psexec", "name": "PsExec", "description": "Shell SYSTEM via SMB"},
            {"id": "wmiexec", "name": "WMIExec", "description": "Exécution via WMI (furtif)"},
            {"id": "smbexec", "name": "SMBExec", "description": "Exécution via SMB"},
            {"id": "dcomexec", "name": "DCOMExec", "description": "Exécution via DCOM"},
            {"id": "atexec", "name": "AtExec", "description": "Exécution via Task Scheduler"},
            {"id": "lookupsid", "name": "LookupSID", "description": "Énumération SID/utilisateurs"},
            {"id": "getTGT", "name": "GetTGT", "description": "Obtenir un TGT Kerberos"},
            {"id": "getST", "name": "GetST", "description": "Obtenir un Service Ticket"},
        ],
        "bloodhound": [
            {"id": "bloodhound", "name": "BloodHound Collect", "description": "Collecte AD avec bloodhound-python"},
            {"id": "bloodhound_dns", "name": "BloodHound DNS", "description": "Collecte DNS only (sans auth)"},
            {"id": "sharphound", "name": "SharpHound", "description": "Collecteur Windows (instructions)"},
        ],
        "kerbrute": [
            {"id": "kerbrute_userenum", "name": "User Enum", "description": "Énumération utilisateurs Kerberos"},
            {"id": "kerbrute_spray", "name": "Password Spray", "description": "Spray mot de passe Kerberos"},
            {"id": "kerbrute_brute", "name": "Brute Force", "description": "Brute-force Kerberos"},
        ],
        "evilwinrm": [
            {"id": "evilwinrm_check", "name": "Check Access", "description": "Vérifier accès WinRM"},
            {"id": "evilwinrm_exec", "name": "Execute", "description": "Exécuter commande PowerShell"},
            {"id": "evilwinrm_upload", "name": "Upload", "description": "Upload fichier vers cible"},
            {"id": "evilwinrm_download", "name": "Download", "description": "Download fichier depuis cible"},
            {"id": "evilwinrm_mimikatz", "name": "Mimikatz", "description": "Exécuter Invoke-Mimikatz"},
            {"id": "evilwinrm_amsi", "name": "AMSI Bypass", "description": "Bypass AMSI"},
        ],
        "privesc": [
            {"id": "linpeas", "name": "LinPEAS", "description": "Énumération privesc Linux locale"},
            {"id": "linpeas_remote", "name": "LinPEAS Remote", "description": "LinPEAS via SSH"},
            {"id": "winpeas", "name": "WinPEAS", "description": "Énumération privesc Windows"},
            {"id": "winpeas_cmd", "name": "WinPEAS Cmd", "description": "Générer commande WinPEAS"},
            {"id": "lse", "name": "LSE", "description": "Linux Smart Enumeration"},
            {"id": "pspy", "name": "pspy", "description": "Surveillance processus Linux"},
            {"id": "suid_search", "name": "SUID Search", "description": "Recherche binaires SUID"},
            {"id": "creds_search", "name": "Creds Search", "description": "Recherche credentials fichiers"},
        ],
        "exploitation": [
            {"id": "enum4linux", "name": "Enum4linux", "description": "Énumération SMB/Windows complète"},
            {"id": "smbclient", "name": "SMBClient", "description": "Lister partages SMB"},
            {"id": "ldapsearch", "name": "LDAP Search", "description": "Recherche LDAP anonyme"},
            {"id": "arp_scan", "name": "ARP Scan", "description": "Découverte réseau local"},
        ],
    }

# ============================================================================
# ROUTES - Workflows
# ============================================================================

@app.get("/api/workflows/available")
async def get_available_workflows():
    """Liste des workflows prédéfinis"""
    return workflow_engine.get_available_workflows()

@app.post("/api/workflows/run")
async def run_workflow(request: WorkflowRequest):
    """Lancer un workflow sur une cible"""
    target = next((t for t in current_session["targets"] if t["id"] == request.target_id), None)
    if not target:
        raise HTTPException(status_code=404, detail="Cible non trouvée")
    
    # Créer un ID unique pour cette exécution
    import uuid
    task_id = f"{request.workflow_id}_{request.target_id}_{uuid.uuid4().hex[:8]}"
    
    # Lancer le workflow en arrière-plan et stocker la tâche
    task = asyncio.create_task(
        workflow_engine.execute(
            request.workflow_id,
            target,
            request.options or {},
            ws_manager,
            current_session["results"]
        )
    )
    active_workflow_tasks[task_id] = task
    
    # Nettoyer automatiquement quand la tâche se termine
    def cleanup_task(t):
        active_workflow_tasks.pop(task_id, None)
    task.add_done_callback(cleanup_task)
    
    return {"status": "started", "workflow_id": request.workflow_id, "task_id": task_id}

@app.post("/api/workflows/custom")
async def run_custom_workflow(request: dict):
    """Lancer un workflow personnalisé avec actions sélectionnées"""
    target_id = request.get("target_id")
    actions = request.get("actions", [])
    
    target = next((t for t in current_session["targets"] if t["id"] == target_id), None)
    if not target:
        raise HTTPException(status_code=404, detail="Cible non trouvée")
    
    # Créer un ID unique pour cette exécution
    import uuid
    task_id = f"custom_{target_id}_{uuid.uuid4().hex[:8]}"
    
    task = asyncio.create_task(
        workflow_engine.execute_custom(
            actions,
            target,
            ws_manager,
            current_session["results"]
        )
    )
    active_workflow_tasks[task_id] = task
    
    # Nettoyer automatiquement quand la tâche se termine
    def cleanup_task(t):
        active_workflow_tasks.pop(task_id, None)
    task.add_done_callback(cleanup_task)
    
    return {"status": "started", "actions": actions, "task_id": task_id}


@app.post("/api/workflows/cancel")
async def cancel_workflow(request: dict):
    """Annuler un workflow en cours d'exécution"""
    task_id = request.get("task_id")
    
    if not task_id:
        raise HTTPException(status_code=400, detail="task_id requis")
    
    task = active_workflow_tasks.get(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Workflow non trouvé ou déjà terminé")
    
    if task.done():
        active_workflow_tasks.pop(task_id, None)
        return {"status": "already_completed", "message": "Le workflow était déjà terminé"}
    
    task.cancel()
    active_workflow_tasks.pop(task_id, None)
    
    await ws_manager.send_log("warning", f"Workflow {task_id} annulé par l'utilisateur")
    await ws_manager.send_workflow_update(
        workflow_id=task_id,
        status="cancelled"
    )
    
    return {"status": "cancelled", "message": f"Workflow {task_id} annulé"}


@app.get("/api/workflows/active")
async def get_active_workflows():
    """Liste des workflows actuellement en cours d'exécution"""
    active = []
    for task_id, task in list(active_workflow_tasks.items()):
        if task.done():
            active_workflow_tasks.pop(task_id, None)
        else:
            active.append({
                "task_id": task_id,
                "status": "running"
            })
    return {"active_workflows": active, "count": len(active)}

# ============================================================================
# ROUTES - Metasploit (API spécifique)
# ============================================================================

@app.post("/api/metasploit/payload")
async def generate_msf_payload(request: dict):
    """Générer un payload avec msfvenom"""
    return await metasploit_module.generate_payload(request)

@app.post("/api/metasploit/search")
async def search_msf_exploits(request: dict):
    """Rechercher des exploits dans Metasploit"""
    query = request.get("query", "")
    options = request.get("options", {})
    return await metasploit_module.search_exploits(query, options)

@app.post("/api/metasploit/check")
async def check_msf_exploit(request: dict):
    """Vérifier si une cible est vulnérable (sans exploitation)"""
    exploit = request.get("exploit", "")
    target = request.get("target", "")
    options = request.get("options", {})
    return await metasploit_module.check_exploit(exploit, target, options)

@app.post("/api/metasploit/exploit")
async def run_msf_exploit(request: dict):
    """Exécuter un exploit Metasploit"""
    return await metasploit_module.run_exploit(request)

@app.post("/api/metasploit/auxiliary")
async def run_msf_auxiliary(request: dict):
    """Exécuter un module auxiliaire Metasploit"""
    module = request.get("module", "")
    target = request.get("target", "")
    options = request.get("options", {})
    return await metasploit_module.run_auxiliary(module, target, options)

@app.post("/api/metasploit/handler")
async def start_msf_handler(request: dict):
    """Démarrer un handler Metasploit"""
    return await metasploit_module.start_handler(request)

@app.get("/api/metasploit/payloads")
async def list_msf_payloads(filter: str = ""):
    """Lister les payloads disponibles"""
    return await metasploit_module.list_payloads(filter)

# ============================================================================
# ROUTES - Résultats
# ============================================================================

@app.get("/api/results")
async def get_all_results():
    """Récupérer tous les résultats"""
    return current_session["results"]

@app.get("/api/results/{target_id}")
async def get_target_results(target_id: int):
    """Récupérer les résultats pour une cible"""
    if target_id not in current_session["results"]:
        raise HTTPException(status_code=404, detail="Aucun résultat pour cette cible")
    return current_session["results"][target_id]

@app.delete("/api/results")
async def clear_results():
    """Effacer tous les résultats"""
    current_session["results"] = {}
    return {"status": "success"}

# ============================================================================
# ROUTES - Rapports
# ============================================================================

@app.post("/api/reports/generate")
async def generate_report(request: dict):
    """Générer un rapport"""
    report_type = request.get("type", "oscp")  # oscp, client, json
    include_screenshots = request.get("include_screenshots", True)
    
    report = await report_generator.generate(
        report_type=report_type,
        targets=current_session["targets"],
        results=current_session["results"],
        include_screenshots=include_screenshots
    )
    
    return {"status": "success", "report_path": report}

@app.get("/api/reports/download/{filename}")
async def download_report(filename: str):
    """Télécharger un rapport généré"""
    reports_dir = Path(settings.REPORTS_DIR).resolve()
    filepath = (reports_dir / filename).resolve()

    if reports_dir not in filepath.parents and filepath != reports_dir:
        raise HTTPException(status_code=400, detail="Nom de fichier invalide")

    if not filepath.exists() or not filepath.is_file():
        raise HTTPException(status_code=404, detail="Rapport non trouvé")
    return FileResponse(str(filepath), filename=filepath.name)


async def replay_stored_command(command: str, task_id: str):
    """Rejoue une commande historique en tâche de fond"""
    executor = CommandExecutor()
    await ws_manager.send_log("info", f"Replay {task_id} démarré")

    try:
        result = await executor.run(command)

        if result.stdout:
            await ws_manager.send_output(command, result.stdout, "stdout")
        if result.stderr:
            await ws_manager.send_output(command, result.stderr, "stderr")

        level = "success" if result.return_code == 0 else "error"
        await ws_manager.send_log(
            level,
            f"Replay {task_id} terminé (exit={result.return_code}, durée={result.duration:.2f}s)"
        )
    except Exception as e:
        await ws_manager.send_log("error", f"Replay {task_id} échoué: {str(e)}")

@app.get("/api/reports/list")
async def list_reports():
    """Lister les rapports disponibles"""
    reports = []
    if os.path.exists(settings.REPORTS_DIR):
        for f in os.listdir(settings.REPORTS_DIR):
            filepath = os.path.join(settings.REPORTS_DIR, f)
            reports.append({
                "filename": f,
                "size": os.path.getsize(filepath),
                "created": os.path.getctime(filepath)
            })
    return reports

# ============================================================================
# ROUTES - Cache des résultats
# ============================================================================

@app.get("/api/cache/stats")
async def get_cache_stats():
    """Statistiques du cache des résultats"""
    from core.cache import cache
    return cache.get_stats()

@app.get("/api/cache/target/{target}")
async def get_cached_for_target(target: str):
    """Liste les résultats en cache pour une cible"""
    from core.cache import cache
    entries = cache.get_cached_for_target(target)
    return {"target": target, "cached_entries": entries, "count": len(entries)}

@app.post("/api/cache/invalidate")
async def invalidate_cache(request: dict):
    """Invalide des entrées du cache"""
    from core.cache import cache
    
    action = request.get("action")
    target = request.get("target")
    
    deleted = cache.invalidate(action=action, target=target)
    return {"status": "ok", "deleted": deleted}

@app.post("/api/cache/cleanup")
async def cleanup_cache():
    """Nettoie les entrées expirées du cache"""
    from core.cache import cache
    deleted = cache.cleanup_expired()
    return {"status": "ok", "deleted": deleted}

# ============================================================================
# ROUTES - Historique des commandes
# ============================================================================

@app.get("/api/history")
async def get_command_history(
    action: str = None,
    target: str = None,
    limit: int = 100,
    offset: int = 0
):
    """Récupère l'historique des commandes"""
    from core.history import command_history
    entries = command_history.search(action=action, target=target, limit=limit, offset=offset)
    return {
        "status": "ok",
        "count": len(entries),
        "entries": [
            {
                "id": e.id,
                "action": e.action,
                "target": e.target,
                "status": e.status,
                "timestamp": e.executed_at,
                "duration": e.duration,
                "success": e.status == "success",
                "exit_code": e.return_code
            } for e in entries
        ]
    }

@app.get("/api/history/stats")
async def get_history_stats():
    """Récupère les statistiques d'utilisation"""
    from core.history import command_history
    stats = command_history.get_statistics()
    return {"status": "ok", **stats}

@app.get("/api/history/{entry_id}")
async def get_history_entry(entry_id: int):
    """Récupère une entrée d'historique complète"""
    from core.history import command_history
    entry = command_history.get_entry(entry_id)
    if not entry:
        raise HTTPException(status_code=404, detail="Entrée non trouvée")
    return {
        "status": "ok",
        "entry": {
            "id": entry.id,
            "action": entry.action,
            "target": entry.target,
            "session_id": entry.session_id,
            "status": entry.status,
            "command": entry.command,
            "timestamp": entry.executed_at,
            "duration": entry.duration,
            "success": entry.status == "success",
            "exit_code": entry.return_code,
            "stdout_preview": entry.stdout_preview,
            "stderr_preview": entry.stderr_preview
        }
    }

@app.post("/api/history/{entry_id}/replay")
async def replay_history_entry(entry_id: int, background_tasks: BackgroundTasks):
    """Rejoue une commande depuis l'historique"""
    from core.history import command_history
    entry = command_history.get_entry(entry_id)
    if not entry:
        raise HTTPException(status_code=404, detail="Entrée non trouvée")
    
    # Créer un nouveau task_id pour la commande rejouée
    import uuid
    task_id = str(uuid.uuid4())[:8]
    
    # Lancer la commande en arrière-plan
    background_tasks.add_task(
        replay_stored_command,
        entry.command,
        task_id
    )
    
    return {
        "status": "ok",
        "message": f"Commande {entry.action} rejouée",
        "original_id": entry_id,
        "new_task_id": task_id
    }

@app.delete("/api/history")
async def clear_history(before_date: str = None):
    """Vide l'historique (optionnellement avant une date)"""
    from core.history import command_history
    deleted = command_history.clear(before_date)
    return {"status": "ok", "deleted": deleted}

@app.get("/api/history/export")
async def export_history(format: str = "json"):
    """Exporte l'historique complet"""
    from core.history import command_history
    if format == "json":
        data = command_history.export_history()
        return Response(
            content=data,
            media_type="application/json",
            headers={"Content-Disposition": "attachment; filename=history_export.json"}
        )
    else:
        raise HTTPException(status_code=400, detail="Format non supporté (json uniquement)")

# ============================================================================
# ROUTES - Templates de workflows personnalisés
# ============================================================================

@app.get("/api/templates")
async def list_workflow_templates(
    author: str = None,
    tags: str = None,
    target_type: str = None,
    is_public: bool = None,
    search: str = None,
    limit: int = 50,
    offset: int = 0
):
    """Liste les templates de workflows"""
    from workflows.templates import template_manager
    
    tag_list = tags.split(",") if tags else None
    templates = template_manager.list_templates(
        author=author,
        tags=tag_list,
        target_type=target_type,
        is_public=is_public,
        search=search,
        limit=limit,
        offset=offset
    )
    
    return {
        "status": "ok",
        "count": len(templates),
        "templates": [
            {
                "id": t.id,
                "name": t.name,
                "description": t.description,
                "author": t.author,
                "target_types": t.target_types,
                "step_count": len(t.steps),
                "auto_chain": t.auto_chain,
                "tags": t.tags,
                "is_public": t.is_public,
                "usage_count": t.usage_count,
                "rating": t.rating
            } for t in templates
        ]
    }

@app.post("/api/templates")
async def create_workflow_template(template: Dict[str, Any] = Body(...)):
    """Crée un nouveau template de workflow"""
    from workflows.templates import template_manager
    
    try:
        template_id = template_manager.create_template(template)
        return {"status": "ok", "template_id": template_id}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/api/templates/popular")
async def get_popular_templates(limit: int = 10):
    """Récupère les templates les plus populaires"""
    from workflows.templates import template_manager
    
    templates = template_manager.get_popular_templates(limit)
    return {
        "status": "ok",
        "templates": [
            {
                "id": t.id,
                "name": t.name,
                "description": t.description,
                "usage_count": t.usage_count,
                "rating": t.rating,
                "tags": t.tags
            } for t in templates
        ]
    }

@app.get("/api/templates/stats")
async def get_templates_stats():
    """Récupère les statistiques sur les templates"""
    from workflows.templates import template_manager
    return {"status": "ok", **template_manager.get_statistics()}

@app.get("/api/templates/{template_id}")
async def get_workflow_template(template_id: int):
    """Récupère un template par son ID"""
    from workflows.templates import template_manager
    
    template = template_manager.get_template(template_id)
    if not template:
        raise HTTPException(status_code=404, detail="Template non trouvé")
    
    return {
        "status": "ok",
        "template": {
            "id": template.id,
            "name": template.name,
            "description": template.description,
            "author": template.author,
            "target_types": template.target_types,
            "steps": template.steps,
            "auto_chain": template.auto_chain,
            "tags": template.tags,
            "is_public": template.is_public,
            "created_at": template.created_at,
            "updated_at": template.updated_at,
            "usage_count": template.usage_count,
            "rating": template.rating
        }
    }

@app.put("/api/templates/{template_id}")
async def update_workflow_template(template_id: int, updates: Dict[str, Any] = Body(...)):
    """Met à jour un template"""
    from workflows.templates import template_manager
    
    if not template_manager.update_template(template_id, updates):
        raise HTTPException(status_code=404, detail="Template non trouvé")
    
    return {"status": "ok", "message": "Template mis à jour"}

@app.delete("/api/templates/{template_id}")
async def delete_workflow_template(template_id: int):
    """Supprime un template"""
    from workflows.templates import template_manager
    
    if not template_manager.delete_template(template_id):
        raise HTTPException(status_code=404, detail="Template non trouvé")
    
    return {"status": "ok", "message": "Template supprimé"}

@app.post("/api/templates/{template_id}/clone")
async def clone_workflow_template(template_id: int, new_name: str, author: str = "user"):
    """Clone un template existant"""
    from workflows.templates import template_manager
    
    try:
        new_id = template_manager.clone_template(template_id, new_name, author)
        return {"status": "ok", "new_template_id": new_id}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

@app.get("/api/templates/{template_id}/export")
async def export_workflow_template(template_id: int):
    """Exporte un template en JSON"""
    from workflows.templates import template_manager
    from fastapi.responses import Response
    
    try:
        json_data = template_manager.export_template(template_id)
        return Response(
            content=json_data,
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename=template_{template_id}.json"}
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

@app.post("/api/templates/import")
async def import_workflow_template(json_data: str = Body(..., embed=True), author: str = "user"):
    """Importe un template depuis JSON"""
    from workflows.templates import template_manager
    
    try:
        template_id = template_manager.import_template(json_data, author)
        return {"status": "ok", "template_id": template_id}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/templates/{template_id}/rate")
async def rate_workflow_template(template_id: int, rating: float = Body(..., embed=True)):
    """Note un template (0-5)"""
    from workflows.templates import template_manager
    
    if rating < 0 or rating > 5:
        raise HTTPException(status_code=400, detail="Rating doit être entre 0 et 5")
    
    template_manager.rate_template(template_id, rating)
    return {"status": "ok", "message": f"Template noté: {rating}/5"}

@app.post("/api/templates/{template_id}/execute")
async def execute_template_workflow(
    template_id: int,
    target: Dict[str, Any] = Body(...),
    background_tasks: BackgroundTasks = None
):
    """Exécute un workflow depuis un template"""
    from workflows.templates import template_manager
    from workflows.engine import WorkflowEngine
    
    template = template_manager.get_template(template_id)
    if not template:
        raise HTTPException(status_code=404, detail="Template non trouvé")
    
    # Incrémenter le compteur d'utilisation
    template_manager.increment_usage(template_id)
    
    # Préparer le workflow pour exécution
    workflow_engine = WorkflowEngine()
    
    # Ajouter le template comme workflow temporaire
    temp_workflow_id = f"template_{template_id}"
    workflow_engine.workflows[temp_workflow_id] = {
        "id": temp_workflow_id,
        "name": template.name,
        "description": template.description,
        "target_types": template.target_types,
        "steps": template.steps,
        "auto_chain": template.auto_chain
    }
    
    # Exécuter en arrière-plan
    if background_tasks:
        background_tasks.add_task(
            workflow_engine.execute,
            temp_workflow_id,
            target,
            {},
            ws_manager,
            current_session.get("results", {})
        )
    
    return {
        "status": "ok",
        "message": f"Workflow '{template.name}' démarré",
        "template_id": template_id
    }

# ============================================================================
# ROUTES - Vérification des outils
# ============================================================================

@app.get("/api/tools/status")
async def get_tools_status():
    """Vérifie la disponibilité de tous les outils configurés"""
    from core.executor import executor
    
    available_tools = executor.get_available_tools()
    missing_tools = executor.get_missing_tools()
    
    return {
        "status": "ok" if not missing_tools else "warning",
        "total_tools": len(available_tools),
        "available_count": sum(1 for v in available_tools.values() if v),
        "missing_count": len(missing_tools),
        "tools": available_tools,
        "missing": missing_tools
    }


@app.get("/api/tools/check/{tool_name}")
async def check_single_tool(tool_name: str):
    """Vérifie si un outil spécifique est disponible"""
    from core.executor import executor
    
    is_available = executor.check_tool_available(tool_name)
    
    return {
        "tool": tool_name,
        "available": is_available,
        "message": f"{tool_name} est disponible" if is_available else f"{tool_name} n'est pas installé"
    }


# ============================================================================
# WebSocket - Communication temps réel
# ============================================================================

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket pour les mises à jour en temps réel"""
    if settings.REQUIRE_API_AUTH:
        headers = {k.lower(): v for k, v in websocket.headers.items()}
        query_token = websocket.query_params.get("token")
        if not _is_valid_api_token(headers, query_token):
            await websocket.close(code=1008, reason="API token invalide")
            return

    await ws_manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            # Gérer les messages entrants si nécessaire
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)

# ============================================================================
# ROUTES - Sessions persistantes (SQLite)
# ============================================================================

@app.get("/api/session/context")
async def get_session_context():
    """Retourne le contexte de session mémoire courant"""
    session_key = _current_client_session_key.get()
    targets = current_session.get("targets", []) or []
    results = current_session.get("results", {}) or {}
    action_count = sum(
        len(target_results)
        for target_results in results.values()
        if isinstance(target_results, dict)
    )

    return {
        "status": "ok",
        "session_key": session_key,
        "has_persistent_session": current_session.get("id") is not None,
        "target_count": len(targets),
        "result_target_count": len(results),
        "result_action_count": action_count
    }


@app.post("/api/session/context")
async def set_session_context(payload: Dict[str, Any] = Body(...)):
    """Change/rotate la clé de session mémoire pour les prochains appels"""
    previous_key = _current_client_session_key.get()

    rotate = bool(payload.get("rotate", False))
    requested_key = str(payload.get("session_key", "")).strip()
    set_cookie = bool(payload.get("set_cookie", True))

    if rotate or not requested_key:
        new_key = f"s_{uuid.uuid4().hex[:16]}"
    else:
        new_key = requested_key

    if not SESSION_KEY_PATTERN.match(new_key):
        raise HTTPException(
            status_code=400,
            detail="session_key invalide (caractères autorisés: a-zA-Z0-9_- ; taille max 64)"
        )

    # Initialiser l'espace mémoire de la nouvelle clé si absent
    token = _current_client_session_key.set(new_key)
    try:
        current_session.get("id")
    finally:
        _current_client_session_key.reset(token)

    response = JSONResponse(
        content={
            "status": "ok",
            "previous_session_key": previous_key,
            "session_key": new_key,
            "message": "Utilisez cette clé via X-Session-Key ou session_key query param"
        }
    )

    if set_cookie:
        response.set_cookie(
            key="hackinterface_session",
            value=new_key,
            httponly=True,
            samesite="lax",
            secure=False,
            path="/"
        )

    return response

@app.get("/api/sessions")
async def list_sessions():
    """Liste toutes les sessions sauvegardées"""
    return db.get_all_sessions()

@app.post("/api/sessions")
async def create_session(name: str = "Nouvelle Session", description: str = None, 
                         client_name: str = None):
    """Crée une nouvelle session persistante"""
    session_id = db.create_session(name, description, client_name)
    current_session["id"] = session_id
    current_session["targets"] = []
    current_session["results"] = {}
    return {"status": "success", "session_id": session_id}

@app.get("/api/sessions/{session_id}")
async def get_session(session_id: int):
    """Récupère les détails d'une session"""
    session = db.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session non trouvée")
    
    return {
        "session": session,
        "targets": db.get_targets(session_id),
        "stats": db.get_discovery_stats(session_id),
        "vuln_stats": db.get_vulnerability_stats(session_id)
    }

@app.post("/api/sessions/{session_id}/load")
async def load_session(session_id: int):
    """Charge une session existante dans la mémoire de travail"""
    session = db.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session non trouvée")
    
    # Charger dans current_session
    current_session["id"] = session_id
    targets = db.get_targets(session_id)
    current_session["targets"] = [
        {"id": t["id"], "type": t["type"], "value": t["value"], "description": t.get("name")}
        for t in targets
    ]
    
    # Charger les résultats
    current_session["results"] = {}
    for target in targets:
        results = db.get_results(session_id, target["id"])
        current_session["results"][target["id"]] = {
            r["action"]: {
                "status": r["status"],
                "output": r["output"],
                "parsed_data": r["parsed_data"]
            }
            for r in results
        }
    
    return {"status": "success", "message": f"Session '{session['name']}' chargée"}

@app.delete("/api/sessions/{session_id}")
async def delete_session(session_id: int):
    """Supprime une session"""
    if db.delete_session(session_id):
        if current_session["id"] == session_id:
            current_session["id"] = None
            current_session["targets"] = []
            current_session["results"] = {}
        return {"status": "success"}
    raise HTTPException(status_code=404, detail="Session non trouvée")

@app.get("/api/sessions/{session_id}/discoveries")
async def get_session_discoveries(session_id: int, discovery_type: str = None):
    """Récupère les découvertes d'une session"""
    return db.get_discoveries(session_id, discovery_type)

@app.get("/api/sessions/{session_id}/stats")
async def get_session_stats(session_id: int):
    """Statistiques complètes d'une session pour les graphiques"""
    session = db.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session non trouvée")
    
    return {
        "discovery_stats": db.get_discovery_stats(session_id),
        "vulnerability_stats": db.get_vulnerability_stats(session_id),
        "targets_count": len(db.get_targets(session_id)),
        "results_count": len(db.get_results(session_id))
    }

# ============================================================================
# ROUTES - Export / Import JSON
# ============================================================================

@app.get("/api/session/export")
async def export_current_session():
    """Exporte la session courante en JSON"""
    import json
    from datetime import datetime
    
    export_data = {
        "export_version": "1.0",
        "exported_at": datetime.now().isoformat(),
        "session": {
            "id": current_session.get("id"),
            "name": "Current Session"
        },
        "targets": current_session["targets"],
        "results": current_session["results"]
    }
    
    # Si session DB active, enrichir avec les données DB
    if current_session["id"]:
        db_export = db.export_session(current_session["id"])
        if db_export:
            export_data = db_export
    
    return export_data

@app.get("/api/sessions/{session_id}/export")
async def export_session(session_id: int):
    """Exporte une session spécifique en JSON"""
    export_data = db.export_session(session_id)
    if not export_data:
        raise HTTPException(status_code=404, detail="Session non trouvée")
    return export_data

@app.post("/api/session/import")
async def import_session(data: dict):
    """Importe une session depuis un JSON"""
    try:
        session_id = db.import_session(data)
        return {"status": "success", "session_id": session_id}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Erreur d'import: {str(e)}")

# ============================================================================
# Point d'entrée
# ============================================================================

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=settings.PORT,
        reload=True
    )
