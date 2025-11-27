#!/usr/bin/env python3
"""
HackInterface - Interface Web pour Pentest Automatisé
Point d'entrée principal de l'API FastAPI
"""

import os
import asyncio
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, UploadFile, File, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import uvicorn

from core.config import settings
from core.vpn import vpn_manager
from core.executor import CommandExecutor
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

# CORS pour usage local
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Servir les fichiers statiques du frontend
app.mount("/static", StaticFiles(directory="frontend/static"), name="static")

# ============================================================================
# ROUTES - Interface principale
# ============================================================================

@app.get("/", response_class=HTMLResponse)
async def root():
    """Page principale de l'interface"""
    return FileResponse("frontend/index.html")

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
    executor = CommandExecutor()
    result = await executor.run(f"ping -c 3 {request.target}")
    success = result.return_code == 0
    return {
        "success": success,
        "target": request.target,
        "output": result.stdout if success else result.stderr
    }

# ============================================================================
# ROUTES - Gestion des cibles
# ============================================================================

# Stockage en mémoire pour la session (pas de persistance multi-projets)
current_session = {
    "id": None,  # ID de session SQLite actuelle
    "targets": [],
    "results": {},
    "workflow_status": None
}

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
    
    # Lancer le workflow en arrière-plan
    asyncio.create_task(
        workflow_engine.execute(
            request.workflow_id,
            target,
            request.options or {},
            ws_manager,
            current_session["results"]
        )
    )
    
    return {"status": "started", "workflow_id": request.workflow_id}

@app.post("/api/workflows/custom")
async def run_custom_workflow(request: dict):
    """Lancer un workflow personnalisé avec actions sélectionnées"""
    target_id = request.get("target_id")
    actions = request.get("actions", [])
    
    target = next((t for t in current_session["targets"] if t["id"] == target_id), None)
    if not target:
        raise HTTPException(status_code=404, detail="Cible non trouvée")
    
    asyncio.create_task(
        workflow_engine.execute_custom(
            actions,
            target,
            ws_manager,
            current_session["results"]
        )
    )
    
    return {"status": "started", "actions": actions}

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
    filepath = os.path.join(settings.REPORTS_DIR, filename)
    if not os.path.exists(filepath):
        raise HTTPException(status_code=404, detail="Rapport non trouvé")
    return FileResponse(filepath, filename=filename)

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
# WebSocket - Communication temps réel
# ============================================================================

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket pour les mises à jour en temps réel"""
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
