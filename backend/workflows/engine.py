"""
Moteur de workflows
Gère l'exécution des workflows prédéfinis et personnalisés
avec enchaînement automatique basé sur les découvertes
"""
import asyncio
from typing import Dict, Any, List, Optional, Callable
from datetime import datetime

from core.websocket_manager import ConnectionManager
from modules.recon import ReconModule
from modules.web_enum import WebEnumModule
from modules.vuln_scan import VulnScanModule
from modules.exploitation import ExploitationModule
from modules.password_attacks import PasswordAttacksModule
from modules.metasploit import MetasploitModule
from modules.network import NetworkModule
from modules.osint import OSINTModule
from modules.web_advanced import WebAdvancedModule

class WorkflowEngine:
    """Moteur d'exécution de workflows"""
    
    def __init__(self):
        self.recon = ReconModule()
        self.web_enum = WebEnumModule()
        self.vuln_scan = VulnScanModule()
        self.exploit = ExploitationModule()
        self.password = PasswordAttacksModule()
        self.metasploit = MetasploitModule()
        self.network = NetworkModule()
        self.osint = OSINTModule()
        self.web_advanced = WebAdvancedModule()
        
        # Mapping des actions vers les fonctions
        self.action_map = {
            # Recon
            "nmap_quick": self.recon.nmap_quick,
            "nmap_full": self.recon.nmap_full,
            "nmap_vuln": self.recon.nmap_vuln,
            "nmap_udp": self.recon.nmap_udp,
            "whois": self.recon.whois_lookup,
            "dns_enum": self.recon.dns_enumeration,
            "subdomain_enum": self.recon.subdomain_enumeration,
            # Web Enum
            "gobuster": self.web_enum.gobuster,
            "feroxbuster": self.web_enum.feroxbuster,
            "ffuf": self.web_enum.ffuf,
            "nikto": self.web_enum.nikto,
            "whatweb": self.web_enum.whatweb,
            "wpscan": self.web_enum.wpscan,
            "curl_headers": self.web_enum.curl_headers,
            "screenshot": self.web_enum.screenshot,
            # Vuln Scan
            "nuclei": self.vuln_scan.nuclei_scan,
            "nuclei_network": self.vuln_scan.nuclei_network,
            "searchsploit": self.vuln_scan.searchsploit,
            "nmap_vulners": self.vuln_scan.nmap_vulners,
            "check_default_creds": self.vuln_scan.check_default_creds,
            "ssl_scan": self.vuln_scan.ssl_scan,
            # Exploitation
            "enum4linux": self.exploit.run_enum4linux,
            "smbclient": self.exploit.run_smbclient,
            "rpcclient": self.exploit.run_rpcclient,
            "ldapsearch": self.exploit.run_ldapsearch,
            # Password Attacks
            "hydra_ssh": self.password.hydra_ssh,
            "hydra_ftp": self.password.hydra_ftp,
            "hydra_smb": self.password.hydra_smb,
            "hydra_rdp": self.password.hydra_rdp,
            "hydra_http": self.password.hydra_http_post,
            "cewl": self.password.cewl,
            # Network
            "masscan": self.network.masscan,
            "sslscan": self.network.sslscan,
            "testssl": self.network.testssl,
            "arp_scan": self.network.arp_scan,
            "responder": self.network.responder,
            # OSINT
            "theharvester": self.osint.theharvester,
            "amass": self.osint.amass_enum,
            "sherlock": self.osint.sherlock,
            "wafw00f": self.osint.wafw00f,
            "exiftool": self.osint.exiftool,
            # Web Advanced
            "sqlmap": self.web_advanced.sqlmap_url,
            "ffuf_dir": self.web_advanced.ffuf_dir,
            "ffuf_vhost": self.web_advanced.ffuf_vhost,
            "feroxbuster_adv": self.web_advanced.feroxbuster,
            "commix": self.web_advanced.commix,
            "xsser": self.web_advanced.xsser,
            "dalfox": self.web_advanced.dalfox,
            "eyewitness": self.web_advanced.eyewitness,
            "droopescan": self.web_advanced.droopescan,
            "joomscan": self.web_advanced.joomscan,
            # Metasploit
            "msf_smb_version": self.metasploit.smb_version,
            "msf_smb_ms17_010": self.metasploit.smb_ms17_010,
            "msf_ssh_version": self.metasploit.ssh_version,
            "msf_ftp_version": self.metasploit.ftp_version,
            "msf_http_version": self.metasploit.http_version,
            "msf_mysql_login": self.metasploit.mysql_login,
            "msf_postgres_login": self.metasploit.postgres_login,
        }
        
        # Définition des workflows prédéfinis
        self.workflows = {
            "full_recon": {
                "id": "full_recon",
                "name": "Reconnaissance Complète",
                "description": "Scan complet: Nmap, DNS, sous-domaines (pour domaines)",
                "target_types": ["ip", "fqdn", "domain"],
                "steps": [
                    {"action": "nmap_quick", "name": "Nmap Quick Scan"},
                    {"action": "whois", "name": "WHOIS Lookup", "condition": "is_domain"},
                    {"action": "dns_enum", "name": "DNS Enumeration", "condition": "is_domain"},
                    {"action": "subdomain_enum", "name": "Subdomain Enumeration", "condition": "is_domain"},
                ],
                "auto_chain": True
            },
            "web_full": {
                "id": "web_full",
                "name": "Audit Web Complet",
                "description": "Énumération web complète avec scan de vulnérabilités",
                "target_types": ["ip", "fqdn", "url"],
                "steps": [
                    {"action": "whatweb", "name": "Technology Detection"},
                    {"action": "curl_headers", "name": "HTTP Headers Analysis"},
                    {"action": "screenshot", "name": "Screenshot"},
                    {"action": "gobuster", "name": "Directory Bruteforce"},
                    {"action": "nikto", "name": "Nikto Scan"},
                    {"action": "nuclei", "name": "Nuclei Vulnerability Scan"},
                ],
                "auto_chain": True
            },
            "wordpress_audit": {
                "id": "wordpress_audit",
                "name": "Audit WordPress",
                "description": "Audit complet d'un site WordPress",
                "target_types": ["url", "fqdn"],
                "steps": [
                    {"action": "whatweb", "name": "Technology Detection"},
                    {"action": "wpscan", "name": "WPScan Analysis"},
                    {"action": "nuclei", "name": "Nuclei WP Templates", "options": {"tags": "wordpress"}},
                ],
                "auto_chain": True
            },
            "network_vuln": {
                "id": "network_vuln",
                "name": "Scan Vulnérabilités Réseau",
                "description": "Scan complet des vulnérabilités réseau",
                "target_types": ["ip", "cidr"],
                "steps": [
                    {"action": "nmap_full", "name": "Full Port Scan"},
                    {"action": "nmap_vuln", "name": "Nmap Vuln Scripts"},
                    {"action": "nmap_vulners", "name": "Vulners Check"},
                    {"action": "nuclei_network", "name": "Nuclei Network Scan"},
                ],
                "auto_chain": True
            },
            "smb_enum": {
                "id": "smb_enum",
                "name": "Énumération SMB/Windows",
                "description": "Énumération complète des services Windows/SMB",
                "target_types": ["ip"],
                "steps": [
                    {"action": "nmap_quick", "name": "Quick Scan", "options": {"ports": "139,445"}},
                    {"action": "enum4linux", "name": "Enum4linux"},
                    {"action": "smbclient", "name": "SMB Shares"},
                    {"action": "rpcclient", "name": "RPC Enumeration"},
                ],
                "auto_chain": False
            },
            "quick_web": {
                "id": "quick_web",
                "name": "Audit Web Rapide",
                "description": "Audit web rapide pour une première évaluation",
                "target_types": ["ip", "fqdn", "url"],
                "steps": [
                    {"action": "whatweb", "name": "Technology Detection"},
                    {"action": "curl_headers", "name": "HTTP Headers"},
                    {"action": "screenshot", "name": "Screenshot"},
                    {"action": "nuclei", "name": "Quick Nuclei", "options": {"severity": "high,critical"}},
                ],
                "auto_chain": False
            },
            "oscp_box": {
                "id": "oscp_box",
                "name": "OSCP Box Methodology",
                "description": "Méthodologie complète style OSCP pour une machine",
                "target_types": ["ip"],
                "steps": [
                    {"action": "nmap_quick", "name": "Initial Scan"},
                    {"action": "nmap_full", "name": "Full Port Scan"},
                    {"action": "nmap_vuln", "name": "Vulnerability Scripts"},
                    # Auto-chain ajoutera les actions web si ports 80/443 détectés
                ],
                "auto_chain": True
            },
            # === NOUVEAUX WORKFLOWS ===
            "ad_pentest": {
                "id": "ad_pentest",
                "name": "Active Directory Pentest",
                "description": "Énumération et attaque Active Directory",
                "target_types": ["ip", "domain"],
                "steps": [
                    {"action": "nmap_quick", "name": "Port Scan", "options": {"ports": "53,88,135,139,389,445,464,636,3268,3269"}},
                    {"action": "enum4linux", "name": "SMB/Windows Enumeration"},
                    {"action": "ldapsearch", "name": "LDAP Enumeration"},
                    {"action": "msf_smb_ms17_010", "name": "EternalBlue Check"},
                    {"action": "responder", "name": "Responder (passive)", "options": {"analyze": True}},
                ],
                "auto_chain": True
            },
            "sql_injection": {
                "id": "sql_injection",
                "name": "SQL Injection Testing",
                "description": "Recherche et exploitation d'injections SQL",
                "target_types": ["url"],
                "steps": [
                    {"action": "wafw00f", "name": "WAF Detection"},
                    {"action": "sqlmap", "name": "SQLMap Scan"},
                    {"action": "nuclei", "name": "Nuclei SQLi Templates", "options": {"tags": "sqli"}},
                ],
                "auto_chain": False
            },
            "xss_testing": {
                "id": "xss_testing",
                "name": "XSS Testing",
                "description": "Recherche de vulnérabilités XSS",
                "target_types": ["url"],
                "steps": [
                    {"action": "wafw00f", "name": "WAF Detection"},
                    {"action": "xsser", "name": "XSSer Scan"},
                    {"action": "dalfox", "name": "Dalfox XSS Scanner"},
                    {"action": "nuclei", "name": "Nuclei XSS Templates", "options": {"tags": "xss"}},
                ],
                "auto_chain": False
            },
            "bruteforce_services": {
                "id": "bruteforce_services",
                "name": "Service Brute-Force",
                "description": "Brute-force des services courants (SSH, FTP, SMB, RDP)",
                "target_types": ["ip"],
                "steps": [
                    {"action": "nmap_quick", "name": "Port Scan"},
                    {"action": "hydra_ssh", "name": "SSH Brute-Force", "condition": "has_ssh"},
                    {"action": "hydra_ftp", "name": "FTP Brute-Force", "condition": "has_ftp"},
                    {"action": "hydra_smb", "name": "SMB Brute-Force", "condition": "has_smb"},
                    {"action": "hydra_rdp", "name": "RDP Brute-Force", "condition": "has_rdp"},
                ],
                "auto_chain": True
            },
            "external_recon": {
                "id": "external_recon",
                "name": "External OSINT Recon",
                "description": "Reconnaissance OSINT externe complète",
                "target_types": ["domain", "fqdn"],
                "steps": [
                    {"action": "whois", "name": "WHOIS Lookup"},
                    {"action": "dns_enum", "name": "DNS Enumeration"},
                    {"action": "theharvester", "name": "theHarvester OSINT"},
                    {"action": "amass", "name": "Amass Subdomain Enum"},
                    {"action": "subdomain_enum", "name": "Subdomain Discovery"},
                ],
                "auto_chain": True
            },
            "full_web_audit": {
                "id": "full_web_audit",
                "name": "Full Web Application Audit",
                "description": "Audit complet d'application web avec tous les tests",
                "target_types": ["url", "fqdn"],
                "steps": [
                    {"action": "wafw00f", "name": "WAF Detection"},
                    {"action": "whatweb", "name": "Technology Detection"},
                    {"action": "sslscan", "name": "SSL/TLS Analysis"},
                    {"action": "ffuf_dir", "name": "Directory Fuzzing"},
                    {"action": "nikto", "name": "Nikto Scan"},
                    {"action": "nuclei", "name": "Nuclei Full Scan"},
                    {"action": "sqlmap", "name": "SQL Injection Test"},
                    {"action": "xsser", "name": "XSS Test"},
                    {"action": "commix", "name": "Command Injection Test"},
                ],
                "auto_chain": False
            },
            "internal_network": {
                "id": "internal_network",
                "name": "Internal Network Discovery",
                "description": "Découverte et scan du réseau interne",
                "target_types": ["cidr", "ip"],
                "steps": [
                    {"action": "arp_scan", "name": "ARP Scan"},
                    {"action": "masscan", "name": "Fast Port Scan"},
                    {"action": "nmap_quick", "name": "Service Detection"},
                ],
                "auto_chain": True
            },
            "metasploit_scan": {
                "id": "metasploit_scan",
                "name": "Metasploit Auxiliary Scan",
                "description": "Scans avec modules auxiliaires Metasploit",
                "target_types": ["ip"],
                "steps": [
                    {"action": "nmap_quick", "name": "Initial Port Scan"},
                    {"action": "msf_smb_version", "name": "SMB Version", "condition": "has_smb"},
                    {"action": "msf_smb_ms17_010", "name": "EternalBlue Check", "condition": "has_smb"},
                    {"action": "msf_ssh_version", "name": "SSH Version", "condition": "has_ssh"},
                    {"action": "msf_ftp_version", "name": "FTP Version", "condition": "has_ftp"},
                    {"action": "msf_http_version", "name": "HTTP Version", "condition": "has_web"},
                ],
                "auto_chain": True
            },
            "database_enum": {
                "id": "database_enum",
                "name": "Database Enumeration",
                "description": "Énumération des bases de données",
                "target_types": ["ip"],
                "steps": [
                    {"action": "nmap_quick", "name": "DB Port Scan", "options": {"ports": "1433,1521,3306,5432,27017,6379"}},
                    {"action": "msf_mysql_login", "name": "MySQL Login Test", "condition": "has_mysql"},
                    {"action": "msf_postgres_login", "name": "PostgreSQL Login Test", "condition": "has_postgres"},
                ],
                "auto_chain": True
            },
            "cms_audit": {
                "id": "cms_audit",
                "name": "CMS Security Audit",
                "description": "Audit de sécurité CMS (WordPress, Joomla, Drupal)",
                "target_types": ["url", "fqdn"],
                "steps": [
                    {"action": "whatweb", "name": "CMS Detection"},
                    {"action": "wpscan", "name": "WordPress Scan", "condition": "has_wordpress"},
                    {"action": "joomscan", "name": "Joomla Scan", "condition": "has_joomla"},
                    {"action": "droopescan", "name": "Drupal/Other CMS Scan", "condition": "has_drupal"},
                    {"action": "nuclei", "name": "CMS Vulnerability Scan", "options": {"tags": "cms,wordpress,joomla,drupal"}},
                ],
                "auto_chain": True
            },
        }
    
    def get_available_workflows(self) -> List[Dict[str, Any]]:
        """Retourne la liste des workflows disponibles"""
        return [
            {
                "id": w["id"],
                "name": w["name"],
                "description": w["description"],
                "target_types": w["target_types"],
                "step_count": len(w["steps"]),
                "auto_chain": w["auto_chain"]
            }
            for w in self.workflows.values()
        ]
    
    async def execute(
        self,
        workflow_id: str,
        target: Dict[str, Any],
        options: Dict[str, Any],
        ws_manager: ConnectionManager,
        results_store: Dict[str, Any]
    ):
        """
        Exécute un workflow prédéfini
        """
        if workflow_id not in self.workflows:
            await ws_manager.send_log("error", f"Workflow inconnu: {workflow_id}")
            return
        
        workflow = self.workflows[workflow_id]
        target_id = target["id"]
        target_value = target["value"]
        target_type = target["type"]
        
        await ws_manager.send_workflow_update(
            workflow_id=workflow_id,
            status="started",
            total_steps=len(workflow["steps"])
        )
        
        # Initialiser le stockage des résultats
        if target_id not in results_store:
            results_store[target_id] = {}
        
        executed_actions = []
        discovered_services = []
        
        for i, step in enumerate(workflow["steps"]):
            action = step["action"]
            step_name = step["name"]
            step_options = {**options, **step.get("options", {})}
            
            # Vérifier les conditions
            if "condition" in step:
                if not self._check_condition(step["condition"], target_type, results_store.get(target_id, {})):
                    await ws_manager.send_log("info", f"Étape '{step_name}' ignorée (condition non remplie)")
                    continue
            
            await ws_manager.send_workflow_update(
                workflow_id=workflow_id,
                status="running",
                current_step=step_name,
                current_step_num=i + 1,
                total_steps=len(workflow["steps"])
            )
            
            await ws_manager.send_log("info", f"Exécution: {step_name}")
            
            try:
                if action in self.action_map:
                    result = await self.action_map[action](target_value, step_options)
                    results_store[target_id][action] = result
                    executed_actions.append(action)
                    
                    # Envoyer la mise à jour
                    await ws_manager.send_action_update(
                        action=action,
                        status="completed",
                        target_id=target_id,
                        data=result
                    )
                    
                    # Analyser les découvertes pour l'enchaînement automatique
                    if workflow["auto_chain"]:
                        new_services = self._analyze_discoveries(action, result)
                        discovered_services.extend(new_services)
                        
            except Exception as e:
                await ws_manager.send_log("error", f"Erreur lors de '{step_name}': {str(e)}")
                results_store[target_id][action] = {
                    "action": action,
                    "status": "error",
                    "error": str(e)
                }
        
        # Enchaînement automatique basé sur les découvertes
        if workflow["auto_chain"] and discovered_services:
            await self._auto_chain(
                discovered_services,
                target,
                ws_manager,
                results_store,
                executed_actions
            )
        
        await ws_manager.send_workflow_update(
            workflow_id=workflow_id,
            status="completed"
        )
        
        await ws_manager.send_log("success", f"Workflow '{workflow['name']}' terminé")
    
    async def execute_custom(
        self,
        actions: List[str],
        target: Dict[str, Any],
        ws_manager: ConnectionManager,
        results_store: Dict[str, Any]
    ):
        """
        Exécute un workflow personnalisé
        """
        target_id = target["id"]
        target_value = target["value"]
        
        await ws_manager.send_workflow_update(
            workflow_id="custom",
            status="started",
            total_steps=len(actions)
        )
        
        if target_id not in results_store:
            results_store[target_id] = {}
        
        for i, action in enumerate(actions):
            await ws_manager.send_workflow_update(
                workflow_id="custom",
                status="running",
                current_step=action,
                current_step_num=i + 1,
                total_steps=len(actions)
            )
            
            await ws_manager.send_log("info", f"Exécution: {action}")
            
            try:
                if action in self.action_map:
                    result = await self.action_map[action](target_value, {})
                    results_store[target_id][action] = result
                    
                    await ws_manager.send_action_update(
                        action=action,
                        status="completed",
                        target_id=target_id,
                        data=result
                    )
            except Exception as e:
                await ws_manager.send_log("error", f"Erreur: {str(e)}")
                results_store[target_id][action] = {
                    "action": action,
                    "status": "error",
                    "error": str(e)
                }
        
        await ws_manager.send_workflow_update(
            workflow_id="custom",
            status="completed"
        )
    
    def _check_condition(
        self,
        condition: str,
        target_type: str,
        current_results: Dict[str, Any]
    ) -> bool:
        """Vérifie une condition basée sur le type de cible ou les résultats précédents"""
        
        # Conditions basées sur le type de cible
        if condition == "is_domain":
            return target_type in ["domain", "fqdn"]
        elif condition == "is_ip":
            return target_type == "ip"
        elif condition == "is_url":
            return target_type == "url"
        elif condition == "is_cidr":
            return target_type == "cidr"
        
        # Conditions basées sur les ports découverts
        elif condition == "has_web":
            return self._has_port(current_results, [80, 443, 8080, 8443, 8000, 8888])
        elif condition == "has_http":
            return self._has_port(current_results, [80, 8080, 8000, 8888])
        elif condition == "has_https":
            return self._has_port(current_results, [443, 8443])
        elif condition == "has_ssh":
            return self._has_port(current_results, [22])
        elif condition == "has_ftp":
            return self._has_port(current_results, [21])
        elif condition == "has_smb":
            return self._has_port(current_results, [139, 445])
        elif condition == "has_rdp":
            return self._has_port(current_results, [3389])
        elif condition == "has_mysql":
            return self._has_port(current_results, [3306])
        elif condition == "has_postgres":
            return self._has_port(current_results, [5432])
        elif condition == "has_mssql":
            return self._has_port(current_results, [1433])
        elif condition == "has_oracle":
            return self._has_port(current_results, [1521])
        elif condition == "has_mongodb":
            return self._has_port(current_results, [27017])
        elif condition == "has_redis":
            return self._has_port(current_results, [6379])
        elif condition == "has_ldap":
            return self._has_port(current_results, [389, 636, 3268, 3269])
        elif condition == "has_kerberos":
            return self._has_port(current_results, [88])
        elif condition == "has_dns":
            return self._has_port(current_results, [53])
        elif condition == "has_smtp":
            return self._has_port(current_results, [25, 587, 465])
        elif condition == "has_snmp":
            return self._has_port(current_results, [161, 162])
        elif condition == "has_vnc":
            return self._has_port(current_results, [5900, 5901, 5902])
        elif condition == "has_telnet":
            return self._has_port(current_results, [23])
        elif condition == "has_winrm":
            return self._has_port(current_results, [5985, 5986])
        
        # Conditions basées sur les résultats d'analyse
        elif condition == "has_wordpress":
            return self._has_technology(current_results, "wordpress")
        elif condition == "has_joomla":
            return self._has_technology(current_results, "joomla")
        elif condition == "has_drupal":
            return self._has_technology(current_results, "drupal")
        elif condition == "has_waf":
            return self._has_waf(current_results)
        
        # Condition par défaut : True (exécuter l'étape)
        return True
    
    def _has_port(self, current_results: Dict[str, Any], ports: List[int]) -> bool:
        """Vérifie si un port est ouvert dans les résultats Nmap"""
        # Chercher dans tous les résultats Nmap possibles
        nmap_keys = ["nmap_quick", "nmap_full", "nmap_vuln", "nmap_udp", "masscan"]
        
        for key in nmap_keys:
            nmap_result = current_results.get(key, {})
            if nmap_result and isinstance(nmap_result, dict) and "parsed_data" in nmap_result:
                parsed_data = nmap_result["parsed_data"]
                if isinstance(parsed_data, dict):
                    for host in parsed_data.get("hosts", []):
                        for port_info in host.get("ports", []):
                            if port_info.get("state") == "open" and port_info.get("port") in ports:
                                return True
        return False
    
    def _has_technology(self, current_results: Dict[str, Any], tech: str) -> bool:
        """Vérifie si une technologie spécifique a été détectée"""
        whatweb_result = current_results.get("whatweb", {})
        if whatweb_result:
            output = whatweb_result.get("output", "").lower()
            if tech.lower() in output:
                return True
            parsed = whatweb_result.get("parsed_data", {})
            if isinstance(parsed, dict) and parsed.get("cms", "").lower() == tech.lower():
                return True
        return False
    
    def _has_waf(self, current_results: Dict[str, Any]) -> bool:
        """Vérifie si un WAF a été détecté"""
        wafw00f_result = current_results.get("wafw00f", {})
        if wafw00f_result:
            output = wafw00f_result.get("output", "").lower()
            # wafw00f affiche "No WAF detected" si pas de WAF
            if "no waf detected" in output or "is not behind" in output:
                return False
            if "is behind" in output or "waf detected" in output:
                return True
        return False
    
    def _analyze_discoveries(
        self,
        action: str,
        result: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Analyse les résultats pour identifier les services à exploiter
        """
        services = []
        
        # Analyse des résultats Nmap
        if action in ["nmap_quick", "nmap_full", "nmap_vuln", "masscan"]:
            parsed = result.get("parsed_data", {})
            for host in parsed.get("hosts", []):
                for port in host.get("ports", []):
                    if port["state"] == "open":
                        services.append({
                            "port": port["port"],
                            "service": port["service"],
                            "version": port.get("version", ""),
                            "scripts": port.get("scripts", [])
                        })
        
        # Analyse des résultats WhatWeb pour détecter les CMS
        if action == "whatweb":
            output = result.get("output", "").lower()
            parsed = result.get("parsed_data", {})
            
            if "wordpress" in output or parsed.get("cms") == "wordpress":
                services.append({"detected_cms": "wordpress"})
            elif "joomla" in output or parsed.get("cms") == "joomla":
                services.append({"detected_cms": "joomla"})
            elif "drupal" in output or parsed.get("cms") == "drupal":
                services.append({"detected_cms": "drupal"})
        
        # Analyse des résultats pour détecter des vulnérabilités connues
        if action in ["nmap_vuln", "nmap_vulners"]:
            output = result.get("output", "").lower()
            parsed = result.get("parsed_data", {})
            
            # Détecter des vulnérabilités spécifiques
            if "ms17-010" in output or "eternalblue" in output:
                services.append({"vulnerability": "ms17-010", "exploit": "eternalblue"})
            if "ms08-067" in output:
                services.append({"vulnerability": "ms08-067", "exploit": "netapi"})
        
        return services
    
    async def _auto_chain(
        self,
        discovered_services: List[Dict[str, Any]],
        target: Dict[str, Any],
        ws_manager: ConnectionManager,
        results_store: Dict[str, Any],
        already_executed: List[str]
    ):
        """
        Enchaîne automatiquement des actions basées sur les découvertes
        """
        target_id = target["id"]
        target_value = target["value"]
        
        additional_actions = []
        
        for service in discovered_services:
            # Détection de CMS
            if "detected_cms" in service:
                cms = service["detected_cms"]
                if cms == "wordpress" and "wpscan" not in already_executed:
                    additional_actions.append(("wpscan", {}))
                elif cms == "joomla" and "joomscan" not in already_executed:
                    additional_actions.append(("joomscan", {}))
                elif cms == "drupal" and "droopescan" not in already_executed:
                    additional_actions.append(("droopescan", {}))
                continue
            
            # Détection de vulnérabilités connues
            if "vulnerability" in service:
                vuln = service["vulnerability"]
                if vuln == "ms17-010" and "msf_smb_ms17_010" not in already_executed:
                    additional_actions.append(("msf_smb_ms17_010", {}))
                continue
            
            port = service.get("port")
            svc = service.get("service", "").lower()
            version = service.get("version", "").lower()
            
            if not port:
                continue
            
            # Services web HTTP
            if port in [80, 8080, 8000, 8888] or ("http" in svc and "https" not in svc):
                if "whatweb" not in already_executed:
                    additional_actions.append(("whatweb", {}))
                if "gobuster" not in already_executed:
                    additional_actions.append(("gobuster", {}))
                if "nuclei" not in already_executed:
                    additional_actions.append(("nuclei", {}))
                if "nikto" not in already_executed:
                    additional_actions.append(("nikto", {}))
            
            # Services web HTTPS
            if port in [443, 8443] or "https" in svc or "ssl" in svc:
                if "ssl_scan" not in already_executed:
                    additional_actions.append(("ssl_scan", {}))
                if "whatweb" not in already_executed:
                    additional_actions.append(("whatweb", {}))
                if "nuclei" not in already_executed:
                    additional_actions.append(("nuclei", {}))
            
            # SSH
            if port == 22 or "ssh" in svc:
                if "msf_ssh_version" not in already_executed:
                    additional_actions.append(("msf_ssh_version", {}))
                # Rechercher des vulnérabilités connues dans la version
                if version and ("7.2" in version or "libssh" in version):
                    if "searchsploit" not in already_executed:
                        additional_actions.append(("searchsploit", {"query": f"ssh {version}"}))
            
            # FTP
            if port == 21 or "ftp" in svc:
                if "msf_ftp_version" not in already_executed:
                    additional_actions.append(("msf_ftp_version", {}))
                # Vérifier si anonymous login possible
                if "anonymous" in version.lower() or "anonymous" in str(service.get("scripts", [])).lower():
                    additional_actions.append(("ftp_anonymous", {}))
            
            # SMB / Windows
            if port in [139, 445] or "smb" in svc or "microsoft-ds" in svc or "netbios" in svc:
                if "enum4linux" not in already_executed:
                    additional_actions.append(("enum4linux", {}))
                if "smbclient" not in already_executed:
                    additional_actions.append(("smbclient", {}))
                if "msf_smb_version" not in already_executed:
                    additional_actions.append(("msf_smb_version", {}))
                if "msf_smb_ms17_010" not in already_executed:
                    additional_actions.append(("msf_smb_ms17_010", {}))
            
            # RDP
            if port == 3389 or "rdp" in svc or "ms-wbt-server" in svc:
                if "nmap_rdp" not in already_executed:
                    # Scan RDP spécifique avec scripts NSE
                    additional_actions.append(("nmap_quick", {"ports": "3389", "scripts": "rdp-*"}))
            
            # LDAP / Active Directory
            if port in [389, 636, 3268, 3269] or "ldap" in svc:
                if "ldapsearch" not in already_executed:
                    additional_actions.append(("ldapsearch", {}))
            
            # Kerberos
            if port == 88 or "kerberos" in svc:
                if "enum4linux" not in already_executed:
                    additional_actions.append(("enum4linux", {}))
            
            # MySQL
            if port == 3306 or "mysql" in svc:
                if "msf_mysql_login" not in already_executed:
                    additional_actions.append(("msf_mysql_login", {}))
            
            # PostgreSQL
            if port == 5432 or "postgres" in svc:
                if "msf_postgres_login" not in already_executed:
                    additional_actions.append(("msf_postgres_login", {}))
            
            # MSSQL
            if port == 1433 or "ms-sql" in svc or "mssql" in svc:
                if "nmap_quick" not in already_executed or True:  # Toujours faire un scan spécifique
                    additional_actions.append(("nmap_quick", {"ports": "1433", "scripts": "ms-sql-*"}))
            
            # Redis
            if port == 6379 or "redis" in svc:
                additional_actions.append(("nmap_quick", {"ports": "6379", "scripts": "redis-*"}))
            
            # MongoDB
            if port == 27017 or "mongodb" in svc:
                additional_actions.append(("nmap_quick", {"ports": "27017", "scripts": "mongodb-*"}))
            
            # SNMP
            if port == 161 or "snmp" in svc:
                additional_actions.append(("nmap_quick", {"ports": "161", "scripts": "snmp-*"}))
            
            # DNS
            if port == 53 or "dns" in svc or "domain" in svc:
                if "dns_enum" not in already_executed:
                    additional_actions.append(("dns_enum", {}))
            
            # SMTP
            if port == 25 or port == 587 or "smtp" in svc:
                additional_actions.append(("nmap_quick", {"ports": "25,587", "scripts": "smtp-*"}))
            
            # Recherche d'exploits si version détectée
            if version and len(version) > 3:
                service_name = svc.split("/")[0] if "/" in svc else svc
                if service_name and "searchsploit" not in already_executed:
                    # Ne pas faire trop de recherches searchsploit
                    pass  # On pourrait ajouter: additional_actions.append(("searchsploit", {"query": f"{service_name} {version}"}))
        
        # Dédupliquer les actions
        seen_actions = set()
        unique_actions = []
        for action, options in additional_actions:
            action_key = f"{action}_{str(options)}"
            if action_key not in seen_actions and action not in already_executed:
                seen_actions.add(action_key)
                unique_actions.append((action, options))
        
        # Exécuter les actions additionnelles
        if unique_actions:
            await ws_manager.send_log("info", f"🔗 Enchaînement automatique: {len(unique_actions)} actions supplémentaires détectées")
            
            for action, options in unique_actions:
                if action in already_executed:
                    continue
                
                # Vérifier que l'action existe
                if action not in self.action_map:
                    await ws_manager.send_log("warning", f"Action inconnue ignorée: {action}")
                    continue
                    
                await ws_manager.send_log("info", f"⚡ Auto-chain: {action}")
                
                try:
                    result = await self.action_map[action](target_value, options)
                    results_store[target_id][action] = result
                    already_executed.append(action)
                    
                    await ws_manager.send_action_update(
                        action=action,
                        status="completed",
                        target_id=target_id,
                        data=result
                    )
                    
                    # Analyser récursivement les nouvelles découvertes
                    new_discoveries = self._analyze_discoveries(action, result)
                    if new_discoveries:
                        await ws_manager.send_log("info", f"🔍 Nouvelles découvertes depuis {action}, analyse en cours...")
                        await self._auto_chain(
                            new_discoveries,
                            target,
                            ws_manager,
                            results_store,
                            already_executed
                        )
                        
                except Exception as e:
                    await ws_manager.send_log("error", f"❌ Auto-chain error ({action}): {str(e)}")
