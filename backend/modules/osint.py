"""
Module OSINT et Information Gathering avancé
"""
import re
import json
from typing import Dict, Any, List
from datetime import datetime

from core.executor import CommandExecutor, escape_shell_arg
from core.config import settings


class OSINTModule:
    """Module de collecte d'informations OSINT"""
    
    def __init__(self):
        self.executor = CommandExecutor()
    
    async def theharvester(self, domain: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Collecte d'emails et sous-domaines avec theHarvester
        """
        options = options or {}
        domain_safe = escape_shell_arg(domain)
        
        sources = options.get("sources", "bing,google,linkedin,twitter,yahoo")
        limit = options.get("limit", 500)
        
        cmd = f"theHarvester -d {domain_safe} -b {sources} -l {limit}"
        
        result = await self.executor.run(cmd, timeout=300)
        
        parsed = self._parse_theharvester(result.stdout)
        
        return {
            "action": "theharvester",
            "target": domain,
            "status": "completed" if result.return_code == 0 else "error",
            "command": cmd,
            "output": result.stdout,
            "error": result.stderr if result.return_code != 0 else None,
            "duration": result.duration,
            "timestamp": result.timestamp,
            "parsed_data": parsed
        }
    
    async def amass_enum(self, domain: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Énumération de sous-domaines avec Amass
        """
        options = options or {}
        domain_safe = escape_shell_arg(domain)
        
        passive = options.get("passive", True)
        output_file = f"/tmp/amass_{domain_safe}_{int(datetime.now().timestamp())}.json"
        
        mode = "-passive" if passive else ""
        cmd = f"amass enum {mode} -d {domain_safe} -json {output_file}"
        
        result = await self.executor.run(cmd, timeout=600)
        
        # Lire les résultats JSON
        subdomains = []
        if result.return_code == 0:
            try:
                with open(output_file, 'r') as f:
                    for line in f:
                        data = json.loads(line)
                        if data.get('name'):
                            subdomains.append(data['name'])
            except:
                pass
        
        return {
            "action": "amass",
            "target": domain,
            "status": "completed" if result.return_code == 0 else "error",
            "command": cmd,
            "output": result.stdout,
            "error": result.stderr if result.return_code != 0 else None,
            "duration": result.duration,
            "timestamp": result.timestamp,
            "parsed_data": {
                "subdomains": subdomains,
                "count": len(subdomains)
            }
        }
    
    async def recon_ng(self, domain: str, modules: List[str] = None) -> Dict[str, Any]:
        """
        Exécuter des modules recon-ng
        """
        domain_safe = escape_shell_arg(domain)
        
        if not modules:
            modules = [
                "recon/domains-hosts/bing_domain_web",
                "recon/domains-hosts/google_site_web",
                "recon/domains-hosts/hackertarget",
            ]
        
        # Créer un resource script pour recon-ng
        rc_content = f"""
workspaces create hackinterface
set DOMAIN {domain}
"""
        for module in modules:
            rc_content += f"""
modules load {module}
run
"""
        rc_content += "exit\n"
        
        rc_file = f"/tmp/reconng_{int(datetime.now().timestamp())}.rc"
        with open(rc_file, 'w') as f:
            f.write(rc_content)
        
        cmd = f"recon-ng -r {rc_file}"
        
        result = await self.executor.run(cmd, timeout=300)
        
        return {
            "action": "recon_ng",
            "target": domain,
            "modules": modules,
            "status": "completed" if result.return_code == 0 else "error",
            "command": cmd,
            "output": result.stdout,
            "error": result.stderr if result.return_code != 0 else None,
            "duration": result.duration,
            "timestamp": result.timestamp
        }
    
    async def spiderfoot(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Scan OSINT avec SpiderFoot
        """
        options = options or {}
        target_safe = escape_shell_arg(target)
        
        modules = options.get("modules", "")
        output_file = f"/tmp/spiderfoot_{int(datetime.now().timestamp())}.json"
        
        modules_arg = f"-m {modules}" if modules else ""
        cmd = f"spiderfoot -s {target_safe} {modules_arg} -o json > {output_file}"
        
        result = await self.executor.run(cmd, timeout=600)
        
        # Lire les résultats
        parsed = {"results": []}
        try:
            with open(output_file, 'r') as f:
                parsed = json.load(f)
        except:
            pass
        
        return {
            "action": "spiderfoot",
            "target": target,
            "status": "completed" if result.return_code == 0 else "error",
            "command": cmd,
            "output": result.stdout,
            "duration": result.duration,
            "timestamp": result.timestamp,
            "parsed_data": parsed
        }
    
    async def sherlock(self, username: str) -> Dict[str, Any]:
        """
        Recherche de comptes sur les réseaux sociaux avec Sherlock
        """
        username_safe = escape_shell_arg(username)
        
        cmd = f"sherlock {username_safe} --print-found"
        
        result = await self.executor.run(cmd, timeout=300)
        
        parsed = self._parse_sherlock(result.stdout)
        
        return {
            "action": "sherlock",
            "target": username,
            "status": "completed" if result.return_code == 0 else "error",
            "command": cmd,
            "output": result.stdout,
            "error": result.stderr if result.return_code != 0 else None,
            "duration": result.duration,
            "timestamp": result.timestamp,
            "parsed_data": parsed
        }
    
    async def dmitry(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Reconnaissance avec DMitry
        """
        options = options or {}
        target_safe = escape_shell_arg(target)
        
        # Options: -w (whois), -n (netcraft), -s (subdomains), -e (emails), -p (port scan)
        flags = options.get("flags", "-wns")
        
        cmd = f"dmitry {flags} {target_safe}"
        
        result = await self.executor.run(cmd, timeout=180)
        
        return {
            "action": "dmitry",
            "target": target,
            "status": "completed" if result.return_code == 0 else "error",
            "command": cmd,
            "output": result.stdout,
            "error": result.stderr if result.return_code != 0 else None,
            "duration": result.duration,
            "timestamp": result.timestamp
        }
    
    async def maltego_transform(self, entity_type: str, value: str) -> Dict[str, Any]:
        """
        Information sur les transforms Maltego disponibles
        Note: Maltego est un outil GUI, on fournit les commandes pour utilisation manuelle
        """
        transforms = {
            "domain": [
                "ToDNSName",
                "ToEmailAddress",
                "ToIPAddress",
                "ToMXRecord",
                "ToNSRecord",
                "ToWebsite",
            ],
            "email": [
                "ToPersonalDomain",
                "ToPerson",
            ],
            "ip": [
                "ToLocation",
                "ToDomain",
                "ToNetblock",
            ],
            "person": [
                "ToPhoneNumber",
                "ToEmailAddress",
                "ToSocialMediaProfile",
            ]
        }
        
        suggested = transforms.get(entity_type.lower(), [])
        
        return {
            "action": "maltego_info",
            "entity_type": entity_type,
            "value": value,
            "status": "info",
            "message": "Maltego est un outil GUI. Voici les transforms suggérés:",
            "parsed_data": {
                "suggested_transforms": suggested,
                "usage": f"Dans Maltego, créez une entité {entity_type} avec la valeur '{value}' et appliquez les transforms"
            }
        }
    
    async def exiftool(self, file_path: str) -> Dict[str, Any]:
        """
        Extraire les métadonnées avec exiftool
        """
        cmd = f"exiftool -j '{file_path}'"
        
        result = await self.executor.run(cmd, timeout=60)
        
        parsed = {}
        if result.return_code == 0:
            try:
                parsed = json.loads(result.stdout)[0]
            except:
                pass
        
        return {
            "action": "exiftool",
            "target": file_path,
            "status": "completed" if result.return_code == 0 else "error",
            "command": cmd,
            "output": result.stdout,
            "error": result.stderr if result.return_code != 0 else None,
            "duration": result.duration,
            "timestamp": result.timestamp,
            "parsed_data": parsed
        }
    
    async def metagoofil(self, domain: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Extraction de métadonnées de documents publics
        """
        options = options or {}
        domain_safe = escape_shell_arg(domain)
        
        file_types = options.get("types", "pdf,doc,xls,ppt,docx,xlsx,pptx")
        limit = options.get("limit", 50)
        output_dir = options.get("output", f"/tmp/metagoofil_{domain_safe}")
        
        cmd = f"metagoofil -d {domain_safe} -t {file_types} -l {limit} -o {output_dir}"
        
        result = await self.executor.run(cmd, timeout=600)
        
        return {
            "action": "metagoofil",
            "target": domain,
            "status": "completed" if result.return_code == 0 else "error",
            "command": cmd,
            "output": result.stdout,
            "error": result.stderr if result.return_code != 0 else None,
            "output_directory": output_dir,
            "duration": result.duration,
            "timestamp": result.timestamp
        }
    
    async def wafw00f(self, url: str) -> Dict[str, Any]:
        """
        Détection de WAF avec wafw00f
        """
        url_safe = escape_shell_arg(url)
        
        cmd = f"wafw00f {url_safe}"
        
        result = await self.executor.run(cmd, timeout=60)
        
        parsed = self._parse_wafw00f(result.stdout)
        
        return {
            "action": "wafw00f",
            "target": url,
            "status": "completed" if result.return_code == 0 else "error",
            "command": cmd,
            "output": result.stdout,
            "error": result.stderr if result.return_code != 0 else None,
            "duration": result.duration,
            "timestamp": result.timestamp,
            "parsed_data": parsed
        }
    
    def _parse_theharvester(self, output: str) -> Dict[str, Any]:
        """Parse la sortie de theHarvester"""
        result = {
            "emails": [],
            "hosts": [],
            "ips": []
        }
        
        # Emails
        email_pattern = r'[\w\.-]+@[\w\.-]+'
        result["emails"] = list(set(re.findall(email_pattern, output)))
        
        # IPs
        ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
        result["ips"] = list(set(re.findall(ip_pattern, output)))
        
        return result
    
    def _parse_sherlock(self, output: str) -> Dict[str, Any]:
        """Parse la sortie de Sherlock"""
        profiles = []
        
        for line in output.split('\n'):
            if 'http' in line.lower() and '[+]' in line:
                # Format: [+] Site: URL
                match = re.search(r'\[\+\]\s+(\w+):\s+(https?://\S+)', line)
                if match:
                    profiles.append({
                        "site": match.group(1),
                        "url": match.group(2)
                    })
        
        return {
            "profiles": profiles,
            "count": len(profiles)
        }
    
    def _parse_wafw00f(self, output: str) -> Dict[str, Any]:
        """Parse la sortie de wafw00f"""
        waf_detected = None
        
        if "is behind" in output.lower():
            match = re.search(r'is behind\s+(.+?)(?:\s+WAF|\s*$)', output, re.IGNORECASE)
            if match:
                waf_detected = match.group(1).strip()
        elif "no waf" in output.lower():
            waf_detected = None
        
        return {
            "waf_detected": waf_detected,
            "protected": waf_detected is not None
        }
    
    # =========================================================================
    # SUBFINDER & HTTPX - Quick Win #1
    # =========================================================================
    
    async def subfinder(self, domain: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Énumération rapide de sous-domaines avec Subfinder
        """
        options = options or {}
        domain_safe = escape_shell_arg(domain)
        
        output_file = f"/tmp/subfinder_{domain_safe}_{int(datetime.now().timestamp())}.txt"
        
        silent = "-silent" if options.get("silent", True) else ""
        recursive = "-recursive" if options.get("recursive", False) else ""
        
        cmd = f"subfinder -d {domain_safe} {silent} {recursive} -o {output_file}"
        
        result = await self.executor.run(cmd, timeout=300)
        
        # Lire les résultats
        subdomains = []
        try:
            with open(output_file, 'r') as f:
                subdomains = [line.strip() for line in f if line.strip()]
        except:
            pass
        
        return {
            "action": "subfinder",
            "target": domain,
            "status": "completed" if result.return_code == 0 else "error",
            "command": cmd,
            "output": result.stdout,
            "error": result.stderr if result.return_code != 0 else None,
            "duration": result.duration,
            "timestamp": result.timestamp,
            "parsed_data": {
                "subdomains": subdomains,
                "count": len(subdomains)
            }
        }
    
    async def httpx_probe(self, targets: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Probe HTTP avec httpx - vérifie quels hosts sont vivants et extrait infos
        targets peut être une IP, domaine, ou fichier de liste
        """
        options = options or {}
        targets_safe = escape_shell_arg(targets)
        
        output_file = f"/tmp/httpx_{int(datetime.now().timestamp())}.json"
        
        # Options httpx
        threads = options.get("threads", 50)
        timeout_sec = options.get("timeout", 10)
        
        # Flags pour les infos à extraire
        flags = "-json -silent"
        if options.get("title", True):
            flags += " -title"
        if options.get("status_code", True):
            flags += " -status-code"
        if options.get("tech_detect", True):
            flags += " -tech-detect"
        if options.get("content_length", False):
            flags += " -content-length"
        if options.get("web_server", True):
            flags += " -web-server"
        if options.get("follow_redirects", True):
            flags += " -follow-redirects"
        
        # Déterminer si c'est un fichier ou une cible unique
        import os
        if os.path.isfile(targets):
            cmd = f"httpx -l {targets_safe} {flags} -t {threads} -timeout {timeout_sec} -o {output_file}"
        else:
            cmd = f"echo '{targets_safe}' | httpx {flags} -t {threads} -timeout {timeout_sec} -o {output_file}"
        
        result = await self.executor.run(cmd, timeout=600)
        
        # Parser les résultats JSON
        hosts = []
        try:
            with open(output_file, 'r') as f:
                for line in f:
                    try:
                        hosts.append(json.loads(line))
                    except:
                        pass
        except:
            pass
        
        return {
            "action": "httpx",
            "target": targets,
            "status": "completed" if result.return_code == 0 else "error",
            "command": cmd,
            "output": result.stdout,
            "error": result.stderr if result.return_code != 0 else None,
            "duration": result.duration,
            "timestamp": result.timestamp,
            "parsed_data": {
                "hosts": hosts,
                "alive_count": len(hosts)
            }
        }
    
    async def subfinder_httpx(self, domain: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Pipeline combiné: Subfinder pour trouver les sous-domaines, puis httpx pour vérifier
        """
        options = options or {}
        domain_safe = escape_shell_arg(domain)
        
        output_file = f"/tmp/subfinder_httpx_{domain_safe}_{int(datetime.now().timestamp())}.json"
        
        # Pipeline: subfinder | httpx
        cmd = f"subfinder -d {domain_safe} -silent | httpx -silent -json -title -status-code -tech-detect -web-server -o {output_file}"
        
        result = await self.executor.run(cmd, timeout=600)
        
        # Parser les résultats
        hosts = []
        try:
            with open(output_file, 'r') as f:
                for line in f:
                    try:
                        hosts.append(json.loads(line))
                    except:
                        pass
        except:
            pass
        
        # Extraire les stats
        technologies = {}
        status_codes = {}
        for host in hosts:
            # Compter les technos
            for tech in host.get("tech", []):
                technologies[tech] = technologies.get(tech, 0) + 1
            # Compter les status codes
            sc = str(host.get("status_code", "unknown"))
            status_codes[sc] = status_codes.get(sc, 0) + 1
        
        return {
            "action": "subfinder_httpx",
            "target": domain,
            "status": "completed" if result.return_code == 0 else "error",
            "command": cmd,
            "output": result.stdout,
            "error": result.stderr if result.return_code != 0 else None,
            "duration": result.duration,
            "timestamp": result.timestamp,
            "parsed_data": {
                "hosts": hosts,
                "alive_count": len(hosts),
                "technologies": technologies,
                "status_codes": status_codes
            }
        }
