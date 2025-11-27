"""
Module Web Avancé
SQLMap, FFuf, et autres outils web avancés
"""
import re
import json
import os
from typing import Dict, Any, List
from datetime import datetime

from core.executor import CommandExecutor, escape_shell_arg
from core.config import settings


class WebAdvancedModule:
    """Module d'outils web avancés"""
    
    def __init__(self):
        self.executor = CommandExecutor()
    
    # =========================================================================
    # SQLMAP - Injection SQL automatisée
    # =========================================================================
    
    async def sqlmap_url(self, url: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Test d'injection SQL avec SQLMap
        """
        options = options or {}
        url_safe = escape_shell_arg(url)
        
        level = options.get("level", 1)  # 1-5
        risk = options.get("risk", 1)    # 1-3
        dbs = options.get("enumerate_dbs", False)
        tables = options.get("enumerate_tables", False)
        dump = options.get("dump", False)
        batch = options.get("batch", True)
        
        output_dir = f"/tmp/sqlmap_{int(datetime.now().timestamp())}"
        
        cmd = f"sqlmap -u '{url_safe}' --level={level} --risk={risk} --output-dir={output_dir}"
        
        if batch:
            cmd += " --batch"
        if dbs:
            cmd += " --dbs"
        if tables:
            cmd += " --tables"
        if dump:
            cmd += " --dump"
        
        result = await self.executor.run(cmd, timeout=1800)
        
        parsed = self._parse_sqlmap(result.stdout)
        
        return {
            "action": "sqlmap",
            "target": url,
            "status": "completed" if result.return_code == 0 else "error",
            "command": cmd,
            "output": result.stdout,
            "error": result.stderr if result.return_code != 0 else None,
            "output_directory": output_dir,
            "duration": result.duration,
            "timestamp": result.timestamp,
            "parsed_data": parsed
        }
    
    async def sqlmap_request(self, request_file: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        SQLMap avec fichier de requête (export Burp)
        """
        options = options or {}
        
        level = options.get("level", 2)
        risk = options.get("risk", 2)
        
        output_dir = f"/tmp/sqlmap_req_{int(datetime.now().timestamp())}"
        
        cmd = f"sqlmap -r {request_file} --level={level} --risk={risk} --batch --output-dir={output_dir}"
        
        result = await self.executor.run(cmd, timeout=1800)
        
        parsed = self._parse_sqlmap(result.stdout)
        
        return {
            "action": "sqlmap_request",
            "target": request_file,
            "status": "completed" if result.return_code == 0 else "error",
            "command": cmd,
            "output": result.stdout,
            "error": result.stderr if result.return_code != 0 else None,
            "output_directory": output_dir,
            "duration": result.duration,
            "timestamp": result.timestamp,
            "parsed_data": parsed
        }
    
    # =========================================================================
    # FFUF - Fuzzing Web ultra-rapide
    # =========================================================================
    
    async def ffuf_dir(self, url: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Fuzzing de répertoires avec FFUF
        """
        options = options or {}
        url_safe = escape_shell_arg(url)
        
        wordlist = options.get("wordlist", "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt")
        extensions = options.get("extensions", "")
        threads = options.get("threads", 40)
        filter_status = options.get("filter_status", "")
        filter_size = options.get("filter_size", "")
        
        output_file = f"/tmp/ffuf_{int(datetime.now().timestamp())}.json"
        
        # FUZZ est le placeholder pour ffuf
        target_url = url_safe if "FUZZ" in url_safe else f"{url_safe}/FUZZ"
        
        cmd = f"ffuf -u '{target_url}' -w {wordlist} -t {threads} -o {output_file} -of json"
        
        if extensions:
            cmd += f" -e {extensions}"
        if filter_status:
            cmd += f" -fc {filter_status}"
        if filter_size:
            cmd += f" -fs {filter_size}"
        
        result = await self.executor.run(cmd, timeout=1800)
        
        # Lire les résultats JSON
        parsed = {"results": [], "count": 0}
        if os.path.exists(output_file):
            try:
                with open(output_file, 'r') as f:
                    data = json.load(f)
                    parsed["results"] = data.get("results", [])
                    parsed["count"] = len(parsed["results"])
            except:
                pass
        
        return {
            "action": "ffuf_dir",
            "target": url,
            "status": "completed" if result.return_code == 0 else "error",
            "command": cmd,
            "output": result.stdout,
            "error": result.stderr if result.return_code != 0 else None,
            "duration": result.duration,
            "timestamp": result.timestamp,
            "parsed_data": parsed
        }
    
    async def ffuf_vhost(self, url: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Fuzzing de virtual hosts avec FFUF
        """
        options = options or {}
        url_safe = escape_shell_arg(url)
        
        wordlist = options.get("wordlist", "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt")
        
        output_file = f"/tmp/ffuf_vhost_{int(datetime.now().timestamp())}.json"
        
        cmd = f"ffuf -u '{url_safe}' -H 'Host: FUZZ.{url_safe.replace('http://', '').replace('https://', '').split('/')[0]}' -w {wordlist} -o {output_file} -of json"
        
        result = await self.executor.run(cmd, timeout=600)
        
        parsed = {"results": [], "count": 0}
        if os.path.exists(output_file):
            try:
                with open(output_file, 'r') as f:
                    data = json.load(f)
                    parsed["results"] = data.get("results", [])
                    parsed["count"] = len(parsed["results"])
            except:
                pass
        
        return {
            "action": "ffuf_vhost",
            "target": url,
            "status": "completed" if result.return_code == 0 else "error",
            "command": cmd,
            "output": result.stdout,
            "duration": result.duration,
            "timestamp": result.timestamp,
            "parsed_data": parsed
        }
    
    async def ffuf_params(self, url: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Fuzzing de paramètres GET avec FFUF
        """
        options = options or {}
        url_safe = escape_shell_arg(url)
        
        wordlist = options.get("wordlist", "/usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt")
        
        # Ajouter le placeholder pour les paramètres
        target_url = f"{url_safe}?FUZZ=test"
        
        output_file = f"/tmp/ffuf_params_{int(datetime.now().timestamp())}.json"
        
        cmd = f"ffuf -u '{target_url}' -w {wordlist} -o {output_file} -of json"
        
        result = await self.executor.run(cmd, timeout=600)
        
        parsed = {"results": [], "count": 0}
        if os.path.exists(output_file):
            try:
                with open(output_file, 'r') as f:
                    data = json.load(f)
                    parsed["results"] = data.get("results", [])
                    parsed["count"] = len(parsed["results"])
            except:
                pass
        
        return {
            "action": "ffuf_params",
            "target": url,
            "status": "completed" if result.return_code == 0 else "error",
            "command": cmd,
            "output": result.stdout,
            "duration": result.duration,
            "timestamp": result.timestamp,
            "parsed_data": parsed
        }
    
    # =========================================================================
    # FEROXBUSTER - Alternative à Gobuster
    # =========================================================================
    
    async def feroxbuster(self, url: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Bruteforce de répertoires avec Feroxbuster
        """
        options = options or {}
        url_safe = escape_shell_arg(url)
        
        wordlist = options.get("wordlist", "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt")
        extensions = options.get("extensions", "php,html,txt,js")
        threads = options.get("threads", 50)
        depth = options.get("depth", 4)
        
        output_file = f"/tmp/feroxbuster_{int(datetime.now().timestamp())}.json"
        
        cmd = f"feroxbuster -u '{url_safe}' -w {wordlist} -x {extensions} -t {threads} -d {depth} --json -o {output_file}"
        
        result = await self.executor.run(cmd, timeout=1800)
        
        parsed = {"results": [], "count": 0}
        if os.path.exists(output_file):
            try:
                with open(output_file, 'r') as f:
                    lines = f.readlines()
                    for line in lines:
                        try:
                            data = json.loads(line)
                            if data.get("type") == "response":
                                parsed["results"].append(data)
                        except:
                            pass
                    parsed["count"] = len(parsed["results"])
            except:
                pass
        
        return {
            "action": "feroxbuster",
            "target": url,
            "status": "completed" if result.return_code == 0 else "error",
            "command": cmd,
            "output": result.stdout,
            "duration": result.duration,
            "timestamp": result.timestamp,
            "parsed_data": parsed
        }
    
    # =========================================================================
    # COMMIX - Command Injection
    # =========================================================================
    
    async def commix(self, url: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Détection d'injection de commandes avec Commix
        """
        options = options or {}
        url_safe = escape_shell_arg(url)
        
        level = options.get("level", 1)
        
        cmd = f"commix -u '{url_safe}' --level={level} --batch"
        
        result = await self.executor.run(cmd, timeout=600)
        
        vulnerable = "command injection" in result.stdout.lower() and "is vulnerable" in result.stdout.lower()
        
        return {
            "action": "commix",
            "target": url,
            "status": "completed" if result.return_code == 0 else "error",
            "command": cmd,
            "output": result.stdout,
            "error": result.stderr if result.return_code != 0 else None,
            "duration": result.duration,
            "timestamp": result.timestamp,
            "parsed_data": {
                "vulnerable": vulnerable
            }
        }
    
    # =========================================================================
    # XSS TESTING
    # =========================================================================
    
    async def xsser(self, url: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Test XSS avec XSSer
        """
        options = options or {}
        url_safe = escape_shell_arg(url)
        
        auto = options.get("auto", True)
        
        cmd = f"xsser -u '{url_safe}'"
        if auto:
            cmd += " --auto"
        
        result = await self.executor.run(cmd, timeout=600)
        
        vulnerable = "XSS" in result.stdout and ("found" in result.stdout.lower() or "vulnerable" in result.stdout.lower())
        
        return {
            "action": "xsser",
            "target": url,
            "status": "completed" if result.return_code == 0 else "error",
            "command": cmd,
            "output": result.stdout,
            "error": result.stderr if result.return_code != 0 else None,
            "duration": result.duration,
            "timestamp": result.timestamp,
            "parsed_data": {
                "vulnerable": vulnerable
            }
        }
    
    async def dalfox(self, url: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Test XSS avancé avec Dalfox
        """
        options = options or {}
        url_safe = escape_shell_arg(url)
        
        output_file = f"/tmp/dalfox_{int(datetime.now().timestamp())}.json"
        
        cmd = f"dalfox url '{url_safe}' -o {output_file} --format json"
        
        result = await self.executor.run(cmd, timeout=600)
        
        parsed = {"vulnerabilities": [], "count": 0}
        if os.path.exists(output_file):
            try:
                with open(output_file, 'r') as f:
                    parsed["vulnerabilities"] = json.load(f)
                    parsed["count"] = len(parsed["vulnerabilities"])
            except:
                pass
        
        return {
            "action": "dalfox",
            "target": url,
            "status": "completed" if result.return_code == 0 else "error",
            "command": cmd,
            "output": result.stdout,
            "duration": result.duration,
            "timestamp": result.timestamp,
            "parsed_data": parsed
        }
    
    # =========================================================================
    # EYEWITNESS - Screenshots
    # =========================================================================
    
    async def eyewitness(self, targets: List[str], options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Prendre des screenshots de sites web avec EyeWitness
        """
        options = options or {}
        
        output_dir = options.get("output", f"/tmp/eyewitness_{int(datetime.now().timestamp())}")
        
        # Créer un fichier avec les URLs
        urls_file = f"/tmp/eyewitness_urls_{int(datetime.now().timestamp())}.txt"
        with open(urls_file, 'w') as f:
            f.write('\n'.join(targets))
        
        cmd = f"eyewitness --web -f {urls_file} -d {output_dir} --no-prompt"
        
        result = await self.executor.run(cmd, timeout=600)
        
        return {
            "action": "eyewitness",
            "targets": targets,
            "status": "completed" if result.return_code == 0 else "error",
            "command": cmd,
            "output": result.stdout,
            "error": result.stderr if result.return_code != 0 else None,
            "output_directory": output_dir,
            "report": f"{output_dir}/report.html",
            "duration": result.duration,
            "timestamp": result.timestamp
        }
    
    # =========================================================================
    # CMS SPECIFIC
    # =========================================================================
    
    async def droopescan(self, url: str, cms: str = "drupal") -> Dict[str, Any]:
        """
        Scanner Drupal/Joomla/SilverStripe avec Droopescan
        """
        url_safe = escape_shell_arg(url)
        
        cmd = f"droopescan scan {cms} -u {url_safe}"
        
        result = await self.executor.run(cmd, timeout=300)
        
        return {
            "action": "droopescan",
            "target": url,
            "cms": cms,
            "status": "completed" if result.return_code == 0 else "error",
            "command": cmd,
            "output": result.stdout,
            "error": result.stderr if result.return_code != 0 else None,
            "duration": result.duration,
            "timestamp": result.timestamp
        }
    
    async def joomscan(self, url: str) -> Dict[str, Any]:
        """
        Scanner Joomla avec JoomScan
        """
        url_safe = escape_shell_arg(url)
        
        cmd = f"joomscan -u {url_safe}"
        
        result = await self.executor.run(cmd, timeout=300)
        
        return {
            "action": "joomscan",
            "target": url,
            "status": "completed" if result.return_code == 0 else "error",
            "command": cmd,
            "output": result.stdout,
            "error": result.stderr if result.return_code != 0 else None,
            "duration": result.duration,
            "timestamp": result.timestamp
        }
    
    def _parse_sqlmap(self, output: str) -> Dict[str, Any]:
        """Parse la sortie SQLMap"""
        result = {
            "vulnerable": False,
            "injection_points": [],
            "databases": [],
            "tables": [],
            "dbms": None
        }
        
        # Détecter si vulnérable
        if "is vulnerable" in output.lower() or "parameter" in output.lower() and "injectable" in output.lower():
            result["vulnerable"] = True
        
        # Extraire le DBMS
        dbms_match = re.search(r"back-end DBMS:\s*(.+)", output)
        if dbms_match:
            result["dbms"] = dbms_match.group(1).strip()
        
        # Extraire les bases de données
        dbs_section = re.search(r"available databases \[\d+\]:(.*?)(?:\n\n|\Z)", output, re.DOTALL)
        if dbs_section:
            dbs = re.findall(r'\[\*\]\s*(\S+)', dbs_section.group(1))
            result["databases"] = dbs
        
        return result
