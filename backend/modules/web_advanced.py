"""
Module Web Avancé
SQLMap, FFuf, et autres outils web avancés
"""
import re
import json
import os
from typing import Dict, Any, List
from datetime import datetime
from urllib.parse import urlparse

from core.executor import CommandExecutor, escape_shell_arg
from core.config import settings


class WebAdvancedModule:
    """Module d'outils web avancés"""
    
    def __init__(self):
        self.executor = CommandExecutor()

    def _sanitize_int(self, value: Any, default: int, minimum: int, maximum: int) -> int:
        try:
            parsed = int(value)
        except (TypeError, ValueError):
            return default
        return max(minimum, min(parsed, maximum))

    def _sanitize_wordlist(self, value: Any, default: str) -> str:
        if not isinstance(value, str) or not value.strip():
            value = default
        return value.strip()

    def _sanitize_extensions(self, value: Any, default: str = "") -> str:
        if not isinstance(value, str):
            return default
        cleaned = value.strip().replace(" ", "")
        if not cleaned:
            return default
        if not re.match(r'^[a-zA-Z0-9,]+$', cleaned):
            return default
        return cleaned[:120]

    def _extract_host(self, url: str) -> str:
        candidate = url if url.startswith(("http://", "https://")) else f"http://{url}"
        parsed = urlparse(candidate)
        host = parsed.hostname or ""
        if not re.match(r'^[a-zA-Z0-9.-]+$', host):
            return ""
        return host
    
    # =========================================================================
    # SQLMAP - Injection SQL automatisée
    # =========================================================================
    
    async def sqlmap_url(self, url: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Test d'injection SQL avec SQLMap
        """
        options = options or {}
        url_safe = url

        level = self._sanitize_int(options.get("level"), 1, 1, 5)
        risk = self._sanitize_int(options.get("risk"), 1, 1, 3)
        dbs = options.get("enumerate_dbs", False)
        tables = options.get("enumerate_tables", False)
        dump = options.get("dump", False)
        batch = options.get("batch", True)
        
        output_dir = f"/tmp/sqlmap_{int(datetime.now().timestamp())}"
        
        command_args = [
            "sqlmap", "-u", url_safe,
            f"--level={level}", f"--risk={risk}", "--output-dir", output_dir
        ]

        if batch:
            command_args.append("--batch")
        if dbs:
            command_args.append("--dbs")
        if tables:
            command_args.append("--tables")
        if dump:
            command_args.append("--dump")

        result = await self.executor.run_args(command_args, timeout=1800)
        
        parsed = self._parse_sqlmap(result.stdout)
        
        return {
            "action": "sqlmap",
            "target": url,
            "status": "completed" if result.return_code == 0 else "error",
            "command": result.command,
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
        
        level = self._sanitize_int(options.get("level"), 2, 1, 5)
        risk = self._sanitize_int(options.get("risk"), 2, 1, 3)
        
        output_dir = f"/tmp/sqlmap_req_{int(datetime.now().timestamp())}"
        
        command_args = [
            "sqlmap", "-r", request_file,
            f"--level={level}", f"--risk={risk}", "--batch",
            "--output-dir", output_dir
        ]

        result = await self.executor.run_args(command_args, timeout=1800)
        
        parsed = self._parse_sqlmap(result.stdout)
        
        return {
            "action": "sqlmap_request",
            "target": request_file,
            "status": "completed" if result.return_code == 0 else "error",
            "command": result.command,
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
        url_safe = url

        wordlist = self._sanitize_wordlist(options.get("wordlist"), "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt")
        extensions = self._sanitize_extensions(options.get("extensions"), "")
        threads = self._sanitize_int(options.get("threads"), 40, 1, 200)
        filter_status = self._sanitize_extensions(options.get("filter_status"), "")
        filter_size = self._sanitize_extensions(options.get("filter_size"), "")
        
        output_file = f"/tmp/ffuf_{int(datetime.now().timestamp())}.json"
        
        # FUZZ est le placeholder pour ffuf
        target_url = url_safe if "FUZZ" in url_safe else f"{url_safe}/FUZZ"
        
        command_args = ["ffuf", "-u", target_url, "-w", wordlist, "-t", str(threads), "-o", output_file, "-of", "json"]

        if extensions:
            command_args.extend(["-e", extensions])
        if filter_status:
            command_args.extend(["-fc", filter_status])
        if filter_size:
            command_args.extend(["-fs", filter_size])

        result = await self.executor.run_args(command_args, timeout=1800)
        
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
            "command": result.command,
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
        url_safe = url

        wordlist = self._sanitize_wordlist(options.get("wordlist"), "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt")
        host = self._extract_host(url)
        if not host:
            return {
                "action": "ffuf_vhost",
                "target": url,
                "status": "error",
                "command": "",
                "output": "",
                "error": "URL invalide pour le fuzzing vhost",
                "duration": 0,
                "timestamp": datetime.now().isoformat(),
                "parsed_data": {"results": [], "count": 0}
            }
        
        output_file = f"/tmp/ffuf_vhost_{int(datetime.now().timestamp())}.json"
        
        command_args = [
            "ffuf", "-u", url_safe, "-H", f"Host: FUZZ.{host}",
            "-w", wordlist, "-o", output_file, "-of", "json"
        ]

        result = await self.executor.run_args(command_args, timeout=600)
        
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
            "command": result.command,
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
        url_safe = url

        wordlist = self._sanitize_wordlist(options.get("wordlist"), "/usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt")
        
        # Ajouter le placeholder pour les paramètres
        target_url = f"{url_safe}?FUZZ=test"
        
        output_file = f"/tmp/ffuf_params_{int(datetime.now().timestamp())}.json"
        
        command_args = ["ffuf", "-u", target_url, "-w", wordlist, "-o", output_file, "-of", "json"]

        result = await self.executor.run_args(command_args, timeout=600)
        
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
            "command": result.command,
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
        url_safe = url

        wordlist = self._sanitize_wordlist(options.get("wordlist"), "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt")
        extensions = self._sanitize_extensions(options.get("extensions"), "php,html,txt,js")
        threads = self._sanitize_int(options.get("threads"), 50, 1, 200)
        depth = self._sanitize_int(options.get("depth"), 4, 1, 10)
        
        output_file = f"/tmp/feroxbuster_{int(datetime.now().timestamp())}.json"
        
        command_args = [
            "feroxbuster", "-u", url_safe, "-w", wordlist, "-x", extensions,
            "-t", str(threads), "-d", str(depth), "--json", "-o", output_file
        ]

        result = await self.executor.run_args(command_args, timeout=1800)
        
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
            "command": result.command,
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
        url_safe = url
        
        level = options.get("level", 1)
        
        command_args = ["commix", "-u", url_safe, f"--level={level}", "--batch"]

        result = await self.executor.run_args(command_args, timeout=600)
        
        vulnerable = "command injection" in result.stdout.lower() and "is vulnerable" in result.stdout.lower()
        
        return {
            "action": "commix",
            "target": url,
            "status": "completed" if result.return_code == 0 else "error",
            "command": result.command,
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
        url_safe = url
        
        auto = options.get("auto", True)
        
        command_args = ["xsser", "-u", url_safe]
        if auto:
            command_args.append("--auto")

        result = await self.executor.run_args(command_args, timeout=600)
        
        vulnerable = "XSS" in result.stdout and ("found" in result.stdout.lower() or "vulnerable" in result.stdout.lower())
        
        return {
            "action": "xsser",
            "target": url,
            "status": "completed" if result.return_code == 0 else "error",
            "command": result.command,
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
        url_safe = url
        
        output_file = f"/tmp/dalfox_{int(datetime.now().timestamp())}.json"
        
        command_args = ["dalfox", "url", url_safe, "-o", output_file, "--format", "json"]

        result = await self.executor.run_args(command_args, timeout=600)
        
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
            "command": result.command,
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
        
        command_args = ["eyewitness", "--web", "-f", urls_file, "-d", output_dir, "--no-prompt"]

        result = await self.executor.run_args(command_args, timeout=600)
        
        return {
            "action": "eyewitness",
            "targets": targets,
            "status": "completed" if result.return_code == 0 else "error",
            "command": result.command,
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
        url_safe = url

        command_args = ["droopescan", "scan", cms, "-u", url_safe]

        result = await self.executor.run_args(command_args, timeout=300)
        
        return {
            "action": "droopescan",
            "target": url,
            "cms": cms,
            "status": "completed" if result.return_code == 0 else "error",
            "command": result.command,
            "output": result.stdout,
            "error": result.stderr if result.return_code != 0 else None,
            "duration": result.duration,
            "timestamp": result.timestamp
        }
    
    async def joomscan(self, url: str) -> Dict[str, Any]:
        """
        Scanner Joomla avec JoomScan
        """
        url_safe = url

        command_args = ["joomscan", "-u", url_safe]

        result = await self.executor.run_args(command_args, timeout=300)
        
        return {
            "action": "joomscan",
            "target": url,
            "status": "completed" if result.return_code == 0 else "error",
            "command": result.command,
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
