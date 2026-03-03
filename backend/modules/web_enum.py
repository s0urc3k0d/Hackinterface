"""
Module d'énumération Web
Gobuster, Nikto, WhatWeb, WPScan, etc.
"""
import re
from typing import Dict, Any, Optional
from datetime import datetime

from core.executor import CommandExecutor
from core.config import settings

class WebEnumModule:
    """Module d'énumération web"""
    
    def __init__(self):
        self.executor = CommandExecutor()

    def _sanitize_int(self, value: Any, default: int, minimum: int, maximum: int) -> int:
        """Valide un entier dans un intervalle borné"""
        try:
            parsed = int(value)
        except (TypeError, ValueError):
            return default
        return max(minimum, min(parsed, maximum))

    def _sanitize_wordlist(self, value: Any, default: str) -> str:
        """Valide un chemin de wordlist"""
        if not isinstance(value, str) or not value.strip():
            value = default
        return value.strip()

    def _sanitize_enum(self, value: Any, default: str = "vp,vt,u") -> str:
        """Valide les options d'énumération WPScan"""
        if not isinstance(value, str):
            return default
        cleaned = value.strip().replace(" ", "")
        if not cleaned:
            return default
        if not re.match(r'^[a-zA-Z,]+$', cleaned):
            return default
        return cleaned

    def _sanitize_extensions(self, value: Any, default: str = "") -> str:
        """Valide la liste d'extensions (format csv alphanumérique)"""
        if not isinstance(value, str):
            return default
        cleaned = value.strip().replace(" ", "")
        if not cleaned:
            return default
        if not re.match(r'^[a-zA-Z0-9,]+$', cleaned):
            return default
        return cleaned[:120]
    
    async def gobuster(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Brute-force de répertoires avec Gobuster
        """
        options = options or {}
        
        # S'assurer que la cible a un schéma
        if not target.startswith(('http://', 'https://')):
            target = f"http://{target}"
        
        target_safe = target
        wordlist = self._sanitize_wordlist(options.get("wordlist"), settings.DEFAULT_WORDLIST_DIR)
        extensions = self._sanitize_extensions(options.get("extensions"), "php,html,txt,js,asp,aspx")
        threads = self._sanitize_int(options.get("threads"), 50, 1, 200)

        command_args = [
            "gobuster", "dir", "-u", target_safe, "-w", wordlist,
            "-x", extensions, "-t", str(threads), "-q", "--no-progress"
        ]

        result = await self.executor.run_args(command_args, timeout=1800)
        
        parsed = self._parse_gobuster(result.stdout) if result.return_code == 0 else None
        
        return {
            "action": "gobuster",
            "target": target,
            "status": "completed" if result.return_code == 0 else "error",
            "command": result.command,
            "output": result.stdout,
            "error": result.stderr if result.return_code != 0 else None,
            "duration": result.duration,
            "timestamp": result.timestamp,
            "parsed_data": parsed
        }
    
    async def feroxbuster(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Brute-force de répertoires avec Feroxbuster (plus rapide)
        """
        options = options or {}
        
        if not target.startswith(('http://', 'https://')):
            target = f"http://{target}"
        
        target_safe = target
        wordlist = self._sanitize_wordlist(options.get("wordlist"), settings.DEFAULT_WORDLIST_DIR)
        extensions = self._sanitize_extensions(options.get("extensions"), "php,html,txt,js")
        threads = self._sanitize_int(options.get("threads"), 50, 1, 200)
        depth = self._sanitize_int(options.get("depth"), 2, 1, 10)

        command_args = [
            "feroxbuster", "-u", target_safe, "-w", wordlist,
            "-x", extensions, "-t", str(threads), "-d", str(depth),
            "--quiet", "--no-state"
        ]

        result = await self.executor.run_args(command_args, timeout=1800)
        
        parsed = self._parse_feroxbuster(result.stdout) if result.return_code == 0 else None
        
        return {
            "action": "feroxbuster",
            "target": target,
            "status": "completed" if result.return_code == 0 else "error",
            "command": result.command,
            "output": result.stdout,
            "error": result.stderr if result.return_code != 0 else None,
            "duration": result.duration,
            "timestamp": result.timestamp,
            "parsed_data": parsed
        }
    
    async def ffuf(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Fuzzing web avec FFUF
        """
        options = options or {}
        
        if not target.startswith(('http://', 'https://')):
            target = f"http://{target}"
        
        # Ajouter FUZZ si pas présent
        if "FUZZ" not in target:
            target = f"{target}/FUZZ"
        
        target_safe = target
        wordlist = self._sanitize_wordlist(options.get("wordlist"), settings.DEFAULT_WORDLIST_DIR)
        extensions = self._sanitize_extensions(options.get("extensions"), "")
        threads = self._sanitize_int(options.get("threads"), 50, 1, 200)

        command_args = [
            "ffuf", "-u", target_safe, "-w", wordlist, "-t", str(threads),
            "-mc", "all", "-fc", "404", "-of", "json", "-o", "/tmp/ffuf_output.json"
        ]
        if extensions:
            command_args.extend(["-e", extensions])

        result = await self.executor.run_args(command_args, timeout=1800)
        
        # Parser le JSON de sortie
        parsed = self._parse_ffuf(result.return_code)
        
        return {
            "action": "ffuf",
            "target": target,
            "status": "completed" if result.return_code == 0 else "error",
            "command": result.command,
            "output": result.stdout,
            "error": result.stderr if result.return_code != 0 else None,
            "duration": result.duration,
            "timestamp": result.timestamp,
            "parsed_data": parsed
        }
    
    def _parse_ffuf(self, return_code: int) -> Optional[Dict[str, Any]]:
        """Parse la sortie JSON de FFUF"""
        import json
        import os
        
        output_file = "/tmp/ffuf_output.json"
        if not os.path.exists(output_file):
            return None
        
        try:
            with open(output_file, 'r') as f:
                data = json.load(f)
            
            findings = []
            for result in data.get("results", []):
                findings.append({
                    "url": result.get("url", ""),
                    "status": result.get("status", 0),
                    "length": result.get("length", 0),
                    "words": result.get("words", 0),
                    "lines": result.get("lines", 0),
                    "content_type": result.get("content-type", ""),
                    "input": result.get("input", {}).get("FUZZ", "")
                })
            
            # Trier par status code
            findings.sort(key=lambda x: (x["status"], -x["length"]))
            
            # Grouper par status code
            by_status = {}
            for f in findings:
                status = f["status"]
                if status not in by_status:
                    by_status[status] = []
                by_status[status].append(f)
            
            # Nettoyer le fichier temporaire
            os.remove(output_file)
            
            return {
                "findings": findings,
                "count": len(findings),
                "by_status": by_status,
                "config": data.get("config", {})
            }
        except Exception as e:
            return {"error": str(e)}
    
    async def nikto(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Scan de vulnérabilités web avec Nikto
        """
        options = options or {}
        
        if not target.startswith(('http://', 'https://')):
            target = f"http://{target}"
        
        result = await self.executor.run_args(["nikto", "-h", target, "-Format", "txt", "-nointeractive"], timeout=1800)
        
        parsed = self._parse_nikto(result.stdout) if result.return_code == 0 else None
        
        return {
            "action": "nikto",
            "target": target,
            "status": "completed" if result.return_code == 0 else "error",
            "command": result.command,
            "output": result.stdout,
            "error": result.stderr if result.return_code != 0 else None,
            "duration": result.duration,
            "timestamp": result.timestamp,
            "parsed_data": parsed
        }
    
    async def whatweb(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Identification des technologies avec WhatWeb
        """
        options = options or {}
        
        if not target.startswith(('http://', 'https://')):
            target = f"http://{target}"
        
        aggression = self._sanitize_int(options.get("aggression"), 3, 1, 4)

        result = await self.executor.run_args(["whatweb", "-a", str(aggression), "--color=never", target], timeout=120)
        
        parsed = self._parse_whatweb(result.stdout) if result.return_code == 0 else None
        
        return {
            "action": "whatweb",
            "target": target,
            "status": "completed" if result.return_code == 0 else "error",
            "command": result.command,
            "output": result.stdout,
            "error": result.stderr if result.return_code != 0 else None,
            "duration": result.duration,
            "timestamp": result.timestamp,
            "parsed_data": parsed
        }
    
    async def wpscan(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Scan WordPress avec WPScan
        """
        options = options or {}
        
        if not target.startswith(('http://', 'https://')):
            target = f"http://{target}"
        
        target_safe = target
        enumerate = self._sanitize_enum(options.get("enumerate"), "vp,vt,u")  # plugins, themes, users

        command_args = ["wpscan", "--url", target_safe, "--enumerate", enumerate, "--no-banner"]

        # Ajouter l'API token si disponible
        api_token = options.get("api_token")
        if api_token:
            command_args.extend(["--api-token", str(api_token)])

        result = await self.executor.run_args(command_args, timeout=600)
        
        parsed = self._parse_wpscan(result.stdout) if result.return_code == 0 else None
        
        return {
            "action": "wpscan",
            "target": target,
            "status": "completed" if result.return_code == 0 else "error",
            "command": result.command.replace(str(api_token), "***") if api_token else result.command,
            "output": result.stdout,
            "error": result.stderr if result.return_code != 0 else None,
            "duration": result.duration,
            "timestamp": result.timestamp,
            "parsed_data": parsed
        }
    
    async def curl_headers(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Récupération des headers HTTP
        """
        if not target.startswith(('http://', 'https://')):
            target = f"http://{target}"
        
        target_safe = target

        command_args = ["curl", "-I", "-L", "-s", "-k", target_safe]

        result = await self.executor.run_args(command_args, timeout=30)
        
        parsed = self._parse_headers(result.stdout) if result.return_code == 0 else None
        
        return {
            "action": "curl_headers",
            "target": target,
            "status": "completed" if result.return_code == 0 else "error",
            "command": result.command,
            "output": result.stdout,
            "error": result.stderr if result.return_code != 0 else None,
            "duration": result.duration,
            "timestamp": result.timestamp,
            "parsed_data": parsed
        }
    
    async def screenshot(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Capture d'écran d'une page web
        """
        import os
        options = options or {}
        
        if not target.startswith(('http://', 'https://')):
            target = f"http://{target}"
        
        target_safe = target
        
        # Nom de fichier basé sur la cible
        safe_filename = re.sub(r'[^\w\-_.]', '_', target.replace('://', '_'))
        output_file = os.path.join(settings.SCREENSHOTS_DIR, f"{safe_filename}.png")
        
        # Essayer cutycapt ou wkhtmltoimage
        if self.executor.check_tool_available("cutycapt"):
            command_args = ["cutycapt", f"--url={target_safe}", f"--out={output_file}"]
        elif self.executor.check_tool_available("wkhtmltoimage"):
            command_args = ["wkhtmltoimage", "--quality", "80", target_safe, output_file]
        else:
            return {
                "action": "screenshot",
                "target": target,
                "status": "error",
                "error": "Aucun outil de capture disponible (cutycapt ou wkhtmltoimage)",
                "timestamp": datetime.now().isoformat()
            }
        
        result = await self.executor.run_args(command_args, timeout=60)
        
        return {
            "action": "screenshot",
            "target": target,
            "status": "completed" if result.return_code == 0 else "error",
            "command": result.command,
            "output": output_file if result.return_code == 0 else None,
            "error": result.stderr if result.return_code != 0 else None,
            "duration": result.duration,
            "timestamp": result.timestamp,
            "parsed_data": {"screenshot_path": output_file} if result.return_code == 0 else None
        }
    
    def _parse_gobuster(self, output: str) -> Dict[str, Any]:
        """Parse la sortie de Gobuster"""
        findings = []
        for line in output.split('\n'):
            # Format: /path (Status: 200) [Size: 1234]
            match = re.search(r'(/\S+)\s+\(Status:\s*(\d+)\)\s+\[Size:\s*(\d+)\]', line)
            if match:
                findings.append({
                    "path": match.group(1),
                    "status": int(match.group(2)),
                    "size": int(match.group(3))
                })
        return {
            "findings": findings,
            "count": len(findings)
        }
    
    def _parse_feroxbuster(self, output: str) -> Dict[str, Any]:
        """Parse la sortie de Feroxbuster"""
        findings = []
        for line in output.split('\n'):
            # Format: 200 GET 1234l 5678w 12345c http://target/path
            match = re.search(r'(\d+)\s+\w+\s+\d+l\s+\d+w\s+(\d+)c\s+(https?://\S+)', line)
            if match:
                findings.append({
                    "url": match.group(3),
                    "status": int(match.group(1)),
                    "size": int(match.group(2))
                })
        return {
            "findings": findings,
            "count": len(findings)
        }
    
    def _parse_nikto(self, output: str) -> Dict[str, Any]:
        """Parse la sortie de Nikto"""
        findings = []
        for line in output.split('\n'):
            if line.startswith('+'):
                findings.append(line.strip('+ '))
        
        vulns = [f for f in findings if 'OSVDB' in f or 'CVE' in f]
        
        return {
            "findings": findings,
            "vulnerabilities": vulns,
            "count": len(findings)
        }
    
    def _parse_whatweb(self, result: dict) -> Dict[str, Any]:
        """Parse la sortie de WhatWeb avec détection CMS/frameworks"""
        # Extraire la sortie texte du résultat
        output = result.get("output", "") if isinstance(result, dict) else str(result)
        
        technologies = []
        
        # Extraire les technologies entre crochets
        matches = re.findall(r'\[([^\]]+)\]', output)
        for match in matches:
            technologies.append(match)
        
        # Détection des CMS
        output_lower = output.lower()
        cms = None
        cms_version = None
        
        cms_patterns = {
            "wordpress": [r'wordpress\[?([\d.]+)?\]?', r'wp-content', r'wp-includes'],
            "joomla": [r'joomla\[?([\d.]+)?\]?', r'/administrator', r'joomla!'],
            "drupal": [r'drupal\[?([\d.]+)?\]?', r'sites/default', r'drupal.org'],
            "magento": [r'magento\[?([\d.]+)?\]?', r'mage', r'/skin/frontend'],
            "prestashop": [r'prestashop\[?([\d.]+)?\]?', r'prestashop'],
            "typo3": [r'typo3\[?([\d.]+)?\]?', r'typo3'],
            "shopify": [r'shopify', r'cdn.shopify'],
            "wix": [r'wix\.com', r'wixstatic'],
            "squarespace": [r'squarespace', r'sqsp'],
        }
        
        for cms_name, patterns in cms_patterns.items():
            for pattern in patterns:
                match = re.search(pattern, output_lower)
                if match:
                    cms = cms_name
                    if match.groups():
                        cms_version = match.group(1)
                    break
            if cms:
                break
        
        # Détection des frameworks
        framework = None
        framework_patterns = {
            "laravel": [r'laravel', r'x-powered-by.*laravel'],
            "django": [r'django', r'csrfmiddlewaretoken'],
            "rails": [r'ruby on rails', r'x-powered-by.*phusion', r'rails'],
            "express": [r'express', r'x-powered-by.*express'],
            "flask": [r'flask', r'werkzeug'],
            "spring": [r'spring', r'x-application-context'],
            "asp.net": [r'asp\.net', r'x-aspnet-version', r'__viewstate'],
            "nextjs": [r'next\.js', r'_next/static'],
            "nuxt": [r'nuxt', r'__nuxt'],
            "angular": [r'angular', r'ng-version'],
            "react": [r'react', r'_reactroot'],
            "vue": [r'vue\.js', r'vue@'],
        }
        
        for fw_name, patterns in framework_patterns.items():
            for pattern in patterns:
                if re.search(pattern, output_lower):
                    framework = fw_name
                    break
            if framework:
                break
        
        # Détection serveur web
        server = None
        server_patterns = {
            "nginx": r'nginx[/\s]?([\d.]+)?',
            "apache": r'apache[/\s]?([\d.]+)?',
            "iis": r'microsoft-iis[/\s]?([\d.]+)?',
            "lighttpd": r'lighttpd[/\s]?([\d.]+)?',
            "caddy": r'caddy',
            "tomcat": r'tomcat[/\s]?([\d.]+)?',
        }
        
        for srv_name, pattern in server_patterns.items():
            match = re.search(pattern, output_lower)
            if match:
                server = srv_name
                break
        
        # Détection langage
        language = None
        lang_patterns = {
            "php": r'php[/\s]?([\d.]+)?',
            "python": r'python[/\s]?([\d.]+)?',
            "ruby": r'ruby[/\s]?([\d.]+)?',
            "java": r'java|jsp',
            "node": r'node\.?js',
            "perl": r'perl',
        }
        
        for lang_name, pattern in lang_patterns.items():
            if re.search(pattern, output_lower):
                language = lang_name
                break
        
        return {
            "technologies": technologies,
            "cms": cms,
            "cms_version": cms_version,
            "framework": framework,
            "server": server,
            "language": language,
            "raw": output
        }
    
    def _parse_wpscan(self, output: str) -> Dict[str, Any]:
        """Parse la sortie de WPScan"""
        result = {
            "wordpress_version": None,
            "theme": None,
            "plugins": [],
            "users": [],
            "vulnerabilities": []
        }
        
        # Version WordPress
        version_match = re.search(r'WordPress version (\S+)', output)
        if version_match:
            result["wordpress_version"] = version_match.group(1)
        
        # Thème
        theme_match = re.search(r'WordPress theme in use: (\S+)', output)
        if theme_match:
            result["theme"] = theme_match.group(1)
        
        # Vulnérabilités
        vuln_matches = re.findall(r'\|\s+\[!\]\s+(.+)', output)
        result["vulnerabilities"] = vuln_matches
        
        return result
    
    def _parse_headers(self, output: str) -> Dict[str, Any]:
        """Parse les headers HTTP"""
        headers = {}
        security_headers = {
            "X-Frame-Options": False,
            "X-Content-Type-Options": False,
            "X-XSS-Protection": False,
            "Strict-Transport-Security": False,
            "Content-Security-Policy": False,
        }
        
        for line in output.split('\n'):
            if ':' in line:
                key, value = line.split(':', 1)
                key = key.strip()
                value = value.strip()
                headers[key] = value
                
                if key in security_headers:
                    security_headers[key] = True
        
        return {
            "headers": headers,
            "security_headers": security_headers,
            "missing_security_headers": [k for k, v in security_headers.items() if not v]
        }
