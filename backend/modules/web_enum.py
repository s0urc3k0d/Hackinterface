"""
Module d'énumération Web
Gobuster, Nikto, WhatWeb, WPScan, etc.
"""
import re
from typing import Dict, Any, Optional
from datetime import datetime

from core.executor import CommandExecutor, escape_shell_arg
from core.config import settings

class WebEnumModule:
    """Module d'énumération web"""
    
    def __init__(self):
        self.executor = CommandExecutor()
    
    async def gobuster(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Brute-force de répertoires avec Gobuster
        """
        options = options or {}
        
        # S'assurer que la cible a un schéma
        if not target.startswith(('http://', 'https://')):
            target = f"http://{target}"
        
        target_safe = escape_shell_arg(target)
        wordlist = options.get("wordlist", settings.DEFAULT_WORDLIST_DIR)
        extensions = options.get("extensions", "php,html,txt,js,asp,aspx")
        threads = options.get("threads", 50)
        
        cmd = f"gobuster dir -u {target_safe} -w {wordlist} -x {extensions} -t {threads} -q --no-progress"
        
        result = await self.executor.run(cmd, timeout=1800)
        
        parsed = self._parse_gobuster(result.stdout) if result.return_code == 0 else None
        
        return {
            "action": "gobuster",
            "target": target,
            "status": "completed" if result.return_code == 0 else "error",
            "command": cmd,
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
        
        target_safe = escape_shell_arg(target)
        wordlist = options.get("wordlist", settings.DEFAULT_WORDLIST_DIR)
        extensions = options.get("extensions", "php,html,txt,js")
        threads = options.get("threads", 50)
        depth = options.get("depth", 2)
        
        cmd = f"feroxbuster -u {target_safe} -w {wordlist} -x {extensions} -t {threads} -d {depth} --quiet --no-state"
        
        result = await self.executor.run(cmd, timeout=1800)
        
        parsed = self._parse_feroxbuster(result.stdout) if result.return_code == 0 else None
        
        return {
            "action": "feroxbuster",
            "target": target,
            "status": "completed" if result.return_code == 0 else "error",
            "command": cmd,
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
        
        target_safe = escape_shell_arg(target)
        wordlist = options.get("wordlist", settings.DEFAULT_WORDLIST_DIR)
        extensions = options.get("extensions", "")
        threads = options.get("threads", 50)
        
        cmd = f"ffuf -u {target_safe} -w {wordlist} -t {threads} -mc all -fc 404"
        if extensions:
            cmd += f" -e {extensions}"
        
        result = await self.executor.run(cmd, timeout=1800)
        
        return {
            "action": "ffuf",
            "target": target,
            "status": "completed" if result.return_code == 0 else "error",
            "command": cmd,
            "output": result.stdout,
            "error": result.stderr if result.return_code != 0 else None,
            "duration": result.duration,
            "timestamp": result.timestamp,
            "parsed_data": None  # TODO: parser
        }
    
    async def nikto(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Scan de vulnérabilités web avec Nikto
        """
        options = options or {}
        
        if not target.startswith(('http://', 'https://')):
            target = f"http://{target}"
        
        target_safe = escape_shell_arg(target)
        
        cmd = f"nikto -h {target_safe} -Format txt -nointeractive"
        
        result = await self.executor.run(cmd, timeout=1800)
        
        parsed = self._parse_nikto(result.stdout) if result.return_code == 0 else None
        
        return {
            "action": "nikto",
            "target": target,
            "status": "completed" if result.return_code == 0 else "error",
            "command": cmd,
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
        
        target_safe = escape_shell_arg(target)
        aggression = options.get("aggression", 3)
        
        cmd = f"whatweb -a {aggression} --color=never {target_safe}"
        
        result = await self.executor.run(cmd, timeout=120)
        
        parsed = self._parse_whatweb(result.stdout) if result.return_code == 0 else None
        
        return {
            "action": "whatweb",
            "target": target,
            "status": "completed" if result.return_code == 0 else "error",
            "command": cmd,
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
        
        target_safe = escape_shell_arg(target)
        enumerate = options.get("enumerate", "vp,vt,u")  # plugins, themes, users
        
        cmd = f"wpscan --url {target_safe} --enumerate {enumerate} --no-banner"
        
        # Ajouter l'API token si disponible
        api_token = options.get("api_token")
        if api_token:
            cmd += f" --api-token {api_token}"
        
        result = await self.executor.run(cmd, timeout=600)
        
        parsed = self._parse_wpscan(result.stdout) if result.return_code == 0 else None
        
        return {
            "action": "wpscan",
            "target": target,
            "status": "completed" if result.return_code == 0 else "error",
            "command": cmd.replace(api_token, "***") if api_token else cmd,
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
        
        target_safe = escape_shell_arg(target)
        
        cmd = f"curl -I -L -s -k {target_safe}"
        
        result = await self.executor.run(cmd, timeout=30)
        
        parsed = self._parse_headers(result.stdout) if result.return_code == 0 else None
        
        return {
            "action": "curl_headers",
            "target": target,
            "status": "completed" if result.return_code == 0 else "error",
            "command": cmd,
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
        
        target_safe = escape_shell_arg(target)
        
        # Nom de fichier basé sur la cible
        safe_filename = re.sub(r'[^\w\-_.]', '_', target.replace('://', '_'))
        output_file = os.path.join(settings.SCREENSHOTS_DIR, f"{safe_filename}.png")
        
        # Essayer cutycapt ou wkhtmltoimage
        if self.executor.check_tool_available("cutycapt"):
            cmd = f"cutycapt --url={target_safe} --out={output_file}"
        elif self.executor.check_tool_available("wkhtmltoimage"):
            cmd = f"wkhtmltoimage --quality 80 {target_safe} {output_file}"
        else:
            return {
                "action": "screenshot",
                "target": target,
                "status": "error",
                "error": "Aucun outil de capture disponible (cutycapt ou wkhtmltoimage)",
                "timestamp": datetime.now().isoformat()
            }
        
        result = await self.executor.run(cmd, timeout=60)
        
        return {
            "action": "screenshot",
            "target": target,
            "status": "completed" if result.return_code == 0 else "error",
            "command": cmd,
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
    
    def _parse_whatweb(self, output: str) -> Dict[str, Any]:
        """Parse la sortie de WhatWeb"""
        technologies = []
        
        # Extraire les technologies entre crochets
        matches = re.findall(r'\[([^\]]+)\]', output)
        for match in matches:
            technologies.append(match)
        
        return {
            "technologies": technologies,
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
