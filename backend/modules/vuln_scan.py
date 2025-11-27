"""
Module de scan de vulnérabilités
Nuclei, SearchSploit, etc.
"""
import re
import json
from typing import Dict, Any, List
from datetime import datetime

from core.executor import CommandExecutor, escape_shell_arg
from core.config import settings

class VulnScanModule:
    """Module de scan de vulnérabilités"""
    
    def __init__(self):
        self.executor = CommandExecutor()
    
    async def nuclei_scan(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Scan de vulnérabilités avec Nuclei
        """
        options = options or {}
        
        if not target.startswith(('http://', 'https://')):
            target = f"http://{target}"
        
        target_safe = escape_shell_arg(target)
        
        # Options Nuclei
        severity = options.get("severity", "low,medium,high,critical")
        tags = options.get("tags", "")
        templates = options.get("templates", "")
        
        cmd = f"nuclei -u {target_safe} -severity {severity} -silent -json"
        
        if tags:
            cmd += f" -tags {tags}"
        if templates:
            cmd += f" -t {templates}"
        
        result = await self.executor.run(cmd, timeout=1800)
        
        parsed = self._parse_nuclei(result.stdout) if result.return_code == 0 else None
        
        return {
            "action": "nuclei",
            "target": target,
            "status": "completed" if result.return_code == 0 else "error",
            "command": cmd,
            "output": result.stdout,
            "error": result.stderr if result.return_code != 0 else None,
            "duration": result.duration,
            "timestamp": result.timestamp,
            "parsed_data": parsed
        }
    
    async def nuclei_network(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Scan Nuclei pour les vulnérabilités réseau
        """
        options = options or {}
        target_safe = escape_shell_arg(target)
        
        cmd = f"nuclei -u {target_safe} -t network/ -severity low,medium,high,critical -silent -json"
        
        result = await self.executor.run(cmd, timeout=1800)
        
        parsed = self._parse_nuclei(result.stdout) if result.return_code == 0 else None
        
        return {
            "action": "nuclei_network",
            "target": target,
            "status": "completed" if result.return_code == 0 else "error",
            "command": cmd,
            "output": result.stdout,
            "error": result.stderr if result.return_code != 0 else None,
            "duration": result.duration,
            "timestamp": result.timestamp,
            "parsed_data": parsed
        }
    
    async def searchsploit(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Recherche d'exploits avec SearchSploit
        """
        options = options or {}
        target_safe = escape_shell_arg(target)
        
        # Recherche basique
        cmd = f"searchsploit {target_safe} --json"
        
        result = await self.executor.run(cmd, timeout=60)
        
        parsed = self._parse_searchsploit(result.stdout) if result.return_code == 0 else None
        
        return {
            "action": "searchsploit",
            "target": target,
            "status": "completed" if result.return_code == 0 else "error",
            "command": cmd,
            "output": result.stdout,
            "error": result.stderr if result.return_code != 0 else None,
            "duration": result.duration,
            "timestamp": result.timestamp,
            "parsed_data": parsed
        }
    
    async def searchsploit_nmap(self, nmap_xml: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Recherche d'exploits basée sur un scan Nmap
        """
        import tempfile
        import os
        
        # Écrire le XML dans un fichier temporaire
        with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
            f.write(nmap_xml)
            xml_path = f.name
        
        try:
            cmd = f"searchsploit --nmap {xml_path} --json"
            result = await self.executor.run(cmd, timeout=60)
            
            parsed = self._parse_searchsploit(result.stdout) if result.return_code == 0 else None
            
            return {
                "action": "searchsploit_nmap",
                "target": "nmap_results",
                "status": "completed" if result.return_code == 0 else "error",
                "command": cmd,
                "output": result.stdout,
                "error": result.stderr if result.return_code != 0 else None,
                "duration": result.duration,
                "timestamp": result.timestamp,
                "parsed_data": parsed
            }
        finally:
            os.unlink(xml_path)
    
    async def nmap_vulners(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Scan Nmap avec scripts vulners
        """
        options = options or {}
        target_safe = escape_shell_arg(target)
        ports = options.get("ports", "")
        
        if ports:
            cmd = f"nmap -sV --script=vulners -p {ports} {target_safe}"
        else:
            cmd = f"nmap -sV --script=vulners {target_safe}"
        
        result = await self.executor.run(cmd, timeout=1200)
        
        parsed = self._parse_vulners(result.stdout) if result.return_code == 0 else None
        
        return {
            "action": "nmap_vulners",
            "target": target,
            "status": "completed" if result.return_code == 0 else "error",
            "command": cmd,
            "output": result.stdout,
            "error": result.stderr if result.return_code != 0 else None,
            "duration": result.duration,
            "timestamp": result.timestamp,
            "parsed_data": parsed
        }
    
    async def check_default_creds(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Vérification des credentials par défaut avec Nuclei
        """
        options = options or {}
        
        if not target.startswith(('http://', 'https://')):
            target = f"http://{target}"
        
        target_safe = escape_shell_arg(target)
        
        cmd = f"nuclei -u {target_safe} -tags default-login -silent -json"
        
        result = await self.executor.run(cmd, timeout=600)
        
        parsed = self._parse_nuclei(result.stdout) if result.return_code == 0 else None
        
        return {
            "action": "check_default_creds",
            "target": target,
            "status": "completed" if result.return_code == 0 else "error",
            "command": cmd,
            "output": result.stdout,
            "error": result.stderr if result.return_code != 0 else None,
            "duration": result.duration,
            "timestamp": result.timestamp,
            "parsed_data": parsed
        }
    
    async def ssl_scan(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Scan SSL/TLS
        """
        options = options or {}
        
        # Extraire le host
        host = target.replace('https://', '').replace('http://', '').split('/')[0]
        if ':' not in host:
            host += ':443'
        
        host_safe = escape_shell_arg(host)
        
        # Utiliser sslscan ou testssl.sh
        if self.executor.check_tool_available("sslscan"):
            cmd = f"sslscan --no-colour {host_safe}"
        elif self.executor.check_tool_available("testssl.sh"):
            cmd = f"testssl.sh --quiet {host_safe}"
        else:
            # Fallback avec openssl
            cmd = f"echo | openssl s_client -connect {host_safe} 2>/dev/null | openssl x509 -noout -text"
        
        result = await self.executor.run(cmd, timeout=300)
        
        parsed = self._parse_ssl(result.stdout) if result.return_code == 0 else None
        
        return {
            "action": "ssl_scan",
            "target": host,
            "status": "completed" if result.return_code == 0 else "error",
            "command": cmd,
            "output": result.stdout,
            "error": result.stderr if result.return_code != 0 else None,
            "duration": result.duration,
            "timestamp": result.timestamp,
            "parsed_data": parsed
        }
    
    def _parse_nuclei(self, output: str) -> Dict[str, Any]:
        """Parse la sortie JSON de Nuclei"""
        findings = []
        
        for line in output.split('\n'):
            if line.strip():
                try:
                    data = json.loads(line)
                    findings.append({
                        "template": data.get("template-id", ""),
                        "name": data.get("info", {}).get("name", ""),
                        "severity": data.get("info", {}).get("severity", ""),
                        "matched_at": data.get("matched-at", ""),
                        "description": data.get("info", {}).get("description", ""),
                        "reference": data.get("info", {}).get("reference", []),
                        "extracted_results": data.get("extracted-results", [])
                    })
                except json.JSONDecodeError:
                    pass
        
        # Trier par sévérité
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        findings.sort(key=lambda x: severity_order.get(x["severity"], 5))
        
        return {
            "findings": findings,
            "count": len(findings),
            "by_severity": {
                "critical": len([f for f in findings if f["severity"] == "critical"]),
                "high": len([f for f in findings if f["severity"] == "high"]),
                "medium": len([f for f in findings if f["severity"] == "medium"]),
                "low": len([f for f in findings if f["severity"] == "low"]),
                "info": len([f for f in findings if f["severity"] == "info"]),
            }
        }
    
    def _parse_searchsploit(self, output: str) -> Dict[str, Any]:
        """Parse la sortie JSON de SearchSploit"""
        try:
            data = json.loads(output)
            exploits = data.get("RESULTS_EXPLOIT", [])
            shellcodes = data.get("RESULTS_SHELLCODE", [])
            
            return {
                "exploits": [
                    {
                        "title": e.get("Title", ""),
                        "path": e.get("Path", ""),
                        "type": e.get("Type", ""),
                        "platform": e.get("Platform", ""),
                        "date": e.get("Date", "")
                    }
                    for e in exploits
                ],
                "shellcodes": shellcodes,
                "exploit_count": len(exploits),
                "shellcode_count": len(shellcodes)
            }
        except json.JSONDecodeError:
            return {"raw": output, "error": "Failed to parse JSON"}
    
    def _parse_vulners(self, output: str) -> Dict[str, Any]:
        """Parse la sortie du script vulners de Nmap"""
        vulnerabilities = []
        
        # Pattern pour les CVE et vulnérabilités
        cve_pattern = r'(CVE-\d{4}-\d+)'
        cvss_pattern = r'(\d+\.\d+)\s+https?://'
        
        cves = re.findall(cve_pattern, output)
        cvss_scores = re.findall(cvss_pattern, output)
        
        for cve in set(cves):
            vulnerabilities.append({
                "cve": cve,
                "type": "CVE"
            })
        
        return {
            "vulnerabilities": vulnerabilities,
            "cve_count": len(set(cves)),
            "raw": output
        }
    
    def _parse_ssl(self, output: str) -> Dict[str, Any]:
        """Parse la sortie d'un scan SSL"""
        issues = []
        
        # Détecter les problèmes courants
        checks = {
            "SSLv2": "SSLv2 activé (obsolète)",
            "SSLv3": "SSLv3 activé (vulnérable POODLE)",
            "TLSv1.0": "TLSv1.0 activé (obsolète)",
            "TLSv1.1": "TLSv1.1 activé (obsolète)",
            "RC4": "Cipher RC4 activé (faible)",
            "DES": "Cipher DES activé (faible)",
            "MD5": "Signature MD5 (faible)",
            "NULL": "Cipher NULL activé",
            "EXPORT": "Cipher EXPORT activé",
        }
        
        for pattern, issue in checks.items():
            if pattern.lower() in output.lower():
                if "disabled" not in output.lower() or pattern.lower() not in output.lower().split("disabled")[0]:
                    issues.append(issue)
        
        return {
            "issues": issues,
            "issue_count": len(issues),
            "raw": output
        }
