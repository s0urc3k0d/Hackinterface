"""
Module de scan de vulnérabilités
Nuclei, SearchSploit, etc.
"""
import re
import json
import os
import tempfile
from typing import Dict, Any, List
from datetime import datetime

from core.executor import CommandExecutor
from core.config import settings

class VulnScanModule:
    """Module de scan de vulnérabilités"""
    
    def __init__(self):
        self.executor = CommandExecutor()

    def _sanitize_csv(self, value: Any, default: str, pattern: str) -> str:
        if not isinstance(value, str):
            return default
        cleaned = value.strip().replace(" ", "")
        if not cleaned:
            return default
        if not re.match(pattern, cleaned):
            return default
        return cleaned
    
    async def nuclei_scan(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Scan de vulnérabilités avec Nuclei
        """
        options = options or {}
        
        if not target.startswith(('http://', 'https://')):
            target = f"http://{target}"

        # Options Nuclei
        severity = self._sanitize_csv(
            options.get("severity"),
            "low,medium,high,critical",
            r'^[a-z,]+$'
        )
        tags = self._sanitize_csv(options.get("tags"), "", r'^[a-zA-Z0-9,_-]+$')
        templates = options.get("templates", "")

        command_args = ["nuclei", "-u", target, "-severity", severity, "-silent", "-json"]

        if tags:
            command_args.extend(["-tags", tags])
        if templates:
            command_args.extend(["-t", str(templates)])

        result = await self.executor.run_args(command_args, timeout=1800)
        
        parsed = self._parse_nuclei(result.stdout) if result.return_code == 0 else None
        
        return {
            "action": "nuclei",
            "target": target,
            "status": "completed" if result.return_code == 0 else "error",
            "command": result.command,
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

        command_args = [
            "nuclei", "-u", target, "-t", "network/",
            "-severity", "low,medium,high,critical", "-silent", "-json"
        ]

        result = await self.executor.run_args(command_args, timeout=1800)
        
        parsed = self._parse_nuclei(result.stdout) if result.return_code == 0 else None
        
        return {
            "action": "nuclei_network",
            "target": target,
            "status": "completed" if result.return_code == 0 else "error",
            "command": result.command,
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

        # Recherche basique
        command_args = ["searchsploit", target, "--json"]

        result = await self.executor.run_args(command_args, timeout=60)
        
        parsed = self._parse_searchsploit(result.stdout) if result.return_code == 0 else None
        
        return {
            "action": "searchsploit",
            "target": target,
            "status": "completed" if result.return_code == 0 else "error",
            "command": result.command,
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
        # Écrire le XML dans un fichier temporaire
        with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
            f.write(nmap_xml)
            xml_path = f.name
        
        try:
            command_args = ["searchsploit", "--nmap", xml_path, "--json"]
            result = await self.executor.run_args(command_args, timeout=60)
            
            parsed = self._parse_searchsploit(result.stdout) if result.return_code == 0 else None
            
            return {
                "action": "searchsploit_nmap",
                "target": "nmap_results",
                "status": "completed" if result.return_code == 0 else "error",
                "command": result.command,
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
        ports = options.get("ports", "")

        command_args = ["nmap", "-sV", "--script=vulners"]
        if ports:
            command_args.extend(["-p", str(ports)])
        command_args.append(target)

        result = await self.executor.run_args(command_args, timeout=1200)
        
        parsed = self._parse_vulners(result.stdout) if result.return_code == 0 else None
        
        return {
            "action": "nmap_vulners",
            "target": target,
            "status": "completed" if result.return_code == 0 else "error",
            "command": result.command,
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

        command_args = ["nuclei", "-u", target, "-tags", "default-login", "-silent", "-json"]

        result = await self.executor.run_args(command_args, timeout=600)
        
        parsed = self._parse_nuclei(result.stdout) if result.return_code == 0 else None
        
        return {
            "action": "check_default_creds",
            "target": target,
            "status": "completed" if result.return_code == 0 else "error",
            "command": result.command,
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

        command_args = None
        openssl_cert_path = None

        # Utiliser sslscan ou testssl.sh
        if self.executor.check_tool_available("sslscan"):
            command_args = ["sslscan", "--no-colour", host]
        elif self.executor.check_tool_available("testssl.sh"):
            command_args = ["testssl.sh", "--quiet", host]
        else:
            # Fallback sans pipeline shell: récupérer le certificat puis le parser
            sclient_result = await self.executor.run_args(["openssl", "s_client", "-connect", host, "-showcerts"], timeout=300)
            pem_matches = re.findall(
                r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----',
                sclient_result.stdout,
                flags=re.S
            )

            if pem_matches:
                with tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False) as cert_file:
                    cert_file.write(pem_matches[0])
                    openssl_cert_path = cert_file.name
                result = await self.executor.run_args(
                    ["openssl", "x509", "-in", openssl_cert_path, "-noout", "-text"],
                    timeout=120
                )
            else:
                result = sclient_result

        if command_args is not None:
            result = await self.executor.run_args(command_args, timeout=300)

        try:
            parsed = self._parse_ssl(result.stdout) if result.return_code == 0 else None
        finally:
            if openssl_cert_path and os.path.exists(openssl_cert_path):
                os.unlink(openssl_cert_path)

        command_display = result.command
        
        return {
            "action": "ssl_scan",
            "target": host,
            "status": "completed" if result.return_code == 0 else "error",
            "command": command_display,
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
