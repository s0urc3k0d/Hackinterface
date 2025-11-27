"""
Module de Reconnaissance
Nmap, Whois, DNS, Sous-domaines
"""
import re
import xml.etree.ElementTree as ET
from typing import Dict, Any, List, Optional
from datetime import datetime

from core.executor import CommandExecutor, escape_shell_arg
from core.config import settings
from models.schemas import ActionResult, ActionStatus

class ReconModule:
    """Module de reconnaissance"""
    
    def __init__(self):
        self.executor = CommandExecutor()
    
    async def nmap_quick(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Scan Nmap rapide - Top 1000 ports
        """
        options = options or {}
        target_safe = escape_shell_arg(target)
        
        # Construire la commande
        cmd = f"nmap -sV -sC -T4 --top-ports 1000 -oX - {target_safe}"
        
        result = await self.executor.run(cmd, timeout=600)
        
        parsed = self._parse_nmap_xml(result.stdout) if result.return_code == 0 else None
        
        return {
            "action": "nmap_quick",
            "target": target,
            "status": "completed" if result.return_code == 0 else "error",
            "command": cmd,
            "output": result.stdout,
            "error": result.stderr if result.return_code != 0 else None,
            "duration": result.duration,
            "timestamp": result.timestamp,
            "parsed_data": parsed
        }
    
    async def nmap_full(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Scan Nmap complet - Tous les ports
        """
        options = options or {}
        target_safe = escape_shell_arg(target)
        
        cmd = f"nmap -sV -sC -p- -T4 -oX - {target_safe}"
        
        result = await self.executor.run(cmd, timeout=3600)
        
        parsed = self._parse_nmap_xml(result.stdout) if result.return_code == 0 else None
        
        return {
            "action": "nmap_full",
            "target": target,
            "status": "completed" if result.return_code == 0 else "error",
            "command": cmd,
            "output": result.stdout,
            "error": result.stderr if result.return_code != 0 else None,
            "duration": result.duration,
            "timestamp": result.timestamp,
            "parsed_data": parsed
        }
    
    async def nmap_vuln(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Scan Nmap avec scripts de vulnérabilités
        """
        options = options or {}
        target_safe = escape_shell_arg(target)
        ports = options.get("ports", "")
        
        if ports:
            cmd = f"nmap -sV --script=vuln -p {ports} -oX - {target_safe}"
        else:
            cmd = f"nmap -sV --script=vuln -oX - {target_safe}"
        
        result = await self.executor.run(cmd, timeout=1800)
        
        parsed = self._parse_nmap_xml(result.stdout) if result.return_code == 0 else None
        
        return {
            "action": "nmap_vuln",
            "target": target,
            "status": "completed" if result.return_code == 0 else "error",
            "command": cmd,
            "output": result.stdout,
            "error": result.stderr if result.return_code != 0 else None,
            "duration": result.duration,
            "timestamp": result.timestamp,
            "parsed_data": parsed
        }
    
    async def nmap_udp(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Scan Nmap UDP
        """
        options = options or {}
        target_safe = escape_shell_arg(target)
        
        cmd = f"sudo nmap -sU -sV --top-ports 100 -T4 -oX - {target_safe}"
        
        result = await self.executor.run(cmd, timeout=1800)
        
        parsed = self._parse_nmap_xml(result.stdout) if result.return_code == 0 else None
        
        return {
            "action": "nmap_udp",
            "target": target,
            "status": "completed" if result.return_code == 0 else "error",
            "command": cmd,
            "output": result.stdout,
            "error": result.stderr if result.return_code != 0 else None,
            "duration": result.duration,
            "timestamp": result.timestamp,
            "parsed_data": parsed
        }
    
    async def whois_lookup(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Recherche WHOIS
        """
        target_safe = escape_shell_arg(target)
        cmd = f"whois {target_safe}"
        
        result = await self.executor.run(cmd, timeout=30)
        
        parsed = self._parse_whois(result.stdout) if result.return_code == 0 else None
        
        return {
            "action": "whois",
            "target": target,
            "status": "completed" if result.return_code == 0 else "error",
            "command": cmd,
            "output": result.stdout,
            "error": result.stderr if result.return_code != 0 else None,
            "duration": result.duration,
            "timestamp": result.timestamp,
            "parsed_data": parsed
        }
    
    async def dns_enumeration(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Énumération DNS complète
        """
        target_safe = escape_shell_arg(target)
        
        # Plusieurs requêtes DNS
        commands = {
            "A": f"dig +short A {target_safe}",
            "AAAA": f"dig +short AAAA {target_safe}",
            "MX": f"dig +short MX {target_safe}",
            "NS": f"dig +short NS {target_safe}",
            "TXT": f"dig +short TXT {target_safe}",
            "SOA": f"dig +short SOA {target_safe}",
            "CNAME": f"dig +short CNAME {target_safe}",
        }
        
        results = {}
        full_output = []
        
        for record_type, cmd in commands.items():
            result = await self.executor.run(cmd, timeout=15)
            results[record_type] = result.stdout.strip().split('\n') if result.stdout.strip() else []
            full_output.append(f"=== {record_type} Records ===\n{result.stdout}")
        
        # Zone transfer attempt
        ns_servers = results.get("NS", [])
        if ns_servers:
            for ns in ns_servers[:2]:  # Essayer les 2 premiers NS
                ns_clean = ns.rstrip('.')
                axfr_cmd = f"dig @{ns_clean} {target_safe} AXFR"
                axfr_result = await self.executor.run(axfr_cmd, timeout=30)
                full_output.append(f"=== Zone Transfer from {ns_clean} ===\n{axfr_result.stdout}")
                if "XFR size" in axfr_result.stdout:
                    results["zone_transfer"] = {
                        "success": True,
                        "server": ns_clean,
                        "data": axfr_result.stdout
                    }
        
        return {
            "action": "dns_enum",
            "target": target,
            "status": "completed",
            "command": "Multiple dig commands",
            "output": "\n\n".join(full_output),
            "duration": 0,
            "timestamp": datetime.now().isoformat(),
            "parsed_data": results
        }
    
    async def subdomain_enumeration(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Énumération des sous-domaines avec plusieurs outils
        """
        options = options or {}
        target_safe = escape_shell_arg(target)
        
        subdomains = set()
        full_output = []
        
        # Subfinder
        if self.executor.check_tool_available("subfinder"):
            cmd = f"subfinder -d {target_safe} -silent"
            result = await self.executor.run(cmd, timeout=300)
            if result.return_code == 0:
                subs = [s.strip() for s in result.stdout.split('\n') if s.strip()]
                subdomains.update(subs)
                full_output.append(f"=== Subfinder ({len(subs)} found) ===\n{result.stdout}")
        
        # Amass (passif)
        if self.executor.check_tool_available("amass"):
            cmd = f"amass enum -passive -d {target_safe}"
            result = await self.executor.run(cmd, timeout=600)
            if result.return_code == 0:
                subs = [s.strip() for s in result.stdout.split('\n') if s.strip()]
                subdomains.update(subs)
                full_output.append(f"=== Amass ({len(subs)} found) ===\n{result.stdout}")
        
        # Vérification des sous-domaines avec httpx
        live_subdomains = []
        if subdomains and self.executor.check_tool_available("httpx"):
            subs_list = '\n'.join(subdomains)
            cmd = f"echo '{subs_list}' | httpx -silent -status-code -title"
            result = await self.executor.run(cmd, timeout=300)
            if result.return_code == 0:
                for line in result.stdout.split('\n'):
                    if line.strip():
                        live_subdomains.append(line.strip())
                full_output.append(f"=== Live Subdomains ===\n{result.stdout}")
        
        return {
            "action": "subdomain_enum",
            "target": target,
            "status": "completed",
            "command": "subfinder + amass + httpx",
            "output": "\n\n".join(full_output),
            "duration": 0,
            "timestamp": datetime.now().isoformat(),
            "parsed_data": {
                "all_subdomains": list(subdomains),
                "live_subdomains": live_subdomains,
                "count": len(subdomains)
            }
        }
    
    def _parse_nmap_xml(self, xml_output: str) -> Optional[Dict[str, Any]]:
        """Parse la sortie XML de Nmap"""
        try:
            # Trouver le début du XML
            xml_start = xml_output.find('<?xml')
            if xml_start == -1:
                return None
            
            xml_content = xml_output[xml_start:]
            root = ET.fromstring(xml_content)
            
            results = {
                "hosts": [],
                "scan_info": {}
            }
            
            # Infos du scan
            scaninfo = root.find('scaninfo')
            if scaninfo is not None:
                results["scan_info"] = {
                    "type": scaninfo.get('type'),
                    "protocol": scaninfo.get('protocol'),
                    "services": scaninfo.get('services')
                }
            
            # Hosts
            for host in root.findall('host'):
                host_data = {
                    "addresses": [],
                    "hostnames": [],
                    "ports": [],
                    "os": None,
                    "state": "unknown"
                }
                
                # État
                status = host.find('status')
                if status is not None:
                    host_data["state"] = status.get('state')
                
                # Adresses
                for addr in host.findall('address'):
                    host_data["addresses"].append({
                        "addr": addr.get('addr'),
                        "type": addr.get('addrtype')
                    })
                
                # Hostnames
                hostnames = host.find('hostnames')
                if hostnames is not None:
                    for hostname in hostnames.findall('hostname'):
                        host_data["hostnames"].append(hostname.get('name'))
                
                # Ports
                ports = host.find('ports')
                if ports is not None:
                    for port in ports.findall('port'):
                        port_data = {
                            "port": int(port.get('portid')),
                            "protocol": port.get('protocol'),
                            "state": "unknown",
                            "service": "unknown",
                            "version": None,
                            "scripts": []
                        }
                        
                        state = port.find('state')
                        if state is not None:
                            port_data["state"] = state.get('state')
                        
                        service = port.find('service')
                        if service is not None:
                            port_data["service"] = service.get('name', 'unknown')
                            port_data["version"] = service.get('product', '')
                            if service.get('version'):
                                port_data["version"] += f" {service.get('version')}"
                        
                        # Scripts NSE
                        for script in port.findall('script'):
                            port_data["scripts"].append({
                                "id": script.get('id'),
                                "output": script.get('output')
                            })
                        
                        host_data["ports"].append(port_data)
                
                # OS Detection
                os_elem = host.find('os')
                if os_elem is not None:
                    osmatch = os_elem.find('osmatch')
                    if osmatch is not None:
                        host_data["os"] = {
                            "name": osmatch.get('name'),
                            "accuracy": osmatch.get('accuracy')
                        }
                
                results["hosts"].append(host_data)
            
            return results
            
        except Exception as e:
            return {"error": str(e), "raw": xml_output[:500]}
    
    def _parse_whois(self, output: str) -> Dict[str, Any]:
        """Parse la sortie WHOIS"""
        parsed = {
            "registrar": None,
            "creation_date": None,
            "expiration_date": None,
            "name_servers": [],
            "registrant": {},
            "raw": output
        }
        
        patterns = {
            "registrar": r"Registrar:\s*(.+)",
            "creation_date": r"Creation Date:\s*(.+)",
            "expiration_date": r"(?:Expir(?:y|ation) Date|Registry Expiry Date):\s*(.+)",
            "name_server": r"Name Server:\s*(.+)",
        }
        
        for key, pattern in patterns.items():
            matches = re.findall(pattern, output, re.IGNORECASE)
            if matches:
                if key == "name_server":
                    parsed["name_servers"] = [m.strip().lower() for m in matches]
                else:
                    parsed[key] = matches[0].strip()
        
        return parsed
