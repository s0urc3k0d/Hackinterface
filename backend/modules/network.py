"""
Module Sniffing & Network
Capture réseau, MITM et analyse
"""
import os
import re
from typing import Dict, Any, List
from datetime import datetime

from core.executor import CommandExecutor, escape_shell_arg
from core.config import settings


class NetworkModule:
    """Module d'analyse réseau et sniffing"""
    
    def __init__(self):
        self.executor = CommandExecutor()
    
    async def tcpdump_capture(self, interface: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Capture de paquets avec tcpdump
        """
        options = options or {}
        
        count = options.get("count", 100)
        filter_expr = options.get("filter", "")
        output_file = options.get("output", f"/tmp/capture_{int(datetime.now().timestamp())}.pcap")
        
        filter_arg = f"'{filter_expr}'" if filter_expr else ""
        cmd = f"tcpdump -i {interface} -c {count} -w {output_file} {filter_arg}"
        
        result = await self.executor.run(cmd, timeout=120)
        
        return {
            "action": "tcpdump",
            "interface": interface,
            "status": "completed" if result.return_code == 0 else "error",
            "command": cmd,
            "output": result.stdout + result.stderr,
            "capture_file": output_file if result.return_code == 0 else None,
            "duration": result.duration,
            "timestamp": result.timestamp
        }
    
    async def tshark_analyze(self, pcap_file: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Analyser un fichier pcap avec tshark
        """
        options = options or {}
        
        display_filter = options.get("filter", "")
        fields = options.get("fields", "")
        
        filter_arg = f"-Y '{display_filter}'" if display_filter else ""
        fields_arg = f"-T fields {' '.join([f'-e {f}' for f in fields.split(',')])}" if fields else ""
        
        cmd = f"tshark -r {pcap_file} {filter_arg} {fields_arg}"
        
        result = await self.executor.run(cmd, timeout=120)
        
        return {
            "action": "tshark",
            "file": pcap_file,
            "status": "completed" if result.return_code == 0 else "error",
            "command": cmd,
            "output": result.stdout,
            "error": result.stderr if result.return_code != 0 else None,
            "duration": result.duration,
            "timestamp": result.timestamp
        }
    
    async def tshark_statistics(self, pcap_file: str) -> Dict[str, Any]:
        """
        Générer des statistiques depuis un pcap
        """
        stats = {}
        
        # Conversations
        cmd = f"tshark -r {pcap_file} -q -z conv,ip"
        result = await self.executor.run(cmd, timeout=60)
        stats["conversations"] = result.stdout
        
        # Protocoles
        cmd = f"tshark -r {pcap_file} -q -z io,phs"
        result = await self.executor.run(cmd, timeout=60)
        stats["protocols"] = result.stdout
        
        # Endpoints
        cmd = f"tshark -r {pcap_file} -q -z endpoints,ip"
        result = await self.executor.run(cmd, timeout=60)
        stats["endpoints"] = result.stdout
        
        return {
            "action": "tshark_stats",
            "file": pcap_file,
            "status": "completed",
            "parsed_data": stats,
            "timestamp": datetime.now().isoformat()
        }
    
    async def responder(self, interface: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Lancer Responder pour capturer des hashes NTLM
        Note: Nécessite les droits root
        """
        options = options or {}
        
        analyze_only = options.get("analyze", False)
        
        cmd = f"responder -I {interface}"
        if analyze_only:
            cmd += " -A"  # Mode analyse seulement
        
        # Responder tourne en continu, on le lance en background
        result = await self.executor.run(f"timeout 60 {cmd}", timeout=70)
        
        # Lire les logs
        log_file = "/usr/share/responder/logs/Responder-Session.log"
        logs = ""
        if os.path.exists(log_file):
            with open(log_file, 'r') as f:
                logs = f.read()
        
        parsed = self._parse_responder_logs(logs)
        
        return {
            "action": "responder",
            "interface": interface,
            "status": "completed",
            "command": cmd,
            "output": result.stdout,
            "logs": logs,
            "duration": result.duration,
            "timestamp": result.timestamp,
            "parsed_data": parsed
        }
    
    async def arp_scan(self, network: str) -> Dict[str, Any]:
        """
        Scan ARP du réseau local
        """
        network_safe = escape_shell_arg(network)
        
        cmd = f"arp-scan {network_safe}"
        
        result = await self.executor.run(cmd, timeout=120)
        
        parsed = self._parse_arp_scan(result.stdout)
        
        return {
            "action": "arp_scan",
            "network": network,
            "status": "completed" if result.return_code == 0 else "error",
            "command": cmd,
            "output": result.stdout,
            "error": result.stderr if result.return_code != 0 else None,
            "duration": result.duration,
            "timestamp": result.timestamp,
            "parsed_data": parsed
        }
    
    async def netdiscover(self, interface: str, network: str = "") -> Dict[str, Any]:
        """
        Découverte réseau passive/active avec netdiscover
        """
        range_arg = f"-r {network}" if network else ""
        cmd = f"netdiscover -i {interface} {range_arg} -P -N"  # -P = passive, -N = no header
        
        result = await self.executor.run(f"timeout 30 {cmd}", timeout=40)
        
        parsed = self._parse_netdiscover(result.stdout)
        
        return {
            "action": "netdiscover",
            "interface": interface,
            "status": "completed",
            "command": cmd,
            "output": result.stdout,
            "duration": result.duration,
            "timestamp": result.timestamp,
            "parsed_data": parsed
        }
    
    async def masscan(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Scan de ports ultra-rapide avec masscan
        """
        options = options or {}
        target_safe = escape_shell_arg(target)
        
        ports = options.get("ports", "1-65535")
        rate = options.get("rate", 1000)
        
        output_file = f"/tmp/masscan_{int(datetime.now().timestamp())}.json"
        cmd = f"masscan {target_safe} -p{ports} --rate={rate} -oJ {output_file}"
        
        result = await self.executor.run(cmd, timeout=600)
        
        # Lire le fichier JSON
        parsed = {"hosts": []}
        if os.path.exists(output_file):
            try:
                with open(output_file, 'r') as f:
                    import json
                    data = json.load(f)
                    parsed["hosts"] = data
            except:
                pass
        
        return {
            "action": "masscan",
            "target": target,
            "status": "completed" if result.return_code == 0 else "error",
            "command": cmd,
            "output": result.stdout,
            "error": result.stderr if result.return_code != 0 else None,
            "duration": result.duration,
            "timestamp": result.timestamp,
            "parsed_data": parsed
        }
    
    async def sslscan(self, target: str) -> Dict[str, Any]:
        """
        Analyse SSL/TLS avec sslscan
        """
        target_safe = escape_shell_arg(target)
        
        cmd = f"sslscan --no-colour {target_safe}"
        
        result = await self.executor.run(cmd, timeout=60)
        
        parsed = self._parse_sslscan(result.stdout)
        
        return {
            "action": "sslscan",
            "target": target,
            "status": "completed" if result.return_code == 0 else "error",
            "command": cmd,
            "output": result.stdout,
            "error": result.stderr if result.return_code != 0 else None,
            "duration": result.duration,
            "timestamp": result.timestamp,
            "parsed_data": parsed
        }
    
    async def testssl(self, target: str) -> Dict[str, Any]:
        """
        Analyse SSL/TLS approfondie avec testssl.sh
        """
        target_safe = escape_shell_arg(target)
        
        cmd = f"testssl --quiet --color 0 {target_safe}"
        
        result = await self.executor.run(cmd, timeout=300)
        
        return {
            "action": "testssl",
            "target": target,
            "status": "completed" if result.return_code == 0 else "error",
            "command": cmd,
            "output": result.stdout,
            "error": result.stderr if result.return_code != 0 else None,
            "duration": result.duration,
            "timestamp": result.timestamp
        }
    
    def _parse_responder_logs(self, logs: str) -> Dict[str, Any]:
        """Parse les logs Responder"""
        hashes = []
        
        # Chercher les hashes NTLM
        patterns = [
            r'NTLMv2-SSP Hash\s*:\s*(.+)',
            r'NTLMv1 Hash\s*:\s*(.+)',
            r'NTLM Hash\s*:\s*(.+)',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, logs)
            for match in matches:
                hashes.append(match.strip())
        
        return {
            "hashes": hashes,
            "count": len(hashes)
        }
    
    def _parse_arp_scan(self, output: str) -> Dict[str, Any]:
        """Parse la sortie arp-scan"""
        hosts = []
        
        for line in output.split('\n'):
            match = re.match(r'(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f:]+)\s+(.*)', line)
            if match:
                hosts.append({
                    "ip": match.group(1),
                    "mac": match.group(2),
                    "vendor": match.group(3).strip()
                })
        
        return {
            "hosts": hosts,
            "count": len(hosts)
        }
    
    def _parse_netdiscover(self, output: str) -> Dict[str, Any]:
        """Parse la sortie netdiscover"""
        hosts = []
        
        for line in output.split('\n'):
            parts = line.split()
            if len(parts) >= 3 and re.match(r'\d+\.\d+\.\d+\.\d+', parts[0]):
                hosts.append({
                    "ip": parts[0],
                    "mac": parts[1] if len(parts) > 1 else "",
                    "vendor": ' '.join(parts[2:]) if len(parts) > 2 else ""
                })
        
        return {
            "hosts": hosts,
            "count": len(hosts)
        }
    
    def _parse_sslscan(self, output: str) -> Dict[str, Any]:
        """Parse la sortie sslscan"""
        result = {
            "ssl_versions": [],
            "ciphers": [],
            "vulnerabilities": [],
            "certificate": {}
        }
        
        # Versions SSL/TLS
        if "SSLv2" in output and "enabled" in output.lower():
            result["vulnerabilities"].append("SSLv2 enabled")
        if "SSLv3" in output and "enabled" in output.lower():
            result["vulnerabilities"].append("SSLv3 enabled")
        
        # Vulnérabilités
        if "Heartbleed" in output and "vulnerable" in output.lower():
            result["vulnerabilities"].append("Heartbleed")
        if "POODLE" in output:
            result["vulnerabilities"].append("POODLE")
        
        return result
