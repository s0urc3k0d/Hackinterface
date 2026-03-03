"""
NetExec Module (ex-CrackMapExec)
================================
Module d'intégration de NetExec pour l'énumération Active Directory et réseau
"""

from typing import Dict, Any, List, Optional
from datetime import datetime
from core.executor import CommandExecutor, escape_shell_arg
import json
import re
import shlex


class NetExecModule:
    """
    Module pour NetExec (anciennement CrackMapExec)
    Outil polyvalent pour:
    - Énumération SMB/WinRM/SSH/LDAP/MSSQL/RDP
    - Spray de mots de passe
    - Exécution de commandes
    - Extraction de credentials
    """
    
    def __init__(self):
        self.executor = CommandExecutor()

    async def _run_cmd(self, cmd: str, timeout: int):
        """Exécute la commande via argv (sans shell)"""
        return await self.executor.run_args(shlex.split(cmd), timeout=timeout)
    
    async def smb_enum(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Énumération SMB avec NetExec
        Découvre OS, nom NetBIOS, domaine, signing, etc.
        """
        options = options or {}
        target_safe = escape_shell_arg(target)
        
        # Authentification optionnelle
        auth = self._build_auth_string(options)
        
        # Options supplémentaires
        extra_flags = ""
        if options.get("shares", False):
            extra_flags += " --shares"
        if options.get("sessions", False):
            extra_flags += " --sessions"
        if options.get("disks", False):
            extra_flags += " --disks"
        if options.get("loggedon_users", False):
            extra_flags += " --loggedon-users"
        if options.get("users", False):
            extra_flags += " --users"
        if options.get("groups", False):
            extra_flags += " --groups"
        if options.get("rid_brute", False):
            extra_flags += " --rid-brute"
        if options.get("pass_pol", False):
            extra_flags += " --pass-pol"
        
        cmd = f"nxc smb {target_safe} {auth} {extra_flags}"
        
        result = await self._run_cmd(cmd, timeout=300)
        
        # Parser les résultats
        parsed = self._parse_smb_output(result.stdout)
        
        return {
            "action": "netexec_smb",
            "target": target,
            "status": "completed" if result.return_code == 0 else "error",
            "command": cmd.replace(options.get("password", ""), "****") if options.get("password") else cmd,
            "output": result.stdout,
            "error": result.stderr if result.return_code != 0 else None,
            "duration": result.duration,
            "timestamp": result.timestamp,
            "parsed_data": parsed
        }
    
    async def smb_shares(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Énumération des partages SMB
        """
        options = options or {}
        options["shares"] = True
        return await self.smb_enum(target, options)
    
    async def smb_users(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Énumération des utilisateurs via SMB
        """
        options = options or {}
        options["users"] = True
        return await self.smb_enum(target, options)
    
    async def smb_pass_spray(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Password spray via SMB
        Attention: peut verrouiller des comptes!
        """
        options = options or {}
        target_safe = escape_shell_arg(target)
        
        username = options.get("username", "")
        password = options.get("password", "")
        userfile = options.get("userfile", "")
        passfile = options.get("passfile", "")
        domain = options.get("domain", "")
        
        auth = ""
        if userfile and passfile:
            auth = f"-u {escape_shell_arg(userfile)} -p {escape_shell_arg(passfile)}"
        elif userfile and password:
            auth = f"-u {escape_shell_arg(userfile)} -p {escape_shell_arg(password)}"
        elif username and passfile:
            auth = f"-u {escape_shell_arg(username)} -p {escape_shell_arg(passfile)}"
        elif username and password:
            auth = f"-u {escape_shell_arg(username)} -p {escape_shell_arg(password)}"
        
        if domain:
            auth += f" -d {escape_shell_arg(domain)}"
        
        # Options de spray
        extra = ""
        if options.get("continue_on_success", False):
            extra += " --continue-on-success"
        if options.get("no_bruteforce", True):
            extra += " --no-bruteforce"  # Évite le lockout
        
        cmd = f"nxc smb {target_safe} {auth} {extra}"
        
        result = await self._run_cmd(cmd, timeout=600)
        
        # Chercher les credentials valides
        valid_creds = self._parse_valid_creds(result.stdout)
        
        return {
            "action": "netexec_spray",
            "target": target,
            "status": "completed" if result.return_code == 0 else "error",
            "command": cmd.replace(password, "****") if password else cmd,
            "output": result.stdout,
            "error": result.stderr if result.return_code != 0 else None,
            "duration": result.duration,
            "timestamp": result.timestamp,
            "parsed_data": {
                "valid_credentials": valid_creds,
                "success_count": len(valid_creds)
            }
        }
    
    async def winrm_enum(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Énumération WinRM avec NetExec
        """
        options = options or {}
        target_safe = escape_shell_arg(target)
        auth = self._build_auth_string(options)
        
        cmd = f"nxc winrm {target_safe} {auth}"
        
        result = await self._run_cmd(cmd, timeout=300)
        
        # Vérifier si WinRM est accessible
        winrm_enabled = "Pwn3d!" in result.stdout or "[+]" in result.stdout
        
        return {
            "action": "netexec_winrm",
            "target": target,
            "status": "completed" if result.return_code == 0 else "error",
            "command": cmd.replace(options.get("password", ""), "****") if options.get("password") else cmd,
            "output": result.stdout,
            "error": result.stderr if result.return_code != 0 else None,
            "duration": result.duration,
            "timestamp": result.timestamp,
            "parsed_data": {
                "winrm_enabled": winrm_enabled,
                "can_execute": "Pwn3d!" in result.stdout
            }
        }
    
    async def winrm_exec(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Exécution de commande via WinRM
        """
        options = options or {}
        target_safe = escape_shell_arg(target)
        auth = self._build_auth_string(options)
        
        command = options.get("command", "whoami")
        command_safe = escape_shell_arg(command)
        
        cmd = f"nxc winrm {target_safe} {auth} -x '{command_safe}'"
        
        result = await self._run_cmd(cmd, timeout=120)
        
        return {
            "action": "netexec_winrm_exec",
            "target": target,
            "status": "completed" if result.return_code == 0 else "error",
            "command": cmd.replace(options.get("password", ""), "****") if options.get("password") else cmd,
            "output": result.stdout,
            "error": result.stderr if result.return_code != 0 else None,
            "duration": result.duration,
            "timestamp": result.timestamp,
            "parsed_data": {
                "command_executed": command,
                "command_output": self._extract_command_output(result.stdout)
            }
        }
    
    async def ssh_enum(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Énumération/brute-force SSH avec NetExec
        """
        options = options or {}
        target_safe = escape_shell_arg(target)
        auth = self._build_auth_string(options)
        
        cmd = f"nxc ssh {target_safe} {auth}"
        
        result = await self._run_cmd(cmd, timeout=300)
        
        return {
            "action": "netexec_ssh",
            "target": target,
            "status": "completed" if result.return_code == 0 else "error",
            "command": cmd.replace(options.get("password", ""), "****") if options.get("password") else cmd,
            "output": result.stdout,
            "error": result.stderr if result.return_code != 0 else None,
            "duration": result.duration,
            "timestamp": result.timestamp,
            "parsed_data": {
                "ssh_enabled": "[+]" in result.stdout,
                "shell_access": "Pwn3d!" in result.stdout
            }
        }
    
    async def ldap_enum(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Énumération LDAP/Active Directory
        """
        options = options or {}
        target_safe = escape_shell_arg(target)
        auth = self._build_auth_string(options)
        
        extra = ""
        if options.get("users", False):
            extra += " --users"
        if options.get("groups", False):
            extra += " --groups"
        if options.get("gmsa", False):
            extra += " --gmsa"  # Group Managed Service Accounts
        if options.get("trusted_for_delegation", False):
            extra += " --trusted-for-delegation"
        if options.get("password_not_required", False):
            extra += " --password-not-required"
        if options.get("admin_count", False):
            extra += " --admin-count"
        if options.get("asreproast", False):
            extra += " --asreproast /tmp/asreproast.txt"
        if options.get("kerberoasting", False):
            extra += " --kerberoasting /tmp/kerberoast.txt"
        
        cmd = f"nxc ldap {target_safe} {auth} {extra}"
        
        result = await self._run_cmd(cmd, timeout=300)
        
        return {
            "action": "netexec_ldap",
            "target": target,
            "status": "completed" if result.return_code == 0 else "error",
            "command": cmd.replace(options.get("password", ""), "****") if options.get("password") else cmd,
            "output": result.stdout,
            "error": result.stderr if result.return_code != 0 else None,
            "duration": result.duration,
            "timestamp": result.timestamp,
            "parsed_data": self._parse_ldap_output(result.stdout, options)
        }
    
    async def mssql_enum(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Énumération MSSQL
        """
        options = options or {}
        target_safe = escape_shell_arg(target)
        auth = self._build_auth_string(options)
        
        extra = ""
        if options.get("query"):
            query_safe = escape_shell_arg(options["query"])
            extra += f" -q '{query_safe}'"
        
        cmd = f"nxc mssql {target_safe} {auth} {extra}"
        
        result = await self._run_cmd(cmd, timeout=300)
        
        return {
            "action": "netexec_mssql",
            "target": target,
            "status": "completed" if result.return_code == 0 else "error",
            "command": cmd.replace(options.get("password", ""), "****") if options.get("password") else cmd,
            "output": result.stdout,
            "error": result.stderr if result.return_code != 0 else None,
            "duration": result.duration,
            "timestamp": result.timestamp,
            "parsed_data": {
                "mssql_enabled": "[+]" in result.stdout,
                "admin_access": "Pwn3d!" in result.stdout
            }
        }
    
    async def rdp_enum(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Énumération RDP
        """
        options = options or {}
        target_safe = escape_shell_arg(target)
        auth = self._build_auth_string(options)
        
        extra = ""
        if options.get("nla", False):
            extra += " --nla"
        if options.get("screenshot", False):
            extra += " --screenshot"
        
        cmd = f"nxc rdp {target_safe} {auth} {extra}"
        
        result = await self._run_cmd(cmd, timeout=300)
        
        return {
            "action": "netexec_rdp",
            "target": target,
            "status": "completed" if result.return_code == 0 else "error",
            "command": cmd.replace(options.get("password", ""), "****") if options.get("password") else cmd,
            "output": result.stdout,
            "error": result.stderr if result.return_code != 0 else None,
            "duration": result.duration,
            "timestamp": result.timestamp,
            "parsed_data": {
                "rdp_enabled": "[+]" in result.stdout,
                "can_connect": "Pwn3d!" in result.stdout
            }
        }
    
    async def dump_sam(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Dump SAM hashes via SMB (nécessite admin local)
        """
        options = options or {}
        target_safe = escape_shell_arg(target)
        auth = self._build_auth_string(options)
        
        cmd = f"nxc smb {target_safe} {auth} --sam"
        
        result = await self._run_cmd(cmd, timeout=300)
        
        # Parser les hashes
        hashes = self._parse_sam_hashes(result.stdout)
        
        return {
            "action": "netexec_sam",
            "target": target,
            "status": "completed" if result.return_code == 0 else "error",
            "command": cmd.replace(options.get("password", ""), "****") if options.get("password") else cmd,
            "output": result.stdout,
            "error": result.stderr if result.return_code != 0 else None,
            "duration": result.duration,
            "timestamp": result.timestamp,
            "parsed_data": {
                "hashes": hashes,
                "hash_count": len(hashes)
            }
        }
    
    async def dump_lsa(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Dump LSA secrets via SMB (nécessite admin local)
        """
        options = options or {}
        target_safe = escape_shell_arg(target)
        auth = self._build_auth_string(options)
        
        cmd = f"nxc smb {target_safe} {auth} --lsa"
        
        result = await self._run_cmd(cmd, timeout=300)
        
        return {
            "action": "netexec_lsa",
            "target": target,
            "status": "completed" if result.return_code == 0 else "error",
            "command": cmd.replace(options.get("password", ""), "****") if options.get("password") else cmd,
            "output": result.stdout,
            "error": result.stderr if result.return_code != 0 else None,
            "duration": result.duration,
            "timestamp": result.timestamp,
            "parsed_data": {
                "secrets_found": "LSA" in result.stdout
            }
        }
    
    # =========================================================================
    # Helpers
    # =========================================================================
    
    def _build_auth_string(self, options: Dict[str, Any]) -> str:
        """Construit la chaîne d'authentification pour NetExec"""
        auth_parts = []
        
        if options.get("username"):
            auth_parts.append(f"-u {escape_shell_arg(options['username'])}")
        
        if options.get("password"):
            auth_parts.append(f"-p {escape_shell_arg(options['password'])}")
        elif options.get("hash"):
            auth_parts.append(f"-H {escape_shell_arg(options['hash'])}")
        
        if options.get("domain"):
            auth_parts.append(f"-d {escape_shell_arg(options['domain'])}")
        
        if options.get("local_auth", False):
            auth_parts.append("--local-auth")
        
        return " ".join(auth_parts)
    
    def _parse_smb_output(self, output: str) -> Dict[str, Any]:
        """Parse la sortie SMB de NetExec"""
        parsed = {
            "hosts": [],
            "shares": [],
            "users": [],
            "signing": None,
            "smbv1": None
        }
        
        for line in output.split('\n'):
            # Parse host info: SMB 192.168.1.1  445  DC01  [*] Windows 10.0 Build 17763 x64
            if 'SMB' in line and '[' in line:
                # Extraire les infos
                match = re.search(r'SMB\s+(\d+\.\d+\.\d+\.\d+)\s+\d+\s+(\S+)', line)
                if match:
                    host_info = {
                        "ip": match.group(1),
                        "hostname": match.group(2),
                        "raw_line": line.strip()
                    }
                    
                    # Check signing
                    if "signing:True" in line:
                        parsed["signing"] = True
                        host_info["signing"] = True
                    elif "signing:False" in line:
                        parsed["signing"] = False
                        host_info["signing"] = False
                    
                    # Check SMBv1
                    if "SMBv1:True" in line:
                        parsed["smbv1"] = True
                        host_info["smbv1"] = True
                    elif "SMBv1:False" in line:
                        parsed["smbv1"] = False
                        host_info["smbv1"] = False
                    
                    parsed["hosts"].append(host_info)
            
            # Parse shares
            if line.strip().startswith("SHARE"):
                # Format: SHARE           READ            WRITE
                continue  # Header
            elif "READ" in line or "WRITE" in line:
                share_match = re.search(r'(\S+)\s+(READ|NO ACCESS)\s+(WRITE|NO ACCESS)?', line)
                if share_match:
                    parsed["shares"].append({
                        "name": share_match.group(1),
                        "read": share_match.group(2) == "READ",
                        "write": share_match.group(3) == "WRITE" if share_match.group(3) else False
                    })
            
            # Parse users
            if "\\\\User:" in line or "User:" in line:
                user_match = re.search(r'User:\s*(\S+)', line)
                if user_match:
                    parsed["users"].append(user_match.group(1))
        
        return parsed
    
    def _parse_valid_creds(self, output: str) -> List[Dict[str, str]]:
        """Parse les credentials valides depuis la sortie"""
        valid = []
        
        for line in output.split('\n'):
            if "[+]" in line and (":" in line or "\\" in line):
                # Format: [+] DOMAIN\user:password
                match = re.search(r'\[+\]\s*(?:(\S+)\\)?(\S+):(\S+)', line)
                if match:
                    valid.append({
                        "domain": match.group(1) or "",
                        "username": match.group(2),
                        "password": match.group(3)
                    })
        
        return valid
    
    def _parse_ldap_output(self, output: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """Parse la sortie LDAP"""
        parsed = {
            "domain_info": {},
            "users": [],
            "groups": [],
            "kerberoastable": [],
            "asreproastable": []
        }
        
        for line in output.split('\n'):
            # Parse domain info
            if "Domain:" in line:
                match = re.search(r'Domain:\s*(\S+)', line)
                if match:
                    parsed["domain_info"]["domain"] = match.group(1)
            
            # Parse users
            if "User:" in line:
                match = re.search(r'User:\s*(\S+)', line)
                if match:
                    parsed["users"].append(match.group(1))
            
            # Kerberoastable
            if options.get("kerberoasting") and "SPN:" in line:
                parsed["kerberoastable"].append(line.strip())
            
            # ASREProastable
            if options.get("asreproast") and "DONT_REQ_PREAUTH" in line:
                parsed["asreproastable"].append(line.strip())
        
        return parsed
    
    def _parse_sam_hashes(self, output: str) -> List[Dict[str, str]]:
        """Parse les hashes SAM"""
        hashes = []
        
        for line in output.split('\n'):
            # Format: Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
            if ":::" in line:
                parts = line.strip().split(':')
                if len(parts) >= 4:
                    hashes.append({
                        "username": parts[0],
                        "rid": parts[1],
                        "lm_hash": parts[2],
                        "nt_hash": parts[3]
                    })
        
        return hashes
    
    def _extract_command_output(self, output: str) -> str:
        """Extrait la sortie d'une commande depuis la sortie NetExec"""
        lines = output.split('\n')
        cmd_output = []
        capture = False
        
        for line in lines:
            if capture:
                cmd_output.append(line)
            if "[+]" in line and "Executed" in line:
                capture = True
        
        return '\n'.join(cmd_output).strip()
