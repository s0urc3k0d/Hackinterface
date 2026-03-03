"""
Kerbrute Module
===============
Énumération et brute-force Kerberos
"""

from typing import Dict, Any, List, Optional
from datetime import datetime
from core.executor import CommandExecutor
import re


class KerbruteModule:
    """
    Module pour Kerbrute
    - Énumération d'utilisateurs via Kerberos (sans auth)
    - Brute-force de mots de passe
    - Password spray
    """
    
    def __init__(self):
        self.executor = CommandExecutor()

    def _sanitize_int(self, value: Any, default: int, minimum: int, maximum: int) -> int:
        try:
            parsed = int(value)
        except (TypeError, ValueError):
            return default
        return max(minimum, min(parsed, maximum))

    def _sanitize_path(self, value: Any, default: str) -> str:
        if not isinstance(value, str) or not value.strip():
            return default
        return value.strip()
    
    async def userenum(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Énumération d'utilisateurs via Kerberos
        Ne génère pas de logs d'échec d'auth!
        """
        options = options or {}
        domain = options.get("domain", target)
        
        userlist = self._sanitize_path(options.get("userlist"), "/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt")
        output_file = f"/tmp/kerbrute_users_{int(datetime.now().timestamp())}.txt"
        
        threads = self._sanitize_int(options.get("threads"), 10, 1, 128)

        cmd_args = [
            "kerbrute", "userenum", "--dc", target,
            "-d", str(domain), userlist, "-t", str(threads), "-o", output_file
        ]

        result = await self.executor.run_args(cmd_args, timeout=1800)
        
        # Parser les utilisateurs valides
        valid_users = self._parse_valid_users(result.stdout)
        
        # Lire le fichier de sortie
        try:
            with open(output_file, 'r') as f:
                file_users = [line.strip() for line in f if line.strip()]
        except:
            file_users = []
        
        return {
            "action": "kerbrute_userenum",
            "target": target,
            "status": "completed" if result.return_code == 0 else "error",
            "command": result.command,
            "output": result.stdout,
            "error": result.stderr if result.return_code != 0 else None,
            "duration": result.duration,
            "timestamp": result.timestamp,
            "parsed_data": {
                "valid_users": valid_users or file_users,
                "user_count": len(valid_users or file_users),
                "output_file": output_file
            }
        }
    
    async def passwordspray(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Password spray via Kerberos
        Teste un mot de passe contre plusieurs utilisateurs
        """
        options = options or {}
        domain = options.get("domain", target)
        
        userlist = options.get("userlist", "")
        password = options.get("password", "")
        
        if not userlist or not password:
            return {
                "action": "kerbrute_spray",
                "target": target,
                "status": "error",
                "error": "userlist et password sont requis",
                "timestamp": datetime.now().isoformat()
            }
        
        output_file = f"/tmp/kerbrute_spray_{int(datetime.now().timestamp())}.txt"
        threads = self._sanitize_int(options.get("threads"), 10, 1, 128)

        cmd_args = [
            "kerbrute", "passwordspray", "--dc", target,
            "-d", str(domain), str(userlist), str(password), "-t", str(threads), "-o", output_file
        ]

        result = await self.executor.run_args(cmd_args, timeout=1800)
        
        # Parser les credentials valides
        valid_creds = self._parse_valid_creds(result.stdout)
        
        return {
            "action": "kerbrute_spray",
            "target": target,
            "status": "completed" if result.return_code == 0 else "error",
            "command": result.command.replace(password, "****"),
            "output": result.stdout,
            "error": result.stderr if result.return_code != 0 else None,
            "duration": result.duration,
            "timestamp": result.timestamp,
            "parsed_data": {
                "valid_credentials": valid_creds,
                "success_count": len(valid_creds),
                "output_file": output_file
            }
        }
    
    async def bruteforce(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Brute-force de mot de passe pour un utilisateur spécifique
        """
        options = options or {}
        domain = options.get("domain", target)
        
        username = options.get("username", "")
        passlist = self._sanitize_path(options.get("passlist"), "/usr/share/wordlists/rockyou.txt")
        
        if not username:
            return {
                "action": "kerbrute_bruteforce",
                "target": target,
                "status": "error",
                "error": "username est requis",
                "timestamp": datetime.now().isoformat()
            }
        
        output_file = f"/tmp/kerbrute_brute_{int(datetime.now().timestamp())}.txt"
        threads = self._sanitize_int(options.get("threads"), 10, 1, 128)

        cmd_args = [
            "kerbrute", "bruteuser", "--dc", target,
            "-d", str(domain), passlist, str(username), "-t", str(threads), "-o", output_file
        ]

        result = await self.executor.run_args(cmd_args, timeout=3600)
        
        # Chercher le mot de passe trouvé
        found_password = self._parse_found_password(result.stdout, username)
        
        return {
            "action": "kerbrute_bruteforce",
            "target": target,
            "status": "completed" if result.return_code == 0 else "error",
            "command": result.command,
            "output": result.stdout,
            "error": result.stderr if result.return_code != 0 else None,
            "duration": result.duration,
            "timestamp": result.timestamp,
            "parsed_data": {
                "username": username,
                "password_found": found_password,
                "success": found_password is not None,
                "output_file": output_file
            }
        }
    
    async def bruteforce_multi(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Brute-force avec liste d'utilisateurs et liste de mots de passe
        """
        options = options or {}
        domain = options.get("domain", target)
        
        userlist = options.get("userlist", "")
        passlist = self._sanitize_path(options.get("passlist"), "/usr/share/wordlists/rockyou.txt")
        
        if not userlist:
            return {
                "action": "kerbrute_bruteforce_multi",
                "target": target,
                "status": "error",
                "error": "userlist est requis",
                "timestamp": datetime.now().isoformat()
            }
        
        output_file = f"/tmp/kerbrute_multi_{int(datetime.now().timestamp())}.txt"
        threads = self._sanitize_int(options.get("threads"), 10, 1, 128)

        cmd_args = [
            "kerbrute", "bruteforce", "--dc", target,
            "-d", str(domain), "-users", str(userlist), "-passwords", passlist,
            "-t", str(threads), "-o", output_file
        ]

        result = await self.executor.run_args(cmd_args, timeout=7200)
        
        # Parser tous les credentials trouvés
        valid_creds = self._parse_valid_creds(result.stdout)
        
        return {
            "action": "kerbrute_bruteforce_multi",
            "target": target,
            "status": "completed" if result.return_code == 0 else "error",
            "command": result.command,
            "output": result.stdout,
            "error": result.stderr if result.return_code != 0 else None,
            "duration": result.duration,
            "timestamp": result.timestamp,
            "parsed_data": {
                "valid_credentials": valid_creds,
                "success_count": len(valid_creds),
                "output_file": output_file
            }
        }
    
    # =========================================================================
    # Parsers
    # =========================================================================
    
    def _parse_valid_users(self, output: str) -> List[str]:
        """Parse les utilisateurs valides"""
        users = []
        for line in output.split('\n'):
            # Format: [+] VALID USERNAME: user@domain.local
            if 'VALID USERNAME' in line.upper():
                match = re.search(r'VALID USERNAME[:\s]+(\S+)', line, re.I)
                if match:
                    users.append(match.group(1))
        return users
    
    def _parse_valid_creds(self, output: str) -> List[Dict[str, str]]:
        """Parse les credentials valides"""
        creds = []
        for line in output.split('\n'):
            # Format: [+] VALID LOGIN: user@domain.local:password
            if 'VALID LOGIN' in line.upper() or 'SUCCESS' in line.upper():
                match = re.search(r'(\S+@\S+):(\S+)', line)
                if match:
                    creds.append({
                        "username": match.group(1),
                        "password": match.group(2)
                    })
        return creds
    
    def _parse_found_password(self, output: str, username: str) -> Optional[str]:
        """Parse le mot de passe trouvé pour un utilisateur"""
        for line in output.split('\n'):
            if username.lower() in line.lower() and ('VALID' in line.upper() or 'SUCCESS' in line.upper()):
                match = re.search(rf'{re.escape(username)}[^:]*:(\S+)', line, re.I)
                if match:
                    return match.group(1)
        return None
