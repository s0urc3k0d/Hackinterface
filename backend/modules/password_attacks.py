"""
Module Password Attacks
Brute-force et cracking de mots de passe
"""
import re
import os
from typing import Dict, Any, List
from datetime import datetime

from core.executor import CommandExecutor, escape_shell_arg
from core.config import settings


class PasswordAttacksModule:
    """Module d'attaques sur les mots de passe"""
    
    def __init__(self):
        self.executor = CommandExecutor()
        
        # Wordlists par défaut
        self.default_userlist = "/usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt"
        self.default_passlist = "/usr/share/wordlists/rockyou.txt"
        self.small_passlist = "/usr/share/wordlists/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt"
    
    async def hydra_ssh(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Brute-force SSH avec Hydra
        """
        options = options or {}
        target_safe = escape_shell_arg(target)
        
        userlist = options.get("userlist", self.default_userlist)
        passlist = options.get("passlist", self.small_passlist)
        port = options.get("port", 22)
        threads = options.get("threads", 4)
        
        cmd = f"hydra -L {userlist} -P {passlist} -s {port} -t {threads} -f {target_safe} ssh -o /tmp/hydra_ssh_{target_safe}.txt"
        
        result = await self.executor.run(cmd, timeout=3600)
        
        parsed = self._parse_hydra_output(result.stdout)
        
        return {
            "action": "hydra_ssh",
            "target": target,
            "status": "completed" if result.return_code in [0, 1] else "error",
            "command": cmd,
            "output": result.stdout,
            "error": result.stderr if result.return_code not in [0, 1] else None,
            "duration": result.duration,
            "timestamp": result.timestamp,
            "parsed_data": parsed
        }
    
    async def hydra_ftp(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Brute-force FTP avec Hydra
        """
        options = options or {}
        target_safe = escape_shell_arg(target)
        
        userlist = options.get("userlist", self.default_userlist)
        passlist = options.get("passlist", self.small_passlist)
        port = options.get("port", 21)
        threads = options.get("threads", 4)
        
        cmd = f"hydra -L {userlist} -P {passlist} -s {port} -t {threads} -f {target_safe} ftp"
        
        result = await self.executor.run(cmd, timeout=3600)
        parsed = self._parse_hydra_output(result.stdout)
        
        return {
            "action": "hydra_ftp",
            "target": target,
            "status": "completed" if result.return_code in [0, 1] else "error",
            "command": cmd,
            "output": result.stdout,
            "error": result.stderr if result.return_code not in [0, 1] else None,
            "duration": result.duration,
            "timestamp": result.timestamp,
            "parsed_data": parsed
        }
    
    async def hydra_http_post(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Brute-force formulaire HTTP POST avec Hydra
        """
        options = options or {}
        target_safe = escape_shell_arg(target)
        
        userlist = options.get("userlist", self.default_userlist)
        passlist = options.get("passlist", self.small_passlist)
        path = options.get("path", "/login")
        user_field = options.get("user_field", "username")
        pass_field = options.get("pass_field", "password")
        fail_string = options.get("fail_string", "Invalid")
        port = options.get("port", 80)
        ssl = options.get("ssl", False)
        
        protocol = "https-post-form" if ssl else "http-post-form"
        form_data = f"{path}:{user_field}=^USER^&{pass_field}=^PASS^:F={fail_string}"
        
        cmd = f"hydra -L {userlist} -P {passlist} -s {port} {target_safe} {protocol} '{form_data}'"
        
        result = await self.executor.run(cmd, timeout=3600)
        parsed = self._parse_hydra_output(result.stdout)
        
        return {
            "action": "hydra_http_post",
            "target": target,
            "status": "completed" if result.return_code in [0, 1] else "error",
            "command": cmd,
            "output": result.stdout,
            "error": result.stderr if result.return_code not in [0, 1] else None,
            "duration": result.duration,
            "timestamp": result.timestamp,
            "parsed_data": parsed
        }
    
    async def hydra_smb(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Brute-force SMB avec Hydra
        """
        options = options or {}
        target_safe = escape_shell_arg(target)
        
        userlist = options.get("userlist", self.default_userlist)
        passlist = options.get("passlist", self.small_passlist)
        
        cmd = f"hydra -L {userlist} -P {passlist} -t 1 {target_safe} smb"
        
        result = await self.executor.run(cmd, timeout=3600)
        parsed = self._parse_hydra_output(result.stdout)
        
        return {
            "action": "hydra_smb",
            "target": target,
            "status": "completed" if result.return_code in [0, 1] else "error",
            "command": cmd,
            "output": result.stdout,
            "error": result.stderr if result.return_code not in [0, 1] else None,
            "duration": result.duration,
            "timestamp": result.timestamp,
            "parsed_data": parsed
        }
    
    async def hydra_rdp(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Brute-force RDP avec Hydra
        """
        options = options or {}
        target_safe = escape_shell_arg(target)
        
        userlist = options.get("userlist", self.default_userlist)
        passlist = options.get("passlist", self.small_passlist)
        
        cmd = f"hydra -L {userlist} -P {passlist} -t 1 {target_safe} rdp"
        
        result = await self.executor.run(cmd, timeout=3600)
        parsed = self._parse_hydra_output(result.stdout)
        
        return {
            "action": "hydra_rdp",
            "target": target,
            "status": "completed" if result.return_code in [0, 1] else "error",
            "command": cmd,
            "output": result.stdout,
            "error": result.stderr if result.return_code not in [0, 1] else None,
            "duration": result.duration,
            "timestamp": result.timestamp,
            "parsed_data": parsed
        }
    
    async def hashid(self, hash_value: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Identifier le type d'un hash
        """
        hash_safe = escape_shell_arg(hash_value)
        
        cmd = f"hashid -m '{hash_safe}'"
        
        result = await self.executor.run(cmd, timeout=30)
        parsed = self._parse_hashid(result.stdout)
        
        return {
            "action": "hashid",
            "target": hash_value[:20] + "..." if len(hash_value) > 20 else hash_value,
            "status": "completed" if result.return_code == 0 else "error",
            "command": cmd,
            "output": result.stdout,
            "error": result.stderr if result.return_code != 0 else None,
            "duration": result.duration,
            "timestamp": result.timestamp,
            "parsed_data": parsed
        }
    
    async def john_crack(self, hash_file: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Cracker des hashes avec John the Ripper
        """
        options = options or {}
        
        wordlist = options.get("wordlist", self.small_passlist)
        format_type = options.get("format", "")
        
        format_arg = f"--format={format_type}" if format_type else ""
        cmd = f"john --wordlist={wordlist} {format_arg} {hash_file}"
        
        result = await self.executor.run(cmd, timeout=3600)
        
        # Récupérer les résultats crackés
        show_cmd = f"john --show {hash_file}"
        show_result = await self.executor.run(show_cmd, timeout=30)
        
        parsed = self._parse_john_output(show_result.stdout)
        
        return {
            "action": "john_crack",
            "target": hash_file,
            "status": "completed",
            "command": cmd,
            "output": result.stdout + "\n\n=== Cracked ===\n" + show_result.stdout,
            "duration": result.duration,
            "timestamp": result.timestamp,
            "parsed_data": parsed
        }
    
    async def hashcat_crack(self, hash_file: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Cracker des hashes avec Hashcat (si GPU disponible)
        """
        options = options or {}
        
        wordlist = options.get("wordlist", self.small_passlist)
        hash_mode = options.get("mode", 0)  # 0 = MD5, 1000 = NTLM, etc.
        
        cmd = f"hashcat -m {hash_mode} -a 0 {hash_file} {wordlist} --potfile-disable -o /tmp/hashcat_cracked.txt"
        
        result = await self.executor.run(cmd, timeout=3600)
        
        # Lire les résultats
        cracked = []
        if os.path.exists("/tmp/hashcat_cracked.txt"):
            with open("/tmp/hashcat_cracked.txt", "r") as f:
                cracked = f.read().strip().split("\n")
        
        return {
            "action": "hashcat_crack",
            "target": hash_file,
            "status": "completed" if result.return_code in [0, 1] else "error",
            "command": cmd,
            "output": result.stdout,
            "error": result.stderr if result.return_code not in [0, 1] else None,
            "duration": result.duration,
            "timestamp": result.timestamp,
            "parsed_data": {"cracked": cracked, "count": len(cracked)}
        }
    
    async def cewl(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Générer une wordlist depuis un site web avec CeWL
        """
        options = options or {}
        target_safe = escape_shell_arg(target)
        
        depth = options.get("depth", 2)
        min_length = options.get("min_length", 6)
        output_file = f"/tmp/cewl_{target_safe.replace('/', '_').replace(':', '_')}.txt"
        
        cmd = f"cewl -d {depth} -m {min_length} -w {output_file} {target_safe}"
        
        result = await self.executor.run(cmd, timeout=300)
        
        # Compter les mots générés
        word_count = 0
        words = []
        if os.path.exists(output_file):
            with open(output_file, "r") as f:
                words = f.read().strip().split("\n")
                word_count = len(words)
        
        return {
            "action": "cewl",
            "target": target,
            "status": "completed" if result.return_code == 0 else "error",
            "command": cmd,
            "output": result.stdout,
            "error": result.stderr if result.return_code != 0 else None,
            "duration": result.duration,
            "timestamp": result.timestamp,
            "parsed_data": {
                "wordlist_file": output_file,
                "word_count": word_count,
                "sample": words[:20] if words else []
            }
        }
    
    def _parse_hydra_output(self, output: str) -> Dict[str, Any]:
        """Parse la sortie de Hydra"""
        credentials = []
        
        # Format: [SERVICE][HOST] host: X   login: USER   password: PASS
        pattern = r'\[.*\]\s+host:\s+\S+\s+login:\s+(\S+)\s+password:\s+(\S+)'
        matches = re.findall(pattern, output)
        
        for match in matches:
            credentials.append({
                "username": match[0],
                "password": match[1]
            })
        
        return {
            "credentials": credentials,
            "found": len(credentials) > 0,
            "count": len(credentials)
        }
    
    def _parse_hashid(self, output: str) -> Dict[str, Any]:
        """Parse la sortie de hashid"""
        hash_types = []
        
        for line in output.split('\n'):
            if '[+]' in line:
                # Format: [+] Type [Hashcat Mode: X]
                match = re.search(r'\[\+\]\s+(.+?)(?:\s+\[Hashcat Mode:\s*(\d+)\])?$', line)
                if match:
                    hash_types.append({
                        "type": match.group(1).strip(),
                        "hashcat_mode": match.group(2) if match.group(2) else None
                    })
        
        return {
            "possible_types": hash_types,
            "count": len(hash_types)
        }
    
    def _parse_john_output(self, output: str) -> Dict[str, Any]:
        """Parse la sortie de john --show"""
        cracked = []
        
        for line in output.split('\n'):
            if ':' in line and 'password hashes cracked' not in line:
                parts = line.split(':')
                if len(parts) >= 2:
                    cracked.append({
                        "user": parts[0],
                        "password": parts[1]
                    })
        
        return {
            "cracked": cracked,
            "count": len(cracked)
        }
