"""
BloodHound Module
=================
Intégration de BloodHound et SharpHound pour la cartographie AD
"""

from typing import Dict, Any, List, Optional
from datetime import datetime
from core.executor import CommandExecutor, escape_shell_arg
import json
import os
import zipfile


class BloodHoundModule:
    """
    Module pour BloodHound
    - bloodhound-python: Collecteur Python (furtif)
    - SharpHound: Collecteur .NET (complet)
    - Analyse des chemins d'attaque AD
    """
    
    def __init__(self):
        self.executor = CommandExecutor()
        self.output_dir = "/tmp/bloodhound"
        os.makedirs(self.output_dir, exist_ok=True)
    
    async def bloodhound_python(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Collecte avec bloodhound-python (collecteur Python)
        Plus furtif, fonctionne depuis Linux
        """
        options = options or {}
        target_safe = escape_shell_arg(target)
        
        username = options.get("username", "")
        password = options.get("password", "")
        domain = options.get("domain", target)
        
        output_dir = f"{self.output_dir}/{domain}_{int(datetime.now().timestamp())}"
        os.makedirs(output_dir, exist_ok=True)
        
        # Méthodes de collecte
        collect_methods = options.get("collect", "Default")  # All, Default, DCOnly, Group, LocalAdmin, Session, Trusts, etc.
        
        cmd = f"bloodhound-python -u {escape_shell_arg(username)} -p {escape_shell_arg(password)} -d {escape_shell_arg(domain)}"
        
        if options.get("dc_ip"):
            cmd += f" -dc {escape_shell_arg(options['dc_ip'])}"
        else:
            cmd += f" -dc {target_safe}"
        
        if options.get("nameserver"):
            cmd += f" -ns {escape_shell_arg(options['nameserver'])}"
        
        cmd += f" -c {collect_methods}"
        cmd += f" --zip -o {output_dir}"
        
        result = await self.executor.run(cmd, timeout=900)
        
        # Trouver le fichier ZIP généré
        zip_files = [f for f in os.listdir(output_dir) if f.endswith('.zip')]
        
        # Analyser les stats si fichier trouvé
        stats = {}
        if zip_files:
            stats = self._analyze_bloodhound_zip(os.path.join(output_dir, zip_files[0]))
        
        return {
            "action": "bloodhound_collect",
            "target": target,
            "status": "completed" if result.return_code == 0 else "error",
            "command": cmd.replace(password, "****") if password else cmd,
            "output": result.stdout,
            "error": result.stderr if result.return_code != 0 else None,
            "duration": result.duration,
            "timestamp": result.timestamp,
            "parsed_data": {
                "output_directory": output_dir,
                "zip_files": zip_files,
                "collect_methods": collect_methods,
                "statistics": stats
            }
        }
    
    async def bloodhound_dns(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Collecte via DNS uniquement (sans auth)
        Utile pour la reconnaissance initiale
        """
        options = options or {}
        domain = options.get("domain", target)
        
        output_dir = f"{self.output_dir}/{domain}_dns_{int(datetime.now().timestamp())}"
        os.makedirs(output_dir, exist_ok=True)
        
        # Collecte DNS only
        cmd = f"bloodhound-python -d {escape_shell_arg(domain)} -c DCOnly --dns-tcp -o {output_dir}"
        
        if options.get("nameserver"):
            cmd += f" -ns {escape_shell_arg(options['nameserver'])}"
        
        result = await self.executor.run(cmd, timeout=300)
        
        return {
            "action": "bloodhound_dns",
            "target": target,
            "status": "completed" if result.return_code == 0 else "error",
            "command": cmd,
            "output": result.stdout,
            "error": result.stderr if result.return_code != 0 else None,
            "duration": result.duration,
            "timestamp": result.timestamp,
            "parsed_data": {
                "output_directory": output_dir
            }
        }
    
    async def sharphound_run(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Exécution de SharpHound via un shell distant (nécessite accès Windows)
        """
        options = options or {}
        
        # Chemin vers SharpHound
        sharphound_path = options.get("sharphound_path", "SharpHound.exe")
        collect_methods = options.get("collect", "All")
        
        # Commande SharpHound
        cmd = f"{sharphound_path} -c {collect_methods}"
        
        if options.get("domain"):
            cmd += f" -d {options['domain']}"
        if options.get("output"):
            cmd += f" -o {options['output']}"
        if options.get("stealth", False):
            cmd += " --stealth"
        if options.get("excludedcs", False):
            cmd += " --excludedcs"
        
        # Cette commande devrait être exécutée via evil-winrm ou psexec
        # Pour l'instant, on retourne les instructions
        return {
            "action": "sharphound",
            "target": target,
            "status": "info",
            "command": cmd,
            "output": f"Exécutez cette commande sur la cible Windows:\n{cmd}\n\nOu utilisez evil-winrm/psexec pour l'exécuter à distance.",
            "duration": 0,
            "timestamp": datetime.now().isoformat(),
            "parsed_data": {
                "sharphound_command": cmd,
                "collect_methods": collect_methods,
                "instructions": [
                    "1. Transférez SharpHound.exe sur la cible",
                    "2. Exécutez la commande ci-dessus",
                    "3. Récupérez le fichier ZIP généré",
                    "4. Importez dans BloodHound GUI"
                ]
            }
        }
    
    async def import_to_neo4j(self, zip_path: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Import des données dans Neo4j pour BloodHound
        """
        options = options or {}
        
        neo4j_uri = options.get("neo4j_uri", "bolt://localhost:7687")
        neo4j_user = options.get("neo4j_user", "neo4j")
        neo4j_pass = options.get("neo4j_pass", "neo4j")
        
        # Utiliser bloodhound-import si disponible
        cmd = f"bloodhound-import -du {neo4j_user} -dp {neo4j_pass} {escape_shell_arg(zip_path)}"
        
        result = await self.executor.run(cmd, timeout=300)
        
        return {
            "action": "bloodhound_import",
            "target": zip_path,
            "status": "completed" if result.return_code == 0 else "error",
            "command": cmd.replace(neo4j_pass, "****"),
            "output": result.stdout,
            "error": result.stderr if result.return_code != 0 else None,
            "duration": result.duration,
            "timestamp": result.timestamp,
            "parsed_data": {
                "imported_file": zip_path
            }
        }
    
    def _analyze_bloodhound_zip(self, zip_path: str) -> Dict[str, int]:
        """Analyse le contenu du ZIP BloodHound"""
        stats = {
            "users": 0,
            "computers": 0,
            "groups": 0,
            "domains": 0,
            "gpos": 0,
            "ous": 0
        }
        
        try:
            with zipfile.ZipFile(zip_path, 'r') as z:
                for filename in z.namelist():
                    if filename.endswith('.json'):
                        with z.open(filename) as f:
                            data = json.load(f)
                            if isinstance(data, dict) and 'data' in data:
                                count = len(data['data'])
                                
                                if 'users' in filename.lower():
                                    stats['users'] = count
                                elif 'computers' in filename.lower():
                                    stats['computers'] = count
                                elif 'groups' in filename.lower():
                                    stats['groups'] = count
                                elif 'domains' in filename.lower():
                                    stats['domains'] = count
                                elif 'gpos' in filename.lower():
                                    stats['gpos'] = count
                                elif 'ous' in filename.lower():
                                    stats['ous'] = count
        except Exception as e:
            stats['error'] = str(e)
        
        return stats
