"""
Exécuteur de commandes système
Gère l'exécution des outils de pentest
"""
import asyncio
import subprocess
import shlex
import os
from dataclasses import dataclass
from typing import Optional, List, Dict, Any
from datetime import datetime
from .config import settings

@dataclass
class CommandResult:
    """Résultat d'une commande exécutée"""
    command: str
    stdout: str
    stderr: str
    return_code: int
    duration: float
    timestamp: str
    
    def to_dict(self) -> dict:
        return {
            "command": self.command,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "return_code": self.return_code,
            "duration": self.duration,
            "timestamp": self.timestamp,
            "success": self.return_code == 0
        }

class CommandExecutor:
    """Exécuteur de commandes avec gestion async"""
    
    def __init__(self):
        self.running_processes: Dict[str, subprocess.Popen] = {}
    
    async def run(
        self,
        command: str,
        timeout: Optional[int] = None,
        working_dir: Optional[str] = None,
        env: Optional[Dict[str, str]] = None
    ) -> CommandResult:
        """
        Exécute une commande de manière asynchrone
        """
        if timeout is None:
            timeout = settings.COMMAND_TIMEOUT
        
        start_time = datetime.now()
        timestamp = start_time.isoformat()
        
        # Préparer l'environnement
        cmd_env = os.environ.copy()
        if env:
            cmd_env.update(env)
        
        try:
            # Exécution asynchrone
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=working_dir,
                env=cmd_env
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=timeout
                )
            except asyncio.TimeoutError:
                process.kill()
                await process.communicate()
                return CommandResult(
                    command=command,
                    stdout="",
                    stderr=f"Commande interrompue après {timeout} secondes",
                    return_code=-1,
                    duration=timeout,
                    timestamp=timestamp
                )
            
            duration = (datetime.now() - start_time).total_seconds()
            
            return CommandResult(
                command=command,
                stdout=stdout.decode('utf-8', errors='replace'),
                stderr=stderr.decode('utf-8', errors='replace'),
                return_code=process.returncode,
                duration=duration,
                timestamp=timestamp
            )
            
        except Exception as e:
            duration = (datetime.now() - start_time).total_seconds()
            return CommandResult(
                command=command,
                stdout="",
                stderr=str(e),
                return_code=-1,
                duration=duration,
                timestamp=timestamp
            )
    
    async def run_with_callback(
        self,
        command: str,
        callback,
        timeout: Optional[int] = None
    ):
        """
        Exécute une commande et envoie les résultats via callback (pour WebSocket)
        """
        if timeout is None:
            timeout = settings.COMMAND_TIMEOUT
        
        start_time = datetime.now()
        
        try:
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            # Lire la sortie en temps réel
            async def read_stream(stream, stream_type):
                while True:
                    line = await stream.readline()
                    if not line:
                        break
                    text = line.decode('utf-8', errors='replace')
                    await callback({
                        "type": stream_type,
                        "data": text,
                        "command": command
                    })
            
            await asyncio.gather(
                read_stream(process.stdout, "stdout"),
                read_stream(process.stderr, "stderr")
            )
            
            await process.wait()
            
            duration = (datetime.now() - start_time).total_seconds()
            
            await callback({
                "type": "completed",
                "command": command,
                "return_code": process.returncode,
                "duration": duration
            })
            
        except Exception as e:
            await callback({
                "type": "error",
                "command": command,
                "error": str(e)
            })
    
    def check_tool_available(self, tool: str) -> bool:
        """Vérifie si un outil est disponible"""
        try:
            result = subprocess.run(
                ["which", tool],
                capture_output=True,
                timeout=5
            )
            return result.returncode == 0
        except:
            return False
    
    def get_available_tools(self) -> Dict[str, bool]:
        """Liste tous les outils et leur disponibilité"""
        return {
            tool: self.check_tool_available(path)
            for tool, path in settings.TOOLS.items()
        }

# Fonctions utilitaires
def escape_shell_arg(arg: str) -> str:
    """Échappe un argument shell de manière sécurisée"""
    return shlex.quote(arg)

def validate_ip(ip: str) -> bool:
    """Valide une adresse IP"""
    import re
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if not re.match(pattern, ip):
        return False
    parts = ip.split('.')
    return all(0 <= int(part) <= 255 for part in parts)

def validate_domain(domain: str) -> bool:
    """Valide un nom de domaine"""
    import re
    pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$'
    return bool(re.match(pattern, domain))

def validate_cidr(cidr: str) -> bool:
    """Valide une plage CIDR"""
    import re
    pattern = r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$'
    if not re.match(pattern, cidr):
        return False
    ip, prefix = cidr.split('/')
    return validate_ip(ip) and 0 <= int(prefix) <= 32
