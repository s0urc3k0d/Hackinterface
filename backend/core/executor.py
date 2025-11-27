"""
Exécuteur de commandes système
Gère l'exécution des outils de pentest
"""
import asyncio
import subprocess
import shlex
import os
import re
from dataclasses import dataclass
from typing import Optional, List, Dict, Any
from datetime import datetime
from .config import settings


# Patterns pour masquer les informations sensibles
CREDENTIAL_PATTERNS = [
    # Mots de passe en ligne de commande
    (r'(-p\s*|--password[=\s]*|--pass[=\s]*|--pwd[=\s]*|:)([^\s@"\']+)(@)', r'\1***MASKED***\3'),
    (r'(-p\s*|--password[=\s]*|--pass[=\s]*|--pwd[=\s]*)([^\s"\']+)', r'\1***MASKED***'),
    # Hashes NTLM/LM
    (r'([a-fA-F0-9]{32}:[a-fA-F0-9]{32})', r'***HASH_MASKED***'),
    (r'(aad3b435b51404eeaad3b435b51404ee:[a-fA-F0-9]{32})', r'***EMPTY_LM:NTLM_MASKED***'),
    # Tokens et clés API
    (r'(token[=:\s]*|api[_-]?key[=:\s]*|secret[=:\s]*|bearer\s+)([a-zA-Z0-9_\-]+)', r'\1***MASKED***'),
    # Credentials dans URLs
    (r'(://[^:]+:)([^@]+)(@)', r'\1***MASKED***\3'),
]


def mask_credentials(text: str) -> str:
    """
    Masque les informations sensibles dans une chaîne de texte
    Utilise plusieurs patterns pour détecter et masquer les credentials
    """
    if not text:
        return text
    
    masked = text
    for pattern, replacement in CREDENTIAL_PATTERNS:
        masked = re.sub(pattern, replacement, masked, flags=re.IGNORECASE)
    
    return masked


@dataclass
class CommandResult:
    """Résultat d'une commande exécutée"""
    command: str
    stdout: str
    stderr: str
    return_code: int
    duration: float
    timestamp: str
    
    def to_dict(self, mask_sensitive: bool = True) -> dict:
        """
        Convertit en dictionnaire
        Args:
            mask_sensitive: Si True, masque les credentials dans la commande et la sortie
        """
        cmd = mask_credentials(self.command) if mask_sensitive else self.command
        out = mask_credentials(self.stdout) if mask_sensitive else self.stdout
        err = mask_credentials(self.stderr) if mask_sensitive else self.stderr
        
        return {
            "command": cmd,
            "stdout": out,
            "stderr": err,
            "return_code": self.return_code,
            "duration": self.duration,
            "timestamp": self.timestamp,
            "success": self.return_code == 0
        }


class RateLimiter:
    """Gestionnaire de rate limiting intelligent"""
    
    def __init__(self, max_concurrent: int = 5, delay_between: float = 0.5):
        self.max_concurrent = max_concurrent
        self.delay_between = delay_between
        self.current_count = 0
        self.lock = asyncio.Lock()
        self.last_execution = datetime.now()
        # Historique pour adapter le délai
        self.error_count = 0
        self.success_count = 0
    
    async def acquire(self):
        """Acquiert un slot d'exécution"""
        async with self.lock:
            while self.current_count >= self.max_concurrent:
                await asyncio.sleep(0.1)
            
            # Délai adaptatif basé sur les erreurs
            adaptive_delay = self.delay_between
            if self.error_count > 5:
                adaptive_delay *= 2  # Double le délai après 5 erreurs
            elif self.error_count > 10:
                adaptive_delay *= 4  # Quadruple après 10 erreurs
            
            # Attendre le délai minimum entre exécutions
            elapsed = (datetime.now() - self.last_execution).total_seconds()
            if elapsed < adaptive_delay:
                await asyncio.sleep(adaptive_delay - elapsed)
            
            self.current_count += 1
            self.last_execution = datetime.now()
    
    async def release(self, success: bool = True):
        """Libère un slot d'exécution"""
        async with self.lock:
            self.current_count = max(0, self.current_count - 1)
            if success:
                self.success_count += 1
                # Réduire progressivement le compteur d'erreurs
                if self.success_count % 10 == 0:
                    self.error_count = max(0, self.error_count - 1)
            else:
                self.error_count += 1
    
    def get_stats(self) -> Dict[str, Any]:
        """Retourne les statistiques du rate limiter"""
        return {
            "current_count": self.current_count,
            "max_concurrent": self.max_concurrent,
            "error_count": self.error_count,
            "success_count": self.success_count,
            "adaptive_delay": self.delay_between * (1 + min(self.error_count, 10) / 5)
        }


class CommandExecutor:
    """Exécuteur de commandes avec gestion async, rate limiting et retry"""
    
    def __init__(self, max_concurrent: int = 5, delay_between: float = 0.5):
        self.running_processes: Dict[str, subprocess.Popen] = {}
        self.rate_limiter = RateLimiter(max_concurrent, delay_between)
    
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
        
        # Rate limiting
        await self.rate_limiter.acquire()
        
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
                await self.rate_limiter.release(success=False)
                return CommandResult(
                    command=command,
                    stdout="",
                    stderr=f"Commande interrompue après {timeout} secondes",
                    return_code=-1,
                    duration=timeout,
                    timestamp=timestamp
                )
            
            duration = (datetime.now() - start_time).total_seconds()
            success = process.returncode == 0
            await self.rate_limiter.release(success=success)
            
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
            await self.rate_limiter.release(success=False)
            return CommandResult(
                command=command,
                stdout="",
                stderr=str(e),
                return_code=-1,
                duration=duration,
                timestamp=timestamp
            )
    
    async def run_with_retry(
        self,
        command: str,
        max_retries: int = 3,
        timeout: Optional[int] = None,
        working_dir: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
        retry_on_codes: Optional[List[int]] = None
    ) -> CommandResult:
        """
        Exécute une commande avec retry automatique et backoff exponentiel
        
        Args:
            command: Commande à exécuter
            max_retries: Nombre maximum de tentatives
            timeout: Timeout en secondes
            working_dir: Répertoire de travail
            env: Variables d'environnement
            retry_on_codes: Codes de retour déclenchant un retry (défaut: tous sauf 0)
        """
        retry_on_codes = retry_on_codes or []
        last_result = None
        base_delay = 1.0
        
        for attempt in range(max_retries + 1):
            result = await self.run(command, timeout, working_dir, env)
            last_result = result
            
            # Succès
            if result.return_code == 0:
                return result
            
            # Vérifier si on doit retry
            should_retry = (
                attempt < max_retries and
                (not retry_on_codes or result.return_code in retry_on_codes)
            )
            
            if not should_retry:
                break
            
            # Backoff exponentiel: 1s, 2s, 4s, 8s...
            delay = base_delay * (2 ** attempt)
            # Ajouter un jitter aléatoire (±20%)
            import random
            delay *= (0.8 + random.random() * 0.4)
            
            await asyncio.sleep(delay)
        
        return last_result
    
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
    
    def get_tool_from_command(self, command: str) -> Optional[str]:
        """
        Extrait le nom de l'outil principal d'une commande
        Gère les cas avec sudo, timeout, nice, etc.
        """
        prefixes = {'sudo', 'timeout', 'nice', 'ionice', 'strace', 'time', 'env'}
        parts = shlex.split(command)
        
        for part in parts:
            # Ignorer les options (commencent par -)
            if part.startswith('-'):
                continue
            # Ignorer les préfixes communs
            if part in prefixes:
                continue
            # Ignorer les arguments numériques (ex: timeout 300)
            if part.isdigit():
                continue
            # Ignorer les assignations de variables (ex: VAR=value)
            if '=' in part:
                continue
            # C'est probablement l'outil
            return part
        
        return None
    
    async def run_with_check(
        self,
        command: str,
        timeout: Optional[int] = None,
        working_dir: Optional[str] = None,
        env: Optional[Dict[str, str]] = None
    ) -> CommandResult:
        """
        Exécute une commande après avoir vérifié que l'outil est disponible
        Retourne une erreur informative si l'outil n'est pas installé
        """
        tool = self.get_tool_from_command(command)
        
        if tool and not self.check_tool_available(tool):
            return CommandResult(
                command=command,
                stdout="",
                stderr=f"Outil '{tool}' non trouvé. Installez-le avec: sudo apt install {tool} ou consultez la documentation.",
                return_code=-2,
                duration=0.0,
                timestamp=datetime.now().isoformat()
            )
        
        return await self.run(command, timeout, working_dir, env)
    
    def get_available_tools(self) -> Dict[str, bool]:
        """Liste tous les outils et leur disponibilité"""
        return {
            tool: self.check_tool_available(path)
            for tool, path in settings.TOOLS.items()
        }
    
    def get_missing_tools(self) -> List[str]:
        """Retourne la liste des outils manquants"""
        return [
            tool for tool, available in self.get_available_tools().items()
            if not available
        ]


# Instance globale de l'executor avec vérification
executor = CommandExecutor()

# Fonctions utilitaires
def escape_shell_arg(arg: str) -> str:
    """Échappe un argument shell de manière sécurisée"""
    return shlex.quote(arg)


@dataclass
class ValidationResult:
    """Résultat de validation d'une cible"""
    valid: bool
    target_type: str
    normalized: str
    message: str
    details: Dict[str, Any]


class TargetValidator:
    """Validateur avancé pour les cibles de pentest"""
    
    # Patterns de validation
    IPV4_PATTERN = re.compile(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$')
    IPV6_PATTERN = re.compile(r'^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::$|^([0-9a-fA-F]{1,4}:){1,7}:$')
    CIDR_V4_PATTERN = re.compile(r'^(\d{1,3}\.){3}\d{1,3}/(\d{1,2})$')
    DOMAIN_PATTERN = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$')
    URL_PATTERN = re.compile(r'^(https?://)([a-zA-Z0-9.-]+)(:\d+)?(/.*)?$')
    
    # TLDs valides (liste partielle des plus courants)
    VALID_TLDS = {
        'com', 'org', 'net', 'edu', 'gov', 'mil', 'int',
        'fr', 'de', 'uk', 'it', 'es', 'pt', 'nl', 'be', 'ch', 'at',
        'us', 'ca', 'au', 'nz', 'jp', 'cn', 'kr', 'in', 'ru', 'br',
        'io', 'co', 'me', 'tv', 'info', 'biz', 'xyz', 'online', 'site',
        'app', 'dev', 'cloud', 'tech', 'ai', 'ml', 'local', 'test', 'htb'
    }
    
    # Plages IP privées
    PRIVATE_RANGES = [
        ('10.0.0.0', '10.255.255.255'),
        ('172.16.0.0', '172.31.255.255'),
        ('192.168.0.0', '192.168.255.255'),
        ('127.0.0.0', '127.255.255.255'),
    ]
    
    @classmethod
    def validate(cls, target: str) -> ValidationResult:
        """
        Valide et identifie le type de cible
        
        Returns:
            ValidationResult avec le type détecté et les informations
        """
        target = target.strip()
        
        if not target:
            return ValidationResult(
                valid=False,
                target_type="unknown",
                normalized="",
                message="La cible ne peut pas être vide",
                details={}
            )
        
        # Essayer de valider comme URL d'abord
        url_result = cls._validate_url(target)
        if url_result.valid:
            return url_result
        
        # Essayer comme CIDR
        cidr_result = cls._validate_cidr(target)
        if cidr_result.valid:
            return cidr_result
        
        # Essayer comme IPv4
        ipv4_result = cls._validate_ipv4(target)
        if ipv4_result.valid:
            return ipv4_result
        
        # Essayer comme IPv6
        ipv6_result = cls._validate_ipv6(target)
        if ipv6_result.valid:
            return ipv6_result
        
        # Essayer comme domaine/FQDN
        domain_result = cls._validate_domain(target)
        if domain_result.valid:
            return domain_result
        
        # Aucun type reconnu
        return ValidationResult(
            valid=False,
            target_type="unknown",
            normalized=target,
            message=f"Format de cible non reconnu: '{target}'. Formats acceptés: IP, CIDR, domaine, URL",
            details={"suggestions": cls._suggest_corrections(target)}
        )
    
    @classmethod
    def _validate_ipv4(cls, target: str) -> ValidationResult:
        """Valide une adresse IPv4"""
        match = cls.IPV4_PATTERN.match(target)
        if not match:
            return ValidationResult(False, "ipv4", target, "", {})
        
        octets = [int(g) for g in match.groups()]
        if not all(0 <= o <= 255 for o in octets):
            return ValidationResult(
                valid=False,
                target_type="ipv4",
                normalized=target,
                message=f"Octets IPv4 invalides (doivent être 0-255): {target}",
                details={"octets": octets}
            )
        
        # Vérifier si IP privée ou spéciale
        is_private = cls._is_private_ip(target)
        is_loopback = octets[0] == 127
        is_broadcast = octets == [255, 255, 255, 255]
        is_zero = octets == [0, 0, 0, 0]
        
        warnings = []
        if is_loopback:
            warnings.append("Adresse loopback (localhost)")
        if is_broadcast:
            warnings.append("Adresse de broadcast")
        if is_zero:
            warnings.append("Adresse non spécifiée")
        
        return ValidationResult(
            valid=True,
            target_type="ipv4",
            normalized=target,
            message="Adresse IPv4 valide" + (f" ({', '.join(warnings)})" if warnings else ""),
            details={
                "is_private": is_private,
                "is_loopback": is_loopback,
                "is_broadcast": is_broadcast,
                "warnings": warnings
            }
        )
    
    @classmethod
    def _validate_ipv6(cls, target: str) -> ValidationResult:
        """Valide une adresse IPv6"""
        # Simplification - vérifie le format basique
        try:
            import socket
            socket.inet_pton(socket.AF_INET6, target)
            return ValidationResult(
                valid=True,
                target_type="ipv6",
                normalized=target.lower(),
                message="Adresse IPv6 valide",
                details={}
            )
        except (socket.error, OSError):
            return ValidationResult(False, "ipv6", target, "", {})
    
    @classmethod
    def _validate_cidr(cls, target: str) -> ValidationResult:
        """Valide une notation CIDR"""
        match = cls.CIDR_V4_PATTERN.match(target)
        if not match:
            return ValidationResult(False, "cidr", target, "", {})
        
        ip_part, prefix = target.rsplit('/', 1)
        prefix = int(prefix)
        
        # Valider l'IP
        ip_result = cls._validate_ipv4(ip_part)
        if not ip_result.valid:
            return ValidationResult(
                valid=False,
                target_type="cidr",
                normalized=target,
                message=f"Partie IP invalide dans la notation CIDR: {ip_part}",
                details={}
            )
        
        # Valider le préfixe
        if not 0 <= prefix <= 32:
            return ValidationResult(
                valid=False,
                target_type="cidr",
                normalized=target,
                message=f"Préfixe CIDR invalide (doit être 0-32): /{prefix}",
                details={}
            )
        
        # Calculer le nombre d'hôtes
        num_hosts = 2 ** (32 - prefix) - 2  # -2 pour réseau et broadcast
        if prefix >= 31:
            num_hosts = 2 ** (32 - prefix)  # /31 et /32 sont des cas spéciaux
        
        warnings = []
        if prefix < 16:
            warnings.append(f"Plage très large ({num_hosts:,} hôtes) - le scan peut être long")
        
        return ValidationResult(
            valid=True,
            target_type="cidr",
            normalized=target,
            message=f"Notation CIDR valide ({num_hosts:,} hôtes)",
            details={
                "network": ip_part,
                "prefix": prefix,
                "num_hosts": num_hosts,
                "warnings": warnings
            }
        )
    
    @classmethod
    def _validate_domain(cls, target: str) -> ValidationResult:
        """Valide un nom de domaine"""
        # Enlever le point final si présent
        target = target.rstrip('.')
        
        if not cls.DOMAIN_PATTERN.match(target):
            return ValidationResult(False, "domain", target, "", {})
        
        # Vérifier la longueur totale
        if len(target) > 253:
            return ValidationResult(
                valid=False,
                target_type="domain",
                normalized=target,
                message="Nom de domaine trop long (max 253 caractères)",
                details={}
            )
        
        parts = target.split('.')
        tld = parts[-1].lower()
        
        # Vérifier chaque label
        for label in parts:
            if len(label) > 63:
                return ValidationResult(
                    valid=False,
                    target_type="domain",
                    normalized=target,
                    message=f"Label trop long (max 63 caractères): {label}",
                    details={}
                )
        
        # Déterminer si c'est un FQDN ou un domaine de base
        is_subdomain = len(parts) > 2
        
        warnings = []
        if tld not in cls.VALID_TLDS:
            warnings.append(f"TLD '{tld}' non standard")
        
        return ValidationResult(
            valid=True,
            target_type="fqdn" if is_subdomain else "domain",
            normalized=target.lower(),
            message=f"{'Sous-domaine' if is_subdomain else 'Domaine'} valide",
            details={
                "tld": tld,
                "is_subdomain": is_subdomain,
                "parts": parts,
                "warnings": warnings
            }
        )
    
    @classmethod
    def _validate_url(cls, target: str) -> ValidationResult:
        """Valide une URL"""
        match = cls.URL_PATTERN.match(target)
        if not match:
            return ValidationResult(False, "url", target, "", {})
        
        scheme, host, port, path = match.groups()
        port = int(port[1:]) if port else (443 if scheme == 'https://' else 80)
        path = path or '/'
        
        # Valider le host (IP ou domaine)
        host_result = cls._validate_ipv4(host)
        if not host_result.valid:
            host_result = cls._validate_domain(host)
        
        if not host_result.valid:
            return ValidationResult(
                valid=False,
                target_type="url",
                normalized=target,
                message=f"Host invalide dans l'URL: {host}",
                details={}
            )
        
        # Vérifier le port
        if not 1 <= port <= 65535:
            return ValidationResult(
                valid=False,
                target_type="url",
                normalized=target,
                message=f"Port invalide (doit être 1-65535): {port}",
                details={}
            )
        
        # Normaliser l'URL
        normalized = f"{scheme}{host}"
        if port not in [80, 443] or (port == 443 and scheme != 'https://') or (port == 80 and scheme != 'http://'):
            normalized += f":{port}"
        normalized += path
        
        return ValidationResult(
            valid=True,
            target_type="url",
            normalized=normalized,
            message="URL valide",
            details={
                "scheme": scheme.rstrip('://'),
                "host": host,
                "port": port,
                "path": path,
                "host_type": host_result.target_type
            }
        )
    
    @classmethod
    def _is_private_ip(cls, ip: str) -> bool:
        """Vérifie si une IP est dans une plage privée"""
        def ip_to_int(ip_str):
            parts = [int(p) for p in ip_str.split('.')]
            return (parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3]
        
        ip_int = ip_to_int(ip)
        for start, end in cls.PRIVATE_RANGES:
            if ip_to_int(start) <= ip_int <= ip_to_int(end):
                return True
        return False
    
    @classmethod
    def _suggest_corrections(cls, target: str) -> List[str]:
        """Suggère des corrections pour une cible invalide"""
        suggestions = []
        
        # Peut-être une URL sans schéma?
        if '.' in target and '/' in target:
            suggestions.append(f"Essayez: http://{target}")
        
        # Peut-être une IP avec des erreurs de frappe?
        if target.replace('.', '').replace(':', '').isdigit():
            suggestions.append("Vérifiez le format de l'adresse IP")
        
        # Peut-être un domaine sans TLD?
        if '.' not in target and target.isalnum():
            suggestions.append(f"Essayez: {target}.com ou {target}.local")
        
        return suggestions


# Fonctions de validation simples pour compatibilité
def validate_ip(ip: str) -> bool:
    """Valide une adresse IP (compatibilité)"""
    result = TargetValidator._validate_ipv4(ip)
    return result.valid

def validate_domain(domain: str) -> bool:
    """Valide un nom de domaine (compatibilité)"""
    result = TargetValidator._validate_domain(domain)
    return result.valid

def validate_cidr(cidr: str) -> bool:
    """Valide une plage CIDR (compatibilité)"""
    result = TargetValidator._validate_cidr(cidr)
    return result.valid

def validate_target(target: str) -> ValidationResult:
    """Valide une cible et retourne des informations détaillées"""
    return TargetValidator.validate(target)
