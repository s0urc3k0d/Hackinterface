"""
Gestionnaire de connexion VPN
"""
import os
import asyncio
import subprocess
from typing import Optional
from .config import settings

class VPNManager:
    def __init__(self):
        self._process: Optional[subprocess.Popen] = None
        self._connected = False
        self._config_path: Optional[str] = None
    
    def is_connected(self) -> bool:
        """Vérifie si le VPN est connecté"""
        if self._process is None:
            return False
        # Vérifier si le processus est toujours en cours
        if self._process.poll() is not None:
            self._connected = False
            self._process = None
        return self._connected
    
    def get_status(self) -> dict:
        """Retourne le statut complet du VPN"""
        connected = self.is_connected()
        tun_ip = None
        
        if connected:
            # Récupérer l'IP du tunnel
            try:
                result = subprocess.run(
                    ["ip", "addr", "show", "tun0"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode == 0:
                    import re
                    match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', result.stdout)
                    if match:
                        tun_ip = match.group(1)
            except:
                pass
        
        return {
            "connected": connected,
            "config_loaded": os.path.exists(settings.VPN_CONFIG_PATH),
            "tun_ip": tun_ip
        }
    
    async def connect(self) -> dict:
        """Connexion au VPN"""
        if self.is_connected():
            return {"status": "already_connected", "message": "VPN déjà connecté"}
        
        if not os.path.exists(settings.VPN_CONFIG_PATH):
            return {"status": "error", "message": "Aucun fichier .ovpn uploadé"}
        
        try:
            # Lancer OpenVPN en arrière-plan
            self._process = subprocess.Popen(
                ["sudo", "openvpn", "--config", settings.VPN_CONFIG_PATH],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Attendre un peu pour la connexion
            await asyncio.sleep(5)
            
            # Vérifier si tun0 existe
            result = subprocess.run(
                ["ip", "link", "show", "tun0"],
                capture_output=True,
                timeout=5
            )
            
            if result.returncode == 0:
                self._connected = True
                status = self.get_status()
                return {
                    "status": "success",
                    "message": f"VPN connecté, IP tunnel: {status['tun_ip']}"
                }
            else:
                # La connexion peut prendre plus de temps
                await asyncio.sleep(10)
                result = subprocess.run(
                    ["ip", "link", "show", "tun0"],
                    capture_output=True,
                    timeout=5
                )
                if result.returncode == 0:
                    self._connected = True
                    status = self.get_status()
                    return {
                        "status": "success",
                        "message": f"VPN connecté, IP tunnel: {status['tun_ip']}"
                    }
                return {"status": "error", "message": "Échec de la connexion VPN"}
                
        except Exception as e:
            return {"status": "error", "message": str(e)}
    
    async def disconnect(self) -> dict:
        """Déconnexion du VPN"""
        if not self.is_connected():
            return {"status": "not_connected", "message": "VPN non connecté"}
        
        try:
            if self._process:
                self._process.terminate()
                await asyncio.sleep(2)
                if self._process.poll() is None:
                    self._process.kill()
                self._process = None
            
            # Kill tous les processus openvpn au cas où
            subprocess.run(["sudo", "killall", "openvpn"], capture_output=True)
            
            self._connected = False
            return {"status": "success", "message": "VPN déconnecté"}
            
        except Exception as e:
            return {"status": "error", "message": str(e)}

# Instance globale
vpn_manager = VPNManager()
