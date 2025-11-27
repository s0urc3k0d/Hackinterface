"""
Gestionnaire de connexions WebSocket
Pour la communication temps réel avec le frontend
"""
from typing import List, Dict, Any
from fastapi import WebSocket
import json

class ConnectionManager:
    """Gère les connexions WebSocket"""
    
    def __init__(self):
        self.active_connections: List[WebSocket] = []
    
    async def connect(self, websocket: WebSocket):
        """Accepte une nouvelle connexion"""
        await websocket.accept()
        self.active_connections.append(websocket)
    
    def disconnect(self, websocket: WebSocket):
        """Déconnecte un client"""
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
    
    async def send_personal_message(self, message: Dict[str, Any], websocket: WebSocket):
        """Envoie un message à un client spécifique"""
        await websocket.send_text(json.dumps(message))
    
    async def broadcast(self, message: Dict[str, Any]):
        """Diffuse un message à tous les clients connectés"""
        for connection in self.active_connections:
            try:
                await connection.send_text(json.dumps(message))
            except:
                # Connexion morte, on la retire
                self.disconnect(connection)
    
    async def send_action_update(
        self,
        action: str,
        status: str,
        target_id: int,
        data: Any = None,
        progress: int = None
    ):
        """Envoie une mise à jour d'action"""
        message = {
            "type": "action_update",
            "action": action,
            "status": status,  # started, running, completed, error
            "target_id": target_id,
            "data": data,
            "progress": progress
        }
        await self.broadcast(message)
    
    async def send_workflow_update(
        self,
        workflow_id: str,
        status: str,
        current_step: str = None,
        total_steps: int = None,
        current_step_num: int = None,
        data: Any = None
    ):
        """Envoie une mise à jour de workflow"""
        message = {
            "type": "workflow_update",
            "workflow_id": workflow_id,
            "status": status,
            "current_step": current_step,
            "total_steps": total_steps,
            "current_step_num": current_step_num,
            "data": data
        }
        await self.broadcast(message)
    
    async def send_log(self, level: str, message: str, source: str = None):
        """Envoie un message de log"""
        log_message = {
            "type": "log",
            "level": level,  # info, warning, error, success
            "message": message,
            "source": source
        }
        await self.broadcast(log_message)
    
    async def send_output(self, command: str, output: str, stream: str = "stdout"):
        """Envoie une sortie de commande en temps réel"""
        message = {
            "type": "output",
            "command": command,
            "output": output,
            "stream": stream
        }
        await self.broadcast(message)
