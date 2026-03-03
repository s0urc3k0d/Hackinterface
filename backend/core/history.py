"""
Historique des commandes exécutées
Permet de suivre, rechercher et réexécuter les commandes
"""
import os
import json
import sqlite3
from datetime import datetime
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, asdict

from .config import settings


@dataclass
class CommandHistoryEntry:
    """Entrée dans l'historique des commandes"""
    id: int
    command: str
    action: str
    target: str
    session_id: Optional[int]
    status: str  # success, error, timeout
    return_code: int
    duration: float
    stdout_preview: str
    stderr_preview: str
    executed_at: str
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class CommandHistory:
    """Gestionnaire d'historique des commandes"""
    
    def __init__(self, db_path: str = None, max_preview_length: int = 500):
        self.db_path = db_path or os.path.join(settings.DATA_DIR, "history.db")
        self.max_preview_length = max_preview_length
        self._init_db()
    
    def _init_db(self):
        """Initialise la base de données"""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS command_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                command TEXT NOT NULL,
                action TEXT NOT NULL,
                target TEXT NOT NULL,
                session_id INTEGER,
                status TEXT NOT NULL,
                return_code INTEGER,
                duration REAL,
                stdout_preview TEXT,
                stderr_preview TEXT,
                executed_at TEXT NOT NULL
            )
        ''')
        
        # Index pour recherche rapide
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_action ON command_history(action)
        ''')
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_target ON command_history(target)
        ''')
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_session ON command_history(session_id)
        ''')
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_executed_at ON command_history(executed_at)
        ''')
        
        # Recherche full-text
        cursor.execute('''
            CREATE VIRTUAL TABLE IF NOT EXISTS command_history_fts 
            USING fts5(command, action, target, stdout_preview, content=command_history, content_rowid=id)
        ''')
        
        conn.commit()
        conn.close()
    
    def add(
        self,
        command: str,
        action: str,
        target: str,
        status: str,
        return_code: int,
        duration: float,
        stdout: str = "",
        stderr: str = "",
        session_id: int = None
    ) -> int:
        """
        Ajoute une commande à l'historique
        
        Returns:
            ID de l'entrée créée
        """
        # Tronquer les previews
        stdout_preview = stdout[:self.max_preview_length] if stdout else ""
        stderr_preview = stderr[:self.max_preview_length] if stderr else ""
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        executed_at = datetime.now().isoformat()
        
        cursor.execute('''
            INSERT INTO command_history 
            (command, action, target, session_id, status, return_code, duration, 
             stdout_preview, stderr_preview, executed_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (command, action, target, session_id, status, return_code, duration,
              stdout_preview, stderr_preview, executed_at))
        
        entry_id = cursor.lastrowid
        
        # Mettre à jour l'index FTS
        cursor.execute('''
            INSERT INTO command_history_fts (rowid, command, action, target, stdout_preview)
            VALUES (?, ?, ?, ?, ?)
        ''', (entry_id, command, action, target, stdout_preview))
        
        conn.commit()
        conn.close()
        
        return entry_id
    
    def search(
        self,
        query: str = None,
        action: str = None,
        target: str = None,
        session_id: int = None,
        status: str = None,
        limit: int = 50,
        offset: int = 0
    ) -> List[CommandHistoryEntry]:
        """
        Recherche dans l'historique
        
        Args:
            query: Recherche full-text dans commande et output
            action: Filtrer par action
            target: Filtrer par cible
            session_id: Filtrer par session
            status: Filtrer par status (success, error, timeout)
            limit: Nombre max de résultats
            offset: Offset pour pagination
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        if query:
            # Recherche full-text
            cursor.execute('''
                SELECT h.* FROM command_history h
                JOIN command_history_fts fts ON h.id = fts.rowid
                WHERE command_history_fts MATCH ?
                ORDER BY h.executed_at DESC
                LIMIT ? OFFSET ?
            ''', (query, limit, offset))
        else:
            # Recherche par filtres
            conditions = []
            params = []
            
            if action:
                conditions.append("action = ?")
                params.append(action)
            if target:
                conditions.append("target LIKE ?")
                params.append(f"%{target}%")
            if session_id is not None:
                conditions.append("session_id = ?")
                params.append(session_id)
            if status:
                conditions.append("status = ?")
                params.append(status)
            
            where_clause = " AND ".join(conditions) if conditions else "1=1"
            params.extend([limit, offset])
            
            cursor.execute(f'''
                SELECT * FROM command_history
                WHERE {where_clause}
                ORDER BY executed_at DESC
                LIMIT ? OFFSET ?
            ''', params)
        
        results = []
        for row in cursor.fetchall():
            results.append(CommandHistoryEntry(
                id=row['id'],
                command=row['command'],
                action=row['action'],
                target=row['target'],
                session_id=row['session_id'],
                status=row['status'],
                return_code=row['return_code'],
                duration=row['duration'],
                stdout_preview=row['stdout_preview'],
                stderr_preview=row['stderr_preview'],
                executed_at=row['executed_at']
            ))
        
        conn.close()
        return results
    
    def get_by_id(self, entry_id: int) -> Optional[CommandHistoryEntry]:
        """Récupère une entrée par son ID"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM command_history WHERE id = ?', (entry_id,))
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return CommandHistoryEntry(
                id=row['id'],
                command=row['command'],
                action=row['action'],
                target=row['target'],
                session_id=row['session_id'],
                status=row['status'],
                return_code=row['return_code'],
                duration=row['duration'],
                stdout_preview=row['stdout_preview'],
                stderr_preview=row['stderr_preview'],
                executed_at=row['executed_at']
            )
        return None

    def get_entry(self, entry_id: int) -> Optional[CommandHistoryEntry]:
        """Alias de compatibilité pour récupérer une entrée par ID"""
        return self.get_by_id(entry_id)
    
    def get_recent(self, limit: int = 20) -> List[CommandHistoryEntry]:
        """Récupère les commandes les plus récentes"""
        return self.search(limit=limit)
    
    def get_by_action(self, action: str, limit: int = 20) -> List[CommandHistoryEntry]:
        """Récupère l'historique d'une action spécifique"""
        return self.search(action=action, limit=limit)
    
    def get_by_target(self, target: str, limit: int = 50) -> List[CommandHistoryEntry]:
        """Récupère l'historique pour une cible"""
        return self.search(target=target, limit=limit)
    
    def get_failed(self, limit: int = 50) -> List[CommandHistoryEntry]:
        """Récupère les commandes échouées"""
        return self.search(status="error", limit=limit)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Retourne des statistiques sur l'historique"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        stats = {
            "total_commands": 0,
            "successful": 0,
            "failed": 0,
            "timeouts": 0,
            "avg_duration": 0,
            "by_action": {},
            "by_target": {},
            "today": 0
        }
        
        # Totaux
        cursor.execute('SELECT COUNT(*) FROM command_history')
        stats["total_commands"] = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM command_history WHERE status = "success"')
        stats["successful"] = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM command_history WHERE status = "error"')
        stats["failed"] = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM command_history WHERE status = "timeout"')
        stats["timeouts"] = cursor.fetchone()[0]
        
        cursor.execute('SELECT AVG(duration) FROM command_history WHERE duration > 0')
        avg = cursor.fetchone()[0]
        stats["avg_duration"] = round(avg, 2) if avg else 0
        
        # Par action
        cursor.execute('''
            SELECT action, COUNT(*), SUM(CASE WHEN status = "success" THEN 1 ELSE 0 END)
            FROM command_history
            GROUP BY action
            ORDER BY COUNT(*) DESC
            LIMIT 10
        ''')
        for action, count, success in cursor.fetchall():
            stats["by_action"][action] = {"total": count, "success": success}
        
        # Par cible (top 10)
        cursor.execute('''
            SELECT target, COUNT(*)
            FROM command_history
            GROUP BY target
            ORDER BY COUNT(*) DESC
            LIMIT 10
        ''')
        for target, count in cursor.fetchall():
            stats["by_target"][target] = count
        
        # Aujourd'hui
        today = datetime.now().strftime("%Y-%m-%d")
        cursor.execute('''
            SELECT COUNT(*) FROM command_history 
            WHERE executed_at LIKE ?
        ''', (f"{today}%",))
        stats["today"] = cursor.fetchone()[0]
        
        conn.close()
        return stats
    
    def clear_old(self, days: int = 30) -> int:
        """Supprime les entrées plus anciennes que X jours"""
        from datetime import timedelta
        
        cutoff = (datetime.now() - timedelta(days=days)).isoformat()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Supprimer de l'index FTS d'abord
        cursor.execute('''
            DELETE FROM command_history_fts 
            WHERE rowid IN (SELECT id FROM command_history WHERE executed_at < ?)
        ''', (cutoff,))
        
        cursor.execute('DELETE FROM command_history WHERE executed_at < ?', (cutoff,))
        deleted = cursor.rowcount
        
        conn.commit()
        conn.close()
        
        return deleted
    
    def clear_all(self) -> int:
        """Supprime tout l'historique"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('DELETE FROM command_history_fts')
        cursor.execute('DELETE FROM command_history')
        deleted = cursor.rowcount
        
        conn.commit()
        conn.close()
        
        return deleted

    def clear(self, before_date: str = None) -> int:
        """
        Supprime l'historique.
        - Si before_date est fourni (ISO date/datetime), supprime avant cette date.
        - Sinon supprime tout.
        """
        if not before_date:
            return self.clear_all()

        try:
            cutoff = datetime.fromisoformat(before_date).isoformat()
        except ValueError:
            raise ValueError("before_date doit être au format ISO (YYYY-MM-DD ou YYYY-MM-DDTHH:MM:SS)")

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            DELETE FROM command_history_fts
            WHERE rowid IN (SELECT id FROM command_history WHERE executed_at < ?)
        ''', (cutoff,))

        cursor.execute('DELETE FROM command_history WHERE executed_at < ?', (cutoff,))
        deleted = cursor.rowcount

        conn.commit()
        conn.close()

        return deleted

    def export_history(self) -> str:
        """Exporte tout l'historique en JSON"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute('''
            SELECT * FROM command_history
            ORDER BY executed_at DESC
        ''')

        rows = [dict(row) for row in cursor.fetchall()]
        conn.close()

        return json.dumps(rows, ensure_ascii=False, indent=2)


# Instance globale
command_history = CommandHistory()
