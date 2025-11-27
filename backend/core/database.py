"""
Database Module - SQLite Persistence
=====================================
Gestion de la persistance des sessions, targets et résultats
"""

import sqlite3
import json
from datetime import datetime
from typing import Dict, Any, List, Optional
from pathlib import Path
from contextlib import contextmanager

from core.config import settings


class Database:
    """Gestionnaire de base de données SQLite pour HackInterface"""
    
    def __init__(self, db_path: str = None):
        self.db_path = db_path or str(Path(settings.DATA_DIR) / "hackinterface.db")
        self._init_db()
    
    @contextmanager
    def get_connection(self):
        """Context manager pour les connexions DB"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
    
    def _init_db(self):
        """Initialise le schéma de la base de données"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Table des sessions de pentest
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    description TEXT,
                    client_name TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    vpn_file TEXT,
                    vpn_connected BOOLEAN DEFAULT FALSE,
                    status TEXT DEFAULT 'active'
                )
            """)
            
            # Table des targets
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS targets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id INTEGER NOT NULL,
                    type TEXT NOT NULL,
                    value TEXT NOT NULL,
                    name TEXT,
                    notes TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
                )
            """)
            
            # Table des résultats d'actions
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id INTEGER NOT NULL,
                    target_id INTEGER NOT NULL,
                    action TEXT NOT NULL,
                    status TEXT NOT NULL,
                    command TEXT,
                    output TEXT,
                    error TEXT,
                    parsed_data TEXT,
                    duration REAL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE,
                    FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE CASCADE
                )
            """)
            
            # Table des découvertes (sous-domaines, ports, vulns, etc.)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS discoveries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id INTEGER NOT NULL,
                    target_id INTEGER,
                    result_id INTEGER,
                    type TEXT NOT NULL,
                    value TEXT NOT NULL,
                    details TEXT,
                    severity TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE,
                    FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE SET NULL,
                    FOREIGN KEY (result_id) REFERENCES results(id) ON DELETE SET NULL
                )
            """)
            
            # Table des workflows exécutés
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS workflow_runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id INTEGER NOT NULL,
                    workflow_name TEXT NOT NULL,
                    status TEXT NOT NULL,
                    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    completed_at TIMESTAMP,
                    actions_completed TEXT,
                    FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
                )
            """)
            
            # Index pour performances
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_targets_session ON targets(session_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_results_session ON results(session_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_results_target ON results(target_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_discoveries_session ON discoveries(session_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_discoveries_type ON discoveries(type)")
    
    # =========================================================================
    # Sessions CRUD
    # =========================================================================
    
    def create_session(self, name: str, description: str = None, 
                       client_name: str = None) -> int:
        """Crée une nouvelle session de pentest"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO sessions (name, description, client_name)
                VALUES (?, ?, ?)
            """, (name, description, client_name))
            return cursor.lastrowid
    
    def get_session(self, session_id: int) -> Optional[Dict[str, Any]]:
        """Récupère une session par ID"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM sessions WHERE id = ?", (session_id,))
            row = cursor.fetchone()
            return dict(row) if row else None
    
    def get_all_sessions(self) -> List[Dict[str, Any]]:
        """Récupère toutes les sessions"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT s.*, 
                       COUNT(DISTINCT t.id) as target_count,
                       COUNT(DISTINCT r.id) as result_count
                FROM sessions s
                LEFT JOIN targets t ON t.session_id = s.id
                LEFT JOIN results r ON r.session_id = s.id
                GROUP BY s.id
                ORDER BY s.updated_at DESC
            """)
            return [dict(row) for row in cursor.fetchall()]
    
    def update_session(self, session_id: int, **kwargs) -> bool:
        """Met à jour une session"""
        allowed_fields = {'name', 'description', 'client_name', 'vpn_file', 
                          'vpn_connected', 'status'}
        updates = {k: v for k, v in kwargs.items() if k in allowed_fields}
        
        if not updates:
            return False
        
        updates['updated_at'] = datetime.now().isoformat()
        set_clause = ", ".join(f"{k} = ?" for k in updates.keys())
        values = list(updates.values()) + [session_id]
        
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(f"UPDATE sessions SET {set_clause} WHERE id = ?", values)
            return cursor.rowcount > 0
    
    def delete_session(self, session_id: int) -> bool:
        """Supprime une session et toutes ses données associées"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM sessions WHERE id = ?", (session_id,))
            return cursor.rowcount > 0
    
    # =========================================================================
    # Targets CRUD
    # =========================================================================
    
    def add_target(self, session_id: int, target_type: str, value: str,
                   name: str = None, notes: str = None) -> int:
        """Ajoute une target à une session"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO targets (session_id, type, value, name, notes)
                VALUES (?, ?, ?, ?, ?)
            """, (session_id, target_type, value, name, notes))
            
            # Mettre à jour updated_at de la session
            cursor.execute("""
                UPDATE sessions SET updated_at = CURRENT_TIMESTAMP 
                WHERE id = ?
            """, (session_id,))
            
            return cursor.lastrowid
    
    def get_targets(self, session_id: int) -> List[Dict[str, Any]]:
        """Récupère toutes les targets d'une session"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT t.*, COUNT(r.id) as result_count
                FROM targets t
                LEFT JOIN results r ON r.target_id = t.id
                WHERE t.session_id = ?
                GROUP BY t.id
            """, (session_id,))
            return [dict(row) for row in cursor.fetchall()]
    
    def delete_target(self, target_id: int) -> bool:
        """Supprime une target"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM targets WHERE id = ?", (target_id,))
            return cursor.rowcount > 0
    
    # =========================================================================
    # Results CRUD
    # =========================================================================
    
    def save_result(self, session_id: int, target_id: int, action: str,
                    result: Dict[str, Any]) -> int:
        """Sauvegarde un résultat d'action"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            parsed_data = json.dumps(result.get('parsed_data', {}))
            
            cursor.execute("""
                INSERT INTO results (session_id, target_id, action, status,
                                     command, output, error, parsed_data, duration)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                session_id, target_id, action,
                result.get('status', 'unknown'),
                result.get('command', ''),
                result.get('output', ''),
                result.get('error'),
                parsed_data,
                result.get('duration', 0)
            ))
            
            result_id = cursor.lastrowid
            
            # Extraire et sauvegarder les découvertes
            self._extract_discoveries(cursor, session_id, target_id, result_id, 
                                       action, result.get('parsed_data', {}))
            
            # Mettre à jour updated_at de la session
            cursor.execute("""
                UPDATE sessions SET updated_at = CURRENT_TIMESTAMP 
                WHERE id = ?
            """, (session_id,))
            
            return result_id
    
    def get_results(self, session_id: int, target_id: int = None,
                    action: str = None) -> List[Dict[str, Any]]:
        """Récupère les résultats filtrés"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            query = "SELECT * FROM results WHERE session_id = ?"
            params = [session_id]
            
            if target_id:
                query += " AND target_id = ?"
                params.append(target_id)
            
            if action:
                query += " AND action = ?"
                params.append(action)
            
            query += " ORDER BY created_at DESC"
            
            cursor.execute(query, params)
            results = []
            for row in cursor.fetchall():
                result = dict(row)
                result['parsed_data'] = json.loads(result.get('parsed_data', '{}'))
                results.append(result)
            return results
    
    def get_latest_result(self, target_id: int, action: str) -> Optional[Dict[str, Any]]:
        """Récupère le dernier résultat pour une target/action"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM results 
                WHERE target_id = ? AND action = ?
                ORDER BY created_at DESC LIMIT 1
            """, (target_id, action))
            row = cursor.fetchone()
            if row:
                result = dict(row)
                result['parsed_data'] = json.loads(result.get('parsed_data', '{}'))
                return result
            return None
    
    # =========================================================================
    # Discoveries
    # =========================================================================
    
    def _extract_discoveries(self, cursor, session_id: int, target_id: int,
                              result_id: int, action: str, parsed_data: Dict):
        """Extrait les découvertes depuis les données parsées"""
        
        # Ports découverts
        if 'ports' in parsed_data:
            for port in parsed_data['ports']:
                cursor.execute("""
                    INSERT INTO discoveries (session_id, target_id, result_id, type, value, details)
                    VALUES (?, ?, ?, 'port', ?, ?)
                """, (
                    session_id, target_id, result_id,
                    str(port.get('port', port)),
                    json.dumps(port) if isinstance(port, dict) else None
                ))
        
        # Sous-domaines découverts
        if 'subdomains' in parsed_data:
            for subdomain in parsed_data['subdomains']:
                cursor.execute("""
                    INSERT INTO discoveries (session_id, target_id, result_id, type, value)
                    VALUES (?, ?, ?, 'subdomain', ?)
                """, (session_id, target_id, result_id, subdomain))
        
        # Vulnérabilités découvertes
        if 'vulnerabilities' in parsed_data:
            for vuln in parsed_data['vulnerabilities']:
                severity = vuln.get('severity', 'info') if isinstance(vuln, dict) else 'info'
                cursor.execute("""
                    INSERT INTO discoveries (session_id, target_id, result_id, type, value, details, severity)
                    VALUES (?, ?, ?, 'vulnerability', ?, ?, ?)
                """, (
                    session_id, target_id, result_id,
                    vuln.get('name', str(vuln)) if isinstance(vuln, dict) else str(vuln),
                    json.dumps(vuln) if isinstance(vuln, dict) else None,
                    severity
                ))
        
        # Emails découverts
        if 'emails' in parsed_data:
            for email in parsed_data['emails']:
                cursor.execute("""
                    INSERT INTO discoveries (session_id, target_id, result_id, type, value)
                    VALUES (?, ?, ?, 'email', ?)
                """, (session_id, target_id, result_id, email))
        
        # Utilisateurs découverts
        if 'users' in parsed_data or 'usernames' in parsed_data:
            users = parsed_data.get('users', parsed_data.get('usernames', []))
            for user in users:
                cursor.execute("""
                    INSERT INTO discoveries (session_id, target_id, result_id, type, value)
                    VALUES (?, ?, ?, 'user', ?)
                """, (session_id, target_id, result_id, str(user)))
        
        # Hashes découverts
        if 'hashes' in parsed_data:
            for h in parsed_data['hashes']:
                cursor.execute("""
                    INSERT INTO discoveries (session_id, target_id, result_id, type, value, details)
                    VALUES (?, ?, ?, 'hash', ?, ?)
                """, (
                    session_id, target_id, result_id,
                    h.get('username', str(h)) if isinstance(h, dict) else str(h),
                    json.dumps(h) if isinstance(h, dict) else None
                ))
    
    def get_discoveries(self, session_id: int, discovery_type: str = None) -> List[Dict[str, Any]]:
        """Récupère les découvertes d'une session"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            query = "SELECT * FROM discoveries WHERE session_id = ?"
            params = [session_id]
            
            if discovery_type:
                query += " AND type = ?"
                params.append(discovery_type)
            
            query += " ORDER BY created_at DESC"
            
            cursor.execute(query, params)
            discoveries = []
            for row in cursor.fetchall():
                d = dict(row)
                if d.get('details'):
                    d['details'] = json.loads(d['details'])
                discoveries.append(d)
            return discoveries
    
    def get_discovery_stats(self, session_id: int) -> Dict[str, int]:
        """Statistiques des découvertes par type"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT type, COUNT(*) as count
                FROM discoveries
                WHERE session_id = ?
                GROUP BY type
            """, (session_id,))
            return {row['type']: row['count'] for row in cursor.fetchall()}
    
    def get_vulnerability_stats(self, session_id: int) -> Dict[str, int]:
        """Statistiques des vulnérabilités par sévérité"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT severity, COUNT(*) as count
                FROM discoveries
                WHERE session_id = ? AND type = 'vulnerability'
                GROUP BY severity
            """, (session_id,))
            return {row['severity'] or 'info': row['count'] for row in cursor.fetchall()}
    
    # =========================================================================
    # Workflow runs
    # =========================================================================
    
    def start_workflow_run(self, session_id: int, workflow_name: str) -> int:
        """Enregistre le début d'un workflow"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO workflow_runs (session_id, workflow_name, status)
                VALUES (?, ?, 'running')
            """, (session_id, workflow_name))
            return cursor.lastrowid
    
    def complete_workflow_run(self, run_id: int, status: str, 
                               actions_completed: List[str]):
        """Marque un workflow comme terminé"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE workflow_runs 
                SET status = ?, completed_at = CURRENT_TIMESTAMP, 
                    actions_completed = ?
                WHERE id = ?
            """, (status, json.dumps(actions_completed), run_id))
    
    # =========================================================================
    # Export / Import
    # =========================================================================
    
    def export_session(self, session_id: int) -> Dict[str, Any]:
        """Exporte une session complète en JSON"""
        session = self.get_session(session_id)
        if not session:
            return None
        
        targets = self.get_targets(session_id)
        results = self.get_results(session_id)
        discoveries = self.get_discoveries(session_id)
        
        return {
            "export_version": "1.0",
            "exported_at": datetime.now().isoformat(),
            "session": session,
            "targets": targets,
            "results": results,
            "discoveries": discoveries
        }
    
    def import_session(self, data: Dict[str, Any]) -> int:
        """Importe une session depuis un export JSON"""
        session_data = data.get('session', {})
        
        # Créer la nouvelle session
        session_id = self.create_session(
            name=session_data.get('name', 'Imported Session'),
            description=session_data.get('description'),
            client_name=session_data.get('client_name')
        )
        
        # Mapper les anciens IDs vers les nouveaux
        target_id_map = {}
        
        # Importer les targets
        for target in data.get('targets', []):
            old_id = target.get('id')
            new_id = self.add_target(
                session_id=session_id,
                target_type=target.get('type', 'ip'),
                value=target.get('value', ''),
                name=target.get('name'),
                notes=target.get('notes')
            )
            target_id_map[old_id] = new_id
        
        # Importer les résultats
        with self.get_connection() as conn:
            cursor = conn.cursor()
            for result in data.get('results', []):
                old_target_id = result.get('target_id')
                new_target_id = target_id_map.get(old_target_id)
                
                if new_target_id:
                    parsed_data = result.get('parsed_data', {})
                    if isinstance(parsed_data, str):
                        parsed_data = json.loads(parsed_data)
                    
                    cursor.execute("""
                        INSERT INTO results (session_id, target_id, action, status,
                                             command, output, error, parsed_data, duration)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        session_id, new_target_id, result.get('action', ''),
                        result.get('status', 'unknown'),
                        result.get('command', ''),
                        result.get('output', ''),
                        result.get('error'),
                        json.dumps(parsed_data),
                        result.get('duration', 0)
                    ))
        
        return session_id


# Instance globale
db = Database()
