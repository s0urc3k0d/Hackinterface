"""
Templates de workflows personnalisés
Permet aux utilisateurs de créer, sauvegarder et charger leurs propres workflows
"""
import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, asdict

@dataclass
class WorkflowTemplate:
    """Template de workflow personnalisé"""
    id: Optional[int]
    name: str
    description: str
    author: str
    target_types: List[str]  # ip, domain, url, cidr, fqdn
    steps: List[Dict[str, Any]]  # action, name, options, condition
    auto_chain: bool
    tags: List[str]
    is_public: bool
    created_at: str
    updated_at: str
    usage_count: int = 0
    rating: float = 0.0

class WorkflowTemplateManager:
    """Gestionnaire de templates de workflows"""
    
    def __init__(self, db_path: str = "data/workflow_templates.db"):
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()
    
    def _init_db(self):
        """Initialise la base de données"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS workflow_templates (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    description TEXT,
                    author TEXT DEFAULT 'user',
                    target_types TEXT NOT NULL,
                    steps TEXT NOT NULL,
                    auto_chain INTEGER DEFAULT 0,
                    tags TEXT,
                    is_public INTEGER DEFAULT 0,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    usage_count INTEGER DEFAULT 0,
                    rating REAL DEFAULT 0.0
                )
            """)
            
            # Index pour la recherche
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_templates_name 
                ON workflow_templates(name)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_templates_tags 
                ON workflow_templates(tags)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_templates_author 
                ON workflow_templates(author)
            """)
            
            # Insérer quelques templates par défaut s'ils n'existent pas
            self._insert_default_templates(conn)
    
    def _insert_default_templates(self, conn: sqlite3.Connection):
        """Insère des templates par défaut"""
        # Vérifier si des templates existent
        count = conn.execute("SELECT COUNT(*) FROM workflow_templates").fetchone()[0]
        if count > 0:
            return
        
        default_templates = [
            {
                "name": "Scan Rapide API",
                "description": "Analyse rapide d'une API REST",
                "author": "system",
                "target_types": ["url"],
                "steps": [
                    {"action": "curl_headers", "name": "Analyse Headers"},
                    {"action": "wafw00f", "name": "Détection WAF"},
                    {"action": "nuclei", "name": "Vulnérabilités API", "options": {"tags": "api,exposure"}},
                ],
                "auto_chain": False,
                "tags": ["api", "rapide"],
                "is_public": True
            },
            {
                "name": "Pentest Box CTF",
                "description": "Méthodologie CTF/Box - Enum complète",
                "author": "system",
                "target_types": ["ip"],
                "steps": [
                    {"action": "nmap_quick", "name": "Scan initial"},
                    {"action": "nmap_full", "name": "Scan tous ports"},
                    {"action": "nmap_vuln", "name": "Scripts vulns"},
                    {"action": "gobuster", "name": "Dir enum", "condition": "has_web"},
                    {"action": "nikto", "name": "Nikto", "condition": "has_web"},
                    {"action": "enum4linux", "name": "SMB enum", "condition": "has_smb"},
                ],
                "auto_chain": True,
                "tags": ["ctf", "oscp", "htb"],
                "is_public": True
            },
            {
                "name": "Audit SSL/TLS Complet",
                "description": "Analyse complète de la configuration SSL/TLS",
                "author": "system",
                "target_types": ["ip", "fqdn", "url"],
                "steps": [
                    {"action": "sslscan", "name": "SSL Scan"},
                    {"action": "testssl", "name": "TestSSL.sh"},
                    {"action": "nuclei", "name": "Nuclei SSL", "options": {"tags": "ssl,tls"}},
                ],
                "auto_chain": False,
                "tags": ["ssl", "tls", "crypto"],
                "is_public": True
            },
            {
                "name": "Discovery Subdomains",
                "description": "Découverte complète de sous-domaines",
                "author": "system",
                "target_types": ["domain", "fqdn"],
                "steps": [
                    {"action": "subdomain_enum", "name": "Sublist3r/Amass"},
                    {"action": "dns_enum", "name": "DNS Enumeration"},
                    {"action": "theharvester", "name": "theHarvester"},
                    {"action": "amass", "name": "Amass Passive"},
                ],
                "auto_chain": False,
                "tags": ["recon", "subdomains", "osint"],
                "is_public": True
            },
            {
                "name": "Credential Spray",
                "description": "Test de credentials sur services courants",
                "author": "system",
                "target_types": ["ip"],
                "steps": [
                    {"action": "nmap_quick", "name": "Port Scan"},
                    {"action": "hydra_ssh", "name": "SSH Brute", "condition": "has_ssh"},
                    {"action": "hydra_ftp", "name": "FTP Brute", "condition": "has_ftp"},
                    {"action": "hydra_smb", "name": "SMB Brute", "condition": "has_smb"},
                    {"action": "msf_mysql_login", "name": "MySQL Login", "condition": "has_mysql"},
                ],
                "auto_chain": True,
                "tags": ["bruteforce", "credentials"],
                "is_public": True
            }
        ]
        
        now = datetime.now().isoformat()
        for template in default_templates:
            conn.execute("""
                INSERT INTO workflow_templates 
                (name, description, author, target_types, steps, auto_chain, 
                 tags, is_public, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                template["name"],
                template["description"],
                template["author"],
                json.dumps(template["target_types"]),
                json.dumps(template["steps"]),
                1 if template["auto_chain"] else 0,
                json.dumps(template["tags"]),
                1 if template["is_public"] else 0,
                now,
                now
            ))
        conn.commit()
    
    def create_template(self, template: Dict[str, Any]) -> int:
        """Crée un nouveau template de workflow"""
        now = datetime.now().isoformat()
        
        # Valider les champs requis
        required = ["name", "steps"]
        for field in required:
            if field not in template:
                raise ValueError(f"Champ requis manquant: {field}")
        
        # Valider les steps
        for step in template["steps"]:
            if "action" not in step:
                raise ValueError("Chaque étape doit avoir une action")
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("""
                INSERT INTO workflow_templates 
                (name, description, author, target_types, steps, auto_chain, 
                 tags, is_public, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                template["name"],
                template.get("description", ""),
                template.get("author", "user"),
                json.dumps(template.get("target_types", ["ip", "domain", "url"])),
                json.dumps(template["steps"]),
                1 if template.get("auto_chain", False) else 0,
                json.dumps(template.get("tags", [])),
                1 if template.get("is_public", False) else 0,
                now,
                now
            ))
            return cursor.lastrowid
    
    def get_template(self, template_id: int) -> Optional[WorkflowTemplate]:
        """Récupère un template par son ID"""
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute("""
                SELECT * FROM workflow_templates WHERE id = ?
            """, (template_id,)).fetchone()
            
            if not row:
                return None
            
            return self._row_to_template(row)
    
    def get_template_by_name(self, name: str) -> Optional[WorkflowTemplate]:
        """Récupère un template par son nom"""
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute("""
                SELECT * FROM workflow_templates WHERE name = ?
            """, (name,)).fetchone()
            
            if not row:
                return None
            
            return self._row_to_template(row)
    
    def list_templates(
        self,
        author: str = None,
        tags: List[str] = None,
        target_type: str = None,
        is_public: bool = None,
        search: str = None,
        limit: int = 50,
        offset: int = 0
    ) -> List[WorkflowTemplate]:
        """Liste les templates avec filtres optionnels"""
        query = "SELECT * FROM workflow_templates WHERE 1=1"
        params = []
        
        if author:
            query += " AND author = ?"
            params.append(author)
        
        if is_public is not None:
            query += " AND is_public = ?"
            params.append(1 if is_public else 0)
        
        if tags:
            for tag in tags:
                query += " AND tags LIKE ?"
                params.append(f'%"{tag}"%')
        
        if target_type:
            query += " AND target_types LIKE ?"
            params.append(f'%"{target_type}"%')
        
        if search:
            query += " AND (name LIKE ? OR description LIKE ?)"
            params.extend([f"%{search}%", f"%{search}%"])
        
        query += " ORDER BY usage_count DESC, rating DESC, name ASC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute(query, params).fetchall()
            return [self._row_to_template(row) for row in rows]
    
    def update_template(self, template_id: int, updates: Dict[str, Any]) -> bool:
        """Met à jour un template"""
        allowed_fields = ["name", "description", "target_types", "steps", 
                         "auto_chain", "tags", "is_public"]
        
        set_clauses = []
        params = []
        
        for field in allowed_fields:
            if field in updates:
                value = updates[field]
                if field in ["target_types", "steps", "tags"]:
                    value = json.dumps(value)
                elif field == "auto_chain":
                    value = 1 if value else 0
                elif field == "is_public":
                    value = 1 if value else 0
                
                set_clauses.append(f"{field} = ?")
                params.append(value)
        
        if not set_clauses:
            return False
        
        set_clauses.append("updated_at = ?")
        params.append(datetime.now().isoformat())
        params.append(template_id)
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(f"""
                UPDATE workflow_templates 
                SET {', '.join(set_clauses)}
                WHERE id = ?
            """, params)
            return cursor.rowcount > 0
    
    def delete_template(self, template_id: int) -> bool:
        """Supprime un template"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("""
                DELETE FROM workflow_templates WHERE id = ?
            """, (template_id,))
            return cursor.rowcount > 0
    
    def increment_usage(self, template_id: int):
        """Incrémente le compteur d'utilisation"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                UPDATE workflow_templates 
                SET usage_count = usage_count + 1
                WHERE id = ?
            """, (template_id,))
    
    def rate_template(self, template_id: int, rating: float):
        """Met à jour la note d'un template (0-5)"""
        rating = max(0.0, min(5.0, rating))
        
        with sqlite3.connect(self.db_path) as conn:
            # Calcul moyenne simple (pourrait être amélioré avec historique)
            current = conn.execute("""
                SELECT rating, usage_count FROM workflow_templates WHERE id = ?
            """, (template_id,)).fetchone()
            
            if current:
                current_rating, usage = current
                # Moyenne pondérée simple
                new_rating = (current_rating * usage + rating) / (usage + 1)
                conn.execute("""
                    UPDATE workflow_templates SET rating = ? WHERE id = ?
                """, (new_rating, template_id))
    
    def clone_template(self, template_id: int, new_name: str, author: str = "user") -> int:
        """Clone un template existant"""
        template = self.get_template(template_id)
        if not template:
            raise ValueError(f"Template {template_id} non trouvé")
        
        now = datetime.now().isoformat()
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("""
                INSERT INTO workflow_templates 
                (name, description, author, target_types, steps, auto_chain, 
                 tags, is_public, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                new_name,
                f"Clonage de: {template.name}. {template.description}",
                author,
                json.dumps(template.target_types),
                json.dumps(template.steps),
                1 if template.auto_chain else 0,
                json.dumps(template.tags),
                0,  # Clone is private by default
                now,
                now
            ))
            return cursor.lastrowid
    
    def export_template(self, template_id: int) -> str:
        """Exporte un template en JSON"""
        template = self.get_template(template_id)
        if not template:
            raise ValueError(f"Template {template_id} non trouvé")
        
        export_data = {
            "name": template.name,
            "description": template.description,
            "author": template.author,
            "target_types": template.target_types,
            "steps": template.steps,
            "auto_chain": template.auto_chain,
            "tags": template.tags,
            "exported_at": datetime.now().isoformat(),
            "version": "1.0"
        }
        
        return json.dumps(export_data, indent=2)
    
    def import_template(self, json_data: str, author: str = "user") -> int:
        """Importe un template depuis JSON"""
        try:
            data = json.loads(json_data)
        except json.JSONDecodeError as e:
            raise ValueError(f"JSON invalide: {e}")
        
        # Valider les champs requis
        required = ["name", "steps"]
        for field in required:
            if field not in data:
                raise ValueError(f"Champ requis manquant: {field}")
        
        # Créer le template
        template = {
            "name": data["name"],
            "description": data.get("description", ""),
            "author": author,
            "target_types": data.get("target_types", ["ip"]),
            "steps": data["steps"],
            "auto_chain": data.get("auto_chain", False),
            "tags": data.get("tags", []),
            "is_public": False
        }
        
        return self.create_template(template)
    
    def get_popular_templates(self, limit: int = 10) -> List[WorkflowTemplate]:
        """Récupère les templates les plus populaires"""
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute("""
                SELECT * FROM workflow_templates 
                WHERE is_public = 1
                ORDER BY usage_count DESC, rating DESC
                LIMIT ?
            """, (limit,)).fetchall()
            return [self._row_to_template(row) for row in rows]
    
    def get_recent_templates(self, limit: int = 10) -> List[WorkflowTemplate]:
        """Récupère les templates récemment créés"""
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute("""
                SELECT * FROM workflow_templates 
                ORDER BY created_at DESC
                LIMIT ?
            """, (limit,)).fetchall()
            return [self._row_to_template(row) for row in rows]
    
    def search_by_action(self, action: str) -> List[WorkflowTemplate]:
        """Recherche les templates contenant une action spécifique"""
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute("""
                SELECT * FROM workflow_templates 
                WHERE steps LIKE ?
                ORDER BY usage_count DESC
            """, (f'%"action": "{action}"%',)).fetchall()
            return [self._row_to_template(row) for row in rows]
    
    def _row_to_template(self, row) -> WorkflowTemplate:
        """Convertit une ligne SQL en WorkflowTemplate"""
        return WorkflowTemplate(
            id=row[0],
            name=row[1],
            description=row[2],
            author=row[3],
            target_types=json.loads(row[4]),
            steps=json.loads(row[5]),
            auto_chain=bool(row[6]),
            tags=json.loads(row[7]) if row[7] else [],
            is_public=bool(row[8]),
            created_at=row[9],
            updated_at=row[10],
            usage_count=row[11],
            rating=row[12]
        )
    
    def get_statistics(self) -> Dict[str, Any]:
        """Statistiques sur les templates"""
        with sqlite3.connect(self.db_path) as conn:
            total = conn.execute("SELECT COUNT(*) FROM workflow_templates").fetchone()[0]
            public = conn.execute(
                "SELECT COUNT(*) FROM workflow_templates WHERE is_public = 1"
            ).fetchone()[0]
            total_usage = conn.execute(
                "SELECT SUM(usage_count) FROM workflow_templates"
            ).fetchone()[0] or 0
            
            # Top tags
            all_tags = conn.execute(
                "SELECT tags FROM workflow_templates"
            ).fetchall()
            tag_counts = {}
            for row in all_tags:
                if row[0]:
                    for tag in json.loads(row[0]):
                        tag_counts[tag] = tag_counts.get(tag, 0) + 1
            
            top_tags = sorted(tag_counts.items(), key=lambda x: x[1], reverse=True)[:10]
            
            # Top actions
            all_steps = conn.execute(
                "SELECT steps FROM workflow_templates"
            ).fetchall()
            action_counts = {}
            for row in all_steps:
                if row[0]:
                    for step in json.loads(row[0]):
                        action = step.get("action", "")
                        if action:
                            action_counts[action] = action_counts.get(action, 0) + 1
            
            top_actions = sorted(action_counts.items(), key=lambda x: x[1], reverse=True)[:10]
            
            return {
                "total_templates": total,
                "public_templates": public,
                "private_templates": total - public,
                "total_usage": total_usage,
                "top_tags": top_tags,
                "top_actions": top_actions
            }


# Instance globale
template_manager = WorkflowTemplateManager()
