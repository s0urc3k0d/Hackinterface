"""
Système de cache pour les résultats des outils
Évite de relancer des scans identiques pendant une durée configurable
"""
import hashlib
import json
import os
import time
from dataclasses import dataclass, asdict
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
from pathlib import Path
import sqlite3
import threading

from .config import settings


@dataclass
class CacheEntry:
    """Entrée de cache"""
    key: str
    action: str
    target: str
    options_hash: str
    result: Dict[str, Any]
    created_at: float
    expires_at: float
    hit_count: int = 0
    
    def is_expired(self) -> bool:
        return time.time() > self.expires_at
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ResultCache:
    """
    Cache des résultats avec support SQLite pour persistance
    et mémoire pour accès rapide
    """
    
    # Durées de cache par défaut par type d'action (en secondes)
    DEFAULT_TTL = {
        # Scans réseau - cache long (les ports changent rarement)
        "nmap_quick": 3600,      # 1 heure
        "nmap_full": 7200,       # 2 heures
        "nmap_vuln": 3600,       # 1 heure
        "nmap_udp": 7200,        # 2 heures
        
        # DNS/WHOIS - cache très long
        "whois": 86400,          # 24 heures
        "dns_enum": 3600,        # 1 heure
        "subdomain_enum": 7200,  # 2 heures
        
        # Web enum - cache moyen
        "gobuster": 1800,        # 30 minutes
        "feroxbuster": 1800,     # 30 minutes
        "ffuf": 1800,            # 30 minutes
        "nikto": 3600,           # 1 heure
        "whatweb": 1800,         # 30 minutes
        "wpscan": 1800,          # 30 minutes
        "curl_headers": 900,     # 15 minutes
        
        # Vuln scan - cache moyen
        "nuclei": 3600,          # 1 heure
        "nuclei_network": 3600,  # 1 heure
        "searchsploit": 86400,   # 24 heures (base locale)
        "nmap_vulners": 3600,    # 1 heure
        "ssl_scan": 3600,        # 1 heure
        
        # Par défaut
        "default": 1800,         # 30 minutes
    }
    
    def __init__(self, db_path: str = None, max_memory_entries: int = 100):
        self.db_path = db_path or os.path.join(settings.DATA_DIR, "cache.db")
        self.max_memory_entries = max_memory_entries
        self.memory_cache: Dict[str, CacheEntry] = {}
        self.lock = threading.Lock()
        self._init_db()
    
    def _init_db(self):
        """Initialise la base de données SQLite"""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cache (
                key TEXT PRIMARY KEY,
                action TEXT NOT NULL,
                target TEXT NOT NULL,
                options_hash TEXT,
                result TEXT NOT NULL,
                created_at REAL NOT NULL,
                expires_at REAL NOT NULL,
                hit_count INTEGER DEFAULT 0
            )
        ''')
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_action_target 
            ON cache(action, target)
        ''')
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_expires 
            ON cache(expires_at)
        ''')
        
        conn.commit()
        conn.close()
    
    def _generate_key(self, action: str, target: str, options: Dict[str, Any] = None) -> str:
        """Génère une clé unique pour l'entrée de cache"""
        options = options or {}
        # Trier les options pour cohérence
        options_str = json.dumps(options, sort_keys=True)
        options_hash = hashlib.md5(options_str.encode()).hexdigest()[:8]
        
        key_base = f"{action}:{target}:{options_hash}"
        return hashlib.sha256(key_base.encode()).hexdigest()[:32]
    
    def get(self, action: str, target: str, options: Dict[str, Any] = None) -> Optional[Dict[str, Any]]:
        """
        Récupère un résultat du cache
        
        Returns:
            Le résultat si trouvé et non expiré, None sinon
        """
        key = self._generate_key(action, target, options)
        
        with self.lock:
            # Chercher d'abord en mémoire
            if key in self.memory_cache:
                entry = self.memory_cache[key]
                if not entry.is_expired():
                    entry.hit_count += 1
                    return {
                        "cached": True,
                        "cached_at": datetime.fromtimestamp(entry.created_at).isoformat(),
                        "expires_at": datetime.fromtimestamp(entry.expires_at).isoformat(),
                        "hit_count": entry.hit_count,
                        **entry.result
                    }
                else:
                    del self.memory_cache[key]
            
            # Chercher en base de données
            try:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                cursor.execute(
                    'SELECT result, created_at, expires_at, hit_count FROM cache WHERE key = ?',
                    (key,)
                )
                row = cursor.fetchone()
                
                if row:
                    result, created_at, expires_at, hit_count = row
                    
                    if time.time() <= expires_at:
                        # Mettre à jour le hit count
                        cursor.execute(
                            'UPDATE cache SET hit_count = hit_count + 1 WHERE key = ?',
                            (key,)
                        )
                        conn.commit()
                        
                        result_dict = json.loads(result)
                        
                        # Ajouter en mémoire pour accès futur rapide
                        self._add_to_memory(key, action, target, options, result_dict, created_at, expires_at, hit_count + 1)
                        
                        conn.close()
                        return {
                            "cached": True,
                            "cached_at": datetime.fromtimestamp(created_at).isoformat(),
                            "expires_at": datetime.fromtimestamp(expires_at).isoformat(),
                            "hit_count": hit_count + 1,
                            **result_dict
                        }
                    else:
                        # Entrée expirée, la supprimer
                        cursor.execute('DELETE FROM cache WHERE key = ?', (key,))
                        conn.commit()
                
                conn.close()
            except Exception as e:
                print(f"[Cache] Erreur lecture: {e}")
        
        return None
    
    def set(self, action: str, target: str, result: Dict[str, Any], 
            options: Dict[str, Any] = None, ttl: int = None) -> str:
        """
        Stocke un résultat dans le cache
        
        Args:
            action: Nom de l'action
            target: Cible
            result: Résultat à cacher
            options: Options de l'action
            ttl: Time-to-live en secondes (optionnel)
        
        Returns:
            Clé de cache
        """
        key = self._generate_key(action, target, options)
        options = options or {}
        options_hash = hashlib.md5(json.dumps(options, sort_keys=True).encode()).hexdigest()[:8]
        
        # Déterminer le TTL
        if ttl is None:
            ttl = self.DEFAULT_TTL.get(action, self.DEFAULT_TTL["default"])
        
        now = time.time()
        expires_at = now + ttl
        
        # Nettoyer le résultat (enlever les données trop volumineuses si nécessaire)
        result_clean = self._clean_result(result)
        
        with self.lock:
            try:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT OR REPLACE INTO cache 
                    (key, action, target, options_hash, result, created_at, expires_at, hit_count)
                    VALUES (?, ?, ?, ?, ?, ?, ?, 0)
                ''', (key, action, target, options_hash, json.dumps(result_clean), now, expires_at))
                
                conn.commit()
                conn.close()
                
                # Ajouter en mémoire
                self._add_to_memory(key, action, target, options, result_clean, now, expires_at, 0)
                
            except Exception as e:
                print(f"[Cache] Erreur écriture: {e}")
        
        return key
    
    def _clean_result(self, result: Dict[str, Any], max_output_size: int = 50000) -> Dict[str, Any]:
        """Nettoie un résultat pour le cache (limite la taille)"""
        result_clean = result.copy()
        
        # Limiter la taille des outputs volumineux
        if "output" in result_clean and len(str(result_clean["output"])) > max_output_size:
            result_clean["output"] = result_clean["output"][:max_output_size] + "\n... [TRUNCATED]"
            result_clean["output_truncated"] = True
        
        return result_clean
    
    def _add_to_memory(self, key: str, action: str, target: str, options: Dict[str, Any],
                       result: Dict[str, Any], created_at: float, expires_at: float, hit_count: int):
        """Ajoute une entrée au cache mémoire"""
        options_hash = hashlib.md5(json.dumps(options or {}, sort_keys=True).encode()).hexdigest()[:8]
        
        # Éviction si nécessaire
        if len(self.memory_cache) >= self.max_memory_entries:
            # Supprimer l'entrée la plus ancienne
            oldest_key = min(self.memory_cache.keys(), 
                           key=lambda k: self.memory_cache[k].created_at)
            del self.memory_cache[oldest_key]
        
        self.memory_cache[key] = CacheEntry(
            key=key,
            action=action,
            target=target,
            options_hash=options_hash,
            result=result,
            created_at=created_at,
            expires_at=expires_at,
            hit_count=hit_count
        )
    
    def invalidate(self, action: str = None, target: str = None) -> int:
        """
        Invalide des entrées de cache
        
        Args:
            action: Invalider toutes les entrées de cette action
            target: Invalider toutes les entrées pour cette cible
        
        Returns:
            Nombre d'entrées supprimées
        """
        deleted = 0
        
        with self.lock:
            # Supprimer de la mémoire
            keys_to_delete = []
            for key, entry in self.memory_cache.items():
                if (action is None or entry.action == action) and \
                   (target is None or entry.target == target):
                    keys_to_delete.append(key)
            
            for key in keys_to_delete:
                del self.memory_cache[key]
                deleted += 1
            
            # Supprimer de la base de données
            try:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                if action and target:
                    cursor.execute('DELETE FROM cache WHERE action = ? AND target = ?', 
                                 (action, target))
                elif action:
                    cursor.execute('DELETE FROM cache WHERE action = ?', (action,))
                elif target:
                    cursor.execute('DELETE FROM cache WHERE target = ?', (target,))
                else:
                    cursor.execute('DELETE FROM cache')
                
                deleted += cursor.rowcount
                conn.commit()
                conn.close()
            except Exception as e:
                print(f"[Cache] Erreur invalidation: {e}")
        
        return deleted
    
    def cleanup_expired(self) -> int:
        """Nettoie les entrées expirées"""
        deleted = 0
        now = time.time()
        
        with self.lock:
            # Mémoire
            expired_keys = [k for k, v in self.memory_cache.items() if v.is_expired()]
            for key in expired_keys:
                del self.memory_cache[key]
                deleted += 1
            
            # Base de données
            try:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                cursor.execute('DELETE FROM cache WHERE expires_at < ?', (now,))
                deleted += cursor.rowcount
                conn.commit()
                conn.close()
            except Exception as e:
                print(f"[Cache] Erreur cleanup: {e}")
        
        return deleted
    
    def get_stats(self) -> Dict[str, Any]:
        """Retourne les statistiques du cache"""
        stats = {
            "memory_entries": len(self.memory_cache),
            "max_memory_entries": self.max_memory_entries,
            "db_entries": 0,
            "total_hits": 0,
            "by_action": {}
        }
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('SELECT COUNT(*) FROM cache WHERE expires_at > ?', (time.time(),))
            stats["db_entries"] = cursor.fetchone()[0]
            
            cursor.execute('SELECT SUM(hit_count) FROM cache')
            total = cursor.fetchone()[0]
            stats["total_hits"] = total or 0
            
            cursor.execute('''
                SELECT action, COUNT(*), SUM(hit_count) 
                FROM cache 
                WHERE expires_at > ?
                GROUP BY action
            ''', (time.time(),))
            
            for action, count, hits in cursor.fetchall():
                stats["by_action"][action] = {
                    "entries": count,
                    "hits": hits or 0
                }
            
            conn.close()
        except Exception as e:
            print(f"[Cache] Erreur stats: {e}")
        
        return stats
    
    def get_cached_for_target(self, target: str) -> List[Dict[str, Any]]:
        """Retourne toutes les entrées cachées pour une cible"""
        entries = []
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT action, options_hash, created_at, expires_at, hit_count
                FROM cache 
                WHERE target = ? AND expires_at > ?
                ORDER BY created_at DESC
            ''', (target, time.time()))
            
            for row in cursor.fetchall():
                action, options_hash, created_at, expires_at, hit_count = row
                entries.append({
                    "action": action,
                    "options_hash": options_hash,
                    "cached_at": datetime.fromtimestamp(created_at).isoformat(),
                    "expires_at": datetime.fromtimestamp(expires_at).isoformat(),
                    "hit_count": hit_count
                })
            
            conn.close()
        except Exception as e:
            print(f"[Cache] Erreur get_cached_for_target: {e}")
        
        return entries


# Instance globale
cache = ResultCache()
