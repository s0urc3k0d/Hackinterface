# HackInterface 🔓

Interface Web moderne pour l'automatisation de pentests, conçue pour fonctionner avec Kali Linux.

![Python](https://img.shields.io/badge/Python-3.9+-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.104-green)
![License](https://img.shields.io/badge/License-MIT-yellow)
![PWA](https://img.shields.io/badge/PWA-Ready-purple)

## 🎯 Fonctionnalités Principales

### 🌐 Gestion VPN
- Upload de fichiers `.ovpn`
- Connexion/Déconnexion VPN automatisée
- Test de connectivité (ping)
- Indicateur de statut en temps réel

### 🎯 Gestion des Cibles
- **Support multi-types** : IPv4, IPv6, CIDR, Domaine, FQDN, URL
- **Validation intelligente** avec détection automatique du type
- Détection IP privées/loopback avec avertissements
- Suggestions de correction pour les entrées invalides
- Liste et gestion des cibles avec descriptions

### 🛠️ Actions de Pentest

| Catégorie | Outils Disponibles |
|-----------|-------------------|
| **Reconnaissance** | Nmap (quick, full, vuln, UDP), Whois, DNS Enum, Subdomain Enum |
| **Énumération Web** | Gobuster, Feroxbuster, FFUF, Nikto, WhatWeb, WPScan, cURL Headers, Screenshots |
| **Scan Vulnérabilités** | Nuclei, Nuclei Network, SearchSploit, Nmap Vulners, SSL Scan, Default Creds Check |
| **Exploitation** | Enum4linux, SMBClient, RPCClient, LDAPSearch |
| **Attaques Password** | Hydra (SSH, FTP, SMB, RDP, HTTP), CeWL |
| **Réseau** | Masscan, SSLScan, TestSSL, ARP Scan, Responder |
| **OSINT** | theHarvester, Amass, Sherlock, wafw00f, ExifTool |
| **Web Avancé** | SQLMap, Commix, XSSer, Dalfox, EyeWitness, DroopeScan, JoomScan |
| **Metasploit** | Modules auxiliaires (SMB, SSH, FTP, HTTP, MySQL, PostgreSQL) |
| **Active Directory** | NetExec, Impacket, BloodHound, Kerbrute, EvilWinRM |
| **Post-Exploitation** | LinPEAS, WinPEAS, Linux Exploit Suggester |

### 🔄 Workflows Automatisés

| Workflow | Description |
|----------|-------------|
| **Reconnaissance Complète** | Nmap + Whois + DNS + Subdomains avec enchaînement intelligent |
| **Audit Web Complet** | WhatWeb → Headers → Screenshot → Gobuster → Nikto → Nuclei |
| **Audit Web Rapide** | Scan rapide pour évaluation initiale |
| **WordPress Audit** | Scan spécialisé WordPress (WPScan + Nuclei WP) |
| **Network Vuln Scan** | Scan complet vulnérabilités réseau |
| **SMB Enumeration** | Énumération Windows/SMB complète |
| **OSCP Box Methodology** | Méthodologie complète CTF/OSCP |
| **Active Directory Pentest** | Énumération et attaque AD |
| **SQL Injection Testing** | Tests SQLi automatisés |
| **XSS Testing** | Recherche vulnérabilités XSS |
| **Bruteforce Services** | Brute-force services détectés |
| **External OSINT Recon** | Reconnaissance OSINT externe |
| **Full Web Application Audit** | Audit complet avec tous les tests |
| **Internal Network Discovery** | Découverte réseau interne |
| **Metasploit Auxiliary Scan** | Scans avec modules MSF |
| **Database Enumeration** | Énumération bases de données |
| **CMS Security Audit** | Audit CMS (WordPress, Joomla, Drupal) |

### 📊 Rapports

- **Format OSCP** : Style rapport OSCP avec sections structurées
- **Format Client** : Rapport professionnel pour client
- **Export JSON** : Données brutes structurées
- **Export Markdown** : Documentation lisible
- **Export PDF** : Rapport PDF professionnel (via wkhtmltopdf)

---

## ⚡ Fonctionnalités Avancées

### 🧠 Parsers Intelligents

#### Parser Nmap Amélioré
- Extraction complète OS avec CPE
- Versions services détaillées
- Scripts NSE avec données structurées (vulns, SMB, SSL, etc.)
- **Détection automatique des CVEs** depuis les scripts vulners/vulnscan
- Statistiques (hosts up, ports ouverts/fermés/filtrés)

#### Parser WhatWeb
- Détection CMS (WordPress, Joomla, Drupal, etc.)
- Identification frameworks (Laravel, Django, Rails, etc.)
- Extraction versions serveur et technologies

#### Parser FFUF
- Support format JSON natif
- Groupement par code HTTP
- Statistiques de découvertes

### 🔒 Sécurité Intégrée

#### Masquage des Credentials
Protection automatique des données sensibles dans les logs :
- Mots de passe et hashes
- Tokens et clés API
- Identifiants de session

#### Validation des Entrées
- Classe `TargetValidator` complète
- Support : IPv4, IPv6, CIDR, domaines, FQDN, URL
- Détection IP privées/loopback avec avertissements
- Suggestions de correction

### ⚙️ Exécution Robuste

#### Rate Limiting Intelligent
- Contrôle de concurrence (`max_concurrent`)
- Délais adaptatifs (augmente automatiquement si erreurs)
- Statistiques temps réel

#### Système de Retry
- `run_with_retry()` avec `max_retries` configurable
- Backoff exponentiel (1s → 2s → 4s → ...)
- Jitter aléatoire ±20% pour éviter les surcharges

### 💾 Cache Résultats

- **Cache intelligent** avec TTL configurable
- Évite les scans redondants sur même cible
- Clés basées sur action + cible + options
- Statistiques de hits/misses
- Invalidation par action ou cible

### 📜 Historique des Commandes

- Suivi complet de toutes les commandes exécutées
- Recherche par action, cible, date
- **Replay** : relancer une commande depuis l'historique
- Statistiques d'utilisation
- Export/Import JSON

### 📋 Templates de Workflows

- Création de workflows personnalisés
- Sauvegarde et chargement depuis SQLite
- Templates publics/privés
- Clone de templates existants
- Système de notation et compteur d'utilisation
- Import/Export JSON
- Tags et recherche

### 📲 Progressive Web App (PWA)

- **Installation** sur bureau/mobile
- **Mode hors-ligne** avec Service Worker
- Cache intelligent des ressources
- Synchronisation automatique au retour en ligne
- Indicateur de statut réseau
- Notifications push (préparé)

### 🔔 Notifications Navigateur

- Notifications natives pour événements importants
- Types : success, error, warning, info
- Son optionnel
- Persistance des préférences
- Toggle on/off dans l'interface

### 🛑 Contrôle des Workflows

- **Annulation** de workflow en cours
- Statut en temps réel via WebSocket
- Détection des outils manquants avant exécution

---

## 📋 Prérequis

- **Kali Linux** (recommandé) ou distribution avec outils de pentest
- **Python 3.9+**
- Outils de pentest installés (voir `install_tools.sh`)

## 🚀 Installation

### 1. Cloner le repository

```bash
git clone https://github.com/yourusername/Hackinterface.git
cd Hackinterface
```

### 2. Installer les outils de pentest (sur Kali)

```bash
chmod +x install_tools.sh
./install_tools.sh
```

### 3. Installer les dépendances Python

```bash
cd backend
pip install -r requirements.txt
```

### 4. Lancer l'application

```bash
chmod +x start.sh
./start.sh
```

L'interface sera accessible sur : **http://127.0.0.1:8080**

---

## 🔧 Configuration

### Fichier : `backend/core/config.py`

```python
# Port du serveur
PORT = 8080

# Timeouts
COMMAND_TIMEOUT = 3600  # 1 heure pour les scans longs

# Sécurité API (optionnel)
API_TOKEN = ""  # ex: "change-moi"
REQUIRE_API_AUTH = False  # True pour exiger le token sur /api et /ws

# CORS (origines autorisées)
ALLOWED_ORIGINS = [
  "http://127.0.0.1:8080",
  "http://localhost:8080"
]

# Wordlists par défaut
DEFAULT_WORDLIST_DIR = "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"

# Répertoires de données
DATA_DIR = "data"
UPLOAD_DIR = "data/uploads"
REPORTS_DIR = "data/reports"
SCREENSHOTS_DIR = "data/screenshots"
```

---

### Variables d'environnement recommandées (Kali)

```bash
export API_TOKEN="change-moi-token-fort"
export REQUIRE_API_AUTH=true
export ALLOWED_ORIGINS="http://127.0.0.1:8080,http://localhost:8080"
```

- `Authorization: Bearer <token>` ou header `X-API-Key: <token>` pour l'API
- WebSocket: `ws://127.0.0.1:8080/ws?token=<token>`
- Isolation mémoire multi-client: header `X-Session-Key: <id>` (ou query `session_key=<id>`)

#### Endpoints contexte session

- `GET /api/session/context` : retourne la clé de session active + stats mémoire
- `POST /api/session/context` : change/rotate la clé active
  - body possible: `{ "session_key": "team-a", "rotate": false, "set_cookie": true }`
  - body possible: `{ "rotate": true }` pour générer une nouvelle clé

#### Intégration Frontend (déjà implémentée)

- Le frontend envoie automatiquement `X-Session-Key` sur tous les appels `fetch`
- Le frontend récupère/synchronise la clé via `GET /api/session/context` au démarrage
- Le WebSocket inclut automatiquement `session_key` et `token` en query params
- Le token API peut être passé via `?api_token=<token>` (persisté ensuite en localStorage)

---

## 📖 Utilisation

### 1. Configuration VPN (optionnel)
- Uploadez votre fichier `.ovpn`
- Cliquez sur "Connecter"
- Testez la connectivité avec un ping

### 2. Ajouter des cibles
- Sélectionnez le type (IP, domaine, URL...)
- Entrez la valeur (validation automatique)
- Ajoutez une description (optionnel)

### 3. Lancer un workflow ou des actions

**Workflows prédéfinis :**
- Sélectionnez une cible
- Choisissez un workflow dans la liste
- Suivez la progression en temps réel

**Actions individuelles :**
- Sélectionnez une cible
- Exécutez des outils spécifiques
- Consultez les résultats parsés

**Workflow personnalisé :**
- Cochez les actions souhaitées
- Lancez le workflow custom

**Templates :**
- Créez vos propres workflows
- Sauvegardez-les pour réutilisation
- Partagez via export JSON

### 4. Consulter les résultats
- Vue en temps réel via WebSocket
- Résultats parsés automatiquement (Nmap, WhatWeb, FFUF...)
- Export JSON disponible
- Historique complet des commandes

### 5. Générer un rapport
- Choisissez le format (OSCP, Client, JSON, Markdown, PDF)
- Téléchargez le rapport généré

---

## 🏗️ Structure du Projet

```
Hackinterface/
├── backend/
│   ├── main.py                    # API FastAPI principale
│   ├── requirements.txt
│   ├── start.sh
│   │
│   ├── core/
│   │   ├── config.py              # Configuration
│   │   ├── database.py            # Gestion SQLite sessions
│   │   ├── executor.py            # Exécution commandes + Rate Limiting + Retry + Validation
│   │   ├── vpn.py                 # Gestion VPN
│   │   ├── websocket_manager.py   # Communication temps réel
│   │   ├── cache.py               # Cache résultats avec TTL
│   │   └── history.py             # Historique commandes
│   │
│   ├── modules/
│   │   ├── recon.py               # Reconnaissance (Nmap amélioré)
│   │   ├── web_enum.py            # Énumération web (WhatWeb, FFUF parsers)
│   │   ├── vuln_scan.py           # Scan vulnérabilités
│   │   ├── exploitation.py        # Exploitation
│   │   ├── password_attacks.py    # Attaques password
│   │   ├── network.py             # Outils réseau
│   │   ├── osint.py               # OSINT
│   │   ├── web_advanced.py        # Web avancé (SQLMap, XSS...)
│   │   ├── metasploit.py          # Modules Metasploit
│   │   ├── netexec.py             # NetExec (AD)
│   │   ├── impacket.py            # Impacket suite
│   │   ├── bloodhound.py          # BloodHound
│   │   ├── kerbrute.py            # Kerbrute
│   │   ├── evilwinrm.py           # EvilWinRM
│   │   └── peas.py                # LinPEAS/WinPEAS
│   │
│   ├── workflows/
│   │   ├── engine.py              # Moteur de workflows + Auto-chain
│   │   └── templates.py           # Templates personnalisés
│   │
│   ├── reports/
│   │   └── generator.py           # Génération multi-format
│   │
│   ├── frontend/
│   │   ├── index.html             # Interface principale (PWA ready)
│   │   ├── manifest.json          # PWA Manifest
│   │   ├── sw.js                  # Service Worker
│   │   └── static/
│   │       ├── css/style.css
│   │       ├── js/app.js          # App JS + Notifications + PWA Manager
│   │       └── icons/
│   │
│   ├── data/
│   │   ├── reports/
│   │   ├── screenshots/
│   │   └── uploads/
│   │
│   ├── models/
│   │   └── schemas.py             # Modèles Pydantic
│   │
│   └── templates/                 # Templates Jinja2 rapports
│
├── install_tools.sh               # Script installation outils
└── README.md
```

---

## 🔌 API Endpoints

### VPN
| Méthode | Endpoint | Description |
|---------|----------|-------------|
| POST | `/api/vpn/upload` | Upload fichier .ovpn |
| POST | `/api/vpn/connect` | Connexion VPN |
| POST | `/api/vpn/disconnect` | Déconnexion VPN |
| GET | `/api/vpn/status` | Statut VPN |
| POST | `/api/vpn/ping` | Test connectivité |

### Cibles
| Méthode | Endpoint | Description |
|---------|----------|-------------|
| GET | `/api/targets` | Liste des cibles |
| POST | `/api/targets` | Ajouter une cible |
| DELETE | `/api/targets/{id}` | Supprimer une cible |
| POST | `/api/validate/target` | Valider une cible |
| POST | `/api/validate/targets` | Valider plusieurs cibles |

### Actions
| Méthode | Endpoint | Description |
|---------|----------|-------------|
| GET | `/api/actions` | Liste des actions disponibles |
| POST | `/api/execute` | Exécuter une action |
| GET | `/api/results/{target_id}` | Résultats d'une cible |

### Workflows
| Méthode | Endpoint | Description |
|---------|----------|-------------|
| GET | `/api/workflows` | Liste des workflows |
| POST | `/api/workflows/execute` | Lancer un workflow |
| POST | `/api/workflows/cancel/{task_id}` | Annuler un workflow |

### Templates
| Méthode | Endpoint | Description |
|---------|----------|-------------|
| GET | `/api/templates` | Liste des templates |
| POST | `/api/templates` | Créer un template |
| GET | `/api/templates/{id}` | Détails d'un template |
| PUT | `/api/templates/{id}` | Modifier un template |
| DELETE | `/api/templates/{id}` | Supprimer un template |
| POST | `/api/templates/{id}/clone` | Cloner un template |
| GET | `/api/templates/{id}/export` | Exporter en JSON |
| POST | `/api/templates/import` | Importer depuis JSON |
| POST | `/api/templates/{id}/execute` | Exécuter un template |
| GET | `/api/templates/popular` | Templates populaires |
| GET | `/api/templates/stats` | Statistiques |

### Cache
| Méthode | Endpoint | Description |
|---------|----------|-------------|
| GET | `/api/cache/status` | Statut du cache |
| DELETE | `/api/cache/clear` | Vider le cache |
| DELETE | `/api/cache/invalidate/{action}` | Invalider par action |
| POST | `/api/cache/cleanup` | Nettoyer entrées expirées |

### Historique
| Méthode | Endpoint | Description |
|---------|----------|-------------|
| GET | `/api/history` | Liste des commandes |
| GET | `/api/history/stats` | Statistiques |
| GET | `/api/history/{id}` | Détails d'une commande |
| POST | `/api/history/{id}/replay` | Rejouer une commande |
| DELETE | `/api/history` | Vider l'historique |
| GET | `/api/history/export` | Exporter en JSON |

### Outils
| Méthode | Endpoint | Description |
|---------|----------|-------------|
| GET | `/api/tools/status` | Statut tous les outils |
| GET | `/api/tools/check/{tool}` | Vérifier un outil |

### Sessions
| Méthode | Endpoint | Description |
|---------|----------|-------------|
| GET | `/api/sessions` | Liste des sessions |
| POST | `/api/sessions` | Créer une session |
| GET | `/api/sessions/{id}` | Détails session |
| DELETE | `/api/sessions/{id}` | Supprimer session |
| POST | `/api/session/export` | Exporter session |
| POST | `/api/session/import` | Importer session |

### Rapports
| Méthode | Endpoint | Description |
|---------|----------|-------------|
| POST | `/api/reports/generate` | Générer un rapport |
| GET | `/api/reports` | Liste des rapports |
| GET | `/api/reports/{filename}` | Télécharger rapport |

### WebSocket
| Endpoint | Description |
|----------|-------------|
| `/ws` | Communication temps réel |

---

## 🔒 Sécurité

⚠️ **ATTENTION** : Cette application est destinée à un usage **local uniquement**.

- Pas d'authentification par défaut (usage local)
- **N'exposez jamais cette interface sur Internet**
- Utilisez uniquement dans un cadre **légal et autorisé**
- Les credentials sont automatiquement masqués dans les logs

---

## 🤝 Contribution

Les contributions sont les bienvenues ! N'hésitez pas à :
- 🐛 Signaler des bugs
- 💡 Proposer de nouvelles fonctionnalités
- 🔧 Soumettre des pull requests
- 📖 Améliorer la documentation

---

## 📜 Licence

MIT License - Voir [LICENSE](LICENSE) pour plus de détails.

---

## 🙏 Crédits

**Outils intégrés :**
- Nmap, Nuclei, Gobuster, Feroxbuster, FFUF
- Nikto, WhatWeb, WPScan
- SQLMap, Commix, XSSer, Dalfox
- Hydra, CeWL, Hashcat
- Metasploit Framework
- Impacket, NetExec, BloodHound
- Et bien d'autres...

**Technologies :**
- FastAPI, Uvicorn
- Jinja2, Chart.js
- SQLite
- Service Workers (PWA)

**Icons :** Font Awesome

---

## ⚠️ Disclaimer

Cet outil est fourni à des fins **éducatives et de test de sécurité autorisé uniquement**. 

L'utilisation de cet outil contre des systèmes **sans autorisation explicite** est **illégale** et peut entraîner des poursuites judiciaires.

Les auteurs ne sont pas responsables de toute utilisation malveillante ou illégale de cet outil.

---

<p align="center">
  <b>HackInterface</b> - Automatisez vos pentests avec style 🔓
</p>

