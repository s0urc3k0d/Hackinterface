# HackInterface 🔓

Interface Web pour l'automatisation de pentests, conçue pour fonctionner avec Kali Linux.

![Python](https://img.shields.io/badge/Python-3.9+-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.104-green)
![License](https://img.shields.io/badge/License-MIT-yellow)

## 🎯 Fonctionnalités

### Gestion VPN
- Upload de fichiers `.ovpn`
- Connexion/Déconnexion VPN
- Test de connectivité (ping)

### Gestion des Cibles
- Support multi-types : IP, FQDN, Domaine, CIDR, URL
- Liste et gestion des cibles

### Actions de Pentest
| Catégorie | Outils |
|-----------|--------|
| **Reconnaissance** | Nmap (quick, full, vuln, UDP), Whois, DNS Enum, Subdomain Enum |
| **Énumération Web** | Gobuster, Feroxbuster, FFUF, Nikto, WhatWeb, WPScan |
| **Scan Vulnérabilités** | Nuclei, SearchSploit, SSL Scan |
| **Exploitation** | Enum4linux, SMBClient, RPCClient, LDAPSearch |

### Workflows Automatisés
- **Reconnaissance Complète** : Scan complet avec enchaînement automatique
- **Audit Web Complet** : Énumération + vulnérabilités web
- **WordPress Audit** : Scan spécialisé WordPress
- **Network Vuln Scan** : Vulnérabilités réseau
- **SMB Enumeration** : Énumération Windows/SMB
- **OSCP Box Methodology** : Méthodologie complète pour CTF/OSCP

### Rapports
- **Format OSCP** : Style rapport OSCP
- **Format Client** : Rapport professionnel pour client
- **Export JSON** : Données brutes structurées

## 📋 Prérequis

- Kali Linux (recommandé) ou distribution avec les outils de pentest
- Python 3.9+
- Outils : nmap, gobuster, nikto, nuclei, etc.

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

### 3. Lancer l'application

```bash
cd backend
chmod +x start.sh
./start.sh
```

L'interface sera accessible sur : **http://127.0.0.1:8443**

## 🔧 Configuration

### Fichier de configuration : `backend/core/config.py`

```python
# Port du serveur
PORT = 8443

# Timeouts
COMMAND_TIMEOUT = 3600  # 1 heure pour les scans longs

# Wordlists par défaut
DEFAULT_WORDLIST_DIR = "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
```

## 📖 Utilisation

### 1. Configuration VPN (optionnel)
- Uploadez votre fichier `.ovpn`
- Cliquez sur "Connecter"
- Testez la connectivité avec un ping

### 2. Ajouter des cibles
- Sélectionnez le type (IP, domaine, etc.)
- Entrez la valeur
- Ajoutez une description (optionnel)

### 3. Lancer un workflow ou des actions
- **Workflows prédéfinis** : Sélectionnez une cible puis un workflow
- **Actions individuelles** : Exécutez des outils spécifiques
- **Workflow personnalisé** : Cochez les actions souhaitées

### 4. Consulter les résultats
- Vue en temps réel via WebSocket
- Résultats parsés automatiquement
- Export possible en JSON

### 5. Générer un rapport
- Choisissez le format (OSCP, Client, JSON)
- Téléchargez le rapport HTML

## 🏗️ Structure du projet

```
Hackinterface/
├── backend/
│   ├── main.py              # API FastAPI
│   ├── core/
│   │   ├── config.py        # Configuration
│   │   ├── vpn.py           # Gestion VPN
│   │   ├── executor.py      # Exécution commandes
│   │   └── websocket_manager.py
│   ├── modules/
│   │   ├── recon.py         # Reconnaissance
│   │   ├── web_enum.py      # Énumération web
│   │   ├── vuln_scan.py     # Scan vulnérabilités
│   │   └── exploitation.py  # Suggestions d'exploitation
│   ├── workflows/
│   │   └── engine.py        # Moteur de workflows
│   ├── reports/
│   │   └── generator.py     # Génération rapports
│   ├── frontend/
│   │   ├── index.html
│   │   └── static/
│   ├── requirements.txt
│   └── start.sh
├── install_tools.sh
└── README.md
```

## 🔒 Sécurité

⚠️ **ATTENTION** : Cette application est destinée à un usage **local uniquement** sur votre machine de pentest.

- Pas d'authentification par défaut (usage local)
- N'exposez jamais cette interface sur Internet
- Utilisez uniquement dans un cadre légal et autorisé

## 🤝 Contribution

Les contributions sont les bienvenues ! N'hésitez pas à :
- Signaler des bugs
- Proposer de nouvelles fonctionnalités
- Soumettre des pull requests

## 📜 Licence

MIT License - Voir [LICENSE](LICENSE) pour plus de détails.

## 🙏 Crédits

- Outils utilisés : Nmap, Nuclei, Gobuster, Nikto, WhatWeb, etc.
- Framework : FastAPI, Jinja2
- Icons : Font Awesome

---

**Disclaimer** : Cet outil est fourni à des fins éducatives et de test de sécurité autorisé uniquement. L'utilisation de cet outil contre des systèmes sans autorisation est illégale.
