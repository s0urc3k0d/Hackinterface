#!/bin/bash
# HackInterface - Script de lancement
# Usage: ./start.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Couleurs
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}"
echo "╔═══════════════════════════════════════════╗"
echo "║         HackInterface - Pentest UI        ║"
echo "╚═══════════════════════════════════════════╝"
echo -e "${NC}"

# Vérifier Python
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}[ERROR] Python3 n'est pas installé${NC}"
    exit 1
fi

# Créer l'environnement virtuel si nécessaire
if [ ! -d "venv" ]; then
    echo -e "${YELLOW}[*] Création de l'environnement virtuel...${NC}"
    python3 -m venv venv
fi

# Activer l'environnement virtuel
source venv/bin/activate

# Installer les dépendances
echo -e "${YELLOW}[*] Installation des dépendances...${NC}"
pip install -q -r requirements.txt

# Créer les dossiers nécessaires
mkdir -p data/uploads data/reports data/screenshots

# Vérifier les outils disponibles
echo -e "${YELLOW}[*] Vérification des outils...${NC}"
TOOLS=("nmap" "gobuster" "nikto" "whatweb" "nuclei" "whois" "dig")
for tool in "${TOOLS[@]}"; do
    if command -v $tool &> /dev/null; then
        echo -e "  ${GREEN}✓${NC} $tool"
    else
        echo -e "  ${RED}✗${NC} $tool (non installé)"
    fi
done

echo ""
echo -e "${GREEN}[+] Démarrage de HackInterface...${NC}"
echo -e "${BLUE}[*] Interface disponible sur: http://127.0.0.1:8443${NC}"
echo -e "${YELLOW}[*] Appuyez sur Ctrl+C pour arrêter${NC}"
echo ""

# Lancer l'application
python3 -m uvicorn main:app --host 0.0.0.0 --port 8443 --reload
