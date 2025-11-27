#!/bin/bash
# Installation des outils de pentest pour HackInterface
# À exécuter sur Kali Linux

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}[*] Mise à jour des paquets...${NC}"
sudo apt update

echo -e "${YELLOW}[*] Installation des outils essentiels...${NC}"

# Outils de base (généralement déjà sur Kali)
TOOLS=(
    "nmap"
    "nikto"
    "whatweb"
    "whois"
    "dnsutils"    # dig
    "enum4linux"
    "smbclient"
    "ldap-utils"
    "sslscan"
    "wpscan"
    "cutycapt"    # Screenshots
)

for tool in "${TOOLS[@]}"; do
    echo -e "${YELLOW}[*] Installation de $tool...${NC}"
    sudo apt install -y $tool 2>/dev/null || echo -e "${RED}  Échec: $tool${NC}"
done

# Outils Go (gobuster, feroxbuster, nuclei, httpx, subfinder)
echo -e "${YELLOW}[*] Installation des outils Go...${NC}"

# Gobuster
if ! command -v gobuster &> /dev/null; then
    sudo apt install -y gobuster 2>/dev/null || {
        echo -e "${YELLOW}[*] Installation de gobuster via Go...${NC}"
        go install github.com/OJ/gobuster/v3@latest 2>/dev/null || echo -e "${RED}  Gobuster non installé${NC}"
    }
fi

# Feroxbuster
if ! command -v feroxbuster &> /dev/null; then
    sudo apt install -y feroxbuster 2>/dev/null || {
        echo -e "${YELLOW}[*] Installation de feroxbuster...${NC}"
        curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | bash 2>/dev/null || echo -e "${RED}  Feroxbuster non installé${NC}"
    }
fi

# Nuclei
if ! command -v nuclei &> /dev/null; then
    echo -e "${YELLOW}[*] Installation de nuclei...${NC}"
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 2>/dev/null || {
        # Alternative: téléchargement binaire
        wget -q https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_linux_amd64.zip -O /tmp/nuclei.zip
        unzip -o /tmp/nuclei.zip -d /tmp/
        sudo mv /tmp/nuclei /usr/local/bin/
        rm /tmp/nuclei.zip
    }
    # Mettre à jour les templates
    nuclei -update-templates 2>/dev/null || true
fi

# Subfinder
if ! command -v subfinder &> /dev/null; then
    echo -e "${YELLOW}[*] Installation de subfinder...${NC}"
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>/dev/null || echo -e "${RED}  Subfinder non installé${NC}"
fi

# Httpx
if ! command -v httpx &> /dev/null; then
    echo -e "${YELLOW}[*] Installation de httpx...${NC}"
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest 2>/dev/null || echo -e "${RED}  Httpx non installé${NC}"
fi

# FFUF
if ! command -v ffuf &> /dev/null; then
    sudo apt install -y ffuf 2>/dev/null || {
        go install github.com/ffuf/ffuf/v2@latest 2>/dev/null || echo -e "${RED}  FFUF non installé${NC}"
    }
fi

# Wordlists
echo -e "${YELLOW}[*] Vérification des wordlists...${NC}"
if [ ! -d "/usr/share/wordlists/seclists" ]; then
    echo -e "${YELLOW}[*] Installation de SecLists...${NC}"
    sudo apt install -y seclists 2>/dev/null || {
        sudo git clone --depth 1 https://github.com/danielmiessler/SecLists.git /usr/share/wordlists/seclists
    }
fi

# Permissions pour OpenVPN (pour le VPN sans sudo constant)
echo -e "${YELLOW}[*] Configuration des permissions...${NC}"
sudo setcap cap_net_admin=ep /usr/sbin/openvpn 2>/dev/null || true

echo ""
echo -e "${GREEN}[+] Installation terminée !${NC}"
echo ""
echo -e "${YELLOW}Outils installés:${NC}"

# Vérification finale
FINAL_TOOLS=("nmap" "gobuster" "feroxbuster" "nikto" "whatweb" "nuclei" "subfinder" "httpx" "ffuf" "wpscan" "enum4linux" "smbclient" "sslscan")
for tool in "${FINAL_TOOLS[@]}"; do
    if command -v $tool &> /dev/null; then
        echo -e "  ${GREEN}✓${NC} $tool"
    else
        echo -e "  ${RED}✗${NC} $tool"
    fi
done
