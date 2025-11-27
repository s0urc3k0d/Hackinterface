"""
Configuration de HackInterface
"""
import os
from pathlib import Path

class Settings:
    # Chemins
    BASE_DIR = Path(__file__).resolve().parent.parent
    DATA_DIR = os.path.join(BASE_DIR, "data")
    UPLOAD_DIR = os.path.join(DATA_DIR, "uploads")
    REPORTS_DIR = os.path.join(DATA_DIR, "reports")
    SCREENSHOTS_DIR = os.path.join(DATA_DIR, "screenshots")
    WORDLISTS_DIR = "/usr/share/wordlists"
    
    # Serveur - Port 8080 pour compatibilité GitHub Codespaces
    PORT = 8080
    HOST = "0.0.0.0"
    
    # VPN
    VPN_CONFIG_PATH = os.path.join(UPLOAD_DIR, "current.ovpn")
    
    # Timeouts (en secondes)
    COMMAND_TIMEOUT = 3600  # 1 heure max pour les scans longs
    PING_TIMEOUT = 10
    
    # Wordlists par défaut
    DEFAULT_WORDLIST_DIR = "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
    DEFAULT_WORDLIST_DNS = "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
    
    # Outils - chemins (au cas où ils ne sont pas dans PATH)
    TOOLS = {
        "nmap": "nmap",
        "gobuster": "gobuster",
        "nikto": "nikto",
        "whatweb": "whatweb",
        "wpscan": "wpscan",
        "nuclei": "nuclei",
        "searchsploit": "searchsploit",
        "whois": "whois",
        "dig": "dig",
        "subfinder": "subfinder",
        "httpx": "httpx",
        "feroxbuster": "feroxbuster",
        "ffuf": "ffuf",
        "amass": "amass",
        "cutycapt": "cutycapt",
        "wkhtmltoimage": "wkhtmltoimage",
    }
    
    # Nmap scripts
    NMAP_SCRIPTS_VULN = "vuln,exploit"
    NMAP_SCRIPTS_DEFAULT = "default,safe"
    
settings = Settings()
