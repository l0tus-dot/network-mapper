"""
modules/arp_scan.py
-------------------
Scan ARP pour la découverte des équipements sur le réseau local.
Compatible Windows (avec Npcap) et Linux.
Nécessite des droits administrateur / root.

Méthode principale : scapy (paquet ARP broadcast)
Fallback          : ping sweep + lecture de la table ARP système
"""

import socket
import ipaddress
import platform
import logging
import subprocess
import re
import concurrent.futures

log = logging.getLogger(__name__)

# --- Tentative d'import de scapy ---
try:
    from scapy.all import ARP, Ether, srp, conf
    SCAPY_AVAILABLE = True
    log.debug("scapy disponible : utilisation de la méthode ARP principale.")
except ImportError:
    SCAPY_AVAILABLE = False
    log.warning(
        "scapy non trouvé. Utilisation du fallback ping sweep.\n"
        "  → Installez scapy pour des résultats plus fiables : pip install scapy"
    )


# ---------------------------------------------------------------------------
# Détection automatique du sous-réseau
# ---------------------------------------------------------------------------

def get_local_subnet() -> str | None:
    """
    Détecte automatiquement le sous-réseau local principal de la machine.

    Technique : ouvre une socket UDP sans vraiment se connecter
    pour obtenir l'adresse IP locale utilisée par le routage par défaut,
    puis suppose un masque /24 (le plus courant en LAN domestique/PME).

    Returns:
        Notation CIDR (ex: '192.168.1.0/24') ou None si détection impossible.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Pas besoin d'une vraie connexion, juste pour lire l'IP source
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()

        # On construit le réseau /24 correspondant
        network = ipaddress.IPv4Network(f"{local_ip}/24", strict=False)
        log.debug(f"IP locale détectée : {local_ip} → réseau : {network}")
        return str(network)

    except Exception as e:
        log.error(f"Impossible de détecter le sous-réseau automatiquement : {e}")
        return None


# ---------------------------------------------------------------------------
# Entrée principale
# ---------------------------------------------------------------------------

def arp_scan(network: str, timeout: float = 2.0) -> list[dict]:
    """
    Effectue un scan ARP sur la plage réseau cible.

    Utilise scapy si disponible, sinon bascule sur le ping sweep.

    Args:
        network  : Notation CIDR (ex: '192.168.1.0/24')
        timeout  : Délai d'attente des réponses ARP en secondes

    Returns:
        Liste de dicts triés par IP :
        [{'ip': '192.168.1.1', 'mac': 'AA:BB:CC:DD:EE:FF'}, ...]
    """
    if SCAPY_AVAILABLE:
        return _scapy_arp_scan(network, timeout)
    else:
        return _fallback_scan(network)


# ---------------------------------------------------------------------------
# Méthode principale : scapy
# ---------------------------------------------------------------------------

def _scapy_arp_scan(network: str, timeout: float) -> list[dict]:
    """
    Envoie un paquet ARP-who-has en broadcast et collecte les réponses.

    Fonctionne sur Linux directement.
    Sur Windows, nécessite Npcap (https://npcap.com) installé.
    """
    try:
        conf.verb = 0  # Supprimer la verbosité scapy

        # Paquet = trame Ethernet broadcast + requête ARP
        packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network)

        log.debug(f"Envoi de paquets ARP broadcast sur {network}…")
        answered, _ = srp(packet, timeout=timeout, verbose=False)

        hosts = []
        for _, received in answered:
            hosts.append({
                "ip":  received.psrc,
                "mac": received.hwsrc.upper().replace("-", ":")
            })

        # Tri par adresse IP
        hosts.sort(key=lambda h: [int(x) for x in h["ip"].split(".")])
        log.debug(f"scapy ARP scan : {len(hosts)} hôte(s) trouvé(s)")
        return hosts

    except PermissionError:
        log.error(
            "Permission refusée. Relancez le script avec les droits admin/root.\n"
            "  Windows : clic droit > Exécuter en tant qu'administrateur\n"
            "  Linux   : sudo python scanner.py"
        )
        return []
    except OSError as e:
        # Erreur typique sur Windows si Npcap n'est pas installé
        if "No such file" in str(e) or "Npcap" in str(e) or "winpcap" in str(e).lower():
            log.error(
                "Npcap n'est pas installé. scapy en a besoin sous Windows.\n"
                "  → Téléchargez Npcap : https://npcap.com/#download\n"
                "  → Cochez 'WinPcap API-compatible Mode' à l'installation."
            )
        else:
            log.error(f"Erreur réseau scapy : {e}")
        return []
    except Exception as e:
        log.error(f"Erreur inattendue dans le scan ARP scapy : {e}")
        return []


# ---------------------------------------------------------------------------
# Méthode fallback : ping sweep + table ARP système
# ---------------------------------------------------------------------------

def _fallback_scan(network: str) -> list[dict]:
    """
    Ping sweep parallèle suivi d'une lecture de la table ARP système.

    Moins fiable que scapy (certains équipements ignorent les pings ICMP),
    mais ne nécessite aucune bibliothèque externe.
    """
    net    = ipaddress.IPv4Network(network, strict=False)
    all_ip = [str(ip) for ip in net.hosts()]

    log.info(f"Ping sweep sur {len(all_ip)} adresses (méthode fallback)…")

    # --- Ping concurrent ---
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        ping_results = list(executor.map(_ping_host, all_ip))

    # --- Lecture de la table ARP ---
    arp_table = _read_arp_table()

    # --- Consolidation ---
    hosts = []
    for ip, responded in zip(all_ip, ping_results):
        mac = arp_table.get(ip)
        if responded and mac:
            hosts.append({"ip": ip, "mac": mac})

    hosts.sort(key=lambda h: [int(x) for x in h["ip"].split(".")])
    log.debug(f"Fallback scan : {len(hosts)} hôte(s) trouvé(s)")
    return hosts


def _ping_host(ip: str) -> bool:
    """Envoie un ping ICMP à une adresse IP. Retourne True si réponse reçue."""
    try:
        if platform.system() == "Windows":
            cmd = ["ping", "-n", "1", "-w", "500", ip]
        else:
            cmd = ["ping", "-c", "1", "-W", "1", ip]
        result = subprocess.run(cmd, capture_output=True, timeout=3)
        return result.returncode == 0
    except Exception:
        return False


def _read_arp_table() -> dict:
    """
    Lit et parse la table ARP du système d'exploitation.

    Returns:
        Dict {ip: mac} depuis la table ARP noyau/OS.
    """
    arp_map = {}
    try:
        if platform.system() == "Windows":
            output = subprocess.check_output("arp -a", shell=True).decode("utf-8", errors="ignore")
            # Format Windows : "  192.168.1.1          aa-bb-cc-dd-ee-ff     dynamique"
            for line in output.splitlines():
                parts = line.split()
                if len(parts) >= 2 and re.match(r"^\d+\.\d+\.\d+\.\d+$", parts[0]):
                    ip  = parts[0]
                    mac = parts[1].replace("-", ":").upper()
                    if re.match(r"^([0-9A-F]{2}:){5}[0-9A-F]{2}$", mac):
                        arp_map[ip] = mac
        else:
            output = subprocess.check_output(["arp", "-n"], stderr=subprocess.DEVNULL).decode("utf-8", errors="ignore")
            # Format Linux : "192.168.1.1  ether  aa:bb:cc:dd:ee:ff  C  eth0"
            for line in output.splitlines():
                parts = line.split()
                if len(parts) >= 3 and re.match(r"^\d+\.\d+\.\d+\.\d+$", parts[0]):
                    ip  = parts[0]
                    mac = parts[2].upper()
                    if re.match(r"^([0-9A-F]{2}:){5}[0-9A-F]{2}$", mac):
                        arp_map[ip] = mac

    except Exception as e:
        log.debug(f"Erreur lecture table ARP : {e}")

    return arp_map
