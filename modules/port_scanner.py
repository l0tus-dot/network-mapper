"""
modules/port_scanner.py
-----------------------
Scan de ports TCP concurrent (optionnel, activé via --ports).

Utilise des connexions socket non-bloquantes avec ThreadPoolExecutor
pour scanner plusieurs ports simultanément sur un même hôte.

Fonctionnalités :
  - Détection de l'état ouvert/fermé d'un port TCP
  - Identification du service par numéro de port (base interne)
  - Banner grab best-effort (HTTP HEAD, lecture brute)
"""

import socket
import concurrent.futures
import logging

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Base de services connus
# ---------------------------------------------------------------------------

PORT_SERVICES: dict[int, str] = {
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    67:   "DHCP",
    80:   "HTTP",
    110:  "POP3",
    111:  "RPC",
    135:  "MSRPC",
    139:  "NetBIOS-SSN",
    143:  "IMAP",
    161:  "SNMP",
    389:  "LDAP",
    443:  "HTTPS",
    445:  "SMB",
    636:  "LDAPS",
    1433: "MSSQL",
    1521: "Oracle",
    2049: "NFS",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    9200: "Elasticsearch",
    27017:"MongoDB",
}


# ---------------------------------------------------------------------------
# Fonctions internes
# ---------------------------------------------------------------------------

def _is_port_open(ip: str, port: int, timeout: float) -> bool:
    """Vérifie si un port TCP est ouvert via connect_ex."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        return sock.connect_ex((ip, port)) == 0
    except Exception:
        return False
    finally:
        sock.close()


def _grab_banner(ip: str, port: int, timeout: float) -> str:
    """
    Tente de récupérer la bannière du service (best-effort).

    Envoie une requête HTTP HEAD pour les ports 80/8080,
    lit directement les données brutes pour les autres (SSH, FTP, SMTP…).

    Returns:
        Première ligne de la réponse (max 120 chars), ou chaîne vide.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))

        # Pour les ports HTTP, envoyer une requête HEAD
        if port in (80, 8080, 8443, 443):
            sock.sendall(b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")

        raw = sock.recv(512).decode("utf-8", errors="ignore").strip()
        sock.close()

        if raw:
            first_line = raw.split("\n")[0].strip()
            return first_line[:120]
        return ""
    except Exception:
        return ""


def _scan_single_port(ip: str, port: int, timeout: float) -> dict | None:
    """
    Scanne un port unique.

    Returns:
        Dict avec port, service et banner si ouvert ; None si fermé/filtré.
    """
    if not _is_port_open(ip, port, timeout):
        return None

    service = PORT_SERVICES.get(port, "Unknown")
    banner  = _grab_banner(ip, port, timeout)

    return {
        "port":    port,
        "service": service,
        "banner":  banner,
    }


# ---------------------------------------------------------------------------
# Fonction publique
# ---------------------------------------------------------------------------

def scan_ports(
    ip:          str,
    ports:       list[int],
    timeout:     float = 0.5,
    max_threads: int   = 100,
) -> list[dict]:
    """
    Scanne une liste de ports TCP sur une adresse IP cible.

    Les ports sont scannés en parallèle avec ThreadPoolExecutor.

    Args:
        ip          : Adresse IPv4 cible
        ports       : Liste des numéros de ports à tester
        timeout     : Délai par connexion en secondes (0.5 recommandé sur LAN)
        max_threads : Nombre maximum de threads concurrents

    Returns:
        Liste triée des ports ouverts :
        [{'port': 22, 'service': 'SSH', 'banner': 'SSH-2.0-OpenSSH_8.9'}, ...]
    """
    open_ports: list[dict] = []
    workers = min(max_threads, len(ports))

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(_scan_single_port, ip, port, timeout): port
            for port in ports
        }
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result is not None:
                open_ports.append(result)

    # Tri par numéro de port croissant
    open_ports.sort(key=lambda p: p["port"])
    return open_ports
