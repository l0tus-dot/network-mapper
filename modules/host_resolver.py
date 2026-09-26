"""
modules/host_resolver.py
------------------------
Résolution des noms d'hôtes (DNS inverse / PTR).

Tente socket.gethostbyaddr() qui interroge le DNS local / mDNS.
Retourne l'IP si aucun enregistrement PTR n'existe.
"""

import socket
import logging

log = logging.getLogger(__name__)


def resolve_hostname(ip: str, timeout: float = 1.5) -> str:
    """
    Résout le nom d'hôte associé à une adresse IP via DNS inverse.

    Args:
        ip      : Adresse IPv4 cible (ex: '192.168.1.42')
        timeout : Délai maximal de résolution en secondes

    Returns:
        Nom d'hôte FQDN si trouvé, sinon l'adresse IP brute.
    """
    original_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror):
        # Pas d'enregistrement PTR → on retourne juste l'IP
        return ip
    except socket.timeout:
        log.debug(f"Timeout DNS inverse pour {ip}")
        return ip
    except Exception as e:
        log.debug(f"Erreur résolution hostname pour {ip} : {e}")
        return ip
    finally:
        socket.setdefaulttimeout(original_timeout)
