"""
modules/terminal_display.py
---------------------------
Affichage formaté des résultats du scan directement dans le terminal.

Utilise uniquement des caractères Unicode standards et des codes ANSI
pour la couleur — aucune dépendance externe requise.

Compatible Windows (PowerShell / Windows Terminal) et Linux/macOS.
"""

import os
import platform
import sys
import logging

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Activation des codes ANSI sous Windows
# ---------------------------------------------------------------------------

def _enable_ansi_windows() -> bool:
    """Active le mode VT100/ANSI dans la console Windows si possible."""
    if platform.system() != "Windows":
        return True
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        # ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
        return True
    except Exception:
        return False

_ANSI_SUPPORTED = _enable_ansi_windows()

# ---------------------------------------------------------------------------
# Palette de couleurs ANSI
# ---------------------------------------------------------------------------

class C:
    """Constantes de couleurs ANSI."""
    RESET  = "\033[0m"   if _ANSI_SUPPORTED else ""
    BOLD   = "\033[1m"   if _ANSI_SUPPORTED else ""
    DIM    = "\033[2m"   if _ANSI_SUPPORTED else ""

    # Couleurs texte
    RED    = "\033[91m"  if _ANSI_SUPPORTED else ""
    GREEN  = "\033[92m"  if _ANSI_SUPPORTED else ""
    YELLOW = "\033[93m"  if _ANSI_SUPPORTED else ""
    BLUE   = "\033[94m"  if _ANSI_SUPPORTED else ""
    MAGENTA= "\033[95m"  if _ANSI_SUPPORTED else ""
    CYAN   = "\033[96m"  if _ANSI_SUPPORTED else ""
    WHITE  = "\033[97m"  if _ANSI_SUPPORTED else ""
    GRAY   = "\033[90m"  if _ANSI_SUPPORTED else ""

    # Couleurs fond
    BG_DARK = "\033[48;5;235m" if _ANSI_SUPPORTED else ""


# ---------------------------------------------------------------------------
# Mapping type → couleur + icône (terminal)
# ---------------------------------------------------------------------------

DEVICE_TERMINAL_STYLE: dict[str, dict] = {
    "router":  {"color": C.RED,     "icon": "[GW]",  "label": "Routeur/Gateway"},
    "server":  {"color": C.BLUE,    "icon": "[SRV]", "label": "Serveur"},
    "windows": {"color": C.CYAN,    "icon": "[WIN]", "label": "Windows"},
    "linux":   {"color": C.YELLOW,  "icon": "[LNX]", "label": "Linux"},
    "nas":     {"color": C.MAGENTA, "icon": "[NAS]", "label": "NAS"},
    "printer": {"color": C.GREEN,   "icon": "[PRN]", "label": "Imprimante"},
    "camera":  {"color": C.RED,     "icon": "[CAM]", "label": "Camera IP"},
    "phone":   {"color": C.GREEN,   "icon": "[MOB]", "label": "Mobile"},
    "switch":  {"color": C.GRAY,    "icon": "[NET]", "label": "Switch/AP"},
    "unknown": {"color": C.GRAY,    "icon": "[???]", "label": "Inconnu"},
}

# Import local pour réutiliser la détection de type
try:
    from modules.report_generator import _detect_device_type
except ImportError:
    from report_generator import _detect_device_type


# ---------------------------------------------------------------------------
# Helpers d'affichage
# ---------------------------------------------------------------------------

def _get_terminal_width() -> int:
    try:
        return os.get_terminal_size().columns
    except Exception:
        return 100


def _hr(char: str = "-", width: int | None = None) -> str:
    w = width or _get_terminal_width()
    return C.GRAY + char * w + C.RESET


def _col(text: str, width: int, align: str = "<") -> str:
    """Tronque et aligne du texte dans une colonne de largeur fixe."""
    plain = _strip_ansi(text)
    if len(plain) > width:
        visible = width - 1
        # Reconstruire en coupant le texte brut
        text = text[:visible] + C.GRAY + "…" + C.RESET
    # Calculer le padding en tenant compte des codes ANSI invisibles
    padding = width - len(_strip_ansi(text))
    if align == ">":
        return " " * padding + text
    elif align == "^":
        lpad = padding // 2
        rpad = padding - lpad
        return " " * lpad + text + " " * rpad
    else:
        return text + " " * padding


def _strip_ansi(text: str) -> str:
    """Supprime les codes ANSI d'une chaîne pour calculer sa largeur réelle."""
    import re
    return re.sub(r'\033\[[0-9;]*m', '', text)


# ---------------------------------------------------------------------------
# Affichage principal
# ---------------------------------------------------------------------------

def display_results(hosts: list[dict], metadata: dict) -> None:
    """
    Affiche les résultats du scan de manière formatée dans le terminal.

    Args:
        hosts    : Liste des hôtes enrichis
        metadata : Métadonnées du scan
    """
    w = min(_get_terminal_width(), 120)

    # -- En-tête ---------------------------------------------------------
    print()
    print(_hr("=", w))
    title = "  NETWORK MAPPER  -  Resultats du scan"
    print(C.BOLD + C.WHITE + title + C.RESET)
    print(_hr("-", w))
    print(
        f"  {C.CYAN}Reseau{C.RESET}      : {C.WHITE}{metadata.get('network','—')}{C.RESET}   "
        f"{C.CYAN}Hotes{C.RESET} : {C.GREEN}{C.BOLD}{len(hosts)}{C.RESET}   "
        f"{C.CYAN}Scan{C.RESET} : {C.GRAY}{metadata.get('scan_time','')}{C.RESET}"
    )
    if metadata.get("ports_scanned"):
        pl = metadata.get("port_list", [])
        print(f"  {C.CYAN}Ports scannes{C.RESET} : {C.GRAY}{', '.join(map(str,pl))}{C.RESET}")
    print(_hr("=", w))
    print()

    if not hosts:
        print(C.YELLOW + "  Aucun équipement découvert." + C.RESET)
        return

    # -- Largeurs de colonnes ---------------------------------------------
    # [TYPE] [IP] [MAC] [HOSTNAME] [FABRICANT] [PORTS]
    C_TYPE   = 10
    C_IP     = 15
    C_MAC    = 19
    C_HOST   = 28
    C_VENDOR = 22
    # Le reste va aux ports

    # En-tête du tableau
    _print_table_header(C_TYPE, C_IP, C_MAC, C_HOST, C_VENDOR, w)

    # -- Lignes du tableau ------------------------------------------------
    for host in hosts:
        _print_host_row(host, C_TYPE, C_IP, C_MAC, C_HOST, C_VENDOR, w)

    print(_hr("-", w))
    print()

    # -- Resume par type
    _print_type_summary(hosts, w)

    # -- Details des ports (si scan effectue)
    if metadata.get("ports_scanned"):
        _print_ports_detail(hosts, w)



def _print_table_header(c_type, c_ip, c_mac, c_host, c_vendor, w):
    sep = C.GRAY + " | " + C.RESET
    header = (
        C.BOLD + C.WHITE
        + _col("TYPE",      c_type)   + sep
        + _col("IP",        c_ip)     + sep
        + _col("MAC",       c_mac)    + sep
        + _col("HOSTNAME",  c_host)   + sep
        + _col("FABRICANT", c_vendor) + sep
        + "PORTS OUVERTS"
        + C.RESET
    )
    print(_hr("-", w))
    print(" " + header)
    print(_hr("-", w))


def _print_host_row(host, c_type, c_ip, c_mac, c_host, c_vendor, w):
    dtype  = _detect_device_type(host)
    style  = DEVICE_TERMINAL_STYLE.get(dtype, DEVICE_TERMINAL_STYLE["unknown"])
    color  = style["color"]
    icon   = style["icon"]
    label  = style["label"]

    ip       = host.get("ip", "")
    mac      = host.get("mac", "")
    hostname = host.get("hostname", ip)
    vendor   = host.get("manufacturer", "Inconnu")
    ports    = host.get("open_ports", [])

    # Formatage des ports ouverts
    if ports:
        ports_str = C.GREEN + "  ".join(
            f"{p['port']}/{p['service']}" for p in ports
        ) + C.RESET
    else:
        ports_str = C.GRAY + "—" + C.RESET

    # Tronquer hostname si trop long
    if len(hostname) > c_host - 1 and hostname != ip:
        hostname_display = hostname[:c_host - 2] + "…"
    else:
        hostname_display = hostname

    sep = C.GRAY + " | " + C.RESET
    type_cell   = color + C.BOLD + _col(icon,             c_type)  + C.RESET
    ip_cell     = C.WHITE        + _col(ip,               c_ip)
    mac_cell    = C.GRAY         + _col(mac,              c_mac)    + C.RESET
    host_cell   = C.WHITE        + _col(hostname_display, c_host)   + C.RESET
    vendor_cell = C.GRAY         + _col(vendor,           c_vendor) + C.RESET

    print(" " + type_cell + sep + ip_cell + sep + mac_cell + sep + host_cell + sep + vendor_cell + sep + ports_str)


def _print_type_summary(hosts: list[dict], w: int) -> None:
    """Affiche un résumé par type d'équipement."""
    from collections import Counter
    type_counts: Counter = Counter()
    for host in hosts:
        dtype = _detect_device_type(host)
        type_counts[dtype] += 1

    print(C.BOLD + C.WHITE + "  Resume par type" + C.RESET)
    print(_hr("-", w))

    for dtype, count in type_counts.most_common():
        style = DEVICE_TERMINAL_STYLE.get(dtype, DEVICE_TERMINAL_STYLE["unknown"])
        bar   = style["color"] + "#" * count + C.GRAY + "." * (20 - count) + C.RESET
        label = style["label"]
        icon  = style["icon"]
        print(f"  {style['color']}{C.BOLD}{icon}{C.RESET}  {label:<18}  {bar}  {C.WHITE}{count}{C.RESET}")

    print(_hr("-", w))
    print()


def _print_ports_detail(hosts: list[dict], w: int) -> None:
    """Affiche le détail des ports ouverts par hôte (si scan de ports activé)."""
    hosts_with_ports = [h for h in hosts if h.get("open_ports")]
    if not hosts_with_ports:
        print(C.GRAY + "  Aucun port ouvert trouvé." + C.RESET)
        return

    print(C.BOLD + C.WHITE + "  Detail des ports ouverts" + C.RESET)
    print(_hr("-", w))

    for host in hosts_with_ports:
        dtype = _detect_device_type(host)
        style = DEVICE_TERMINAL_STYLE.get(dtype, DEVICE_TERMINAL_STYLE["unknown"])
        ip    = host.get("ip", "")
        hn    = host.get("hostname", ip)

        print(f"  {style['color']}{C.BOLD}{style['icon']}{C.RESET} {C.WHITE}{ip}{C.RESET}  {C.GRAY}({hn}){C.RESET}")

        for port_info in host.get("open_ports", []):
            port    = port_info["port"]
            service = port_info["service"]
            banner  = port_info.get("banner", "")

            banner_str = f"  {C.GRAY}{banner[:60]}{C.RESET}" if banner else ""
            print(f"      {C.GREEN}{port:<6}{C.RESET} {C.CYAN}{service:<15}{C.RESET}{banner_str}")

        print()

    print(_hr("-", w))
