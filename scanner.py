#!/usr/bin/env python3
"""
scanner.py – Network Mapper · Point d'entrée principal
======================================================

Découvre tous les équipements actifs sur un réseau local via ARP,
enrichit les données (hostname, fabricant OUI, ports ouverts),
puis génère une cartographie interactive en HTML et exporte les données en JSON.

Usage :
  python scanner.py                              # Auto-détection du sous-réseau
  python scanner.py -n 192.168.1.0/24            # Sous-réseau spécifié manuellement
  python scanner.py --ports                      # + scan de ports (17 ports courants)
  python scanner.py --ports -p 22,80,443,3389    # + liste de ports personnalisée
  python scanner.py -n 10.0.0.0/24 --ports -o rapport.html
"""

import argparse
import json
import sys
import os
import logging
from datetime import datetime

# --- Imports des modules locaux ---
from modules.arp_scan       import arp_scan, get_local_subnet
from modules.host_resolver  import resolve_hostname
from modules.oui_lookup     import get_manufacturer
from modules.port_scanner   import scan_ports
from modules.report_generator import generate_html_report

# ---------------------------------------------------------------------------
# Configuration du logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)-8s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Ports scannés par défaut (option --ports sans -p)
# ---------------------------------------------------------------------------

DEFAULT_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 135,
    139, 143, 443, 445, 3306, 3389, 5900, 8080, 8443,
]


# ---------------------------------------------------------------------------
# Arguments CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="scanner.py",
        description="🗺️  Network Mapper – Cartographie de réseau local",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples :
  python scanner.py
  python scanner.py -n 192.168.1.0/24
  python scanner.py --ports
  python scanner.py -n 10.0.0.0/24 --ports -p 22,80,443,3389 -o map.html
        """,
    )

    # Réseau cible
    parser.add_argument(
        "-n", "--network",
        metavar="CIDR",
        default=None,
        help="Sous-réseau cible (ex: 192.168.1.0/24). Auto-détecté si absent.",
    )

    # Scan de ports
    parser.add_argument(
        "--ports",
        action="store_true",
        default=False,
        help="Activer le scan de ports TCP (désactivé par défaut).",
    )
    parser.add_argument(
        "-p", "--port-list",
        metavar="PORTS",
        default=None,
        help=f"Ports à scanner, séparés par des virgules (défaut: {DEFAULT_PORTS}).",
    )

    # Sorties
    parser.add_argument(
        "-o", "--output",
        metavar="FICHIER",
        default="output/map.html",
        help="Fichier HTML de sortie (défaut: output/map.html).",
    )
    parser.add_argument(
        "-j", "--json-output",
        metavar="FICHIER",
        default="output/data.json",
        help="Fichier JSON de sortie (défaut: output/data.json).",
    )

    # Timeouts et performance
    parser.add_argument(
        "-t", "--timeout",
        metavar="SEC",
        type=float,
        default=2.0,
        help="Timeout du scan ARP en secondes (défaut: 2.0).",
    )
    parser.add_argument(
        "--port-timeout",
        metavar="SEC",
        type=float,
        default=0.5,
        help="Timeout par port TCP en secondes (défaut: 0.5).",
    )
    parser.add_argument(
        "--threads",
        metavar="N",
        type=int,
        default=100,
        help="Threads max pour le scan de ports (défaut: 100).",
    )

    # Verbosité
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Activer le mode verbeux (logs DEBUG).",
    )

    return parser.parse_args()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _banner() -> None:
    print()
    print("╔══════════════════════════════════════════════════════╗")
    print("║         🗺️   N e t w o r k   M a p p e r            ║")
    print("║        Cartographie de réseau local – v1.0           ║")
    print("╚══════════════════════════════════════════════════════╝")
    print()


def _step(n: int, total: int, msg: str) -> None:
    log.info(f"[{n}/{total}] {msg}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    args = parse_args()
    _banner()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    TOTAL_STEPS = 5 if args.ports else 4

    # ── Étape 1 : Sous-réseau ──────────────────────────────────────────────
    _step(1, TOTAL_STEPS, "Détermination du sous-réseau…")

    if args.network:
        target_network = args.network
        log.info(f"  Sous-réseau (manuel) : {target_network}")
    else:
        target_network = get_local_subnet()
        if not target_network:
            log.error(
                "Impossible de détecter le sous-réseau automatiquement.\n"
                "  → Utilisez -n CIDR (ex: -n 192.168.1.0/24)"
            )
            sys.exit(1)
        log.info(f"  Sous-réseau détecté  : {target_network}")

    # ── Étape 2 : Scan ARP ────────────────────────────────────────────────
    _step(2, TOTAL_STEPS, f"Scan ARP sur {target_network} (timeout: {args.timeout}s)…")
    hosts = arp_scan(target_network, timeout=args.timeout)

    if not hosts:
        log.warning(
            "Aucun équipement trouvé.\n"
            "  → Vérifiez vos droits admin/root.\n"
            "  → Sur Windows, assurez-vous que Npcap est installé (https://npcap.com)."
        )
        sys.exit(0)

    log.info(f"  ✅ {len(hosts)} équipement(s) découvert(s)")

    # ── Étape 3 : Enrichissement (hostname + fabricant) ───────────────────
    _step(3, TOTAL_STEPS, f"Enrichissement de {len(hosts)} hôte(s)…")

    for i, host in enumerate(hosts, 1):
        ip  = host["ip"]
        mac = host["mac"]

        hostname     = resolve_hostname(ip)
        manufacturer = get_manufacturer(mac)

        host["hostname"]     = hostname
        host["manufacturer"] = manufacturer
        host["open_ports"]   = []

        log.debug(f"  [{i:>2}/{len(hosts)}] {ip} → {hostname} | {manufacturer}")

    # ── Étape 4 : Scan de ports (optionnel) ───────────────────────────────
    if args.ports:
        port_list = (
            [int(p.strip()) for p in args.port_list.split(",")]
            if args.port_list
            else DEFAULT_PORTS
        )
        _step(4, TOTAL_STEPS, f"Scan de ports ({len(port_list)} ports, {args.threads} threads)…")
        log.info(f"  Ports ciblés : {port_list}")

        for i, host in enumerate(hosts, 1):
            log.info(f"  [{i:>2}/{len(hosts)}] Scan de {host['ip']}…")
            open_ports = scan_ports(
                host["ip"],
                ports=port_list,
                timeout=args.port_timeout,
                max_threads=args.threads,
            )
            host["open_ports"] = open_ports
            if open_ports:
                found = ", ".join(f"{p['port']}/{p['service']}" for p in open_ports)
                log.info(f"           Ports ouverts : {found}")

    # ── Métadonnées du scan ────────────────────────────────────────────────
    active_port_list = (
        ([int(p.strip()) for p in args.port_list.split(",")]
         if args.port_list else DEFAULT_PORTS)
        if args.ports else []
    )
    metadata = {
        "network":       target_network,
        "scan_time":     datetime.now().isoformat(),
        "total_hosts":   len(hosts),
        "ports_scanned": args.ports,
        "port_list":     active_port_list,
    }

    # ── Étape finale : Export JSON + HTML ─────────────────────────────────
    _step(TOTAL_STEPS, TOTAL_STEPS, "Export des résultats…")

    # JSON
    os.makedirs(os.path.dirname(args.json_output) or ".", exist_ok=True)
    with open(args.json_output, "w", encoding="utf-8") as f:
        json.dump({"metadata": metadata, "hosts": hosts}, f, indent=2, ensure_ascii=False)
    log.info(f"  📄 JSON  : {os.path.abspath(args.json_output)}")

    # HTML
    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    generate_html_report(hosts, metadata, args.output)
    log.info(f"  🌐 HTML  : {os.path.abspath(args.output)}")

    # ── Résumé final ──────────────────────────────────────────────────────
    print()
    print("╔══════════════════════════════════════════════════════╗")
    print(f"║  ✅ Scan terminé  –  {len(hosts)} équipement(s) trouvé(s)")
    print(f"║  📄 JSON  : {os.path.abspath(args.json_output)}")
    print(f"║  🌐 HTML  : {os.path.abspath(args.output)}")
    print("╚══════════════════════════════════════════════════════╝")
    print()


if __name__ == "__main__":
    main()
