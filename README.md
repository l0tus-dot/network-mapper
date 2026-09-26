# 🗺️ Network Mapper

**Outil de découverte et cartographie de réseau local** — Python 3.10+

Scanne votre réseau via ARP, identifie chaque équipement (IP, MAC, hostname, fabricant),
et restitue les résultats dans le(s) format(s) de votre choix : **HTML interactif**, **JSON** ou **affichage terminal**.

---

## ✨ Fonctionnalités

| Feature | Détail |
|---|---|
| 🔍 Scan ARP | Découverte rapide via scapy (ou fallback ping sweep) |
| 🏷️ Hostname | Résolution DNS inverse (PTR) |
| 🏭 Fabricant | OUI Lookup via API macvendors.com + cache local |
| 🔓 Ports (optionnel) | Scan TCP concurrent avec détection de service et banner grab |
| 🗺️ Carte HTML | Graphe vis.js interactif avec noeuds cliquables |
| 📋 Tableau | Vue tabulaire triable avec recherche en temps réel |
| 📷 Export PNG | Capture du graphe en un clic |
| 📄 Export JSON | Données brutes structurées |
| 🖥️ Affichage terminal | Tableau coloré ANSI avec résumé par type et détail des ports |

---

## 📋 Prérequis

- Python **3.10+**
- Droits **Administrateur** (Windows) ou **root** (Linux)
- Sur **Windows** : [Npcap](https://npcap.com/#download) installé *(cocher "WinPcap API-compatible Mode")*

---

## 🚀 Installation

```bash
# 1. Cloner / télécharger le projet
cd network-mapper

# 2. Créer un environnement virtuel (recommandé)
python -m venv .venv

# Windows
.venv\Scripts\activate

# Linux / macOS
source .venv/bin/activate

# 3. Installer les dépendances
pip install -r requirements.txt
```

---

## 💻 Utilisation

### Mode de base — auto-détection du sous-réseau
```bash
# Windows (PowerShell Admin)
python scanner.py

# Linux (root)
sudo python scanner.py
```

### Spécifier le sous-réseau manuellement
```bash
python scanner.py -n 192.168.1.0/24
python scanner.py -n 10.0.0.0/24
```

### Activer le scan de ports
```bash
# Ports par défaut : 21,22,23,25,53,80,110,135,139,143,443,445,3306,3389,5900,8080,8443
python scanner.py --ports

# Ports personnalisés
python scanner.py --ports -p 22,80,443,3389,8080
```

### Choisir le format de sortie (`--format`)

Le résultat peut être affiché dans **un ou plusieurs formats simultanément**.

```bash
# HTML seul — cartographie interactive (comportement par défaut)
python scanner.py --format html

# JSON seul — export de données brutes
python scanner.py --format json

# Terminal seul — tableau coloré dans la console (aucun fichier créé)
python scanner.py --format terminal

# HTML + JSON simultanément
python scanner.py --format html json

# Les 3 formats en même temps
python scanner.py --format html json terminal
```

> 💡 **Conseil** : utilisez `--format terminal` pour une démonstration rapide en cours ou en stage sans ouvrir de navigateur.

### Combiner format, réseau et scan de ports
```bash
# Terminal avec scan de ports sur un sous-réseau précis
python scanner.py -n 192.168.1.0/24 --ports --format terminal

# Ports personnalisés + tous les formats
python scanner.py -n 192.168.1.0/24 --ports -p 22,80,443,3389 --format html json terminal

# JSON uniquement avec fichier de sortie personnalisé
python scanner.py --format json -j output/data.json
```

### Commande complète avec toutes les options
```bash
python scanner.py -n 192.168.1.0/24 --ports -p 22,80,443,3389 --format html json terminal -o output/rapport.html -j output/data.json -t 3.0 --port-timeout 0.3 --threads 150 -v
```

---

## ⚙️ Options

| Option | Défaut | Description |
|---|---|---|
| `--format` | `html` | Format(s) de sortie : `html`, `json`, `terminal` (combinables) |
| `-n`, `--network` | Auto | Plage CIDR (ex: `192.168.1.0/24`) |
| `--ports` | Désactivé | Active le scan de ports TCP |
| `-p`, `--port-list` | 17 ports | Ports personnalisés séparés par `,` |
| `-o`, `--output` | `output/map.html` | Fichier HTML de sortie |
| `-j`, `--json-output` | `output/data.json` | Fichier JSON de sortie |
| `-t`, `--timeout` | `2.0` | Timeout ARP en secondes |
| `--port-timeout` | `0.5` | Timeout par port TCP |
| `--threads` | `100` | Threads max pour le scan de ports |
| `-v`, `--verbose` | Désactivé | Logs détaillés (niveau DEBUG) |

---

## 📁 Structure du projet

```
network-mapper/
├── scanner.py                  <- Point d'entrée principal
├── requirements.txt
├── README.md
├── modules/
│   ├── __init__.py
│   ├── arp_scan.py             <- Scan ARP (scapy + fallback)
│   ├── host_resolver.py        <- Résolution DNS inverse
│   ├── oui_lookup.py           <- Fabricant via OUI (cache local)
│   ├── port_scanner.py         <- Scan TCP concurrent
│   ├── report_generator.py     <- Génération HTML (vis.js)
│   └── terminal_display.py     <- Affichage coloré dans le terminal
├── data/
│   └── oui_cache.json          <- Cache OUI auto-généré
└── output/
    ├── map.html                <- Cartographie HTML interactive
    └── data.json               <- Données brutes JSON
```

---

## 🗺️ Aperçu de la cartographie HTML

La carte générée contient :
- **Graphe interactif** (vis.js) : noeuds colorés par type, physique simulée
- **Clic sur un noeud** → panneau détails (IP, MAC, fabricant, ports ouverts)
- **Onglet Tableau** : vue tabulaire avec recherche en temps réel
- **Onglet Légende** : types d'équipements détectés
- **Export PNG** : capture du graphe en un clic
- **100 % autonome** : un seul fichier `.html`, pas de serveur requis

### Types d'équipements détectés automatiquement

| Icône | Type | Critères de détection |
|---|---|---|
| [GW] | Routeur/Gateway | IP `.1`, nom d'hôte (livebox, freebox...) |
| [SRV] | Serveur | SSH + ports web/DB ouverts |
| [WIN] | Windows | RDP (3389), SMB (445), RPC (135) |
| [LNX] | Linux | SSH (22) sans RDP |
| [NAS] | NAS | Fabricant ou hostname (Synology, QNAP...) |
| [PRN] | Imprimante | Fabricant (HP, Epson, Canon...) |
| [CAM] | Caméra IP | Fabricant ou hostname (Hikvision, Dahua...) |
| [MOB] | Mobile | Fabricant (Apple, Samsung, Xiaomi...) |
| [NET] | Switch/AP | Fabricant réseau (Cisco, Ubiquiti...) |
| [???] | Inconnu | Aucun critère correspondant |

---

## 🖥️ Aperçu de l'affichage terminal (`--format terminal`)

```
====================================================================================================
  NETWORK MAPPER  -  Resultats du scan
----------------------------------------------------------------------------------------------------
  Reseau : 192.168.1.0/24   Hotes : 6   Scan : 2026-09-26T23:57:33
  Ports scannes : 22, 80, 443, 445, 3389
====================================================================================================

----------------------------------------------------------------------------------------------------
 TYPE       | IP              | MAC                 | HOSTNAME                     | FABRICANT              | PORTS OUVERTS
----------------------------------------------------------------------------------------------------
 [GW]       | 192.168.1.1     | AA:BB:CC:11:22:33   | livebox.home                 | Orange SA              | -
 [WIN]      | 192.168.1.10    | B4:E6:2D:AA:BB:CC   | DESKTOP-RAPHAEL              | ASUSTeK Computer Inc.  | 3389/RDP  445/SMB
 [SRV]      | 192.168.1.20    | 3C:6A:A7:DD:EE:FF   | raspberrypi.local            | Raspberry Pi Trading   | 22/SSH  80/HTTP
 [MOB]      | 192.168.1.30    | F8:FF:C2:00:11:22   | iPhone-de-Raphael            | Apple, Inc.            | -
 [NAS]      | 192.168.1.45    | 00:11:32:AB:CD:EF   | DiskStation                  | Synology Inc.          | 80/HTTP  443/HTTPS
 [PRN]      | 192.168.1.55    | D4:3B:04:12:34:56   | HP-LaserJet-Pro              | Hewlett Packard        | 80/HTTP
----------------------------------------------------------------------------------------------------

  Resume par type
----------------------------------------------------------------------------------------------------
  [GW]   Routeur/Gateway     #...................  1
  [WIN]  Windows             #...................  1
  [SRV]  Serveur             #...................  1
  [MOB]  Mobile              #...................  1
  [NAS]  NAS                 #...................  1
  [PRN]  Imprimante          #...................  1
----------------------------------------------------------------------------------------------------

  Detail des ports ouverts
----------------------------------------------------------------------------------------------------
  [WIN] 192.168.1.10  (DESKTOP-RAPHAEL)
      3389   RDP
      445    SMB

  [SRV] 192.168.1.20  (raspberrypi.local)
      22     SSH              SSH-2.0-OpenSSH_9.2p1
      80     HTTP             HTTP/1.1 200 OK

  [NAS] 192.168.1.45  (DiskStation)
      80     HTTP
      443    HTTPS

  [PRN] 192.168.1.55  (HP-LaserJet-Pro)
      80     HTTP
----------------------------------------------------------------------------------------------------
```

---

## 🔒 Notes légales et éthiques

> ⚠️ **Scannez uniquement des réseaux dont vous avez l'autorisation.**
> Cet outil est conçu à des fins **éducatives** (cours, stage, lab personnel).
> L'utilisation sur des réseaux sans autorisation est **illégale**.

---

## 🔧 Dépannage

### Windows : `OSError` ou pas d'hôtes trouvés
→ Installez [Npcap](https://npcap.com/#download) et relancez en **Administrateur**.

### Linux : `Permission denied`
→ Relancez avec `sudo python scanner.py`.

### `scapy` non installé
→ Le script bascule automatiquement sur le mode **fallback** (ping sweep).
→ Pour de meilleurs résultats : `pip install scapy`.

### Fabricant = "Inconnu" pour tous les hôtes
→ Vous n'avez peut-être pas accès à Internet pour l'API OUI.
→ Le cache local (`data/oui_cache.json`) sera utilisé pour les prochains scans.
