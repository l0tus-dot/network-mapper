"""
modules/report_generator.py
---------------------------
Génère une cartographie réseau interactive en HTML autonome (self-contained).

Visualisation : vis.js Network (chargé via CDN jsDelivr)
  - Graphe interactif avec nœuds cliquables
  - Icônes et couleurs selon le type détecté d'équipement
  - Panneau de détails au clic (IP, MAC, fabricant, hostname, ports)
  - Tableau récapitulatif triable sous le graphe
  - Recherche / filtre en temps réel
  - Export PNG du graphe
  - 100 % autonome : un seul fichier .html à ouvrir dans un navigateur
"""

import json
import os
import logging
from datetime import datetime

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Détection du type d'équipement
# ---------------------------------------------------------------------------

def _detect_device_type(host: dict) -> str:
    """
    Détermine le type probable d'équipement d'après ses ports ouverts,
    son hostname et son fabricant.

    Returns:
        Clé de type parmi : 'router', 'server', 'windows', 'linux',
        'printer', 'camera', 'phone', 'nas', 'switch', 'unknown'
    """
    ports    = {p["port"] for p in host.get("open_ports", [])}
    hostname = host.get("hostname", "").lower()
    vendor   = host.get("manufacturer", "").lower()

    # --- Logique de détection par priorité décroissante ---

    # Routeur / passerelle (généralement la .1)
    if host.get("ip", "").endswith(".1") or "router" in hostname or "gateway" in hostname or "bbox" in hostname or "livebox" in hostname or "freebox" in hostname:
        return "router"

    # NAS
    if any(k in hostname for k in ("nas", "synology", "qnap", "readynas", "drobo")) or \
       any(k in vendor   for k in ("synology", "qnap", "netgear")):
        return "nas"

    # Imprimante
    if any(k in hostname for k in ("print", "printer", "hp-", "canon", "epson", "ricoh", "brother")) or \
       any(k in vendor   for k in ("hewlett", "canon", "epson", "ricoh", "brother", "lexmark", "xerox")):
        return "printer"

    # Caméra IP / NVR
    if any(k in hostname for k in ("cam", "ipcam", "nvr", "dvr", "hikvision", "dahua")) or \
       any(k in vendor   for k in ("hikvision", "dahua", "axis", "hanwha", "reolink")):
        return "camera"

    # Switch / AP réseau
    if any(k in vendor for k in ("cisco", "ubiquiti", "netgear", "tp-link", "zyxel", "juniper", "aruba", "mikrotik")):
        return "switch"

    # Téléphone / mobile
    if any(k in vendor for k in ("apple", "samsung", "huawei", "xiaomi", "oneplus", "oppo", "vivo", "realme")) or \
       any(k in hostname for k in ("iphone", "android", "galaxy", "pixel")):
        return "phone"

    # Serveur Linux (SSH sans RDP, ou ports typiques)
    if 22 in ports and 3389 not in ports:
        if any(p in ports for p in (80, 443, 8080, 3306, 5432, 6379, 27017, 9200)):
            return "server"
        return "linux"

    # Machine Windows (RDP)
    if 3389 in ports or 135 in ports or 445 in ports:
        return "windows"

    # Serveur web générique
    if any(p in ports for p in (80, 443, 8080, 8443)):
        return "server"

    return "unknown"


# ---------------------------------------------------------------------------
# Thème visuel : couleur + emoji Unicode par type
# ---------------------------------------------------------------------------

DEVICE_STYLE: dict[str, dict] = {
    "router":  {"color": "#e74c3c", "border": "#c0392b", "icon": "🌐", "label": "Routeur / Gateway"},
    "server":  {"color": "#2980b9", "border": "#1a5276", "icon": "🖥️",  "label": "Serveur"},
    "windows": {"color": "#0078d4", "border": "#004578", "icon": "🪟", "label": "Windows"},
    "linux":   {"color": "#f39c12", "border": "#b7770d", "icon": "🐧", "label": "Linux"},
    "nas":     {"color": "#8e44ad", "border": "#6c3483", "icon": "💾", "label": "NAS"},
    "printer": {"color": "#16a085", "border": "#0e6655", "icon": "🖨️",  "label": "Imprimante"},
    "camera":  {"color": "#c0392b", "border": "#922b21", "icon": "📷", "label": "Caméra IP"},
    "phone":   {"color": "#27ae60", "border": "#1e8449", "icon": "📱", "label": "Mobile"},
    "switch":  {"color": "#7f8c8d", "border": "#626567", "icon": "🔀", "label": "Switch / AP"},
    "unknown": {"color": "#95a5a6", "border": "#717d7e", "icon": "❓", "label": "Inconnu"},
}


# ---------------------------------------------------------------------------
# Construction des nœuds et arêtes vis.js
# ---------------------------------------------------------------------------

def _build_graph_data(hosts: list[dict], metadata: dict) -> dict:
    """Construit les structures nodes/edges pour vis.js Network."""
    nodes = []
    edges = []

    # Nœud central = le réseau / sous-réseau
    network_label = metadata.get("network", "Réseau Local")
    nodes.append({
        "id":    0,
        "label": f"🗺️ {network_label}",
        "color": {"background": "#2c3e50", "border": "#1a252f", "highlight": {"background": "#34495e", "border": "#1a252f"}},
        "font":  {"color": "#ffffff", "size": 16, "bold": True},
        "shape": "ellipse",
        "size":  40,
        "title": f"Réseau : {network_label}<br>Scan : {metadata.get('scan_time', '')}<br>Hôtes : {len(hosts)}",
        "fixed": True,
        "x": 0,
        "y": 0,
    })

    for i, host in enumerate(hosts, start=1):
        dtype  = _detect_device_type(host)
        style  = DEVICE_STYLE.get(dtype, DEVICE_STYLE["unknown"])
        ports  = host.get("open_ports", [])
        ip     = host.get("ip", "")
        mac    = host.get("mac", "")
        hn     = host.get("hostname", ip)
        vendor = host.get("manufacturer", "Inconnu")

        # Tooltip HTML affiché au survol
        ports_html = ""
        if ports:
            port_rows = "".join(
                f"<tr><td><b>{p['port']}</b></td><td>{p['service']}</td><td style='color:#aaa;font-size:11px'>{p.get('banner','')[:50]}</td></tr>"
                for p in ports
            )
            ports_html = f"<br><table style='border-collapse:collapse;margin-top:4px'><tr style='color:#7f8c8d'><th>Port</th><th>Service</th><th>Bannière</th></tr>{port_rows}</table>"

        tooltip = (
            f"<div style='font-family:monospace;font-size:13px;max-width:380px'>"
            f"<b style='font-size:15px'>{style['icon']} {hn}</b><br>"
            f"<hr style='border-color:#444;margin:4px 0'>"
            f"<b>IP :</b> {ip}<br>"
            f"<b>MAC :</b> {mac}<br>"
            f"<b>Fabricant :</b> {vendor}<br>"
            f"<b>Type :</b> {style['label']}"
            f"{ports_html}"
            f"</div>"
        )

        # Étiquette courte sous le nœud
        short_label = hn if hn != ip else ip
        if len(short_label) > 20:
            short_label = short_label[:18] + "…"
        node_label = f"{style['icon']}\n{short_label}\n{ip}"

        nodes.append({
            "id":    i,
            "label": node_label,
            "title": tooltip,
            "color": {
                "background": style["color"],
                "border":     style["border"],
                "highlight":  {"background": style["color"], "border": "#ffffff"},
            },
            "font":  {"color": "#ffffff", "size": 13, "multi": True},
            "shape": "box",
            "margin": 8,
            # Métadonnées pour le panneau latéral (pas affichées par vis.js)
            "_meta": {
                "ip":       ip,
                "mac":      mac,
                "hostname": hn,
                "vendor":   vendor,
                "dtype":    dtype,
                "dlabel":   style["label"],
                "icon":     style["icon"],
                "ports":    ports,
            },
        })

        edges.append({"from": 0, "to": i, "color": {"color": style["color"], "opacity": 0.7}})

    return {"nodes": nodes, "edges": edges}


# ---------------------------------------------------------------------------
# Template HTML (self-contained)
# ---------------------------------------------------------------------------

_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Network Mapper – {network}</title>

  <!-- vis.js Network via CDN jsDelivr -->
  <script src="https://cdn.jsdelivr.net/npm/vis-network@9.1.9/standalone/umd/vis-network.min.js"></script>

  <style>
    /* ── Reset & variables ─────────────────────────────────── */
    :root {{
      --bg:       #0f1117;
      --surface:  #1a1d27;
      --surface2: #22273a;
      --border:   #2d3250;
      --text:     #e2e8f0;
      --text2:    #94a3b8;
      --accent:   #6366f1;
      --accent2:  #818cf8;
      --green:    #22d3a6;
      --red:      #f87171;
      --yellow:   #fbbf24;
    }}
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      background: var(--bg);
      color: var(--text);
      font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
      font-size: 14px;
      min-height: 100vh;
    }}

    /* ── Header ────────────────────────────────────────────── */
    header {{
      background: linear-gradient(135deg, #1e1b4b 0%, #312e81 100%);
      padding: 16px 28px;
      display: flex;
      align-items: center;
      gap: 16px;
      border-bottom: 1px solid var(--border);
      flex-wrap: wrap;
    }}
    header h1 {{
      font-size: 1.4rem;
      font-weight: 700;
      letter-spacing: -.3px;
    }}
    header h1 span {{ color: var(--accent2); }}
    .meta-pills {{
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
      margin-left: auto;
    }}
    .pill {{
      background: rgba(99,102,241,.18);
      border: 1px solid rgba(99,102,241,.4);
      border-radius: 20px;
      padding: 3px 12px;
      font-size: 12px;
      color: var(--accent2);
      white-space: nowrap;
    }}

    /* ── Layout principal ──────────────────────────────────── */
    .main-layout {{
      display: flex;
      height: calc(100vh - 64px);
    }}

    /* ── Graphe ────────────────────────────────────────────── */
    #graph-container {{
      flex: 1;
      position: relative;
      background: radial-gradient(ellipse at center, #1a1d27 0%, #0f1117 100%);
    }}
    #network-graph {{
      width: 100%;
      height: 100%;
    }}
    .graph-controls {{
      position: absolute;
      top: 12px;
      left: 12px;
      display: flex;
      flex-direction: column;
      gap: 6px;
      z-index: 10;
    }}
    .ctrl-btn {{
      background: var(--surface);
      border: 1px solid var(--border);
      color: var(--text2);
      width: 36px;
      height: 36px;
      border-radius: 8px;
      font-size: 16px;
      cursor: pointer;
      display: grid;
      place-items: center;
      transition: background .15s, color .15s, border-color .15s;
    }}
    .ctrl-btn:hover {{ background: var(--accent); color: #fff; border-color: var(--accent); }}

    /* ── Panneau latéral ───────────────────────────────────── */
    #side-panel {{
      width: 340px;
      background: var(--surface);
      border-left: 1px solid var(--border);
      display: flex;
      flex-direction: column;
      overflow: hidden;
    }}
    .panel-tabs {{
      display: flex;
      border-bottom: 1px solid var(--border);
    }}
    .tab-btn {{
      flex: 1;
      padding: 11px 6px;
      background: none;
      border: none;
      color: var(--text2);
      font-size: 13px;
      cursor: pointer;
      border-bottom: 2px solid transparent;
      transition: color .15s, border-color .15s;
    }}
    .tab-btn.active {{
      color: var(--accent2);
      border-bottom-color: var(--accent2);
      font-weight: 600;
    }}
    .tab-content {{ display: none; flex: 1; overflow-y: auto; }}
    .tab-content.active {{ display: flex; flex-direction: column; }}

    /* Onglet Détails */
    #detail-placeholder {{
      flex: 1;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      color: var(--text2);
      gap: 10px;
      padding: 20px;
      text-align: center;
    }}
    #detail-placeholder .big-icon {{ font-size: 3rem; opacity: .4; }}
    #device-detail {{ padding: 20px; flex: 1; }}
    .device-header {{
      display: flex;
      align-items: center;
      gap: 12px;
      margin-bottom: 18px;
    }}
    .device-icon {{ font-size: 2.4rem; }}
    .device-name  {{ font-size: 1rem; font-weight: 700; word-break: break-all; }}
    .device-type  {{ font-size: 11px; color: var(--text2); margin-top: 2px; }}
    .info-grid {{
      display: grid;
      grid-template-columns: auto 1fr;
      gap: 6px 14px;
      margin-bottom: 16px;
    }}
    .info-label {{ color: var(--text2); font-size: 12px; white-space: nowrap; }}
    .info-value {{ font-family: monospace; font-size: 13px; word-break: break-all; }}
    .section-title {{
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: .8px;
      color: var(--text2);
      margin-bottom: 8px;
      margin-top: 16px;
      border-bottom: 1px solid var(--border);
      padding-bottom: 4px;
    }}
    .port-row {{
      display: flex;
      align-items: baseline;
      gap: 8px;
      padding: 5px 0;
      border-bottom: 1px solid rgba(255,255,255,.05);
      font-size: 13px;
    }}
    .port-number {{ color: var(--accent2); font-family: monospace; font-weight: 700; min-width: 38px; }}
    .port-service {{ color: var(--green); flex: 1; }}
    .port-banner  {{ color: var(--text2); font-size: 11px; font-style: italic; word-break: break-all; }}
    .no-ports     {{ color: var(--text2); font-size: 13px; font-style: italic; }}

    /* Onglet Tableau */
    #tab-table .search-bar {{
      padding: 10px 12px;
      border-bottom: 1px solid var(--border);
    }}
    #tab-table .search-bar input {{
      width: 100%;
      background: var(--surface2);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 7px 10px;
      color: var(--text);
      font-size: 13px;
      outline: none;
    }}
    #tab-table .search-bar input:focus {{ border-color: var(--accent); }}
    .host-table {{ width: 100%; border-collapse: collapse; }}
    .host-table th, .host-table td {{
      padding: 8px 10px;
      text-align: left;
      border-bottom: 1px solid var(--border);
      font-size: 12px;
      white-space: nowrap;
    }}
    .host-table th {{ color: var(--text2); font-weight: 600; position: sticky; top: 0; background: var(--surface); z-index: 1; }}
    .host-table tr:hover td {{ background: var(--surface2); cursor: pointer; }}
    .host-table .type-badge {{
      border-radius: 4px;
      padding: 2px 6px;
      font-size: 11px;
      font-weight: 600;
    }}

    /* Onglet Légende */
    #tab-legend .legend-list {{ padding: 14px; }}
    .legend-item {{
      display: flex;
      align-items: center;
      gap: 10px;
      padding: 8px;
      border-radius: 8px;
      margin-bottom: 4px;
    }}
    .legend-item:hover {{ background: var(--surface2); }}
    .legend-dot {{
      width: 14px;
      height: 14px;
      border-radius: 50%;
      flex-shrink: 0;
      border: 2px solid rgba(255,255,255,.3);
    }}
    .legend-icon  {{ font-size: 1.2rem; }}
    .legend-label {{ font-size: 13px; }}
    .legend-count {{ margin-left: auto; color: var(--text2); font-size: 12px; }}

    /* ── Tableau inférieur (optionnel, masqué par défaut) ─── */
    #bottom-bar {{
      position: fixed;
      bottom: 0;
      left: 0;
      right: 0;
      background: var(--surface);
      border-top: 1px solid var(--border);
      padding: 6px 20px;
      font-size: 12px;
      color: var(--text2);
      display: flex;
      align-items: center;
      gap: 16px;
      z-index: 100;
    }}
    #bottom-bar .status-dot {{
      width: 8px; height: 8px;
      border-radius: 50%;
      background: var(--green);
      animation: pulse 2s infinite;
    }}
    @keyframes pulse {{
      0%,100% {{ opacity: 1; }}
      50%       {{ opacity: .3; }}
    }}

    /* ── Scrollbar ─────────────────────────────────────────── */
    ::-webkit-scrollbar {{ width: 5px; }}
    ::-webkit-scrollbar-track {{ background: transparent; }}
    ::-webkit-scrollbar-thumb {{ background: var(--border); border-radius: 3px; }}
  </style>
</head>
<body>

<header>
  <div>🗺️ &nbsp;<span style="font-size:1.5rem">&#127760;</span></div>
  <div>
    <h1>Network <span>Mapper</span></h1>
    <div style="color:var(--text2);font-size:12px">Cartographie de réseau local</div>
  </div>
  <div class="meta-pills">
    <span class="pill">📡 {network}</span>
    <span class="pill">🖥️ {total_hosts} hôte(s)</span>
    <span class="pill">🕐 {scan_time}</span>
    {ports_pill}
  </div>
</header>

<div class="main-layout">

  <!-- ── Graphe ─────────────────────────────────────────────── -->
  <div id="graph-container">
    <div id="network-graph"></div>

    <div class="graph-controls">
      <button class="ctrl-btn" title="Zoom +" onclick="network.moveTo({{scale: network.getScale()*1.3}})">+</button>
      <button class="ctrl-btn" title="Zoom -" onclick="network.moveTo({{scale: network.getScale()*0.77}})">−</button>
      <button class="ctrl-btn" title="Recentrer" onclick="network.fit({{animation:true}})">⊙</button>
      <button class="ctrl-btn" title="Exporter PNG" onclick="exportPNG()">📷</button>
    </div>
  </div>

  <!-- ── Panneau latéral ────────────────────────────────────── -->
  <div id="side-panel">
    <div class="panel-tabs">
      <button class="tab-btn active" onclick="switchTab('detail',this)">🔍 Détails</button>
      <button class="tab-btn"        onclick="switchTab('table', this)">📋 Tableau</button>
      <button class="tab-btn"        onclick="switchTab('legend',this)">🎨 Légende</button>
    </div>

    <!-- Onglet Détails -->
    <div id="tab-detail" class="tab-content active">
      <div id="detail-placeholder">
        <div class="big-icon">🖱️</div>
        <div>Cliquez sur un nœud du graphe<br>pour afficher les détails</div>
      </div>
      <div id="device-detail" style="display:none"></div>
    </div>

    <!-- Onglet Tableau -->
    <div id="tab-table" class="tab-content">
      <div class="search-bar">
        <input type="text" id="search-input" placeholder="🔍  Filtrer par IP, hostname, fabricant…" oninput="filterTable()">
      </div>
      <div style="overflow-y:auto;flex:1">
        <table class="host-table">
          <thead>
            <tr>
              <th>Type</th>
              <th>IP</th>
              <th>Hostname</th>
              <th>Fabricant</th>
              <th>Ports</th>
            </tr>
          </thead>
          <tbody id="table-body"></tbody>
        </table>
      </div>
    </div>

    <!-- Onglet Légende -->
    <div id="tab-legend" class="tab-content">
      <div class="legend-list" id="legend-list"></div>
    </div>
  </div>

</div>

<div id="bottom-bar">
  <div class="status-dot"></div>
  <span>Scan terminé</span>
  <span>·</span>
  <span id="bar-network">{network}</span>
  <span>·</span>
  <span>{total_hosts} équipement(s) découvert(s)</span>
  <span style="margin-left:auto">{scan_time}</span>
</div>

<!-- ── Données injectées par Python ─────────────────────────── -->
<script>
const GRAPH_DATA = {graph_json};
const HOSTS_DATA = {hosts_json};
const LEGEND_DATA = {legend_json};

// ── Initialisation vis.js ────────────────────────────────────
const container = document.getElementById('network-graph');

// Filtrer les métadonnées des nœuds (vis.js n'en a pas besoin)
const visNodes = GRAPH_DATA.nodes.map(n => {{
  const {{_meta, ...rest}} = n;
  return rest;
}});

const data = {{
  nodes: new vis.DataSet(visNodes),
  edges: new vis.DataSet(GRAPH_DATA.edges),
}};

const options = {{
  nodes: {{
    borderWidth: 2,
    shadow: {{ enabled: true, size: 8, color: 'rgba(0,0,0,0.5)' }},
  }},
  edges: {{
    width: 1.5,
    smooth: {{ type: 'cubicBezier', roundness: 0.4 }},
    arrows: {{ to: {{ enabled: false }} }},
  }},
  physics: {{
    stabilization: {{ iterations: 150 }},
    barnesHut: {{
      gravitationalConstant: -8000,
      centralGravity: 0.3,
      springLength: 160,
      springConstant: 0.04,
      damping: 0.09,
    }},
  }},
  interaction: {{
    hover: true,
    tooltipDelay: 150,
    navigationButtons: false,
    keyboard: true,
  }},
  layout: {{ randomSeed: 42 }},
}};

const network = new vis.Network(container, data, options);

// ── Clic sur un nœud → affichage des détails ────────────────
network.on('click', function(params) {{
  if (!params.nodes.length) return;
  const nodeId = params.nodes[0];
  if (nodeId === 0) return;            // nœud central

  const rawNode = GRAPH_DATA.nodes.find(n => n.id === nodeId);
  if (!rawNode || !rawNode._meta) return;

  showDetail(rawNode._meta);
  switchTab('detail', document.querySelectorAll('.tab-btn')[0]);
}});

// ── Affichage du panneau détails ─────────────────────────────
function showDetail(meta) {{
  document.getElementById('detail-placeholder').style.display = 'none';
  const box = document.getElementById('device-detail');
  box.style.display = 'block';

  let portsHTML = '';
  if (meta.ports && meta.ports.length) {{
    portsHTML = '<div class="section-title">Ports ouverts</div>';
    meta.ports.forEach(p => {{
      portsHTML += `<div class="port-row">
        <span class="port-number">${{p.port}}</span>
        <span class="port-service">${{p.service}}</span>
        ${{p.banner ? `<span class="port-banner">${{escHtml(p.banner)}}</span>` : ''}}
      </div>`;
    }});
  }} else {{
    portsHTML = '<div class="section-title">Ports</div><div class="no-ports">Aucun scan de ports effectué ou aucun port ouvert trouvé.</div>';
  }}

  box.innerHTML = `
    <div class="device-header">
      <div class="device-icon">${{meta.icon}}</div>
      <div>
        <div class="device-name">${{escHtml(meta.hostname)}}</div>
        <div class="device-type">${{meta.dlabel}}</div>
      </div>
    </div>
    <div class="info-grid">
      <span class="info-label">Adresse IP</span>
      <span class="info-value">${{meta.ip}}</span>
      <span class="info-label">Adresse MAC</span>
      <span class="info-value">${{meta.mac}}</span>
      <span class="info-label">Fabricant</span>
      <span class="info-value">${{escHtml(meta.vendor)}}</span>
    </div>
    ${{portsHTML}}
  `;
}}

// ── Onglets ──────────────────────────────────────────────────
function switchTab(id, btn) {{
  document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.getElementById('tab-' + id).classList.add('active');
  btn.classList.add('active');
}}

// ── Tableau ──────────────────────────────────────────────────
const BADGE_COLORS = {{
  router:  '#e74c3c',
  server:  '#2980b9',
  windows: '#0078d4',
  linux:   '#f39c12',
  nas:     '#8e44ad',
  printer: '#16a085',
  camera:  '#c0392b',
  phone:   '#27ae60',
  switch:  '#7f8c8d',
  unknown: '#95a5a6',
}};

function buildTable() {{
  const tbody = document.getElementById('table-body');
  HOSTS_DATA.forEach((h, idx) => {{
    const color = BADGE_COLORS[h.dtype] || '#666';
    const ports = h.open_ports.map(p => p.port).join(', ') || '—';
    const tr = document.createElement('tr');
    tr.dataset.idx = idx;
    tr.innerHTML = `
      <td><span class="type-badge" style="background:${{color}}22;color:${{color}};border:1px solid ${{color}}40">${{h.icon}} ${{h.dlabel}}</span></td>
      <td style="font-family:monospace">${{h.ip}}</td>
      <td style="color:#94a3b8;max-width:120px;overflow:hidden;text-overflow:ellipsis" title="${{escHtml(h.hostname)}}">${{escHtml(h.hostname)}}</td>
      <td style="color:#94a3b8;max-width:100px;overflow:hidden;text-overflow:ellipsis" title="${{escHtml(h.vendor)}}">${{escHtml(h.vendor)}}</td>
      <td style="font-family:monospace;font-size:11px;color:#6366f1">${{ports}}</td>
    `;
    tr.addEventListener('click', () => {{
      showDetail(h);
      switchTab('detail', document.querySelectorAll('.tab-btn')[0]);
      network.selectNodes([idx + 1]);
      network.focus(idx + 1, {{ animation: true, scale: 1.5 }});
    }});
    tbody.appendChild(tr);
  }});
}}

function filterTable() {{
  const q = document.getElementById('search-input').value.toLowerCase();
  document.querySelectorAll('#table-body tr').forEach(tr => {{
    tr.style.display = tr.innerText.toLowerCase().includes(q) ? '' : 'none';
  }});
}}

// ── Légende ──────────────────────────────────────────────────
function buildLegend() {{
  const list = document.getElementById('legend-list');
  LEGEND_DATA.forEach(item => {{
    if (item.count === 0) return;
    const div = document.createElement('div');
    div.className = 'legend-item';
    div.innerHTML = `
      <div class="legend-dot" style="background:${{item.color}};border-color:${{item.border}}"></div>
      <div class="legend-icon">${{item.icon}}</div>
      <div class="legend-label">${{item.label}}</div>
      <div class="legend-count">${{item.count}}</div>
    `;
    list.appendChild(div);
  }});
}}

// ── Export PNG ───────────────────────────────────────────────
function exportPNG() {{
  const canvas = container.querySelector('canvas');
  if (!canvas) return;
  const link = document.createElement('a');
  link.download = 'network-map.png';
  link.href = canvas.toDataURL('image/png');
  link.click();
}}

// ── Utilitaire ───────────────────────────────────────────────
function escHtml(str) {{
  if (!str) return '';
  return String(str)
    .replace(/&/g,'&amp;')
    .replace(/</g,'&lt;')
    .replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;');
}}

// ── Init ─────────────────────────────────────────────────────
buildTable();
buildLegend();
</script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# Fonction publique
# ---------------------------------------------------------------------------

def generate_html_report(
    hosts:    list[dict],
    metadata: dict,
    output_path: str,
) -> None:
    """
    Génère le fichier HTML de cartographie réseau.

    Args:
        hosts       : Liste des hôtes enrichis
        metadata    : Métadonnées du scan (network, scan_time, …)
        output_path : Chemin de sortie du fichier HTML
    """
    # Enrichir les hôtes avec type/icône pour le tableau JS
    hosts_enriched = []
    type_counts: dict[str, int] = {k: 0 for k in DEVICE_STYLE}

    for host in hosts:
        dtype  = _detect_device_type(host)
        style  = DEVICE_STYLE.get(dtype, DEVICE_STYLE["unknown"])
        type_counts[dtype] = type_counts.get(dtype, 0) + 1
        hosts_enriched.append({
            **host,
            "dtype":  dtype,
            "dlabel": style["label"],
            "icon":   style["icon"],
        })

    # Données de légende (uniquement les types présents)
    legend_data = [
        {
            "dtype":  dtype,
            "label":  style["label"],
            "icon":   style["icon"],
            "color":  style["color"],
            "border": style["border"],
            "count":  type_counts.get(dtype, 0),
        }
        for dtype, style in DEVICE_STYLE.items()
        if type_counts.get(dtype, 0) > 0
    ]

    # Construction des données de graphe
    graph_data = _build_graph_data(hosts, metadata)

    # Pilule "ports scannés" dans le header
    ports_pill = ""
    if metadata.get("ports_scanned"):
        n = sum(len(h.get("open_ports", [])) for h in hosts)
        ports_pill = f'<span class="pill">🔓 {n} port(s) ouvert(s)</span>'

    # Formatage de la date
    scan_dt = metadata.get("scan_time", "")
    try:
        dt = datetime.fromisoformat(scan_dt)
        scan_time_str = dt.strftime("%d/%m/%Y %H:%M:%S")
    except Exception:
        scan_time_str = scan_dt

    # Rendu du template
    html_content = _HTML_TEMPLATE.format(
        network     = metadata.get("network", "—"),
        total_hosts = len(hosts),
        scan_time   = scan_time_str,
        ports_pill  = ports_pill,
        graph_json  = json.dumps(graph_data,        ensure_ascii=False),
        hosts_json  = json.dumps(hosts_enriched,    ensure_ascii=False),
        legend_json = json.dumps(legend_data,        ensure_ascii=False),
    )

    # Écriture du fichier
    os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else ".", exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    log.info(f"Rapport HTML généré : {os.path.abspath(output_path)}")
