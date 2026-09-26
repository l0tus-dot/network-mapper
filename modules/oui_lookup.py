"""
modules/oui_lookup.py
---------------------
Résolution OUI (Organizationally Unique Identifier).

Identifie le fabricant d'un équipement réseau à partir des 3 premiers octets
(les 24 bits de poids fort) de son adresse MAC, attribués par l'IEEE à chaque
constructeur.

Stratégie :
  1. Cache mémoire (session courante)
  2. Cache disque JSON (entre les sessions)
  3. API gratuite macvendors.com (avec rate-limiting 1 req/500 ms)
  4. Fallback → 'Inconnu'
"""

import json
import os
import time
import logging
import urllib.request
import urllib.error

log = logging.getLogger(__name__)

# --- Chemins ---
_CACHE_DIR  = os.path.join(os.path.dirname(__file__), "..", "data")
_CACHE_FILE = os.path.join(_CACHE_DIR, "oui_cache.json")

# --- État global ---
_memory_cache: dict  = {}      # {OUI: "NomFabricant"}
_cache_loaded:  bool = False
_last_api_call: float = 0.0
_API_RATE_DELAY: float = 0.5   # secondes entre deux appels API


# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------

def _load_cache() -> None:
    """Charge le cache OUI depuis le fichier JSON persistant."""
    global _memory_cache, _cache_loaded
    if _cache_loaded:
        return
    if os.path.exists(_CACHE_FILE):
        try:
            with open(_CACHE_FILE, "r", encoding="utf-8") as f:
                _memory_cache = json.load(f)
            log.debug(f"Cache OUI chargé : {len(_memory_cache)} entrée(s)")
        except (json.JSONDecodeError, OSError) as e:
            log.debug(f"Impossible de lire le cache OUI : {e}")
            _memory_cache = {}
    _cache_loaded = True


def _save_cache() -> None:
    """Sauvegarde le cache OUI sur le disque."""
    try:
        os.makedirs(_CACHE_DIR, exist_ok=True)
        with open(_CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(_memory_cache, f, indent=2, ensure_ascii=False)
    except OSError as e:
        log.debug(f"Impossible de sauvegarder le cache OUI : {e}")


def _normalize_oui(mac: str) -> str:
    """Retourne les 3 premiers octets MAC en majuscules séparés par ':'. Ex: 'AA:BB:CC'"""
    clean = mac.upper().replace("-", ":").replace(".", ":")
    parts = clean.split(":")
    return ":".join(parts[:3])


# ---------------------------------------------------------------------------
# API macvendors.com
# ---------------------------------------------------------------------------

def _fetch_from_api(oui: str) -> str | None:
    """
    Interroge l'API macvendors.com pour résoudre un OUI.

    Rate-limiting respecté : au moins _API_RATE_DELAY secondes entre chaque appel.

    Returns:
        Nom du fabricant, ou None en cas d'échec.
    """
    global _last_api_call

    # --- Rate limiting ---
    elapsed = time.time() - _last_api_call
    if elapsed < _API_RATE_DELAY:
        time.sleep(_API_RATE_DELAY - elapsed)

    # OUI sans séparateurs pour l'URL (ex: 'AABBCC')
    oui_hex = oui.replace(":", "")
    url = f"https://api.macvendors.com/{oui_hex}"

    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "NetworkMapper/1.0 (educational project)"}
        )
        with urllib.request.urlopen(req, timeout=3) as resp:
            _last_api_call = time.time()
            return resp.read().decode("utf-8").strip()

    except urllib.error.HTTPError as e:
        _last_api_call = time.time()
        if e.code == 404:
            return "Inconnu"          # OUI non référencé → pas une erreur
        if e.code == 429:
            log.warning("Rate limit macvendors.com atteint, pause de 2 s…")
            time.sleep(2)
        log.debug(f"HTTP {e.code} pour OUI {oui}")
        return None

    except Exception as e:
        log.debug(f"Erreur API OUI pour {oui} : {e}")
        return None


# ---------------------------------------------------------------------------
# Fonction publique
# ---------------------------------------------------------------------------

def get_manufacturer(mac: str) -> str:
    """
    Retourne le nom du fabricant d'un équipement à partir de son adresse MAC.

    Consultée dans l'ordre : cache mémoire → cache disque → API → 'Inconnu'.

    Args:
        mac : Adresse MAC (tous formats acceptés : AA:BB:CC:DD:EE:FF,
              AA-BB-CC-DD-EE-FF, AABB.CCDD.EEFF, AABBCCDDEEFF)

    Returns:
        Nom du fabricant (ex: 'Apple, Inc.') ou 'Inconnu'.
    """
    _load_cache()
    oui = _normalize_oui(mac)

    # 1. Cache mémoire / disque
    if oui in _memory_cache:
        return _memory_cache[oui]

    # 2. API distante
    manufacturer = _fetch_from_api(oui)
    if manufacturer is None:
        manufacturer = "Inconnu"

    # 3. Mise en cache et retour
    _memory_cache[oui] = manufacturer
    _save_cache()
    return manufacturer
