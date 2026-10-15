"""
Optional enrichment sources — all local, cached, and optional
================================================================
GeoIP / ASN    MaxMind-format .mmdb files (GEOIP_CITY_DB / GEOIP_COUNTRY_DB, GEOIP_ASN_DB)
               read with the `geoip2` or `maxminddb` package. Absent → unavailable, and the
               dependent detector parts report not_evaluated. No network lookups.
Threat intel   Files in THREAT_INTEL_DIR, maintained by the operator (e.g. with
               scripts/update_tor_exit_list.py). Every match carries its source, category,
               update time and a staleness flag (INTEL_MAX_AGE_DAYS). Nothing is hardcoded.
                 *.json  {"source": "...", "category": "tor_exit|vpn|...", "updated": "<ISO>",
                          "indicators": {"ips": [], "cidrs": [], "domains": [], "ja3": []}}
                 *.txt   one IP / CIDR / domain / 32-hex JA3 per line; category = file stem,
                         updated = file modification time
Policy         POLICY_FILE (JSON, default policies/destination_policy.json): trusted
               destinations, approved bulk / RDP destinations, egress rules, admin ports.
Files are re-read when their modification time changes (checked at most every 30 s).
"""
import ipaddress
import json
import os
import re
import threading
import time
from datetime import datetime, timezone
from functools import lru_cache
from typing import Any, Dict, List, Optional

from config import Config

try:
    from flask import current_app
except Exception:  # pragma: no cover
    current_app = None

_HEX32 = re.compile(r"^[0-9a-f]{32}$")
_RECHECK_S = 30.0


def _cfg(name, default=None):
    try:
        return current_app.config.get(name, getattr(Config, name, default))
    except Exception:
        return getattr(Config, name, default)


def _is_public(ip: Optional[str]) -> Optional[bool]:
    try:
        addr = ipaddress.ip_address(ip)
    except (TypeError, ValueError):
        return None
    return addr.is_global


# ---------------------------------------------------------------------------------- GeoIP
class GeoIP:
    """Country / ASN lookups. `available` is False with a reason when no database is configured."""

    def __init__(self):
        self._readers = {}
        self.reason = None
        self._lock = threading.Lock()
        self._loaded_paths = None

    def _paths(self):
        return (_cfg("GEOIP_CITY_DB") or _cfg("GEOIP_COUNTRY_DB") or "", _cfg("GEOIP_ASN_DB") or "")

    def _load(self):
        paths = self._paths()
        if paths == self._loaded_paths:
            return
        self._loaded_paths = paths
        self._readers = {}
        self.lookup_cached.cache_clear()
        geo_path, asn_path = paths
        if not geo_path and not asn_path:
            self.reason = "No GeoIP database configured (set GEOIP_COUNTRY_DB / GEOIP_ASN_DB to local .mmdb files)."
            return
        try:
            import maxminddb  # geoip2 depends on it; usable directly
        except ImportError:
            self.reason = "GeoIP database configured but the 'maxminddb' / 'geoip2' package is not installed."
            return
        for kind, path in (("geo", geo_path), ("asn", asn_path)):
            if path:
                if os.path.isfile(path):
                    self._readers[kind] = maxminddb.open_database(path)
                else:
                    self.reason = f"GeoIP database file not found: {os.path.basename(path)}"
        if self._readers:
            self.reason = None

    @property
    def available(self) -> bool:
        with self._lock:
            self._load()
        return bool(self._readers)

    def status(self) -> Dict[str, Any]:
        avail = self.available
        return {"available": avail, "country": "geo" in self._readers, "asn": "asn" in self._readers,
                "reason": None if avail else self.reason}

    @lru_cache(maxsize=8192)
    def lookup_cached(self, ip: str):
        out: Dict[str, Any] = {}
        geo, asn = self._readers.get("geo"), self._readers.get("asn")
        if geo is not None:
            rec = geo.get(ip) or {}
            out["country"] = (rec.get("country") or {}).get("iso_code")
        if asn is not None:
            rec = asn.get(ip) or {}
            out["asn"] = rec.get("autonomous_system_number")
            out["as_org"] = rec.get("autonomous_system_organization")
        return tuple(sorted(out.items()))

    def lookup(self, ip: Optional[str]) -> Optional[Dict[str, Any]]:
        """None = unavailable. {'scope': 'non_public'} for private/reserved addresses.
        Unknown fields stay None — unknown is never treated as malicious."""
        if not self.available:
            return None
        public = _is_public(ip)
        if public is None:
            return None
        if not public:
            return {"scope": "non_public", "country": None, "asn": None}
        return {"scope": "public", **dict(self.lookup_cached(ip))}


# ---------------------------------------------------------------------------------- Intel
class ThreatIntel:
    def __init__(self):
        self._sig = None
        self._checked = 0.0
        self._sources: List[Dict[str, Any]] = []
        self._ips: Dict[str, List[int]] = {}
        self._nets: List = []
        self._domains: Dict[str, List[int]] = {}
        self._ja3: Dict[str, List[int]] = {}
        self._lock = threading.Lock()

    def _dir(self):
        return _cfg("THREAT_INTEL_DIR") or ""

    def _refresh(self):
        now = time.time()
        if now - self._checked < _RECHECK_S and self._sig is not None:
            return
        self._checked = now
        d = self._dir()
        files = sorted(os.path.join(d, f) for f in os.listdir(d) if f.endswith((".json", ".txt"))) if d and os.path.isdir(d) else []
        sig = tuple((f, os.path.getmtime(f)) for f in files)
        if sig == self._sig:
            return
        self._sig = sig
        self._sources, self._ips, self._nets, self._domains, self._ja3 = [], {}, [], {}, {}
        for path, mtime in sig:
            try:
                self._load_file(path, mtime)
            except Exception as exc:
                self._sources.append({"file": os.path.basename(path), "error": f"unreadable ({type(exc).__name__})"})

    def _load_file(self, path, mtime):
        name = os.path.basename(path)
        if path.endswith(".json"):
            doc = json.load(open(path, encoding="utf-8"))
            ind = doc.get("indicators") or {}
            src = {"file": name, "source": doc.get("source") or name, "category": doc.get("category") or "unknown",
                   "updated": doc.get("updated") or datetime.fromtimestamp(mtime, tz=timezone.utc).isoformat()}
            ips, cidrs, domains, ja3 = ind.get("ips", []), ind.get("cidrs", []), ind.get("domains", []), ind.get("ja3", [])
        else:
            lines = [l.strip() for l in open(path, encoding="utf-8") if l.strip() and not l.startswith("#")]
            src = {"file": name, "source": name, "category": os.path.splitext(name)[0],
                   "updated": datetime.fromtimestamp(mtime, tz=timezone.utc).isoformat()}
            ips, cidrs, domains, ja3 = [], [], [], []
            for l in lines:
                if _HEX32.match(l.lower()):
                    ja3.append(l.lower())
                elif "/" in l:
                    cidrs.append(l)
                else:
                    try:
                        ipaddress.ip_address(l)
                        ips.append(l)
                    except ValueError:
                        domains.append(l.lower())
        idx = len(self._sources)
        src["counts"] = {"ips": len(ips), "cidrs": len(cidrs), "domains": len(domains), "ja3": len(ja3)}
        self._sources.append(src)
        for ip in ips:
            self._ips.setdefault(str(ipaddress.ip_address(ip)), []).append(idx)
        for c in cidrs:
            try:
                self._nets.append((ipaddress.ip_network(c, strict=False), idx))
            except ValueError:
                pass
        for dmn in domains:
            self._domains.setdefault(dmn.lower().lstrip("."), []).append(idx)
        for j in ja3:
            self._ja3.setdefault(j.lower(), []).append(idx)

    def _describe(self, idxs) -> List[Dict[str, Any]]:
        max_age = float(_cfg("INTEL_MAX_AGE_DAYS", 7))
        out = []
        for i in sorted(set(idxs)):
            s = self._sources[i]
            stale = None
            try:
                age_days = (datetime.now(timezone.utc) - datetime.fromisoformat(s["updated"].replace("Z", "+00:00"))).total_seconds() / 86400
                stale = age_days > max_age
            except Exception:
                pass
            out.append({"source": s["source"], "category": s["category"], "updated": s["updated"], "stale": stale})
        return out

    def status(self) -> Dict[str, Any]:
        with self._lock:
            self._refresh()
            srcs = [dict(s) for s in self._sources]
        for i, s in enumerate(srcs):
            if "updated" in s:
                s["stale"] = self._describe([i])[0]["stale"]
        return {"configured": bool(self._dir()), "directory_present": bool(self._dir()) and os.path.isdir(self._dir()),
                "sources": srcs, "available": any("counts" in s for s in srcs)}

    @property
    def available(self) -> bool:
        return self.status()["available"]

    def match_ip(self, ip: Optional[str]) -> List[Dict[str, Any]]:
        if not ip:
            return []
        with self._lock:
            self._refresh()
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                return []
            idxs = list(self._ips.get(str(addr), []))
            idxs += [i for net, i in self._nets if addr.version == net.version and addr in net]
            return self._describe(idxs)

    def match_domain(self, name: Optional[str]) -> List[Dict[str, Any]]:
        if not name:
            return []
        with self._lock:
            self._refresh()
            parts = name.lower().rstrip(".").split(".")
            idxs = []
            for i in range(len(parts) - 1):
                idxs += self._domains.get(".".join(parts[i:]), [])
            return self._describe(idxs)

    def match_ja3(self, ja3: Optional[str]) -> List[Dict[str, Any]]:
        if not ja3:
            return []
        with self._lock:
            self._refresh()
            return self._describe(self._ja3.get(ja3.lower(), []))


# ---------------------------------------------------------------------------------- Policy
class DestinationPolicy:
    def __init__(self):
        self._sig = None
        self._checked = 0.0
        self.doc: Dict[str, Any] = {}
        self.error: Optional[str] = None
        self._lock = threading.Lock()

    def _path(self):
        return _cfg("POLICY_FILE") or ""

    def _refresh(self):
        now = time.time()
        if now - self._checked < _RECHECK_S and self._sig is not None:
            return
        self._checked = now
        path = self._path()
        sig = (path, os.path.getmtime(path)) if path and os.path.isfile(path) else (path, None)
        if sig == self._sig:
            return
        self._sig = sig
        self.doc, self.error = {}, None
        if sig[1] is None:
            self.error = "No destination policy file configured." if not path else "Destination policy file not found."
            return
        try:
            self.doc = json.load(open(path, encoding="utf-8"))
        except Exception as exc:
            self.error = f"Destination policy unreadable ({type(exc).__name__})."

    def get(self, key, default=None):
        with self._lock:
            self._refresh()
            return self.doc.get(key, default)

    @property
    def loaded(self) -> bool:
        with self._lock:
            self._refresh()
            return bool(self.doc)

    def status(self) -> Dict[str, Any]:
        loaded = self.loaded
        return {"loaded": loaded, "file": os.path.basename(self._path()) if self._path() else None,
                "error": self.error, "version": self.doc.get("version") if loaded else None,
                "trusted_categories": sorted((self.doc.get("trusted_destinations") or {}).keys()) if loaded else [],
                "egress_rules": len(self.doc.get("egress_rules") or []) if loaded else 0}

    @staticmethod
    def domain_matches(name: Optional[str], suffixes) -> Optional[str]:
        if not name:
            return None
        n = name.lower().rstrip(".")
        for sfx in suffixes or []:
            sfx = sfx.lower().lstrip(".")
            if n == sfx or n.endswith("." + sfx):
                return sfx
        return None

    @staticmethod
    def address_matches(ip: Optional[str], entries) -> Optional[str]:
        if not ip:
            return None
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        for e in entries or []:
            try:
                net = ipaddress.ip_network(e, strict=False)
            except ValueError:
                continue
            if addr.version == net.version and addr in net:
                return e
        return None

    def trusted_category(self, sni: Optional[str]) -> Optional[Dict[str, str]]:
        for category, suffixes in (self.get("trusted_destinations") or {}).items():
            hit = self.domain_matches(sni, suffixes)
            if hit:
                return {"category": category, "matched": hit}
        return None

    def matches_list(self, key: str, sni: Optional[str], ip: Optional[str]) -> Optional[str]:
        """Match an observed SNI against domain entries and the IP against CIDR/IP entries."""
        nets, names = [], []
        for e in self.get(key) or []:
            try:
                ipaddress.ip_network(e, strict=False)
                nets.append(e)
            except ValueError:
                names.append(e)
        return self.domain_matches(sni, names) or self.address_matches(ip, nets)


geoip = GeoIP()
intel = ThreatIntel()
policy = DestinationPolicy()


def set_geoip_provider(provider) -> None:
    """Tests / integrations: replace the GeoIP provider (must expose available, lookup, status)."""
    global geoip
    geoip = provider


def capabilities() -> Dict[str, Any]:
    return {"geoip": geoip.status(), "threat_intel": intel.status(), "policy": policy.status()}
