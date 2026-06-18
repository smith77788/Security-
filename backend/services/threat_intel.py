"""
Offline Threat Intelligence Engine.
Downloads and caches multiple free threat feeds.
Provides sub-millisecond IP/domain lookups via in-memory sets.
No API keys required.

Feeds:
  - Abuse.ch Feodo Tracker C2 IPs (botnet command & control)
  - Abuse.ch URLhaus malware domains
  - DShield known attackers block list
  - Tor exit node list (torproject.org)
  - Emerging Threats compromised IPs
  - CINS Army Score block list
"""
import logging
import os
import re
import threading
import time
from datetime import datetime, timedelta
from typing import Optional
from pathlib import Path

import requests

log = logging.getLogger("threat_intel")

FEEDS = {
    "feodo_ips": {
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist_aggressive.txt",
        "desc": "Abuse.ch Feodo C2 IPs",
        "type": "ip",
    },
    "dshield": {
        "url": "https://feeds.dshield.org/block.txt",
        "desc": "DShield Block List",
        "type": "cidr",
    },
    "tor_exits": {
        "url": "https://check.torproject.org/torbulkexitlist",
        "desc": "Tor Exit Nodes",
        "type": "ip",
    },
    "emerging_threats": {
        "url": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
        "desc": "Emerging Threats Compromised IPs",
        "type": "ip",
    },
    "cins_army": {
        "url": "https://cinsscore.com/list/ci-badguys.txt",
        "desc": "CINS Army Bad Guys",
        "type": "ip",
    },
}

# In-memory lookup sets (populated on startup + refresh)
_bad_ips: set[str] = set()
_tor_ips: set[str] = set()
_ip_reasons: dict[str, str] = {}
_bad_domains: set[str] = set()
_lock = threading.RLock()
_last_update: Optional[datetime] = None
_stats: dict[str, int] = {}

_default_cache = Path.home() / ".cache" / "family-security-intel"
CACHE_DIR = Path(os.environ.get("THREAT_CACHE_DIR", str(_default_cache)))
CACHE_TTL_HOURS = 24


def _fetch(url: str, timeout: int = 15) -> Optional[str]:
    try:
        r = requests.get(url, timeout=timeout, headers={"User-Agent": "FamilySecurity/2.0"})
        r.raise_for_status()
        return r.text
    except Exception as e:
        log.warning("Feed fetch failed [%s]: %s", url, e)
        return None


def _parse_ips(text: str) -> set[str]:
    ips: set[str] = set()
    ip_pat = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = ip_pat.search(line)
        if m:
            ips.add(m.group(1))
    return ips


def _load_feed(name: str, meta: dict) -> int:
    cache_file = CACHE_DIR / f"{name}.txt"
    text: Optional[str] = None

    # Use cache if fresh
    if cache_file.exists():
        age = time.time() - cache_file.stat().st_mtime
        if age < CACHE_TTL_HOURS * 3600:
            text = cache_file.read_text(errors="ignore")

    if text is None:
        text = _fetch(meta["url"])
        if text:
            CACHE_DIR.mkdir(parents=True, exist_ok=True)
            cache_file.write_text(text)

    if not text:
        # Use stale cache if network unavailable
        if cache_file.exists():
            text = cache_file.read_text(errors="ignore")
        else:
            return 0

    count = 0
    if meta["type"] in ("ip", "cidr"):
        ips = _parse_ips(text)
        with _lock:
            for ip in ips:
                _bad_ips.add(ip)
                if name not in _ip_reasons:
                    _ip_reasons[ip] = meta["desc"]
                if name == "tor_exits":
                    _tor_ips.add(ip)
            count = len(ips)
    elif meta["type"] == "domain":
        with _lock:
            for line in text.splitlines():
                line = line.strip().lower()
                if line and not line.startswith("#"):
                    _bad_domains.add(line)
                    count += 1

    log.info("Feed '%s': loaded %d entries", name, count)
    return count


def load_all():
    global _last_update
    log.info("Loading threat intelligence feeds…")
    for name, meta in FEEDS.items():
        try:
            n = _load_feed(name, meta)
            _stats[name] = n
        except Exception as e:
            log.error("Feed '%s' error: %s", name, e)
    _last_update = datetime.utcnow()
    with _lock:
        log.info("Threat intel ready: %d bad IPs, %d Tor exits",
                 len(_bad_ips), len(_tor_ips))


def is_threat_ip(ip: str) -> tuple[bool, str]:
    """Returns (is_threat, reason)."""
    with _lock:
        if ip in _bad_ips:
            return True, _ip_reasons.get(ip, "Known threat")
        if ip in _tor_ips:
            return True, "Tor exit node"
    return False, ""


def is_threat_domain(domain: str) -> tuple[bool, str]:
    domain = domain.lower().rstrip(".")
    with _lock:
        if domain in _bad_domains:
            return True, "Known malware domain"
        # Check parent domains
        parts = domain.split(".")
        for i in range(1, len(parts) - 1):
            if ".".join(parts[i:]) in _bad_domains:
                return True, "Known malware domain (parent)"
    return False, ""


def is_tor(ip: str) -> bool:
    with _lock:
        return ip in _tor_ips


def status() -> dict:
    return {
        "last_update": _last_update.isoformat() if _last_update else None,
        "bad_ips": len(_bad_ips),
        "tor_exits": len(_tor_ips),
        "bad_domains": len(_bad_domains),
        "feeds": {name: {"count": _stats.get(name, 0), "desc": meta["desc"]}
                  for name, meta in FEEDS.items()},
    }
