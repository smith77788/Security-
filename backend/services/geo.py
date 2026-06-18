"""
GeoIP + ASN lookup.
Uses ipwhois (RDAP/WHOIS) with a 7-day SQLite cache.
Private/RFC-1918 addresses are resolved locally without any network call.
"""
import ipaddress
import json
import logging
import threading
from datetime import datetime, timedelta
from typing import Optional

log = logging.getLogger("geo")
_lock = threading.Lock()

# Private / special ranges
_PRIVATE = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
]


def _is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _PRIVATE)
    except Exception:
        return False


def _cache_get(ip: str) -> Optional[dict]:
    try:
        from database import SessionLocal
        from models import GeoCache
        db = SessionLocal()
        try:
            row = db.query(GeoCache).filter(GeoCache.ip == ip).first()
            if row and row.expires_at > datetime.utcnow():
                return json.loads(row.data)
        finally:
            db.close()
    except Exception:
        pass
    return None


def _cache_set(ip: str, data: dict):
    try:
        from database import SessionLocal
        from models import GeoCache
        db = SessionLocal()
        try:
            row = db.query(GeoCache).filter(GeoCache.ip == ip).first()
            exp = datetime.utcnow() + timedelta(days=7)
            if row:
                row.data = json.dumps(data)
                row.expires_at = exp
            else:
                db.add(GeoCache(ip=ip, data=json.dumps(data), expires_at=exp))
            db.commit()
        finally:
            db.close()
    except Exception:
        pass


def lookup(ip: str) -> dict:
    """
    Return {country, country_code, asn, org, city}.
    Returns immediately for private IPs without network calls.
    """
    if not ip or _is_private(ip):
        return {"country": "Local", "country_code": "LAN", "asn": None, "org": "Private Network", "city": None}

    with _lock:
        cached = _cache_get(ip)
        if cached is not None:
            return cached

    result = {"country": None, "country_code": None, "asn": None, "org": None, "city": None}
    try:
        from ipwhois import IPWhois
        obj = IPWhois(ip, timeout=5)
        data = obj.lookup_rdap(asn_methods=["whois"], inc_raw=False, retry_count=1)
        result["country"] = data.get("asn_country_code")
        result["country_code"] = data.get("asn_country_code")
        result["asn"] = data.get("asn")
        result["org"] = (data.get("network") or {}).get("name") or data.get("asn_description")
        result["city"] = None  # RDAP doesn't provide city
    except Exception as e:
        log.debug("GeoIP lookup failed for %s: %s", ip, e)

    with _lock:
        _cache_set(ip, result)
    return result


# Country flag emoji helper
_COUNTRY_FLAGS = {}  # populated lazily


def flag_emoji(country_code: Optional[str]) -> str:
    if not country_code or len(country_code) != 2:
        return "🌍"
    # Convert ISO-3166 alpha-2 to regional indicator symbols
    return chr(0x1F1E6 + ord(country_code[0]) - 65) + chr(0x1F1E6 + ord(country_code[1]) - 65)
