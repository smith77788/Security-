"""
Threat Intelligence API.
- Feed status and refresh
- Single IP/domain lookup
- Beaconing scan results
"""
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from typing import Optional

from database import get_db
from services import threat_intel, beaconing as beaconing_svc

router = APIRouter(prefix="/api/intel", tags=["intel"])


@router.get("/status")
def intel_status():
    return threat_intel.status()


@router.post("/refresh")
def intel_refresh():
    """Re-download all threat feeds (runs in background)."""
    import threading
    t = threading.Thread(target=threat_intel.load_all, daemon=True)
    t.start()
    return {"ok": True, "message": "Feed refresh started in background"}


@router.get("/lookup/ip")
def lookup_ip(ip: str = Query(...)):
    threat, reason = threat_intel.is_threat_ip(ip)
    is_tor = threat_intel.is_tor(ip)
    from services.geo import lookup as geo_lookup, flag_emoji
    geo = geo_lookup(ip)
    return {
        "ip": ip,
        "is_threat": threat,
        "threat_reason": reason,
        "is_tor": is_tor,
        "geo": geo,
        "flag": flag_emoji(geo.get("country_code")),
    }


@router.get("/lookup/domain")
def lookup_domain(domain: str = Query(...)):
    from utils.suspicious_domains import is_suspicious, looks_like_dga
    threat_feed, reason1 = threat_intel.is_threat_domain(domain)
    local_bad = is_suspicious(domain)
    dga = looks_like_dga(domain)
    return {
        "domain": domain,
        "is_threat": threat_feed or local_bad,
        "looks_like_dga": dga,
        "reasons": list(filter(None, [
            reason1 if threat_feed else None,
            "Local suspicious domain list" if local_bad else None,
            "High-entropy / DGA-like domain" if dga else None,
        ])),
    }


@router.get("/beaconing")
def beaconing_results(
    location_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
):
    """Run beaconing detection and return candidates without writing alerts."""
    return beaconing_svc.detect(db, location_id=location_id)


@router.post("/beaconing/alert")
def beaconing_alert(
    location_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
):
    """Run beaconing detection and write alerts for findings."""
    beaconing_svc.run_and_alert(db, location_id=location_id)
    return {"ok": True}
