from typing import List, Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import func
from datetime import datetime, timedelta

from database import get_db
from models import DNSQuery, Device
from schemas import DomainStat, DeviceDNSStat, DNSQueryOut

router = APIRouter(prefix="/api/dns", tags=["dns"])


def _period_start(period: str) -> datetime:
    now = datetime.utcnow()
    return now - {"1h": timedelta(hours=1), "7d": timedelta(days=7)}.get(period, timedelta(hours=24))


@router.get("/top-domains", response_model=List[DomainStat])
def top_domains(
    period: str = Query("24h", pattern="^(1h|24h|7d)$"),
    limit: int = Query(20, le=100),
    location_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
):
    since = _period_start(period)
    q = db.query(
        DNSQuery.domain,
        func.count(DNSQuery.id).label("count"),
        func.max(DNSQuery.timestamp).label("last_seen"),
    ).filter(DNSQuery.timestamp >= since)
    if location_id is not None:
        q = q.filter(DNSQuery.location_id == location_id)
    rows = q.group_by(DNSQuery.domain).order_by(func.count(DNSQuery.id).desc()).limit(limit).all()
    return [DomainStat(domain=r.domain, count=r.count, last_seen=r.last_seen) for r in rows]


@router.get("/top-devices", response_model=List[DeviceDNSStat])
def top_devices(
    period: str = Query("24h", pattern="^(1h|24h|7d)$"),
    limit: int = Query(10, le=50),
    location_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
):
    since = _period_start(period)
    q = db.query(DNSQuery.device_mac, func.count(DNSQuery.id).label("count"))\
        .filter(DNSQuery.timestamp >= since)
    if location_id is not None:
        q = q.filter(DNSQuery.location_id == location_id)
    rows = q.group_by(DNSQuery.device_mac).order_by(func.count(DNSQuery.id).desc()).limit(limit).all()
    result = []
    for mac, cnt in rows:
        dev = db.query(Device).filter(Device.mac == mac).first() if mac else None
        result.append(DeviceDNSStat(
            device_mac=mac or "unknown",
            friendly_name=dev.friendly_name if dev else None,
            ip=dev.ip if dev else None,
            count=cnt,
        ))
    return result


@router.get("/recent", response_model=List[DNSQueryOut])
def recent_queries(
    limit: int = Query(100, le=500),
    location_id: Optional[int] = Query(None),
    device_mac: Optional[str] = Query(None),
    domain: Optional[str] = Query(None),
    db: Session = Depends(get_db),
):
    q = db.query(DNSQuery).order_by(DNSQuery.timestamp.desc())
    if location_id is not None:
        q = q.filter(DNSQuery.location_id == location_id)
    if device_mac:
        q = q.filter(DNSQuery.device_mac == device_mac)
    if domain:
        q = q.filter(DNSQuery.domain.contains(domain))
    return q.limit(limit).all()
