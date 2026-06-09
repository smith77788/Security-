from typing import List
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
    if period == "1h":
        return now - timedelta(hours=1)
    if period == "7d":
        return now - timedelta(days=7)
    return now - timedelta(hours=24)  # default 24h


@router.get("/top-domains", response_model=List[DomainStat])
def top_domains(
    period: str = Query("24h", pattern="^(1h|24h|7d)$"),
    limit: int = Query(20, le=100),
    db: Session = Depends(get_db),
):
    since = _period_start(period)
    rows = (
        db.query(
            DNSQuery.domain,
            func.count(DNSQuery.id).label("count"),
            func.max(DNSQuery.timestamp).label("last_seen"),
        )
        .filter(DNSQuery.timestamp >= since)
        .group_by(DNSQuery.domain)
        .order_by(func.count(DNSQuery.id).desc())
        .limit(limit)
        .all()
    )
    return [DomainStat(domain=r.domain, count=r.count, last_seen=r.last_seen) for r in rows]


@router.get("/top-devices", response_model=List[DeviceDNSStat])
def top_devices(
    period: str = Query("24h", pattern="^(1h|24h|7d)$"),
    limit: int = Query(10, le=50),
    db: Session = Depends(get_db),
):
    since = _period_start(period)
    rows = (
        db.query(DNSQuery.device_mac, func.count(DNSQuery.id).label("count"))
        .filter(DNSQuery.timestamp >= since)
        .group_by(DNSQuery.device_mac)
        .order_by(func.count(DNSQuery.id).desc())
        .limit(limit)
        .all()
    )
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
    device_mac: str = Query(None),
    domain: str = Query(None),
    db: Session = Depends(get_db),
):
    q = db.query(DNSQuery).order_by(DNSQuery.timestamp.desc())
    if device_mac:
        q = q.filter(DNSQuery.device_mac == device_mac)
    if domain:
        q = q.filter(DNSQuery.domain.contains(domain))
    return q.limit(limit).all()
