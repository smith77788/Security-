"""
Agent → Hub data ingestion endpoint.
Each remote location agent authenticates with its API key (X-API-Key header).
"""
import logging
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Header
from sqlalchemy.orm import Session

from database import get_db
from models import Location, Device, DNSQuery, Alert
from schemas import IngestPayload
from utils.oui_lookup import lookup_vendor
from utils.suspicious_domains import is_suspicious, looks_like_dga
from services.realtime import manager
from config import OUI_FILE

router = APIRouter(prefix="/api/ingest", tags=["ingest"])
log = logging.getLogger("ingest")


def _get_location(x_api_key: str = Header(...), db: Session = Depends(get_db)) -> Location:
    loc = db.query(Location).filter(Location.api_key == x_api_key).first()
    if not loc:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return loc


@router.post("/heartbeat")
def heartbeat(loc: Location = Depends(_get_location), db: Session = Depends(get_db)):
    was_offline = not loc.is_online
    loc.last_heartbeat = datetime.utcnow()
    loc.is_online = True
    db.commit()
    if was_offline:
        manager.emit_location_status(loc.id, loc.name, online=True)
    return {"ok": True, "location": loc.name}


@router.post("/scan")
def ingest_scan(
    payload: IngestPayload,
    loc: Location = Depends(_get_location),
    db: Session = Depends(get_db),
):
    now = datetime.utcnow()
    loc.last_heartbeat = now
    loc.is_online = True
    new_count = 0

    for item in payload.devices:
        mac = item.mac.upper()
        vendor = item.vendor or lookup_vendor(mac, OUI_FILE)
        device = db.query(Device).filter(
            Device.location_id == loc.id, Device.mac == mac
        ).first()

        if device is None:
            device = Device(
                location_id=loc.id,
                mac=mac,
                ip=item.ip,
                hostname=item.hostname,
                vendor=vendor,
                first_seen=now,
                last_seen=now,
                is_new=True,
                is_active=True,
            )
            db.add(device)
            db.flush()
            new_count += 1

            alert = Alert(
                location_id=loc.id,
                device_mac=mac,
                device_ip=item.ip,
                alert_type="new_device",
                severity="warning",
                message=f"Новое устройство в сети «{loc.name}»: {vendor} ({mac})",
                detail=f"IP: {item.ip}, Hostname: {item.hostname}",
            )
            db.add(alert)
            db.flush()
            manager.emit_new_device(device, loc.name)
            manager.emit_alert(alert, loc.name)
        else:
            device.ip = item.ip or device.ip
            device.hostname = item.hostname or device.hostname
            device.last_seen = now
            device.is_active = True

    # Process DNS queries
    dns_rows = []
    for q in payload.dns_queries:
        ts = q.timestamp or now
        row = DNSQuery(
            location_id=loc.id,
            device_mac=q.device_mac,
            device_ip=q.device_ip,
            domain=q.domain.lower(),
            query_type=q.query_type,
            timestamp=ts,
        )
        dns_rows.append(row)

        # Inline suspicious domain check
        domain = q.domain.lower()
        if is_suspicious(domain) or looks_like_dga(domain):
            reason = "suspicious domain" if is_suspicious(domain) else "possible DGA domain"
            alert = Alert(
                location_id=loc.id,
                device_mac=q.device_mac,
                device_ip=q.device_ip,
                alert_type="suspicious_domain",
                severity="critical",
                message=f"[{loc.name}] DNS-запрос к подозрительному домену: {domain} ({reason})",
                detail=f"Domain: {domain}",
            )
            db.add(alert)
            db.flush()
            manager.emit_alert(alert, loc.name)

    db.add_all(dns_rows)
    db.commit()

    log.info("Ingest from '%s': %d devices (%d new), %d DNS queries",
             loc.name, len(payload.devices), new_count, len(payload.dns_queries))
    return {"ok": True, "new_devices": new_count, "dns_ingested": len(dns_rows)}
