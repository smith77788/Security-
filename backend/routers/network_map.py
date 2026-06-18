"""
Network topology, connections, bandwidth API.
"""
from datetime import datetime, timedelta
from typing import List, Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import func

from database import get_db
from models import Device, Connection, DeviceFingerprint, BandwidthSample
from services import bandwidth_tracker
from services.auto_config import get as get_net_config

router = APIRouter(prefix="/api/network", tags=["network"])


@router.get("/topology")
def topology(
    location_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
):
    """
    Returns nodes (devices + external IPs) and edges (connections)
    for the network map visualisation.
    """
    since = datetime.utcnow() - timedelta(hours=24)
    dev_q = db.query(Device)
    if location_id is not None:
        dev_q = dev_q.filter(Device.location_id == location_id)
    devices = dev_q.all()

    conn_q = db.query(Connection).filter(Connection.last_seen >= since)
    if location_id is not None:
        conn_q = conn_q.filter(Connection.location_id == location_id)
    connections = conn_q.limit(500).all()

    # Build nodes
    nodes = []
    known_ips = {d.ip: d for d in devices if d.ip}

    for d in devices:
        fp = db.query(DeviceFingerprint).filter(DeviceFingerprint.mac == d.mac).first()
        nodes.append({
            "id": d.ip or d.mac,
            "label": d.friendly_name or d.vendor or d.mac,
            "type": "device",
            "ip": d.ip,
            "mac": d.mac,
            "vendor": d.vendor,
            "os_hint": d.os_hint or (fp.os_hint if fp else None),
            "is_new": d.is_new,
            "is_active": d.is_active,
            "location_id": d.location_id,
        })

    # External IP nodes
    ext_ips: dict[str, dict] = {}
    for c in connections:
        if c.dst_ip not in known_ips and c.dst_ip not in ext_ips:
            ext_ips[c.dst_ip] = {
                "id": c.dst_ip,
                "label": c.tls_sni or c.org or c.dst_ip,
                "type": "external_threat" if c.is_threat else "external",
                "ip": c.dst_ip,
                "country": c.country,
                "country_code": c.country_code,
                "org": c.org,
                "is_threat": c.is_threat,
                "is_tor": c.is_tor,
            }
    nodes.extend(ext_ips.values())

    # Edges
    edges = []
    for c in connections:
        edges.append({
            "source": c.src_ip,
            "target": c.dst_ip,
            "bytes": c.bytes_out or 0,
            "is_threat": c.is_threat,
            "protocol": c.protocol,
            "port": c.dst_port,
            "sni": c.tls_sni,
        })

    return {"nodes": nodes, "edges": edges}


@router.get("/connections")
def list_connections(
    location_id: Optional[int] = Query(None),
    threat_only: bool = False,
    hours: int = Query(24, le=168),
    limit: int = Query(200, le=1000),
    db: Session = Depends(get_db),
):
    since = datetime.utcnow() - timedelta(hours=hours)
    q = db.query(Connection).filter(Connection.last_seen >= since)
    if location_id is not None:
        q = q.filter(Connection.location_id == location_id)
    if threat_only:
        q = q.filter(Connection.is_threat == True)  # noqa: E712
    return q.order_by(Connection.last_seen.desc()).limit(limit).all()


@router.get("/bandwidth/timeline")
def bandwidth_timeline(
    hours: int = Query(1, le=720),
    device_mac: Optional[str] = Query(None),
    location_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
):
    return bandwidth_tracker.get_timeline(db, hours=hours, device_mac=device_mac, location_id=location_id)


@router.get("/bandwidth/top")
def bandwidth_top(
    minutes: int = Query(60, le=1440),
    location_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
):
    return bandwidth_tracker.get_top_consumers(db, minutes=minutes, location_id=location_id)


@router.get("/config")
def network_config():
    """Return auto-detected network configuration."""
    return get_net_config()


@router.get("/fingerprints")
def device_fingerprints(
    db: Session = Depends(get_db),
):
    fps = db.query(DeviceFingerprint).order_by(DeviceFingerprint.updated_at.desc()).limit(200).all()
    return [
        {
            "mac": f.mac,
            "ip": f.src_ip,
            "os_hint": f.os_hint,
            "device_type": f.device_type,
            "hostname": f.hostname,
            "type": f.fingerprint_type,
            "updated_at": f.updated_at,
        }
        for f in fps
    ]
