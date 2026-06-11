"""
Per-device bandwidth tracking using psutil (no root required).
Samples network interface counters every N seconds and derives
per-device traffic from the Connection table as a proxy.
Stores time-series BandwidthSample rows for timeline charts.
"""
import logging
import threading
import time
from datetime import datetime, timedelta
from typing import Optional

import psutil

log = logging.getLogger("bandwidth")


def _get_iface_counters(interface: str) -> Optional[tuple[int, int]]:
    """Returns (bytes_sent, bytes_recv) for the given interface."""
    try:
        stats = psutil.net_io_counters(pernic=True)
        if interface in stats:
            s = stats[interface]
            return s.bytes_sent, s.bytes_recv
    except Exception:
        pass
    return None


def sample_network(interface: str, location_id: Optional[int] = None):
    """
    Take one bandwidth sample for the whole interface and store it.
    Also derive per-device estimates from recent Connection rows.
    """
    from database import SessionLocal
    from models import BandwidthSample, Connection

    counters = _get_iface_counters(interface)
    if counters is None:
        return

    db = SessionLocal()
    try:
        now = datetime.utcnow()
        bytes_up, bytes_down = counters

        # Interface-level sample (device_mac = None = whole network)
        db.add(BandwidthSample(
            location_id=location_id,
            device_mac=None,
            timestamp=now,
            bytes_up=bytes_up,
            bytes_down=bytes_down,
        ))

        # Per-device samples derived from Connection bytes_out
        since = now - timedelta(minutes=1)
        recent = (
            db.query(
                Connection.src_ip,
                Connection.bytes_out,
            )
            .filter(Connection.last_seen >= since)
            .filter(Connection.location_id == location_id if location_id else True)
            .all()
        )
        for src_ip, bw in recent:
            from models import Device
            dev = db.query(Device).filter(Device.ip == src_ip).first()
            mac = dev.mac if dev else None
            db.add(BandwidthSample(
                location_id=location_id,
                device_mac=mac,
                device_ip=src_ip,
                timestamp=now,
                bytes_up=bw or 0,
                bytes_down=0,
            ))

        db.commit()
    finally:
        db.close()


def get_timeline(
    db,
    hours: int = 1,
    device_mac: Optional[str] = None,
    location_id: Optional[int] = None,
) -> list[dict]:
    """
    Возвращает хронологию трафика.
    hours <= 24  → группировка по 5 минут
    hours > 24   → группировка по часам
    """
    from models import BandwidthSample

    since = datetime.utcnow() - timedelta(hours=hours)
    q = db.query(BandwidthSample).filter(BandwidthSample.timestamp >= since)
    if device_mac is not None:
        q = q.filter(BandwidthSample.device_mac == device_mac)
    else:
        q = q.filter(BandwidthSample.device_mac == None)  # noqa: E711 — только агрегат интерфейса
    if location_id is not None:
        q = q.filter(BandwidthSample.location_id == location_id)

    rows = q.order_by(BandwidthSample.timestamp).all()
    if not rows:
        return []

    use_hourly = hours > 24
    buckets: dict[datetime, dict] = {}
    for row in rows:
        ts = row.timestamp.replace(second=0, microsecond=0)
        if use_hourly:
            ts = ts.replace(minute=0)
        else:
            ts = ts.replace(minute=(ts.minute // 5) * 5)
        if ts not in buckets:
            buckets[ts] = {"ts": ts.isoformat(), "bytes_up": 0, "bytes_down": 0}
        buckets[ts]["bytes_up"] += row.bytes_up or 0
        buckets[ts]["bytes_down"] += row.bytes_down or 0

    return sorted(buckets.values(), key=lambda x: x["ts"])


def get_top_consumers(
    db,
    minutes: int = 60,
    location_id: Optional[int] = None,
) -> list[dict]:
    """Top devices by outbound traffic in the last N minutes."""
    from models import BandwidthSample, Device
    from sqlalchemy import func

    since = datetime.utcnow() - timedelta(minutes=minutes)
    q = (
        db.query(
            BandwidthSample.device_mac,
            BandwidthSample.device_ip,
            func.sum(BandwidthSample.bytes_up).label("total_up"),
            func.sum(BandwidthSample.bytes_down).label("total_down"),
        )
        .filter(BandwidthSample.timestamp >= since)
        .filter(BandwidthSample.device_mac != None)  # noqa: E711
    )
    if location_id is not None:
        q = q.filter(BandwidthSample.location_id == location_id)
    rows = q.group_by(BandwidthSample.device_mac, BandwidthSample.device_ip)\
            .order_by(func.sum(BandwidthSample.bytes_up).desc())\
            .limit(10).all()

    result = []
    for mac, ip, up, down in rows:
        dev = db.query(Device).filter(Device.mac == mac).first() if mac else None
        result.append({
            "mac": mac,
            "ip": ip,
            "name": (dev.friendly_name or dev.vendor or mac) if dev else (mac or ip),
            "bytes_up": up or 0,
            "bytes_down": down or 0,
            "total": (up or 0) + (down or 0),
        })
    return result
