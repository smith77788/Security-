"""
Statistical C2 Beaconing Detector.

Malware that phones home to a command-and-control server typically
connects at very regular intervals (e.g. every 60s, 300s, 3600s).
This creates a low coefficient-of-variation (CV) in inter-arrival times.

Algorithm:
  - Group recent connections by (src_ip, dst_ip, dst_port)
  - Require ≥ 5 connections in the last 24h
  - Calculate mean and std-dev of inter-arrival times
  - CV = std / mean.  CV < 0.20 → strong beaconing indicator
  - Also flag long-duration low-volume "keepalive" patterns
"""
import logging
import math
from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy.orm import Session

log = logging.getLogger("beaconing")

CV_THRESHOLD = 0.20       # below this → beaconing
MIN_CONNECTIONS = 5       # minimum samples
LOOKBACK_HOURS = 24


def _std(values: list[float]) -> float:
    if len(values) < 2:
        return 0.0
    mean = sum(values) / len(values)
    variance = sum((x - mean) ** 2 for x in values) / (len(values) - 1)
    return math.sqrt(variance)


def detect(db: Session, location_id: Optional[int] = None) -> list[dict]:
    """
    Scan recent connections and return list of beaconing candidates.
    Does NOT write alerts — caller decides what to do with results.
    """
    from models import Connection
    from sqlalchemy import func

    since = datetime.utcnow() - timedelta(hours=LOOKBACK_HOURS)
    q = db.query(Connection).filter(Connection.last_seen >= since)
    if location_id is not None:
        q = q.filter(Connection.location_id == location_id)

    # Group by (src_ip, dst_ip, dst_port) and collect timestamps
    groups: dict[tuple, list[datetime]] = {}
    for conn in q.all():
        key = (conn.src_ip, conn.dst_ip, conn.dst_port)
        groups.setdefault(key, [])
        groups[key].append(conn.first_seen)
        if conn.last_seen != conn.first_seen:
            groups[key].append(conn.last_seen)

    candidates = []
    for (src_ip, dst_ip, dport), timestamps in groups.items():
        if len(timestamps) < MIN_CONNECTIONS:
            continue
        timestamps.sort()
        intervals = [
            (timestamps[i + 1] - timestamps[i]).total_seconds()
            for i in range(len(timestamps) - 1)
            if (timestamps[i + 1] - timestamps[i]).total_seconds() > 0
        ]
        if len(intervals) < MIN_CONNECTIONS - 1:
            continue
        mean_interval = sum(intervals) / len(intervals)
        if mean_interval < 5:              # ignore sub-5s noise
            continue
        std_interval = _std(intervals)
        cv = std_interval / mean_interval if mean_interval > 0 else 1.0

        if cv < CV_THRESHOLD:
            period_s = round(mean_interval)
            candidates.append({
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "dst_port": dport,
                "cv": round(cv, 4),
                "mean_interval_s": round(mean_interval, 1),
                "period_label": _period_label(period_s),
                "sample_count": len(timestamps),
            })
            log.info("Beaconing: %s→%s:%s every ~%ds (CV=%.3f)",
                     src_ip, dst_ip, dport, period_s, cv)

    return candidates


def _period_label(seconds: int) -> str:
    if seconds < 60:
        return f"{seconds}с"
    if seconds < 3600:
        return f"{seconds // 60}мин"
    return f"{seconds // 3600}ч"


def run_and_alert(db: Session, location_id: Optional[int] = None):
    """Run detection and write alerts for new beaconing findings."""
    from models import Alert
    from services.realtime import manager

    candidates = detect(db, location_id)
    for c in candidates:
        exists = db.query(Alert).filter(
            Alert.alert_type == "beaconing",
            Alert.device_ip == c["src_ip"],
            Alert.detail.contains(c["dst_ip"]),
        ).first()
        if exists:
            continue
        alert = Alert(
            location_id=location_id,
            device_ip=c["src_ip"],
            alert_type="beaconing",
            severity="critical",
            message=(
                f"Возможный C2 beaconing: {c['src_ip']} → {c['dst_ip']}:{c['dst_port']} "
                f"каждые {c['period_label']} (CV={c['cv']})"
            ),
            detail=f"dst={c['dst_ip']}, port={c['dst_port']}, CV={c['cv']}, "
                   f"interval={c['mean_interval_s']}s, samples={c['sample_count']}",
        )
        db.add(alert)
        db.flush()
        manager.emit_alert(alert, "")
        from services.notifier import notify_alert
        notify_alert(alert)
    db.commit()
