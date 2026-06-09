"""
Rule-based anomaly detection. No ML, no external calls.
All analysis is read-only over the local SQLite database.
"""
import logging
from datetime import datetime, timedelta, timezone
from collections import defaultdict

from sqlalchemy.orm import Session
from sqlalchemy import func

from models import Device, DNSQuery, Alert
from utils.suspicious_domains import is_suspicious, looks_like_dga

log = logging.getLogger("anomaly")

# --- Thresholds (tunable via env or settings later) ---
DNS_SPIKE_MULTIPLIER = 3.0       # current hour vs 7-day hourly average
NEW_DOMAIN_THRESHOLD = 30        # unique new domains in 1 hour = anomalous
UNUSUAL_HOUR_START = 2           # 02:00 local
UNUSUAL_HOUR_END = 5             # 05:00 local
PORT_SCAN_THRESHOLD = 20         # distinct IPs hit by a device in 5 min


def _already_alerted(db: Session, mac: str, alert_type: str, since: datetime) -> bool:
    return db.query(Alert).filter(
        Alert.device_mac == mac,
        Alert.alert_type == alert_type,
        Alert.timestamp >= since,
    ).first() is not None


def check_suspicious_domains(db: Session):
    """Alert on DNS queries to known-bad or DGA-looking domains in the last hour."""
    since = datetime.utcnow() - timedelta(hours=1)
    rows = db.query(DNSQuery).filter(DNSQuery.timestamp >= since).all()
    alerted: set[tuple[str, str]] = set()
    for row in rows:
        domain = row.domain
        mac = row.device_mac or "unknown"
        key = (mac, domain)
        if key in alerted:
            continue
        reason = None
        if is_suspicious(domain):
            reason = f"Query to known suspicious domain: {domain}"
        elif looks_like_dga(domain):
            reason = f"Possible DGA domain: {domain}"
        if reason and not _already_alerted(db, mac, "suspicious_domain", since):
            db.add(Alert(
                device_mac=mac,
                device_ip=row.device_ip,
                alert_type="suspicious_domain",
                severity="critical",
                message=reason,
                detail=f"Domain: {domain}",
            ))
            alerted.add(key)
    db.commit()


def check_dns_spike(db: Session):
    """Alert if a device's DNS query rate in the last hour is >> 7-day average."""
    now = datetime.utcnow()
    hour_ago = now - timedelta(hours=1)
    week_ago = now - timedelta(days=7)

    # Per-device count in last hour
    hourly = dict(
        db.query(DNSQuery.device_mac, func.count(DNSQuery.id))
        .filter(DNSQuery.timestamp >= hour_ago)
        .group_by(DNSQuery.device_mac)
        .all()
    )

    # Per-device average hourly rate over past 7 days
    weekly_total = dict(
        db.query(DNSQuery.device_mac, func.count(DNSQuery.id))
        .filter(DNSQuery.timestamp >= week_ago)
        .group_by(DNSQuery.device_mac)
        .all()
    )

    for mac, current_count in hourly.items():
        weekly_count = weekly_total.get(mac, 0)
        avg_hourly = weekly_count / (7 * 24) if weekly_count else 0
        if avg_hourly > 0 and current_count > avg_hourly * DNS_SPIKE_MULTIPLIER and current_count > 50:
            if not _already_alerted(db, mac or "unknown", "dns_spike", hour_ago):
                db.add(Alert(
                    device_mac=mac,
                    alert_type="dns_spike",
                    severity="warning",
                    message=f"Unusual DNS activity: {current_count} queries in the last hour (avg: {avg_hourly:.0f}/hr)",
                    detail=f"7-day average: {avg_hourly:.1f}/hr, current: {current_count}/hr",
                ))
    db.commit()


def check_new_domain_burst(db: Session):
    """Alert if a device contacts many domains it hasn't queried before."""
    now = datetime.utcnow()
    hour_ago = now - timedelta(hours=1)
    week_ago = now - timedelta(days=7)

    recent = db.query(DNSQuery.device_mac, DNSQuery.domain)\
        .filter(DNSQuery.timestamp >= hour_ago).all()
    historical = db.query(DNSQuery.device_mac, DNSQuery.domain)\
        .filter(DNSQuery.timestamp >= week_ago, DNSQuery.timestamp < hour_ago).all()

    seen: dict[str, set[str]] = defaultdict(set)
    for mac, domain in historical:
        seen[mac or "unknown"].add(domain)

    new_domains: dict[str, set[str]] = defaultdict(set)
    for mac, domain in recent:
        mac = mac or "unknown"
        if domain not in seen[mac]:
            new_domains[mac].add(domain)

    for mac, domains in new_domains.items():
        if len(domains) >= NEW_DOMAIN_THRESHOLD:
            if not _already_alerted(db, mac, "new_domain_burst", hour_ago):
                db.add(Alert(
                    device_mac=mac,
                    alert_type="new_domain_burst",
                    severity="warning",
                    message=f"Device contacted {len(domains)} previously unseen domains in 1 hour",
                    detail=f"Sample: {', '.join(list(domains)[:5])}",
                ))
    db.commit()


def check_unusual_time_activity(db: Session):
    """Alert if a device is active between UNUSUAL_HOUR_START and UNUSUAL_HOUR_END."""
    now = datetime.utcnow()
    hour_ago = now - timedelta(hours=1)
    current_hour = now.hour
    if not (UNUSUAL_HOUR_START <= current_hour < UNUSUAL_HOUR_END):
        return

    active_macs = db.query(DNSQuery.device_mac).filter(
        DNSQuery.timestamp >= hour_ago
    ).distinct().all()

    for (mac,) in active_macs:
        if mac is None:
            continue
        since_yesterday = now - timedelta(hours=24)
        if not _already_alerted(db, mac, "unusual_time", since_yesterday):
            dev = db.query(Device).filter(Device.mac == mac).first()
            name = (dev.friendly_name or dev.vendor or mac) if dev else mac
            db.add(Alert(
                device_mac=mac,
                alert_type="unusual_time",
                severity="info",
                message=f"Device '{name}' is active at unusual hours ({now.strftime('%H:%M')} UTC)",
                detail=f"Active at hour {current_hour}:00 UTC",
            ))
    db.commit()


def run_all_checks(db: Session):
    """Run every anomaly rule in sequence."""
    try:
        check_suspicious_domains(db)
    except Exception as e:
        log.error("check_suspicious_domains failed: %s", e)
    try:
        check_dns_spike(db)
    except Exception as e:
        log.error("check_dns_spike failed: %s", e)
    try:
        check_new_domain_burst(db)
    except Exception as e:
        log.error("check_new_domain_burst failed: %s", e)
    try:
        check_unusual_time_activity(db)
    except Exception as e:
        log.error("check_unusual_time_activity failed: %s", e)
    log.info("Anomaly checks complete")
