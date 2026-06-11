"""
Rule-based anomaly detection. No ML, no external calls.
All analysis is read-only over the local SQLite database.
"""
import logging
from datetime import datetime, timedelta
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
PORT_SCAN_MIN_PORTS = 15         # distinct dst ports hit by a device in 5 min
EXFIL_THRESHOLD_MB = 100         # MB uploaded in 1 hour → suspicious
EXFIL_THRESHOLD_BYTES = EXFIL_THRESHOLD_MB * 1024 * 1024


def _already_alerted(db: Session, mac: str, alert_type: str, since: datetime) -> bool:
    return db.query(Alert).filter(
        Alert.device_mac == mac,
        Alert.alert_type == alert_type,
        Alert.timestamp >= since,
    ).first() is not None


def _fire(db: Session, alert: Alert) -> None:
    """Save an alert and dispatch notifications (Telegram, WebSocket)."""
    db.add(alert)
    db.flush()
    try:
        from services.notifier import notify_alert
        notify_alert(alert)
    except Exception as e:
        log.debug("Notifier error: %s", e)


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
            reason = f"Запрос к известному вредоносному домену: {domain}"
        elif looks_like_dga(domain):
            reason = f"Возможный DGA-домен: {domain}"
        if reason and not _already_alerted(db, mac, "suspicious_domain", since):
            _fire(db, Alert(
                location_id=row.location_id,
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

    hourly = dict(
        db.query(DNSQuery.device_mac, func.count(DNSQuery.id))
        .filter(DNSQuery.timestamp >= hour_ago)
        .group_by(DNSQuery.device_mac)
        .all()
    )
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
                _fire(db, Alert(
                    device_mac=mac,
                    alert_type="dns_spike",
                    severity="warning",
                    message=f"Всплеск DNS: {current_count} запросов/час (норма {avg_hourly:.0f}/час)",
                    detail=f"7-дневная норма: {avg_hourly:.1f}/час, текущий: {current_count}/час",
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
                _fire(db, Alert(
                    device_mac=mac,
                    alert_type="new_domain_burst",
                    severity="warning",
                    message=f"Устройство обратилось к {len(domains)} новым доменам за 1 час",
                    detail=f"Примеры: {', '.join(list(domains)[:5])}",
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
            _fire(db, Alert(
                device_mac=mac,
                alert_type="unusual_time",
                severity="info",
                message=f"Устройство '{name}' активно в ночное время ({now.strftime('%H:%M')} UTC)",
                detail=f"Активно в {current_hour}:00 UTC",
            ))
    db.commit()


def check_port_scan(db: Session):
    """Alert if a single device connects to many distinct ports within 5 minutes."""
    from models import Connection
    since = datetime.utcnow() - timedelta(minutes=5)
    rows = (
        db.query(
            Connection.src_ip,
            func.count(func.distinct(Connection.dst_port)).label("port_count"),
        )
        .filter(Connection.last_seen >= since)
        .group_by(Connection.src_ip)
        .having(func.count(func.distinct(Connection.dst_port)) >= PORT_SCAN_MIN_PORTS)
        .all()
    )
    for src_ip, port_count in rows:
        dev = db.query(Device).filter(Device.ip == src_ip).first()
        mac = dev.mac if dev else "unknown"
        alert_since = datetime.utcnow() - timedelta(hours=1)
        if not _already_alerted(db, mac, "port_scan", alert_since):
            _fire(db, Alert(
                location_id=dev.location_id if dev else None,
                device_mac=mac,
                device_ip=src_ip,
                alert_type="port_scan",
                severity="critical",
                message=f"Возможное сканирование портов: {src_ip} → {port_count} портов за 5 мин",
                detail=f"Уникальных портов назначения: {port_count} за последние 5 минут",
            ))
    db.commit()


def check_large_upload(db: Session):
    """Alert if a device uploads an unusually large amount of data in one hour."""
    from models import Connection
    since = datetime.utcnow() - timedelta(hours=1)
    rows = (
        db.query(
            Connection.src_ip,
            func.sum(Connection.bytes_out).label("total_out"),
        )
        .filter(Connection.last_seen >= since)
        .group_by(Connection.src_ip)
        .having(func.sum(Connection.bytes_out) >= EXFIL_THRESHOLD_BYTES)
        .all()
    )
    for src_ip, total_out in rows:
        dev = db.query(Device).filter(Device.ip == src_ip).first()
        mac = dev.mac if dev else "unknown"
        alert_since = datetime.utcnow() - timedelta(hours=2)
        if not _already_alerted(db, mac, "large_upload", alert_since):
            mb = (total_out or 0) / (1024 * 1024)
            _fire(db, Alert(
                location_id=dev.location_id if dev else None,
                device_mac=mac,
                device_ip=src_ip,
                alert_type="large_upload",
                severity="warning",
                message=f"Аномально большой upload: {src_ip} → {mb:.0f} МБ за 1 час",
                detail=f"Всего отправлено: {total_out:,} байт ({mb:.1f} МБ) за последний час",
            ))
    db.commit()


def check_blocked_devices(db: Session):
    """Alert when a blocked device is seen active on the network."""
    from models import BlockedDevice
    now = datetime.utcnow()
    hour_ago = now - timedelta(hours=1)
    blocked = db.query(BlockedDevice).all()
    for bd in blocked:
        dev = db.query(Device).filter(Device.mac == bd.mac).first()
        if not dev or not dev.last_seen or dev.last_seen < hour_ago:
            continue
        alert_since = now - timedelta(hours=6)
        if not _already_alerted(db, bd.mac, "blocked_device", alert_since):
            _fire(db, Alert(
                location_id=dev.location_id,
                device_mac=bd.mac,
                device_ip=dev.ip,
                alert_type="blocked_device",
                severity="critical",
                message=f"Заблокированное устройство активно в сети: {dev.friendly_name or dev.vendor or bd.mac}",
                detail=f"MAC: {bd.mac}, IP: {dev.ip}, Причина блокировки: {bd.reason or 'вручную'}",
            ))
    db.commit()


ALL_CHECKS = [
    check_suspicious_domains,
    check_dns_spike,
    check_new_domain_burst,
    check_unusual_time_activity,
    check_port_scan,
    check_large_upload,
    check_blocked_devices,
]


def run_all_checks(db: Session):
    """Run every anomaly rule in sequence."""
    for check_fn in ALL_CHECKS:
        try:
            check_fn(db)
        except Exception as e:
            log.error("%s failed: %s", check_fn.__name__, e)
    log.info("Anomaly checks complete (%d rules)", len(ALL_CHECKS))
