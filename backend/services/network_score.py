"""Compute a simple home-network health score (0–100)."""
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from models import Device, Alert
from schemas import NetworkScore


def compute_score(db: Session) -> NetworkScore:
    total_devices = db.query(Device).count()
    new_devices = db.query(Device).filter(Device.is_new == True).count()  # noqa: E712
    unnamed = db.query(Device).filter(
        Device.friendly_name == None, Device.is_active == True  # noqa: E711
    ).count()

    since_24h = datetime.utcnow() - timedelta(hours=24)
    unread_alerts = db.query(Alert).filter(Alert.is_read == False).count()  # noqa: E712
    critical_alerts = db.query(Alert).filter(
        Alert.severity == "critical",
        Alert.timestamp >= since_24h,
    ).count()
    warning_alerts = db.query(Alert).filter(
        Alert.severity == "warning",
        Alert.timestamp >= since_24h,
    ).count()

    # Start with 100 and deduct
    score = 100
    details: list[str] = []

    if new_devices:
        penalty = min(new_devices * 10, 30)
        score -= penalty
        details.append(f"{new_devices} new device(s) detected (−{penalty})")

    if critical_alerts:
        penalty = min(critical_alerts * 15, 40)
        score -= penalty
        details.append(f"{critical_alerts} critical alert(s) in 24h (−{penalty})")

    if warning_alerts:
        penalty = min(warning_alerts * 5, 20)
        score -= penalty
        details.append(f"{warning_alerts} warning alert(s) in 24h (−{penalty})")

    if unnamed and total_devices:
        ratio = unnamed / total_devices
        if ratio > 0.5:
            score -= 5
            details.append(f"{unnamed} devices without friendly name (−5)")

    score = max(0, score)

    if score >= 85:
        grade = "A"
    elif score >= 70:
        grade = "B"
    elif score >= 55:
        grade = "C"
    elif score >= 40:
        grade = "D"
    else:
        grade = "F"

    return NetworkScore(
        score=score,
        grade=grade,
        new_devices=new_devices,
        unread_alerts=unread_alerts,
        critical_alerts=critical_alerts,
        unnamed_devices=unnamed,
        total_devices=total_devices,
        details=details if details else ["Everything looks fine!"],
    )
