"""Compute a simple home-network health score (0–100) per location or global."""
from datetime import datetime, timedelta
from typing import Optional
from sqlalchemy.orm import Session
from models import Device, Alert
from schemas import NetworkScore


def compute_score(db: Session, location_id: Optional[int] = None) -> NetworkScore:
    def q(model):
        qq = db.query(model)
        if location_id is not None:
            qq = qq.filter(model.location_id == location_id)
        return qq

    total_devices = q(Device).count()
    new_devices = q(Device).filter(Device.is_new == True).count()  # noqa: E712
    unnamed = q(Device).filter(
        Device.friendly_name == None, Device.is_active == True  # noqa: E711
    ).count()

    since_24h = datetime.utcnow() - timedelta(hours=24)
    unread_alerts = q(Alert).filter(Alert.is_read == False).count()  # noqa: E712
    critical_alerts = q(Alert).filter(
        Alert.severity == "critical", Alert.timestamp >= since_24h
    ).count()
    warning_alerts = q(Alert).filter(
        Alert.severity == "warning", Alert.timestamp >= since_24h
    ).count()

    score = 100
    details: list[str] = []

    if new_devices:
        penalty = min(new_devices * 10, 30)
        score -= penalty
        details.append(f"{new_devices} новых устройств (−{penalty})")

    if critical_alerts:
        penalty = min(critical_alerts * 15, 40)
        score -= penalty
        details.append(f"{critical_alerts} критических событий за 24ч (−{penalty})")

    if warning_alerts:
        penalty = min(warning_alerts * 5, 20)
        score -= penalty
        details.append(f"{warning_alerts} предупреждений за 24ч (−{penalty})")

    if unnamed and total_devices and (unnamed / total_devices) > 0.5:
        score -= 5
        details.append(f"{unnamed} устройств без имени (−5)")

    score = max(0, score)
    grade = "A" if score >= 85 else "B" if score >= 70 else "C" if score >= 55 else "D" if score >= 40 else "F"

    return NetworkScore(
        score=score, grade=grade,
        new_devices=new_devices, unread_alerts=unread_alerts,
        critical_alerts=critical_alerts, unnamed_devices=unnamed,
        total_devices=total_devices,
        details=details if details else ["Всё выглядит нормально!"],
    )
