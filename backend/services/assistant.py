"""
Rule-based local assistant. No LLM, no external calls.
Supports per-location filtering via location_id.
"""
from datetime import datetime, timedelta
from typing import Optional
from sqlalchemy.orm import Session
from sqlalchemy import func
from models import Device, DNSQuery, Alert
from schemas import AssistantResponse


def answer(question: str, db: Session, location_id: Optional[int] = None) -> AssistantResponse:
    q = question.lower().strip()
    if any(k in q for k in ["медленн", "slow", "тормоз", "speed", "performance"]):
        return _why_slow(db, location_id)
    if any(k in q for k in ["новы", "new device", "joined", "подключил"]):
        return _new_devices(db, location_id)
    if any(k in q for k in ["подозр", "suspicious", "threat", "опасн", "угроз"]):
        return _suspicious_today(db, location_id)
    if any(k in q for k in ["активн", "active", "most queries", "top device", "кто больше всего"]):
        return _top_devices(db, location_id)
    if any(k in q for k in ["домен", "domain", "site", "сайт", "запрос"]):
        return _top_domains(db, location_id)
    if any(k in q for k in ["alert", "предупрежден", "алерт", "событи"]):
        return _recent_alerts(db, location_id)
    if any(k in q for k in ["устройств", "device", "сколько", "how many"]):
        return _device_summary(db, location_id)
    return AssistantResponse(
        answer="Я не понял вопрос. Попробуйте: «Почему интернет медленный?», «Есть ли новые устройства?», «Что подозрительного сегодня?», «Какие устройства самые активные?»",
    )


def _filt(query, model, location_id):
    if location_id is not None:
        return query.filter(model.location_id == location_id)
    return query


def _why_slow(db, loc_id):
    since = datetime.utcnow() - timedelta(hours=1)
    top_q = _filt(
        db.query(DNSQuery.device_mac, func.count(DNSQuery.id).label("cnt"))
          .filter(DNSQuery.timestamp >= since),
        DNSQuery, loc_id,
    ).group_by(DNSQuery.device_mac).order_by(func.count(DNSQuery.id).desc()).limit(3).all()

    active = _filt(db.query(Device).filter(Device.is_active == True), Device, loc_id).count()  # noqa: E712
    total_q = _filt(db.query(DNSQuery).filter(DNSQuery.timestamp >= since), DNSQuery, loc_id).count()

    lines = [f"Активных устройств: {active}. DNS-запросов за час: {total_q}."]
    data = [f"Активных устройств: {active}", f"DNS/час: {total_q}"]
    if top_q:
        lines.append("Самые активные устройства за час:")
        for mac, cnt in top_q:
            dev = db.query(Device).filter(Device.mac == mac).first() if mac else None
            name = (dev.friendly_name or dev.vendor or mac) if dev else (mac or "Неизвестно")
            lines.append(f"  • {name}: {cnt} запросов/час")
            data.append(f"{name}: {cnt}/час")

    spike = _filt(db.query(Alert).filter(Alert.alert_type == "dns_spike", Alert.timestamp >= since), Alert, loc_id).count()
    if spike:
        lines.append(f"⚠️ Обнаружено {spike} аномальных всплесков DNS.")
    elif total_q > 500:
        lines.append("Высокая DNS-активность — возможно, устройства обновляются.")
    else:
        lines.append("DNS-активность в норме. Проблема скорее на стороне провайдера.")
    return AssistantResponse(answer="\n".join(lines), data_points=data)


def _new_devices(db, loc_id):
    new = _filt(db.query(Device).filter(Device.is_new == True), Device, loc_id).all()  # noqa: E712
    if not new:
        return AssistantResponse(answer="Новых устройств не обнаружено.", data_points=["Новых: 0"])
    lines = [f"Обнаружено {len(new)} новых устройств:"]
    data = []
    for d in new:
        label = d.friendly_name or d.vendor or d.mac
        lines.append(f"  • {label} (MAC: {d.mac}, IP: {d.ip}) — впервые: {d.first_seen.strftime('%d.%m %H:%M')}")
        data.append(f"{label} ({d.mac})")
    lines.append("Рекомендую задать им понятные имена на вкладке «Устройства».")
    return AssistantResponse(answer="\n".join(lines), data_points=data)


def _suspicious_today(db, loc_id):
    since = datetime.utcnow() - timedelta(hours=24)
    alerts = _filt(
        db.query(Alert).filter(Alert.timestamp >= since, Alert.severity.in_(["warning", "critical"])),
        Alert, loc_id,
    ).order_by(Alert.timestamp.desc()).limit(10).all()
    if not alerts:
        return AssistantResponse(answer="За 24 часа подозрительных событий нет.", data_points=["Событий: 0"])
    lines = [f"За 24 часа: {len(alerts)} подозрительных событий:"]
    data = []
    for a in alerts:
        lines.append(f"  [{a.severity.upper()}] {a.message}")
        data.append(a.message)
    return AssistantResponse(answer="\n".join(lines), data_points=data)


def _top_devices(db, loc_id):
    since = datetime.utcnow() - timedelta(hours=24)
    top = _filt(
        db.query(DNSQuery.device_mac, func.count(DNSQuery.id).label("cnt"))
          .filter(DNSQuery.timestamp >= since),
        DNSQuery, loc_id,
    ).group_by(DNSQuery.device_mac).order_by(func.count(DNSQuery.id).desc()).limit(5).all()
    if not top:
        return AssistantResponse(answer="Нет DNS-данных за 24 часа.", data_points=[])
    lines = ["Самые активные устройства за 24 часа:"]
    data = []
    for mac, cnt in top:
        dev = db.query(Device).filter(Device.mac == mac).first() if mac else None
        name = (dev.friendly_name or dev.vendor or mac) if dev else (mac or "Неизвестно")
        lines.append(f"  • {name}: {cnt} DNS-запросов")
        data.append(f"{name}: {cnt}")
    return AssistantResponse(answer="\n".join(lines), data_points=data)


def _top_domains(db, loc_id):
    since = datetime.utcnow() - timedelta(hours=24)
    top = _filt(
        db.query(DNSQuery.domain, func.count(DNSQuery.id).label("cnt"))
          .filter(DNSQuery.timestamp >= since),
        DNSQuery, loc_id,
    ).group_by(DNSQuery.domain).order_by(func.count(DNSQuery.id).desc()).limit(10).all()
    if not top:
        return AssistantResponse(answer="Нет DNS-данных за 24 часа.", data_points=[])
    lines = ["Топ доменов за 24 часа:"]
    data = []
    for domain, cnt in top:
        lines.append(f"  • {domain}: {cnt} запросов")
        data.append(f"{domain}: {cnt}")
    return AssistantResponse(answer="\n".join(lines), data_points=data)


def _recent_alerts(db, loc_id):
    since = datetime.utcnow() - timedelta(hours=24)
    alerts = _filt(db.query(Alert).filter(Alert.timestamp >= since), Alert, loc_id)\
        .order_by(Alert.timestamp.desc()).limit(10).all()
    if not alerts:
        return AssistantResponse(answer="Событий за 24 часа нет.", data_points=[])
    lines = [f"Последние события ({len(alerts)}):"]
    data = []
    for a in alerts:
        lines.append(f"  [{a.severity.upper()}] {a.timestamp.strftime('%H:%M')} — {a.message}")
        data.append(a.message)
    return AssistantResponse(answer="\n".join(lines), data_points=data)


def _device_summary(db, loc_id):
    total = _filt(db.query(Device), Device, loc_id).count()
    active = _filt(db.query(Device).filter(Device.is_active == True), Device, loc_id).count()  # noqa: E712
    new = _filt(db.query(Device).filter(Device.is_new == True), Device, loc_id).count()  # noqa: E712
    unnamed = _filt(db.query(Device).filter(Device.friendly_name == None, Device.is_active == True), Device, loc_id).count()  # noqa: E711
    return AssistantResponse(
        answer=f"В сети: {total} устройств, активных: {active}.\nНовых: {new}. Без имени: {unnamed}.",
        data_points=[f"Всего: {total}", f"Активных: {active}", f"Новых: {new}", f"Без имени: {unnamed}"],
    )
