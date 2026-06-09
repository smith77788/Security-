"""
Rule-based local assistant — no LLM, no external calls.
Answers plain-language questions using queries against the local DB.
"""
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from sqlalchemy import func
from models import Device, DNSQuery, Alert
from schemas import AssistantResponse


def answer(question: str, db: Session) -> AssistantResponse:
    q = question.lower().strip()

    if any(k in q for k in ["медленн", "slow", "тормоз", "speed", "performance"]):
        return _why_slow(db)
    if any(k in q for k in ["новы", "new device", "joined", "подключил"]):
        return _new_devices(db)
    if any(k in q for k in ["подозр", "suspicious", "threat", "опасн", "угроз"]):
        return _suspicious_today(db)
    if any(k in q for k in ["активн", "active", "most queries", "top device", "кто больше всего"]):
        return _top_devices(db)
    if any(k in q for k in ["домен", "domain", "site", "сайт", "запрос"]):
        return _top_domains(db)
    if any(k in q for k in ["alert", "предупрежден", "алерт", "событи"]):
        return _recent_alerts(db)
    if any(k in q for k in ["устройств", "device", "сколько", "how many"]):
        return _device_summary(db)
    return AssistantResponse(
        answer="Я не понял вопрос. Попробуйте спросить: «Почему интернет медленный?», «Есть ли новые устройства?», «Что подозрительного сегодня?», «Какие устройства самые активные?»",
        data_points=[],
    )


def _why_slow(db: Session) -> AssistantResponse:
    since = datetime.utcnow() - timedelta(hours=1)
    top = (
        db.query(DNSQuery.device_mac, func.count(DNSQuery.id).label("cnt"))
        .filter(DNSQuery.timestamp >= since)
        .group_by(DNSQuery.device_mac)
        .order_by(func.count(DNSQuery.id).desc())
        .limit(3)
        .all()
    )
    active = db.query(Device).filter(Device.is_active == True).count()  # noqa: E712
    total_queries = db.query(DNSQuery).filter(DNSQuery.timestamp >= since).count()

    lines = [f"Активных устройств в сети: {active}. DNS-запросов за час: {total_queries}."]
    data = [f"Активных устройств: {active}", f"DNS-запросов за час: {total_queries}"]

    if top:
        lines.append("Наиболее активные устройства:")
        for mac, cnt in top:
            dev = db.query(Device).filter(Device.mac == mac).first() if mac else None
            name = (dev.friendly_name or dev.vendor or mac) if dev else (mac or "Неизвестно")
            lines.append(f"  • {name}: {cnt} запросов/час")
            data.append(f"{name}: {cnt} DNS/час")

    spike_alerts = db.query(Alert).filter(
        Alert.alert_type == "dns_spike", Alert.timestamp >= since
    ).count()
    if spike_alerts:
        lines.append(f"⚠️ Обнаружено {spike_alerts} аномальных всплесков DNS. Возможно, одно из устройств создаёт высокую нагрузку.")
    elif total_queries > 500:
        lines.append("Высокая DNS-активность. Проверьте, не работает ли на устройствах обновление ПО или синхронизация.")
    else:
        lines.append("DNS-активность в норме. Проблема со скоростью может быть на стороне провайдера.")

    return AssistantResponse(answer="\n".join(lines), data_points=data)


def _new_devices(db: Session) -> AssistantResponse:
    new = db.query(Device).filter(Device.is_new == True).all()  # noqa: E712
    if not new:
        return AssistantResponse(
            answer="Новых устройств не обнаружено. Все устройства в сети уже были зарегистрированы ранее.",
            data_points=["Новых устройств: 0"],
        )
    lines = [f"Обнаружено {len(new)} новых устройств:"]
    data = []
    for d in new:
        label = d.friendly_name or d.vendor or d.mac
        lines.append(f"  • {label} (MAC: {d.mac}, IP: {d.ip}) — впервые: {d.first_seen.strftime('%d.%m %H:%M')}")
        data.append(f"{label} ({d.mac})")
    lines.append("Рекомендую задать им понятные имена на вкладке «Устройства».")
    return AssistantResponse(answer="\n".join(lines), data_points=data)


def _suspicious_today(db: Session) -> AssistantResponse:
    since = datetime.utcnow() - timedelta(hours=24)
    alerts = db.query(Alert).filter(
        Alert.timestamp >= since,
        Alert.severity.in_(["warning", "critical"]),
    ).order_by(Alert.timestamp.desc()).limit(10).all()

    if not alerts:
        return AssistantResponse(
            answer="За последние 24 часа подозрительных событий не обнаружено. Сеть выглядит нормально.",
            data_points=["Подозрительных событий: 0"],
        )
    lines = [f"За 24 часа найдено {len(alerts)} подозрительных событий:"]
    data = []
    for a in alerts:
        lines.append(f"  [{a.severity.upper()}] {a.message}")
        data.append(a.message)
    return AssistantResponse(answer="\n".join(lines), data_points=data)


def _top_devices(db: Session) -> AssistantResponse:
    since = datetime.utcnow() - timedelta(hours=24)
    top = (
        db.query(DNSQuery.device_mac, func.count(DNSQuery.id).label("cnt"))
        .filter(DNSQuery.timestamp >= since)
        .group_by(DNSQuery.device_mac)
        .order_by(func.count(DNSQuery.id).desc())
        .limit(5)
        .all()
    )
    if not top:
        return AssistantResponse(answer="Нет данных DNS за последние 24 часа.", data_points=[])
    lines = ["Самые активные устройства за 24 часа:"]
    data = []
    for mac, cnt in top:
        dev = db.query(Device).filter(Device.mac == mac).first() if mac else None
        name = (dev.friendly_name or dev.vendor or mac) if dev else (mac or "Неизвестно")
        lines.append(f"  • {name}: {cnt} DNS-запросов")
        data.append(f"{name}: {cnt}")
    return AssistantResponse(answer="\n".join(lines), data_points=data)


def _top_domains(db: Session) -> AssistantResponse:
    since = datetime.utcnow() - timedelta(hours=24)
    top = (
        db.query(DNSQuery.domain, func.count(DNSQuery.id).label("cnt"))
        .filter(DNSQuery.timestamp >= since)
        .group_by(DNSQuery.domain)
        .order_by(func.count(DNSQuery.id).desc())
        .limit(10)
        .all()
    )
    if not top:
        return AssistantResponse(answer="Нет DNS-данных за последние 24 часа.", data_points=[])
    lines = ["Топ доменов за 24 часа:"]
    data = []
    for domain, cnt in top:
        lines.append(f"  • {domain}: {cnt} запросов")
        data.append(f"{domain}: {cnt}")
    return AssistantResponse(answer="\n".join(lines), data_points=data)


def _recent_alerts(db: Session) -> AssistantResponse:
    since = datetime.utcnow() - timedelta(hours=24)
    alerts = db.query(Alert).filter(Alert.timestamp >= since)\
        .order_by(Alert.timestamp.desc()).limit(10).all()
    if not alerts:
        return AssistantResponse(answer="Событий за последние 24 часа нет.", data_points=[])
    lines = [f"Последние события ({len(alerts)}):"]
    data = []
    for a in alerts:
        lines.append(f"  [{a.severity.upper()}] {a.timestamp.strftime('%H:%M')} — {a.message}")
        data.append(a.message)
    return AssistantResponse(answer="\n".join(lines), data_points=data)


def _device_summary(db: Session) -> AssistantResponse:
    total = db.query(Device).count()
    active = db.query(Device).filter(Device.is_active == True).count()  # noqa: E712
    new = db.query(Device).filter(Device.is_new == True).count()  # noqa: E712
    unnamed = db.query(Device).filter(
        Device.friendly_name == None, Device.is_active == True  # noqa: E711
    ).count()
    answer = (
        f"В сети всего {total} устройств, из них активных: {active}.\n"
        f"Новых устройств: {new}.\n"
        f"Без понятного имени: {unnamed}."
    )
    return AssistantResponse(
        answer=answer,
        data_points=[f"Всего: {total}", f"Активных: {active}", f"Новых: {new}", f"Без имени: {unnamed}"],
    )
