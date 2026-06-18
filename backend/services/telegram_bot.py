"""
Interactive Telegram bot — remote control for FAMILY SECURITY.

Long-polling (getUpdates) in a daemon thread: works behind NAT,
no webhook / public IP needed. Access is restricted to the single
chat_id configured in settings (telegram_chat_id).

Menu:
  📊 Статус      — security score + per-location summary
  🔔 События     — recent unread alerts
  📡 Устройства  — recently active devices
  🆕 Новые       — unacknowledged devices
  🛡 Угрозы      — threat connections + intel feed status
  📈 Трафик      — top bandwidth consumers
  ⚙️ Действия    — mark alerts read, refresh feeds, beaconing scan
"""
import html
import logging
import threading
import time
from datetime import datetime, timedelta

import requests as http

log = logging.getLogger("tg-bot")

API = "https://api.telegram.org/bot{token}/{method}"
POLL_TIMEOUT = 50          # long-poll seconds
RETRY_DELAY = 15           # seconds to wait when token missing / network error


def _esc(s) -> str:
    return html.escape(str(s)) if s is not None else "—"


def _fmt_bytes(b) -> str:
    b = b or 0
    if b >= 1 << 30: return f"{b / (1 << 30):.1f} ГБ"
    if b >= 1 << 20: return f"{b / (1 << 20):.1f} МБ"
    if b >= 1 << 10: return f"{b / (1 << 10):.0f} КБ"
    return f"{b} Б"


_PORT_LABELS = {
    "22": "Linux/Роутер",  "23": "Telnet-устройство",
    "80": "Веб-устройство", "443": "Веб-устройство",
    "8080": "Веб-сервер",  "8443": "Веб-сервер",
    "554": "IP-камера",    "7547": "Роутер (TR-069)",
    "1883": "IoT (MQTT)",  "53": "DNS-сервер",
    "21": "FTP-сервер",    "8181": "Умный дом",
}

_METHOD_ICONS = {
    "ssdp": "📺", "mdns": "📱", "netbios": "💻",
    "arp": "🔌",  "tcp": "🌐",
}

_PORT_ICONS = {
    "22": "🖥", "23": "📡", "80": "🌐", "443": "🌐",
    "8080": "🌐", "554": "📹", "7547": "📡", "1883": "🔌",
    "53": "🔍",
}


def _device_display(d, gateway: str) -> tuple:
    """Return (icon, label) for a device."""
    ip = d.ip or ""
    vendor = d.vendor or ""

    # Gateway / router
    if ip == gateway or ip.endswith(".1"):
        return "🌐", "Роутер"

    # User gave a name → use it
    if d.friendly_name:
        return "📱", d.friendly_name

    # Hostname resolved
    if d.hostname:
        return "💻", d.hostname

    # Vendor from OUI (real MAC)
    if vendor and not vendor.startswith("tcp:") and vendor not in _METHOD_ICONS:
        return "🔌", vendor

    # TCP scan with port info
    if vendor.startswith("tcp:"):
        port = vendor.split(":")[1]
        icon = _PORT_ICONS.get(port, "📱")
        label = _PORT_LABELS.get(port, f"Устройство (порт {port})")
        return icon, label

    # Method-based label
    if vendor in _METHOD_ICONS:
        return _METHOD_ICONS[vendor], vendor.upper() + "-устройство"

    return "📱", ip


MAIN_MENU = {
    "inline_keyboard": [
        [{"text": "🏠 Моя сеть", "callback_data": "my_network"}],
        [{"text": "📊 Статус", "callback_data": "status"},
         {"text": "🔔 События", "callback_data": "alerts"}],
        [{"text": "📡 Устройства", "callback_data": "devices"},
         {"text": "🆕 Новые", "callback_data": "new_devices"}],
        [{"text": "🛡 Угрозы", "callback_data": "threats"},
         {"text": "📈 Трафик", "callback_data": "traffic"}],
        [{"text": "🔌 Соединения", "callback_data": "connections"},
         {"text": "🌐 DNS", "callback_data": "dns"}],
        [{"text": "⚙️ Действия", "callback_data": "actions"}],
    ]
}

ACTIONS_MENU = {
    "inline_keyboard": [
        [{"text": "✅ Прочитать все события", "callback_data": "read_all"}],
        [{"text": "🔄 Обновить фиды угроз", "callback_data": "refresh_intel"}],
        [{"text": "🎯 Скан C2-маяков", "callback_data": "beacon_scan"}],
        [{"text": "📡 Сканировать сеть сейчас", "callback_data": "scan_now"}],
        [{"text": "📡 Настроить OpenWrt роутер", "callback_data": "openwrt_setup"}],
        [{"text": "🗑 Очистить все данные", "callback_data": "reset_confirm"}],
        [{"text": "⬅️ Меню", "callback_data": "menu"}],
    ]
}

RESET_CONFIRM_MENU = {
    "inline_keyboard": [
        [{"text": "⚠️ ДА, удалить все данные", "callback_data": "reset_execute"}],
        [{"text": "❌ Отмена", "callback_data": "menu"}],
    ]
}

BACK_MENU = {"inline_keyboard": [[{"text": "⬅️ Меню", "callback_data": "menu"}]]}


class TelegramBot:
    def __init__(self):
        self._thread = None
        self._stop = threading.Event()
        self._offset = 0
        self._token = ""
        self._chat_id = ""
        self._waiting_for: dict = {}   # chat_id → {"action": str, "data": dict}

    # ── Telegram API helpers ──────────────────────────────────────────────────

    def _call(self, method: str, **params):
        try:
            r = http.post(API.format(token=self._token, method=method),
                          json=params, timeout=POLL_TIMEOUT + 10)
            data = r.json()
            if not data.get("ok"):
                log.warning("Telegram %s: %s", method, data.get("description"))
            return data
        except Exception as e:
            log.debug("Telegram %s failed: %s", method, e)
            return {"ok": False}

    def _send(self, chat_id, text, keyboard=None):
        params = {"chat_id": chat_id, "text": text, "parse_mode": "HTML"}
        if keyboard:
            params["reply_markup"] = keyboard
        return self._call("sendMessage", **params)

    # ── Data screens (each returns text + keyboard) ───────────────────────────

    def _screen_status(self):
        from database import SessionLocal
        from models import Location, Device, Alert
        db = SessionLocal()
        try:
            locs = db.query(Location).all()
            total_dev = db.query(Device).count()
            new_dev = db.query(Device).filter(Device.is_new == True).count()  # noqa: E712
            unread = db.query(Alert).filter(Alert.is_read == False).count()   # noqa: E712
            critical = db.query(Alert).filter(
                Alert.is_read == False,  # noqa: E712
                Alert.severity == "critical",
            ).count()

            lines = ["<b>📊 СТАТУС СИСТЕМЫ</b>\n"]
            online = sum(1 for l in locs if l.is_online)
            lines.append(f"Локации: {online}/{len(locs)} онлайн")
            for l in locs:
                dot = "🟢" if l.is_online else "⚪️"
                lines.append(f"  {dot} {l.icon} {_esc(l.name)}")
            lines.append(f"\nУстройств: <b>{total_dev}</b> (новых: {new_dev})")
            lines.append(f"Непрочитанных событий: <b>{unread}</b>")
            if critical:
                lines.append(f"🚨 Критических: <b>{critical}</b>")
            else:
                lines.append("✅ Критических угроз нет")
            return "\n".join(lines), MAIN_MENU
        finally:
            db.close()

    def _screen_alerts(self):
        from database import SessionLocal
        from models import Alert
        db = SessionLocal()
        try:
            rows = (db.query(Alert)
                    .filter(Alert.is_read == False)  # noqa: E712
                    .order_by(Alert.timestamp.desc())
                    .limit(8).all())
            if not rows:
                return "✅ Непрочитанных событий нет", BACK_MENU
            icons = {"critical": "🚨", "warning": "⚠️", "info": "ℹ️"}
            lines = [f"<b>🔔 СОБЫТИЯ</b> (последние {len(rows)})\n"]
            for a in rows:
                ts = a.timestamp.strftime("%d.%m %H:%M") if a.timestamp else ""
                lines.append(f"{icons.get(a.severity, '🔔')} <i>{ts}</i>\n{_esc(a.message)}\n")
            kb = {"inline_keyboard": [
                [{"text": "✅ Прочитать все", "callback_data": "read_all"}],
                [{"text": "⬅️ Меню", "callback_data": "menu"}],
            ]}
            return "\n".join(lines), kb
        finally:
            db.close()

    def _screen_devices(self):
        from database import SessionLocal
        from models import Device
        from services.auto_config import get as net_cfg
        db = SessionLocal()
        try:
            rows = (db.query(Device)
                    .filter(Device.is_active == True)  # noqa: E712
                    .order_by(Device.last_seen.desc())
                    .limit(12).all())
            if not rows:
                return "Устройств не найдено", BACK_MENU

            gateway = net_cfg().get("gateway", "")
            lines = [f"<b>📡 УСТРОЙСТВА</b> ({len(rows)} активных)\n"]
            btn_rows = []
            for d in rows:
                icon, label = _device_display(d, gateway)
                badge = " 🆕" if d.is_new else ""
                lines.append(f"{icon} <b>{_esc(label)}</b>{badge}  <code>{_esc(d.ip)}</code>")
                btn_rows.append([
                    {"text": f"✏️ {d.friendly_name or d.ip}", "callback_data": f"name_dev:{d.mac}"},
                    {"text": "ℹ️", "callback_data": f"dev_detail:{d.mac}"},
                ])

            lines.append("\n<i>Нажми ✏️ чтобы назвать устройство</i>")
            btn_rows.append([{"text": "⬅️ Меню", "callback_data": "menu"}])
            return "\n".join(lines), {"inline_keyboard": btn_rows}
        finally:
            db.close()

    def _screen_new_devices(self):
        from database import SessionLocal
        from models import Device
        db = SessionLocal()
        try:
            rows = (db.query(Device)
                    .filter(Device.is_new == True)  # noqa: E712
                    .order_by(Device.first_seen.desc())
                    .limit(10).all())
            if not rows:
                return "✅ Новых (неподтверждённых) устройств нет", BACK_MENU
            lines = [f"<b>🆕 НОВЫЕ УСТРОЙСТВА</b> ({len(rows)})\n"]
            for d in rows:
                seen = d.first_seen.strftime("%d.%m %H:%M") if d.first_seen else ""
                lines.append(
                    f"• {_esc(d.vendor or 'Unknown')} — <code>{_esc(d.ip)}</code>\n"
                    f"   {_esc(d.mac)} · появилось {seen}"
                )
            lines.append("\nПодтвердить устройства можно в веб-интерфейсе → Устройства")
            return "\n".join(lines), BACK_MENU
        finally:
            db.close()

    def _screen_threats(self):
        from database import SessionLocal
        from models import Connection
        from services.threat_intel import status as ti_status
        db = SessionLocal()
        try:
            since = datetime.utcnow() - timedelta(hours=24)
            rows = (db.query(Connection)
                    .filter(Connection.is_threat == True,  # noqa: E712
                            Connection.last_seen >= since)
                    .order_by(Connection.last_seen.desc())
                    .limit(8).all())
            st = ti_status()
            lines = ["<b>🛡 УГРОЗЫ (24ч)</b>\n"]
            if not rows:
                lines.append("✅ Подключений к вредоносным IP не обнаружено\n")
            else:
                for c in rows:
                    lines.append(
                        f"🚨 <code>{_esc(c.src_ip)}</code> → <code>{_esc(c.dst_ip)}:{c.dst_port}</code>\n"
                        f"   {_esc(c.country or '?')} · {_esc(c.org or '')} · {_esc(c.threat_reason or '')}"
                    )
                lines.append("")
            lines.append(
                f"База угроз: {st.get('bad_ips', 0):,} IP · "
                f"{st.get('bad_domains', 0):,} доменов · "
                f"{st.get('tor_exits', 0):,} Tor"
            )
            return "\n".join(lines), BACK_MENU
        finally:
            db.close()

    def _screen_traffic(self):
        from database import SessionLocal
        from services.bandwidth_tracker import get_top_consumers, get_interface_delta
        db = SessionLocal()
        try:
            delta = get_interface_delta(db, hours=1)
            rows = get_top_consumers(db, minutes=60)

            if not delta and not rows:
                return (
                    "📈 <b>ТРАФИК</b>\n\n"
                    "Данных пока нет — счётчики собираются каждую минуту.\n"
                    "Подожди 2–3 минуты и повтори.",
                    BACK_MENU
                )

            lines = ["<b>📈 ТРАФИК</b>\n"]
            if delta:
                lines.append(
                    f"🌐 Весь интерфейс за 1 ч:\n"
                    f"   ↑ {_fmt_bytes(delta['bytes_up'])}  "
                    f"↓ {_fmt_bytes(delta['bytes_down'])}\n"
                )
            if rows:
                lines.append("Топ устройств:")
                for r in rows[:8]:
                    lines.append(
                        f"• {_esc(r['name'])}\n"
                        f"   ↑ {_fmt_bytes(r['bytes_up'])} · ↓ {_fmt_bytes(r['bytes_down'])}"
                    )
            else:
                lines.append(
                    "<i>Детальная статистика по устройствам появится\n"
                    "когда в сети зафиксируются соединения.</i>"
                )
            return "\n".join(lines), BACK_MENU
        finally:
            db.close()

    def _screen_connections(self):
        """Active TCP connections from THIS monitoring device (/proc/net/tcp)."""
        import socket as _sock
        conns: dict[str, int] = {}
        for path in ("/proc/net/tcp", "/proc/net/tcp6"):
            try:
                with open(path) as f:
                    for line in f.readlines()[1:]:
                        parts = line.split()
                        if len(parts) < 4 or parts[3] != "01":  # 01 = ESTABLISHED
                            continue
                        rem = parts[2]
                        ip_hex, port_hex = rem.split(":")
                        port = int(port_hex, 16)
                        if len(ip_hex) == 8:  # IPv4
                            n = int(ip_hex, 16)
                            ip = f"{n&0xFF}.{(n>>8)&0xFF}.{(n>>16)&0xFF}.{(n>>24)&0xFF}"
                            if ip.startswith(("127.", "192.168.", "10.", "172.")):
                                continue  # skip local
                            try:
                                host = _sock.gethostbyaddr(ip)[0]
                            except Exception:
                                host = ip
                            conns[host] = port
            except Exception:
                pass
        if not conns:
            return (
                "🔌 <b>СОЕДИНЕНИЯ МОНИТОРА</b>\n\n"
                "Нет активных внешних TCP-соединений.\n\n"
                "<i>Здесь видны только соединения самого телефона-монитора.\n"
                "Для мониторинга других устройств нужен доступ к роутеру.</i>",
                BACK_MENU
            )
        lines = [f"<b>🔌 СОЕДИНЕНИЯ МОНИТОРА</b> ({len(conns)})\n",
                 "<i>Активные внешние TCP с этого устройства:</i>\n"]
        for host, port in list(conns.items())[:15]:
            lines.append(f"• <code>{_esc(host)}</code> :{port}")
        return "\n".join(lines), BACK_MENU

    def _screen_dns(self):
        from database import SessionLocal
        from models import DNSQuery
        db = SessionLocal()
        try:
            total = db.query(DNSQuery).count()
            if total == 0:
                return (
                    "🌐 <b>DNS-ЗАПРОСЫ</b>\n\n"
                    "Записей нет — DNS-перехват не активен.\n\n"
                    "<b>Чтобы видеть сайты всех устройств</b>, нужно одно из:\n"
                    "• Raspberry Pi как шлюз сети (~$35)\n"
                    "• Настроить роутер использовать этот телефон как DNS\n"
                    "• Телефон как точка доступа (все девайсы через него)\n\n"
                    "<i>В текущей конфигурации телефон — клиент сети,\n"
                    "а не шлюз, поэтому чужой трафик не виден.</i>",
                    BACK_MENU
                )
            from datetime import datetime, timedelta
            since = datetime.utcnow() - timedelta(hours=24)
            rows = (db.query(DNSQuery)
                    .filter(DNSQuery.timestamp >= since)
                    .order_by(DNSQuery.timestamp.desc())
                    .limit(20).all())
            lines = [f"<b>🌐 DNS-ЗАПРОСЫ</b> (за 24ч, всего: {total})\n"]
            seen = {}
            for q in rows:
                key = q.domain
                if key not in seen:
                    seen[key] = q.device_ip or "?"
                    lines.append(f"• <code>{_esc(q.domain)}</code> — {_esc(q.device_ip or '?')}")
            return "\n".join(lines), BACK_MENU
        finally:
            db.close()

    def _screen_device_detail(self, mac: str):
        from database import SessionLocal
        from models import Device, DNSQuery, Connection
        from services.auto_config import get as net_cfg
        db = SessionLocal()
        try:
            d = db.query(Device).filter(Device.mac == mac).first()
            if not d:
                return "❌ Устройство не найдено", BACK_MENU

            gateway = net_cfg().get("gateway", "")
            icon, label = _device_display(d, gateway)
            badge = " 🆕" if d.is_new else ""

            lines = [f"<b>{icon} {_esc(label)}</b>{badge}\n"]
            lines.append(f"IP: <code>{_esc(d.ip)}</code>")
            if d.hostname:
                lines.append(f"Хост: <code>{_esc(d.hostname)}</code>")
            if d.vendor:
                lines.append(f"Тип: {_esc(d.vendor)}")
            lines.append(f"MAC: <code>{_esc(d.mac)}</code>")
            if d.first_seen:
                lines.append(f"Первый раз: {d.first_seen.strftime('%d.%m %H:%M')}")
            if d.last_seen:
                lines.append(f"Последний раз: {d.last_seen.strftime('%d.%m %H:%M')}")

            # DNS queries from this device
            dns_count = db.query(DNSQuery).filter(DNSQuery.device_ip == d.ip).count()
            conn_count = db.query(Connection).filter(Connection.src_ip == d.ip).count()
            threat_count = db.query(Connection).filter(
                Connection.src_ip == d.ip,
                Connection.is_threat == True  # noqa: E712
            ).count()

            lines.append(f"\nDNS-запросов: {dns_count}")
            lines.append(f"Соединений: {conn_count}")
            if threat_count:
                lines.append(f"🚨 Угроз: {threat_count}")
            else:
                lines.append("✅ Угроз не обнаружено")

            kb = {"inline_keyboard": [
                [{"text": f"✏️ Переименовать", "callback_data": f"name_dev:{d.mac}"}],
                [{"text": "📡 Устройства", "callback_data": "devices"}],
                [{"text": "⬅️ Меню", "callback_data": "menu"}],
            ]}
            return "\n".join(lines), kb
        finally:
            db.close()

    # ── Моя сеть ─────────────────────────────────────────────────────────────

    def _screen_my_network(self):
        from database import SessionLocal
        from models import Location, Device
        from services.auto_config import get as net_cfg
        db = SessionLocal()
        try:
            loc = db.query(Location).first()
            total = db.query(Device).count()
            active = db.query(Device).filter(Device.is_active == True).count()  # noqa: E712
            new = db.query(Device).filter(Device.is_new == True).count()        # noqa: E712
        finally:
            db.close()

        net = net_cfg()
        loc_name = loc.name if loc else "Не настроено"
        loc_id = loc.id if loc else None

        lines = [
            f"<b>🏠 МОЯ СЕТЬ</b>\n",
            f"📍 Название: <b>{_esc(loc_name)}</b>",
            f"🌐 Интерфейс: <code>{_esc(net.get('interface', '?'))}</code>",
            f"📶 Мой IP: <code>{_esc(net.get('my_ip', '?'))}</code>",
            f"🔀 Подсеть: <code>{_esc(net.get('subnet', '?'))}</code>",
            f"🚪 Роутер: <code>{_esc(net.get('gateway', '?'))}</code>",
            f"\n📱 Устройств: <b>{total}</b> (активных: {active}, новых: {new})",
        ]

        kb = {"inline_keyboard": [
            [{"text": "✏️ Переименовать сеть", "callback_data": f"rename_start:{loc_id}"}],
            [{"text": "📡 Сканировать сейчас", "callback_data": "scan_now"}],
            [{"text": "⬅️ Меню", "callback_data": "menu"}],
        ]}
        return "\n".join(lines), kb

    def _screen_openwrt_status(self):
        from services.openwrt_client import test_connection, _cfg, get_public_key
        from services.syslog_server import get_port
        from database import SessionLocal
        from models import AppSetting, DNSQuery, Device

        db = SessionLocal()
        try:
            row = db.query(AppSetting).filter(AppSetting.key == "openwrt_host").first()
            host = (row.value if row else "") or _cfg.get("host", "")
            dns_count = db.query(DNSQuery).count()
            # Count devices with real MACs (not fake 02:00:...)
            real_devs = db.query(Device).filter(
                ~Device.mac.like("02:00:%")
            ).count()
        finally:
            db.close()

        if not host:
            return self._action_openwrt_setup_start()

        ok, msg = test_connection()
        lines = [
            "<b>📡 OPENWRT РОУТЕР</b>\n",
            f"Хост: <code>{_esc(host)}</code>",
            f"Статус: {msg}",
            f"\nDNS-запросов в базе: <b>{dns_count}</b>",
            f"Устройств с реальными MAC: <b>{real_devs}</b>",
            f"Syslog порт: <b>{get_port()}</b>",
        ]
        kb = {"inline_keyboard": [
            [{"text": "🔄 Тест соединения", "callback_data": "openwrt_test"}],
            [{"text": "📋 Команды для роутера", "callback_data": "openwrt_commands"}],
            [{"text": "⚙️ Изменить IP роутера", "callback_data": "openwrt_setup"}],
            [{"text": "⬅️ Меню", "callback_data": "menu"}],
        ]}
        return "\n".join(lines), kb

    def _action_openwrt_setup_start(self):
        self._waiting_for[self._chat_id] = {"action": "openwrt_host"}
        return (
            "📡 <b>Настройка OpenWrt роутера</b>\n\n"
            "Введи IP-адрес роутера (обычно 192.168.1.1):\n\n"
            "<i>Это нужно один раз. После настройки система будет видеть:\n"
            "• Реальные MAC-адреса всех устройств\n"
            "• DNS-запросы каждого устройства\n"
            "• Сайты в реальном времени\n\n"
            "Отправь /отмена чтобы выйти</i>",
            None,
        )

    def _handle_openwrt_host(self, host: str):
        host = host.strip()
        # Basic IP/hostname validation
        import re
        if not re.match(r"^[\d\.]+$|^[a-zA-Z0-9\-\.]+$", host):
            return "❌ Неверный формат IP. Введи что-то вроде 192.168.1.1", None
        from services.openwrt_client import save_to_settings, configure, get_public_key
        from services.auto_config import get as net_cfg
        save_to_settings(host)
        configure(host=host)
        pub_key = get_public_key()
        net = net_cfg()
        phone_ip = net.get("my_ip", "192.168.1.104")
        return (
            f"✅ Роутер сохранён: <code>{_esc(host)}</code>\n\n"
            f"<b>Теперь выполни эти команды на роутере</b>\n"
            f"(через SSH из Termux или через LuCI → System → Terminal):\n\n"
            f"<code>ssh root@{_esc(host)}</code>\n\n"
            f"Затем вставь команды — нажми кнопку ниже:",
            {"inline_keyboard": [
                [{"text": "📋 Показать команды для роутера", "callback_data": "openwrt_commands"}],
                [{"text": "🔄 Проверить соединение", "callback_data": "openwrt_test"}],
                [{"text": "⬅️ Меню", "callback_data": "menu"}],
            ]},
        )

    def _action_openwrt_commands(self):
        from services.openwrt_client import generate_router_setup_commands, _cfg, get_public_key
        from services.auto_config import get as net_cfg
        from services.syslog_server import get_port
        from database import SessionLocal
        from models import AppSetting
        db = SessionLocal()
        try:
            row = db.query(AppSetting).filter(AppSetting.key == "openwrt_host").first()
            host = (row.value if row else "") or _cfg.get("host", "192.168.1.1")
        finally:
            db.close()
        net = net_cfg()
        phone_ip = net.get("my_ip", "?")
        cmds = generate_router_setup_commands(host, phone_ip, get_port())
        return (
            f"<b>📋 Команды для роутера</b>\n\n"
            f"Подключись к роутеру: <code>ssh root@{_esc(host)}</code>\n"
            f"Потом вставь:\n\n"
            f"<pre>{_esc(cmds)}</pre>",
            {"inline_keyboard": [
                [{"text": "🔄 Тест соединения", "callback_data": "openwrt_test"}],
                [{"text": "⬅️ Назад", "callback_data": "openwrt_status"}],
            ]},
        )

    def _action_openwrt_test(self):
        from services.openwrt_client import test_connection, _cfg, start as ow_start
        from database import SessionLocal
        from models import AppSetting
        db = SessionLocal()
        try:
            row = db.query(AppSetting).filter(AppSetting.key == "openwrt_host").first()
            host = (row.value if row else "") or _cfg.get("host", "")
        finally:
            db.close()
        if not host:
            return "❌ Роутер не настроен. Нажми «Настроить OpenWrt»", BACK_MENU
        ok, msg = test_connection()
        if ok:
            ow_start()  # ensure polling is running
        return (
            f"{msg}\n\n"
            + ("Опрос запущен — данные появятся через ~60 сек." if ok else
               "Убедись что:\n"
               "• IP роутера верный\n"
               "• SSH включён на роутере (обычно включён по умолчанию)\n"
               "• Ключ добавлен командами выше"),
            {"inline_keyboard": [
                [{"text": "📋 Команды для роутера", "callback_data": "openwrt_commands"}],
                [{"text": "⬅️ Назад", "callback_data": "openwrt_status"}],
            ]},
        )

    def _action_name_device_start(self, mac: str):
        from database import SessionLocal
        from models import Device
        from services.auto_config import get as net_cfg
        db = SessionLocal()
        try:
            d = db.query(Device).filter(Device.mac == mac).first()
            if not d:
                return "❌ Устройство не найдено", BACK_MENU
            gateway = net_cfg().get("gateway", "")
            _, current_label = _device_display(d, gateway)
        finally:
            db.close()
        self._waiting_for[self._chat_id] = {"action": "name_device", "mac": mac}
        return (
            f"✏️ Устройство: <code>{_esc(mac)}</code>  IP: <code>{_esc(d.ip)}</code>\n"
            f"Сейчас называется: <b>{_esc(current_label)}</b>\n\n"
            f"Введи своё название (например: Телефон Маши, Smart TV, Ноутбук):\n"
            f"<i>Или отправь /отмена чтобы не менять</i>",
            None
        )

    def _handle_name_device_finish(self, chat_id: str, name: str, mac: str):
        from database import SessionLocal
        from models import Device
        db = SessionLocal()
        try:
            d = db.query(Device).filter(Device.mac == mac).first()
            if not d:
                return "❌ Устройство не найдено", BACK_MENU
            d.friendly_name = name.strip()[:64]
            db.commit()
            return (
                f"✅ Устройство <code>{_esc(d.ip)}</code> названо:\n<b>{_esc(d.friendly_name)}</b>",
                MAIN_MENU
            )
        finally:
            db.close()

    def _action_rename_start(self, loc_id: str):
        from database import SessionLocal
        from models import Location
        db = SessionLocal()
        try:
            loc = db.query(Location).filter(Location.id == int(loc_id)).first()
            current = loc.name if loc else "?"
        finally:
            db.close()
        # Сохраняем ожидание ответа
        self._waiting_for[self._chat_id] = {"action": "rename", "loc_id": loc_id}
        return (
            f"✏️ Текущее название: <b>{_esc(current)}</b>\n\n"
            f"Введи новое название сети (например: Квартира, Дача, Офис):\n"
            f"<i>Отправь /отмена чтобы не менять</i>",
            None
        )

    def _handle_rename_finish(self, chat_id: str, new_name: str, loc_id: str):
        from database import SessionLocal
        from models import Location
        db = SessionLocal()
        try:
            loc = db.query(Location).filter(Location.id == int(loc_id)).first()
            if loc:
                old_name = loc.name
                loc.name = new_name.strip()[:64]
                db.commit()
                log.info("Локация #%s переименована: %s → %s", loc_id, old_name, loc.name)
                return (
                    f"✅ Сеть переименована!\n\n"
                    f"<b>{_esc(old_name)}</b> → <b>{_esc(loc.name)}</b>",
                    MAIN_MENU
                )
            return "❌ Локация не найдена", MAIN_MENU
        finally:
            db.close()

    # ── Actions ───────────────────────────────────────────────────────────────

    def _action_read_all(self):
        from database import SessionLocal
        from models import Alert
        db = SessionLocal()
        try:
            n = db.query(Alert).filter(Alert.is_read == False)\
                  .update({Alert.is_read: True})  # noqa: E712
            db.commit()
            return f"✅ Прочитано событий: {n}", BACK_MENU
        finally:
            db.close()

    def _action_refresh_intel(self):
        from services.threat_intel import load_all
        threading.Thread(target=load_all, daemon=True).start()
        return "🔄 Обновление фидов угроз запущено в фоне (1–2 мин)", BACK_MENU

    def _action_beacon_scan(self):
        from database import SessionLocal
        from services.beaconing import detect
        db = SessionLocal()
        try:
            found = detect(db)
            if not found:
                return "✅ C2-маяков не обнаружено", BACK_MENU
            lines = [f"<b>🎯 ОБНАРУЖЕНЫ МАЯКИ ({len(found)})</b>\n"]
            for c in found[:6]:
                lines.append(
                    f"🚨 <code>{_esc(c['src_ip'])}</code> → "
                    f"<code>{_esc(c['dst_ip'])}:{c['dst_port']}</code>\n"
                    f"   каждые {c['period_label']} · CV={c['cv']}"
                )
            return "\n".join(lines), BACK_MENU
        finally:
            db.close()

    def _action_scan_now(self):
        import threading
        from services.device_scanner import run_scan
        threading.Thread(target=run_scan, daemon=True).start()
        return "📡 Сканирование запущено!\nЧерез 15–30 сек нажми «Устройства» для просмотра результатов.", BACK_MENU

    def _action_reset_confirm(self):
        return (
            "⚠️ <b>ПОДТВЕРЖДЕНИЕ СБРОСА</b>\n\n"
            "Это удалит ВСЕ данные: устройства, события, DNS-логи, локации.\n"
            "Система создаст чистую локацию «Мой дом» и сразу просканирует сеть.\n\n"
            "Ты уверен?",
            RESET_CONFIRM_MENU
        )

    def _action_reset_execute(self):
        from database import SessionLocal
        from models import (Device, Connection, Alert, DNSQuery,
                            BlockedDevice, Location, BandwidthSample, AppSetting)
        db = SessionLocal()
        try:
            for model in [Alert, DNSQuery, Connection, BandwidthSample,
                          BlockedDevice, Device, Location]:
                db.query(model).delete()
            db.commit()
            # Создаём чистую локацию
            home = Location(name="Мой дом", icon="🏠", color="#3b82f6",
                            timezone="UTC", is_online=True)
            db.add(home)
            db.commit()
            log.info("База данных очищена через Telegram-бот")
        finally:
            db.close()
        # Запускаем скан
        import threading
        from services.device_scanner import run_scan
        threading.Thread(target=run_scan, daemon=True).start()
        return (
            "✅ <b>Данные очищены!</b>\n\n"
            "Создана локация «Мой дом».\n"
            "Сканирование сети запущено — через 30 сек нажми «Устройства».",
            BACK_MENU
        )

    # ── Dispatch ──────────────────────────────────────────────────────────────

    SCREENS = {
        "menu": None,
        "my_network": "_screen_my_network",
        "status": "_screen_status",
        "alerts": "_screen_alerts",
        "devices": "_screen_devices",
        "new_devices": "_screen_new_devices",
        "threats": "_screen_threats",
        "traffic": "_screen_traffic",
        "connections": "_screen_connections",
        "dns": "_screen_dns",
        "actions": None,
        "read_all": "_action_read_all",
        "refresh_intel": "_action_refresh_intel",
        "beacon_scan": "_action_beacon_scan",
        "scan_now": "_action_scan_now",
        "reset_confirm": "_action_reset_confirm",
        "reset_execute": "_action_reset_execute",
        "openwrt_status": None,
        "openwrt_setup": None,
        "openwrt_commands": None,
        "openwrt_test": None,
    }

    COMMANDS = {
        "/start": "menu", "/menu": "menu", "/status": "status",
        "/devices": "devices", "/alerts": "alerts", "/threats": "threats",
        "/traffic": "traffic", "/new": "new_devices",
        "/scan": "scan_now", "/reset": "reset_confirm",
        "/сеть": "my_network", "/network": "my_network",
        "/connections": "connections", "/соединения": "connections",
        "/dns": "dns",
        "/отмена": "menu", "/cancel": "menu",
    }

    def _render(self, key: str):
        if key == "menu":
            return ("<b>🛡 FAMILY SECURITY</b>\nВыберите раздел:", MAIN_MENU)
        if key == "actions":
            return ("<b>⚙️ ДЕЙСТВИЯ</b>\nЧто сделать?", ACTIONS_MENU)
        # Ключи с параметром: "rename_start:1", "name_dev:AA:BB:..."
        if key.startswith("rename_start:"):
            loc_id = key.split(":", 1)[1]
            return self._action_rename_start(loc_id)
        if key.startswith("name_dev:"):
            mac = key.split(":", 1)[1]
            return self._action_name_device_start(mac)
        if key.startswith("dev_detail:"):
            mac = key.split(":", 1)[1]
            return self._screen_device_detail(mac)
        if key == "openwrt_status":
            return self._screen_openwrt_status()
        if key == "openwrt_setup":
            return self._action_openwrt_setup_start()
        if key == "openwrt_commands":
            return self._action_openwrt_commands()
        if key == "openwrt_test":
            return self._action_openwrt_test()
        method = self.SCREENS.get(key)
        if not method:
            return ("Неизвестная команда. /menu", MAIN_MENU)
        try:
            return getattr(self, method)()
        except Exception as e:
            log.error("Screen %s failed: %s", key, e)
            return (f"⚠️ Ошибка: {_esc(e)}", BACK_MENU)

    def _handle_update(self, upd: dict):
        # Callback button press
        if "callback_query" in upd:
            cq = upd["callback_query"]
            chat_id = str(cq["message"]["chat"]["id"])
            self._call("answerCallbackQuery", callback_query_id=cq["id"])
            if chat_id != self._chat_id:
                return
            text, kb = self._render(cq.get("data", "menu"))
            self._send(chat_id, text, kb)
            return

        # Text message / command
        msg = upd.get("message") or {}
        chat_id = str((msg.get("chat") or {}).get("id", ""))
        text = (msg.get("text") or "").strip()
        if not chat_id or not text:
            return
        if chat_id != self._chat_id:
            self._send(chat_id, "⛔ Доступ запрещён.")
            return

        # Ожидаем ввод от пользователя (диалог переименования/именования)
        waiting = self._waiting_for.get(chat_id)
        if waiting and not text.startswith("/"):
            self._waiting_for.pop(chat_id, None)
            action = waiting.get("action")
            if action == "rename":
                text_out, kb = self._handle_rename_finish(chat_id, text, waiting["loc_id"])
            elif action == "name_device":
                text_out, kb = self._handle_name_device_finish(chat_id, text, waiting["mac"])
            elif action == "openwrt_host":
                text_out, kb = self._handle_openwrt_host(text)
            else:
                text_out, kb = "❓ Неизвестный диалог", MAIN_MENU
            self._send(chat_id, text_out, kb)
            return

        # Обычная команда
        self._waiting_for.pop(chat_id, None)
        cmd = text.split("@")[0].split()[0].lower()
        key = self.COMMANDS.get(cmd, "menu")
        text_out, kb = self._render(key)
        self._send(chat_id, text_out, kb)

    # ── Main loop ─────────────────────────────────────────────────────────────

    def _load_credentials(self) -> bool:
        from services.notifier import _settings
        cfg = _settings()
        self._token = (cfg.get("telegram_bot_token") or "").strip()
        self._chat_id = (cfg.get("telegram_chat_id") or "").strip()
        return bool(self._token and self._chat_id)

    def _set_commands(self):
        self._call("setMyCommands", commands=[
            {"command": "menu",    "description": "Главное меню"},
            {"command": "network", "description": "Моя сеть — IP, имя, устройства"},
            {"command": "status",  "description": "Статус системы"},
            {"command": "devices", "description": "Активные устройства"},
            {"command": "scan",    "description": "Сканировать сеть сейчас"},
            {"command": "alerts",  "description": "Последние события"},
            {"command": "threats", "description": "Угрозы за 24ч"},
            {"command": "new",     "description": "Новые устройства"},
            {"command": "traffic", "description": "Топ трафика"},
            {"command": "reset",   "description": "Очистить все данные"},
        ])

    def _poll_loop(self):
        announced = False
        while not self._stop.is_set():
            if not self._load_credentials():
                time.sleep(RETRY_DELAY)
                continue
            if not announced:
                me = self._call("getMe")
                if me.get("ok"):
                    log.info("Telegram bot online: @%s", me["result"].get("username"))
                    self._set_commands()
                    announced = True
                else:
                    time.sleep(RETRY_DELAY)
                    continue
            data = self._call("getUpdates", offset=self._offset + 1,
                              timeout=POLL_TIMEOUT,
                              allowed_updates=["message", "callback_query"])
            if not data.get("ok"):
                time.sleep(RETRY_DELAY)
                continue
            for upd in data.get("result", []):
                self._offset = max(self._offset, upd["update_id"])
                try:
                    self._handle_update(upd)
                except Exception as e:
                    log.error("Update handling failed: %s", e)

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._poll_loop, daemon=True, name="tg-bot")
        self._thread.start()

    def stop(self):
        self._stop.set()


bot = TelegramBot()
