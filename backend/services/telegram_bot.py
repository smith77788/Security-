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


MAIN_MENU = {
    "inline_keyboard": [
        [{"text": "🏠 Моя сеть", "callback_data": "my_network"}],
        [{"text": "📊 Статус", "callback_data": "status"},
         {"text": "🔔 События", "callback_data": "alerts"}],
        [{"text": "📡 Устройства", "callback_data": "devices"},
         {"text": "🆕 Новые", "callback_data": "new_devices"}],
        [{"text": "🛡 Угрозы", "callback_data": "threats"},
         {"text": "📈 Трафик", "callback_data": "traffic"}],
        [{"text": "⚙️ Действия", "callback_data": "actions"}],
    ]
}

ACTIONS_MENU = {
    "inline_keyboard": [
        [{"text": "✅ Прочитать все события", "callback_data": "read_all"}],
        [{"text": "🔄 Обновить фиды угроз", "callback_data": "refresh_intel"}],
        [{"text": "🎯 Скан C2-маяков", "callback_data": "beacon_scan"}],
        [{"text": "📡 Сканировать сеть сейчас", "callback_data": "scan_now"}],
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
        db = SessionLocal()
        try:
            rows = (db.query(Device)
                    .filter(Device.is_active == True)  # noqa: E712
                    .order_by(Device.last_seen.desc())
                    .limit(15).all())
            if not rows:
                return "Устройств не найдено", BACK_MENU
            lines = [f"<b>📡 УСТРОЙСТВА</b> (активные, {len(rows)})\n"]
            for d in rows:
                name = d.friendly_name or d.vendor or d.mac
                badge = " 🆕" if d.is_new else ""
                lines.append(f"• {_esc(name)}{badge}\n   <code>{_esc(d.ip)}</code> · {_esc(d.mac)}")
            return "\n".join(lines), BACK_MENU
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
        from services.bandwidth_tracker import get_top_consumers
        db = SessionLocal()
        try:
            rows = get_top_consumers(db, minutes=60)
            if not rows:
                return "Нет данных о трафике за последний час", BACK_MENU
            lines = ["<b>📈 ТРАФИК</b> (топ за час)\n"]
            for r in rows[:8]:
                lines.append(
                    f"• {_esc(r['name'])}\n"
                    f"   ↑ {_fmt_bytes(r['bytes_up'])} · ↓ {_fmt_bytes(r['bytes_down'])}"
                )
            return "\n".join(lines), BACK_MENU
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
        "actions": None,
        "read_all": "_action_read_all",
        "refresh_intel": "_action_refresh_intel",
        "beacon_scan": "_action_beacon_scan",
        "scan_now": "_action_scan_now",
        "reset_confirm": "_action_reset_confirm",
        "reset_execute": "_action_reset_execute",
    }

    COMMANDS = {
        "/start": "menu", "/menu": "menu", "/status": "status",
        "/devices": "devices", "/alerts": "alerts", "/threats": "threats",
        "/traffic": "traffic", "/new": "new_devices",
        "/scan": "scan_now", "/reset": "reset_confirm",
        "/сеть": "my_network", "/network": "my_network",
        "/отмена": "menu", "/cancel": "menu",
    }

    def _render(self, key: str):
        if key == "menu":
            return ("<b>🛡 FAMILY SECURITY</b>\nВыберите раздел:", MAIN_MENU)
        if key == "actions":
            return ("<b>⚙️ ДЕЙСТВИЯ</b>\nЧто сделать?", ACTIONS_MENU)
        # Ключи с параметром: "rename_start:1"
        if key.startswith("rename_start:"):
            loc_id = key.split(":", 1)[1]
            return self._action_rename_start(loc_id)
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

        # Ожидаем ввод от пользователя (диалог переименования)
        waiting = self._waiting_for.get(chat_id)
        if waiting and not text.startswith("/"):
            self._waiting_for.pop(chat_id, None)
            if waiting["action"] == "rename":
                text_out, kb = self._handle_rename_finish(chat_id, text, waiting["loc_id"])
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
