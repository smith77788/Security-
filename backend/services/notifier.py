"""
Notification dispatch: Telegram bot.
Settings read from app_settings table at send time so changes take effect immediately.
"""
import logging
import threading
import requests as http

log = logging.getLogger("notifier")

_TELEGRAM_URL = "https://api.telegram.org/bot{token}/sendMessage"


def _settings() -> dict:
    import os
    # Env vars are the fallback; DB rows (set via the Settings UI) override them
    cfg = {
        "telegram_bot_token": os.getenv("TELEGRAM_BOT_TOKEN", ""),
        "telegram_chat_id": os.getenv("TELEGRAM_CHAT_ID", ""),
    }
    try:
        from database import SessionLocal
        from models import AppSetting
        db = SessionLocal()
        try:
            rows = db.query(AppSetting).filter(
                AppSetting.key.in_([
                    "telegram_bot_token", "telegram_chat_id",
                    "notify_on_critical", "notify_on_warning", "notify_on_new_device",
                ])
            ).all()
            for r in rows:
                if r.value:
                    cfg[r.key] = r.value
        finally:
            db.close()
    except Exception:
        pass
    return cfg


def _send_telegram(token: str, chat_id: str, text: str):
    try:
        r = http.post(
            _TELEGRAM_URL.format(token=token),
            json={"chat_id": chat_id, "text": text, "parse_mode": "HTML"},
            timeout=10,
        )
        if not r.ok:
            log.warning("Telegram API %d: %s", r.status_code, r.text[:120])
    except Exception as e:
        log.warning("Telegram send failed: %s", e)


def notify_alert(alert) -> None:
    """Send Telegram notification for an Alert object. Non-blocking."""
    threading.Thread(target=_notify_alert_sync, args=(alert,), daemon=True).start()


def _notify_alert_sync(alert) -> None:
    cfg = _settings()
    token = cfg.get("telegram_bot_token", "").strip()
    chat_id = cfg.get("telegram_chat_id", "").strip()
    if not token or not chat_id:
        return

    sev = getattr(alert, "severity", "info")
    atype = getattr(alert, "alert_type", "")

    if sev == "critical" and cfg.get("notify_on_critical", "true") != "true":
        return
    if sev == "warning" and cfg.get("notify_on_warning", "false") != "true":
        return
    if atype == "new_device" and cfg.get("notify_on_new_device", "true") != "true":
        return

    icon = {"critical": "🚨", "warning": "⚠️", "info": "ℹ️"}.get(sev, "🔔")
    text = f"{icon} <b>FAMILY SECURITY</b>\n\n"
    text += f"<b>[{sev.upper()}]</b> {getattr(alert, 'message', '')}"
    detail = getattr(alert, "detail", None)
    if detail:
        text += f"\n<i>{detail}</i>"

    _send_telegram(token, chat_id, text)


def send_test(token: str, chat_id: str) -> bool:
    """Send a test message. Returns True on success."""
    try:
        r = http.post(
            _TELEGRAM_URL.format(token=token),
            json={"chat_id": chat_id, "text": "✅ <b>FAMILY SECURITY</b> — тестовое сообщение. Уведомления работают!", "parse_mode": "HTML"},
            timeout=10,
        )
        return r.ok
    except Exception:
        return False
