"""
UDP Syslog receiver — real-time DNS monitoring from OpenWrt dnsmasq.

OpenWrt's syslog daemon forwards log messages here. We parse dnsmasq
query lines and store them instantly, enabling threat detection with
zero polling latency.

Port 514 requires root; we use 5514 by default (configure OpenWrt to match).
"""
import logging
import re
import socket
import threading
from datetime import datetime

log = logging.getLogger("syslog-srv")

_DNS_PAT = re.compile(
    r"dnsmasq\[\d+\]: query\[(?:A{1,4})\] (\S+) from (\S+)"
)
_PORT = 5514
_running = False
_thread = None


def _store(domain: str, device_ip: str):
    try:
        from database import SessionLocal
        from models import DNSQuery, Alert, AppSetting
        from utils.suspicious_domains import is_suspicious, looks_like_dga
        from services.notifier import notify_alert

        db = SessionLocal()
        try:
            # Resolve location_id from OpenWrt location if configured
            row = db.query(AppSetting).filter(AppSetting.key == "openwrt_location_id").first()
            loc_id = int(row.value) if row else None

            db.add(DNSQuery(
                location_id=loc_id,
                device_ip=device_ip,
                domain=domain,
                query_type="A",
                timestamp=datetime.utcnow(),
            ))

            if is_suspicious(domain) or looks_like_dga(domain):
                reason = "suspicious" if is_suspicious(domain) else "DGA"
                alert = Alert(
                    location_id=loc_id,
                    device_ip=device_ip,
                    alert_type="suspicious_domain",
                    severity="critical",
                    message=f"Подозрительный домен: {domain} ({reason})",
                    detail=f"Устройство {device_ip}",
                )
                db.add(alert)
                db.flush()
                notify_alert(alert)

            db.commit()
        finally:
            db.close()
    except Exception as e:
        log.debug("DNS store error: %s", e)


def _listen(port: int):
    global _running
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(2.0)
        sock.bind(("0.0.0.0", port))
        log.info("Syslog receiver listening on UDP :%d", port)
        while _running:
            try:
                data, _ = sock.recvfrom(4096)
                line = data.decode(errors="ignore")
                m = _DNS_PAT.search(line)
                if m:
                    domain, device_ip = m.group(1).rstrip("."), m.group(2)
                    if "." in domain and not domain.endswith(".local"):
                        _store(domain.lower(), device_ip)
            except socket.timeout:
                continue
            except Exception:
                pass
        sock.close()
    except OSError as e:
        if port == 514:
            log.warning("Port 514 requires root — falling back to 5514")
            _listen(5514)
        else:
            log.error("Syslog bind failed on port %d: %s", port, e)
    _running = False


def start(port: int = _PORT):
    global _running, _thread, _PORT
    _PORT = port
    if _running:
        return
    _running = True
    _thread = threading.Thread(target=_listen, args=(port,), daemon=True, name="syslog-srv")
    _thread.start()


def stop():
    global _running
    _running = False


def get_port() -> int:
    return _PORT
