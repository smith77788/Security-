"""
OpenWrt router integration — SSH-based polling.

Reads from the router via SSH (key auth, no password needed after setup):
  - /tmp/dhcp.leases     → real MAC addresses + hostnames for all devices
  - logread | grep dnsmasq → DNS queries made by every device on the network
  - /proc/net/arp        → ARP table (backup device discovery)

The data is injected into the local DB through the same ingest pipeline
used by remote agents, so all alerts, threat checks, and DNS analysis
apply automatically.
"""
import logging
import os
import re
import secrets
import subprocess
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

log = logging.getLogger("openwrt")

_SSH_KEY = str(Path.home() / ".ssh" / "openwrt_key")
_DNS_PAT = re.compile(
    r"dnsmasq\[\d+\]: query\[(?:A{1,4}|PTR)\] (\S+) from (\S+)"
)
_MAC_PAT = re.compile(r"([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}")

# Runtime config (loaded from DB / env on startup)
_cfg: dict = {}
_lock = threading.Lock()
_last_dns_ts: Optional[str] = None   # track last log line ingested


# ── SSH helper ────────────────────────────────────────────────────────────────

def _ssh(cmd: str, timeout: int = 10) -> Optional[str]:
    host = _cfg.get("host", "")
    if not host:
        return None
    user = _cfg.get("user", "root")
    port = int(_cfg.get("port", 22))
    key  = _cfg.get("key_file", _SSH_KEY)

    args = [
        "ssh",
        "-o", "StrictHostKeyChecking=no",
        "-o", "ConnectTimeout=5",
        "-o", "BatchMode=yes",
        "-o", "LogLevel=ERROR",
    ]
    if Path(key).exists():
        args += ["-i", key]
    if port != 22:
        args += ["-p", str(port)]
    args += [f"{user}@{host}", cmd]

    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return r.stdout if r.returncode == 0 else None
    except Exception as e:
        log.debug("SSH error (%s): %s", host, e)
        return None


# ── Data collectors ───────────────────────────────────────────────────────────

def _dhcp_leases() -> list[dict]:
    """Return list of {mac, ip, hostname} from /tmp/dhcp.leases."""
    out = _ssh("cat /tmp/dhcp.leases 2>/dev/null")
    if not out:
        return []
    results = []
    for line in out.strip().splitlines():
        p = line.split()
        if len(p) < 4:
            continue
        mac = p[1].upper()
        ip  = p[2]
        hn  = p[3] if p[3] != "*" else None
        if _MAC_PAT.match(mac):
            results.append({"mac": mac, "ip": ip, "hostname": hn})
    log.info("OpenWrt DHCP: %d leases", len(results))
    return results


def _arp_table() -> list[dict]:
    out = _ssh("cat /proc/net/arp 2>/dev/null")
    if not out:
        return []
    results = []
    for line in out.splitlines()[1:]:
        p = line.split()
        if len(p) < 4:
            continue
        ip, mac = p[0], p[3]
        if mac != "00:00:00:00:00:00" and _MAC_PAT.match(mac):
            results.append({"mac": mac.upper(), "ip": ip, "hostname": None})
    return results


def _dns_queries(limit: int = 200) -> list[dict]:
    """Return recent dnsmasq DNS query log entries."""
    global _last_dns_ts
    out = _ssh(f"logread 2>/dev/null | grep -i 'dnsmasq.*query\\[' | tail -{limit}")
    if not out:
        out = _ssh(f"tail -n {limit} /tmp/dnsmasq.log 2>/dev/null")
    if not out:
        return []
    queries = []
    for line in out.splitlines():
        m = _DNS_PAT.search(line)
        if m:
            domain    = m.group(1).rstrip(".")
            device_ip = m.group(2)
            if not domain.endswith(".local") and "." in domain:
                queries.append({"domain": domain.lower(), "device_ip": device_ip})
    return queries


# ── Ingest helpers ────────────────────────────────────────────────────────────

def _get_or_create_location(db) -> "Location":  # type: ignore
    from models import Location, AppSetting
    from utils.oui_lookup import lookup_vendor

    # Check if we already have a Location for the router
    row = db.query(AppSetting).filter(AppSetting.key == "openwrt_location_id").first()
    if row:
        from models import Location as Loc
        loc = db.query(Loc).filter(Loc.id == int(row.value)).first()
        if loc:
            return loc

    # Create new Location for the router
    api_key = secrets.token_urlsafe(32)
    loc = Location(
        name=_cfg.get("location_name", "Роутер OpenWrt"),
        icon="📡",
        color="#f59e0b",
        timezone="UTC",
        api_key=api_key,
        is_online=True,
        last_heartbeat=datetime.utcnow(),
    )
    db.add(loc)
    db.flush()

    setting = AppSetting(key="openwrt_location_id", value=str(loc.id))
    db.add(setting)
    db.commit()
    log.info("Created OpenWrt location #%d (api_key saved)", loc.id)
    return loc


def _ingest(leases: list[dict], dns: list[dict]):
    """Push collected data into the DB using the ingest pipeline."""
    if not leases and not dns:
        return
    try:
        from database import SessionLocal
        from models import Device, DNSQuery, Alert
        from utils.oui_lookup import lookup_vendor
        from config import OUI_FILE
        from utils.suspicious_domains import is_suspicious, looks_like_dga
        from services.notifier import notify_alert

        db = SessionLocal()
        try:
            loc = _get_or_create_location(db)
            now = datetime.utcnow()

            # Upsert devices
            for item in leases:
                mac = item["mac"]
                vendor = lookup_vendor(mac, OUI_FILE)
                dev = db.query(Device).filter(Device.mac == mac).first()
                if dev is None:
                    dev = Device(
                        location_id=loc.id,
                        mac=mac, ip=item["ip"],
                        hostname=item["hostname"],
                        vendor=vendor,
                        first_seen=now, last_seen=now,
                        is_new=True, is_active=True,
                    )
                    db.add(dev)
                    db.flush()
                    alert = Alert(
                        location_id=loc.id, device_mac=mac, device_ip=item["ip"],
                        alert_type="new_device", severity="warning",
                        message=f"Новое устройство: {vendor or mac} ({item['ip']})",
                        detail=f"Hostname: {item['hostname']}",
                    )
                    db.add(alert)
                    db.flush()
                    notify_alert(alert)
                    log.info("New device via OpenWrt DHCP: %s %s", mac, item["ip"])
                else:
                    dev.ip = item["ip"] or dev.ip
                    dev.hostname = item["hostname"] or dev.hostname
                    dev.last_seen = now
                    dev.is_active = True

            # Ingest DNS queries (deduplicate by domain+ip in last batch)
            seen = set()
            for q in dns:
                key = (q["domain"], q["device_ip"])
                if key in seen:
                    continue
                seen.add(key)
                db.add(DNSQuery(
                    location_id=loc.id,
                    device_ip=q["device_ip"],
                    domain=q["domain"],
                    query_type="A",
                    timestamp=now,
                ))
                # Threat check
                domain = q["domain"]
                if is_suspicious(domain) or looks_like_dga(domain):
                    reason = "suspicious" if is_suspicious(domain) else "DGA"
                    a = Alert(
                        location_id=loc.id, device_ip=q["device_ip"],
                        alert_type="suspicious_domain", severity="critical",
                        message=f"Подозрительный домен: {domain} ({reason})",
                        detail=f"Устройство {q['device_ip']}",
                    )
                    db.add(a)
                    db.flush()
                    notify_alert(a)

            loc.last_heartbeat = now
            loc.is_online = True
            db.commit()
            log.info("OpenWrt ingest: %d devices, %d DNS", len(leases), len(seen))
        finally:
            db.close()
    except Exception as e:
        log.error("OpenWrt ingest error: %s", e)


# ── Background polling loop ───────────────────────────────────────────────────

_stop_event = threading.Event()


def _poll_loop():
    interval = int(_cfg.get("poll_interval", 60))
    log.info("OpenWrt polling started (every %ds)", interval)
    while not _stop_event.is_set():
        try:
            leases = _dhcp_leases() or _arp_table()
            dns    = _dns_queries()
            _ingest(leases, dns)
        except Exception as e:
            log.error("OpenWrt poll error: %s", e)
        _stop_event.wait(interval)


_poll_thread: Optional[threading.Thread] = None


def start():
    global _poll_thread
    if not _cfg.get("host"):
        return
    if _poll_thread and _poll_thread.is_alive():
        return
    _stop_event.clear()
    _poll_thread = threading.Thread(target=_poll_loop, daemon=True, name="openwrt")
    _poll_thread.start()
    log.info("OpenWrt client started → %s", _cfg.get("host"))


def stop():
    _stop_event.set()


# ── Public API ────────────────────────────────────────────────────────────────

def configure(host: str, user: str = "root", port: int = 22,
              key_file: str = _SSH_KEY, location_name: str = "Роутер OpenWrt",
              poll_interval: int = 60):
    with _lock:
        _cfg.update(dict(host=host, user=user, port=port, key_file=key_file,
                         location_name=location_name, poll_interval=poll_interval))
    log.info("OpenWrt configured: %s@%s", user, host)


def load_from_settings():
    """Load configuration from DB AppSettings + env vars."""
    try:
        from database import SessionLocal
        from models import AppSetting
        db = SessionLocal()
        try:
            rows = {r.key: r.value for r in db.query(AppSetting).filter(
                AppSetting.key.in_([
                    "openwrt_host", "openwrt_user", "openwrt_port",
                    "openwrt_key_file", "openwrt_location_name",
                ])
            ).all()}
        finally:
            db.close()

        host = rows.get("openwrt_host") or os.getenv("OPENWRT_HOST", "")
        if not host:
            return False

        configure(
            host=host,
            user=rows.get("openwrt_user") or os.getenv("OPENWRT_USER", "root"),
            port=int(rows.get("openwrt_port") or os.getenv("OPENWRT_PORT", "22")),
            key_file=rows.get("openwrt_key_file") or os.getenv("OPENWRT_KEY_FILE", _SSH_KEY),
            location_name=rows.get("openwrt_location_name") or "Роутер OpenWrt",
        )
        return True
    except Exception as e:
        log.debug("load_from_settings: %s", e)
        return False


def save_to_settings(host: str, user: str = "root", port: int = 22):
    try:
        from database import SessionLocal
        from models import AppSetting
        db = SessionLocal()
        try:
            for key, val in [
                ("openwrt_host", host),
                ("openwrt_user", user),
                ("openwrt_port", str(port)),
            ]:
                row = db.query(AppSetting).filter(AppSetting.key == key).first()
                if row:
                    row.value = val
                else:
                    db.add(AppSetting(key=key, value=val))
            db.commit()
        finally:
            db.close()
    except Exception as e:
        log.error("save_to_settings: %s", e)


def test_connection() -> tuple[bool, str]:
    out = _ssh("cat /etc/openwrt_release 2>/dev/null | head -2", timeout=8)
    if out and out.strip():
        ver = out.strip().replace("\n", " | ")
        return True, f"✅ Подключено: {ver}"
    return False, "❌ SSH недоступен (неверный IP, пароль или ключ не добавлен)"


def get_public_key() -> str:
    """Return SSH public key, generating keypair if needed."""
    pub = Path(_SSH_KEY + ".pub")
    if not pub.exists():
        try:
            subprocess.run(
                ["ssh-keygen", "-t", "ed25519", "-N", "", "-f", _SSH_KEY],
                capture_output=True, check=True,
            )
            log.info("Generated SSH key: %s", _SSH_KEY)
        except Exception as e:
            return f"Ошибка генерации ключа: {e}"
    return pub.read_text().strip()


def generate_router_setup_commands(host: str, phone_ip: str, syslog_port: int = 5514) -> str:
    """Generate the UCI commands the user should run on the OpenWrt router."""
    pub_key = get_public_key()
    return f"""# === Запусти эти команды на роутере (через SSH или LuCI → Terminal) ===

# 1. Добавить SSH-ключ телефона
mkdir -p /etc/dropbear
echo '{pub_key}' >> /etc/dropbear/authorized_keys
chmod 600 /etc/dropbear/authorized_keys

# 2. Включить логирование DNS-запросов в dnsmasq
uci set dhcp.@dnsmasq[0].logqueries=1
uci commit dhcp
/etc/init.d/dnsmasq restart

# 3. Настроить пересылку syslog на телефон (реальное время)
uci set system.@system[0].log_ip='{phone_ip}'
uci set system.@system[0].log_port='{syslog_port}'
uci set system.@system[0].log_proto='udp'
uci commit system
/etc/init.d/log restart

# Готово! Данные начнут поступать через ~60 секунд."""
