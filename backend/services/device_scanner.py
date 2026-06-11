"""
Device discovery via ARP table, ping-sweep, and optional nmap.
Read-only / passive — no exploitation, no credential testing.

Methods tried in order (most to least compatible with Android/Termux):
  1. ip neigh show     — kernel neighbor table, works on Android without root
  2. /proc/net/arp     — direct kernel ARP table (may need root on some Android)
  3. arp -n            — net-tools, often absent on Android
  4. ping sweep        — populates ARP cache; retries methods 1-3 afterwards
  5. nmap -sn          — optional, requires install
"""
import concurrent.futures
import ipaddress
import logging
import re
import subprocess
import socket
from datetime import datetime
from typing import Optional

from sqlalchemy.orm import Session

from config import LOCAL_SUBNET, OUI_FILE
from database import SessionLocal
from models import Device, Alert
from utils.oui_lookup import lookup_vendor

log = logging.getLogger("scanner")

_MAC_RE = re.compile(r"([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}")


def _ip_neigh_show() -> list[dict]:
    """Parse `ip neigh show` — works on Android/Termux without root.

    Tries Termux `ip` (iproute2) first, then Android system `/system/bin/ip`.
    Output format: IP dev IFACE lladdr MAC STATE
    """
    results: dict[str, dict] = {}
    candidates = [
        ["ip", "neigh", "show"],
        ["/system/bin/ip", "neigh", "show"],
    ]
    for cmd in candidates:
        try:
            out = subprocess.check_output(
                cmd, text=True, timeout=10,
                stderr=subprocess.DEVNULL,
            )
            for line in out.splitlines():
                parts = line.split()
                if "lladdr" not in parts or len(parts) < 5:
                    continue
                ip = parts[0]
                mac = parts[parts.index("lladdr") + 1]
                if _MAC_RE.match(mac):
                    results[mac.upper()] = {"ip": ip, "mac": mac.upper()}
            if results:
                break  # found entries — no need to try next candidate
        except FileNotFoundError:
            continue
        except Exception as e:
            log.debug("ip neigh show (%s) failed: %s", cmd[0], e)
    if not results:
        log.debug("ip neigh show: no entries found")
    return list(results.values())


def _read_proc_arp() -> list[dict]:
    """Read /proc/net/arp — may be restricted on Android without root."""
    results = []
    try:
        with open("/proc/net/arp") as f:
            for line in f.readlines()[1:]:  # skip header
                parts = line.split()
                if len(parts) < 4:
                    continue
                ip, _, _, mac, *_ = parts
                if mac == "00:00:00:00:00:00":
                    continue
                results.append({"ip": ip, "mac": mac.upper()})
    except PermissionError:
        log.debug("/proc/net/arp: permission denied (normal on Android)")
    except Exception as e:
        log.debug("Cannot read /proc/net/arp: %s", e)
    return results


def _arp_command() -> list[dict]:
    """Fallback: parse `arp -n` output."""
    results = []
    try:
        out = subprocess.check_output(
            ["arp", "-n"], text=True, timeout=10,
            stderr=subprocess.DEVNULL,
        )
        for line in out.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 3:
                continue
            ip = parts[0]
            mac = parts[2]
            if _MAC_RE.match(mac):
                results.append({"ip": ip, "mac": mac.upper()})
    except FileNotFoundError:
        log.debug("arp command not available")
    except Exception as e:
        log.debug("arp command failed: %s", e)
    return results


def _udp_probe_sweep(subnet: str) -> int:
    """Send UDP probes to force kernel ARP resolution without root.

    Sends a 1-byte UDP packet to each host on port 65535.
    The kernel must resolve ARP to deliver (or reject) the packet,
    which populates the neighbour table — even if the target drops it.
    This requires only SOCK_DGRAM, no CAP_NET_RAW, works on Android.
    """
    import socket as _socket

    def _probe(ip: str) -> None:
        try:
            s = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
            s.settimeout(0.05)
            s.sendto(b"\x00", (ip, 65535))
            s.close()
        except Exception:
            pass

    try:
        net = ipaddress.IPv4Network(subnet, strict=False)
        hosts = [str(h) for h in net.hosts()]
        if len(hosts) > 254:
            hosts = hosts[:254]
        log.info("UDP probe sweep: %d hosts in %s …", len(hosts), subnet)
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as pool:
            list(pool.map(_probe, hosts))
        log.info("UDP probe sweep complete")
        return len(hosts)
    except Exception as e:
        log.warning("UDP probe sweep error: %s", e)
        return 0


def _ping_sweep(subnet: str) -> int:
    """Ping sweep fallback (requires ping binary with proper permissions)."""

    def _ping_one(ip: str) -> bool:
        try:
            r = subprocess.run(
                ["ping", "-c", "1", "-W", "1", ip],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=3,
            )
            return r.returncode == 0
        except Exception:
            return False

    try:
        net = ipaddress.IPv4Network(subnet, strict=False)
        hosts = [str(h) for h in net.hosts()]
        if len(hosts) > 254:
            hosts = hosts[:254]
        log.info("Ping sweep: %d hosts in %s …", len(hosts), subnet)
        with concurrent.futures.ThreadPoolExecutor(max_workers=40) as pool:
            results = list(pool.map(_ping_one, hosts))
        found = sum(results)
        log.info("Ping sweep: %d hosts responded", found)
        return found
    except Exception as e:
        log.warning("Ping sweep error: %s", e)
        return 0


def _nmap_scan(subnet: str) -> list[dict]:
    """Safe nmap host-discovery only (-sn = no port scan)."""
    results = []
    try:
        out = subprocess.check_output(
            ["nmap", "-sn", "--host-timeout", "5s", subnet],
            text=True, timeout=60, stderr=subprocess.DEVNULL,
        )
        current_ip = None
        for line in out.splitlines():
            m_ip = re.search(r"Nmap scan report for (?:\S+ \()?(\d+\.\d+\.\d+\.\d+)\)?", line)
            if m_ip:
                current_ip = m_ip.group(1)
            m_mac = re.search(r"MAC Address: ([0-9A-F:]{17})", line, re.I)
            if m_mac and current_ip:
                results.append({"ip": current_ip, "mac": m_mac.group(1).upper()})
    except FileNotFoundError:
        log.debug("nmap not installed — skipping")
    except Exception as e:
        log.debug("nmap scan failed: %s", e)
    return results


def _collect_arp() -> list[dict]:
    """Try all ARP-table readers and return combined unique results."""
    found: dict[str, dict] = {}
    for entry in _ip_neigh_show():
        found[entry["mac"]] = entry
    for entry in _read_proc_arp():
        found.setdefault(entry["mac"], entry)
    for entry in _arp_command():
        found.setdefault(entry["mac"], entry)
    return list(found.values())


def _resolve_hostname(ip: str) -> Optional[str]:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def discover_devices(subnet: str = LOCAL_SUBNET) -> list[dict]:
    """Collect devices from all available sources and deduplicate by MAC."""
    found: dict[str, dict] = {}

    # Pass 1: read existing ARP/neighbor cache
    for entry in _collect_arp():
        found[entry["mac"]] = entry

    # Pass 2: if nothing found, do UDP probe sweep (works on Android without root)
    if not found:
        log.info("ARP cache empty — running UDP probe sweep …")
        _udp_probe_sweep(subnet)
        import time
        time.sleep(1)  # let the kernel process ARP responses
        for entry in _collect_arp():
            found[entry["mac"]] = entry

    # Pass 3: if still nothing, also try ping (works if ping has proper caps)
    if not found:
        log.info("UDP sweep found nothing — trying ping sweep …")
        _ping_sweep(subnet)
        import time
        time.sleep(1)
        for entry in _collect_arp():
            found[entry["mac"]] = entry

    # Pass 3: nmap as last resort (optional, requires install)
    for entry in _nmap_scan(subnet):
        found.setdefault(entry["mac"], entry)

    # Enrich with hostname and vendor
    devices = []
    for mac, entry in found.items():
        hostname = _resolve_hostname(entry["ip"])
        vendor = lookup_vendor(mac, OUI_FILE)
        devices.append({
            "mac": mac,
            "ip": entry["ip"],
            "hostname": hostname,
            "vendor": vendor,
        })
    return devices


def upsert_device(db: Session, info: dict) -> tuple[Device, bool]:
    """Insert or update device. Returns (device, is_new)."""
    now = datetime.utcnow()
    device = db.query(Device).filter(Device.mac == info["mac"]).first()
    is_new = device is None

    if is_new:
        device = Device(
            mac=info["mac"],
            ip=info.get("ip"),
            hostname=info.get("hostname"),
            vendor=info.get("vendor"),
            first_seen=now,
            last_seen=now,
            is_new=True,
            is_active=True,
        )
        db.add(device)
    else:
        device.ip = info.get("ip") or device.ip
        device.hostname = info.get("hostname") or device.hostname
        device.vendor = info.get("vendor") or device.vendor
        device.last_seen = now
        device.is_active = True

    db.commit()
    db.refresh(device)
    return device, is_new


def run_scan():
    """Entry point for the background scheduler."""
    log.info("Running device scan on %s", LOCAL_SUBNET)
    devices = discover_devices(LOCAL_SUBNET)
    db = SessionLocal()
    try:
        new_count = 0
        for info in devices:
            _, is_new = upsert_device(db, info)
            if is_new:
                new_count += 1
                alert = Alert(
                    device_mac=info["mac"],
                    device_ip=info.get("ip"),
                    alert_type="new_device",
                    severity="warning",
                    message=f"New device joined the network: {info.get('vendor', 'Unknown')} ({info['mac']})",
                    detail=f"IP: {info.get('ip')}, Hostname: {info.get('hostname')}",
                )
                db.add(alert)
                db.flush()
                from services.notifier import notify_alert
                notify_alert(alert)
        db.commit()
        log.info("Scan complete — %d devices found, %d new", len(devices), new_count)
    finally:
        db.close()
