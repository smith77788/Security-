"""
Device discovery for Android/Termux without root.

Methods (in order):
  1. SSDP/UPnP multicast   — routers, smart TVs, IoT devices
  2. mDNS multicast         — phones, Macs, printers, Chromecasts
  3. NetBIOS broadcast      — Windows / Samba hosts
  4. TCP connect scan       — any host with an open port
  5. ip neigh / /proc/net/arp — if available (Linux with root)

All methods use ordinary sockets — no CAP_NET_RAW, no root required.
Read-only / passive: no exploitation, no credential testing.
"""
import concurrent.futures
import ipaddress
import logging
import re
import select
import socket
import struct
import subprocess
import time
from datetime import datetime
from typing import Optional

from sqlalchemy.orm import Session

from config import LOCAL_SUBNET, OUI_FILE
from database import SessionLocal
from models import Device, Alert
from utils.oui_lookup import lookup_vendor

log = logging.getLogger("scanner")

_MAC_RE = re.compile(r"([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}")

# ── helpers ──────────────────────────────────────────────────────────────────

def _resolve_hostname(ip: str) -> Optional[str]:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def _fake_mac(ip: str) -> str:
    """Deterministic pseudo-MAC from IP (used when real MAC is unavailable)."""
    parts = ip.split(".")
    if len(parts) == 4:
        return f"02:00:{int(parts[0]):02X}:{int(parts[1]):02X}:{int(parts[2]):02X}:{int(parts[3]):02X}"
    return "02:00:00:00:00:01"


# ── Method 1: SSDP / UPnP ────────────────────────────────────────────────────

_SSDP_ADDR = "239.255.255.250"
_SSDP_PORT = 1900
_SSDP_REQUEST = (
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    "MAN: \"ssdp:discover\"\r\n"
    "MX: 3\r\n"
    "ST: ssdp:all\r\n"
    "\r\n"
).encode()


def _ssdp_scan(timeout: float = 4.0) -> list[dict]:
    """Send SSDP M-SEARCH multicast and collect responding device IPs."""
    found: dict[str, dict] = {}
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        sock.settimeout(timeout)
        sock.sendto(_SSDP_REQUEST, (_SSDP_ADDR, _SSDP_PORT))
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                data, addr = sock.recvfrom(4096)
                ip = addr[0]
                if ip not in found:
                    found[ip] = {"ip": ip, "mac": _fake_mac(ip), "method": "ssdp"}
                    # Try to extract device name from SSDP response
                    text = data.decode(errors="ignore")
                    m = re.search(r"(?:SERVER|friendlyName):\s*(.+)", text, re.I)
                    if m:
                        found[ip]["hostname"] = m.group(1).strip()[:64]
            except socket.timeout:
                break
            except Exception:
                pass
        sock.close()
    except Exception as e:
        log.debug("SSDP scan failed: %s", e)
    log.info("SSDP: found %d devices", len(found))
    return list(found.values())


# ── Method 2: mDNS ───────────────────────────────────────────────────────────

_MDNS_ADDR = "224.0.0.251"
_MDNS_PORT = 5353


def _mdns_query() -> bytes:
    """Build a minimal mDNS PTR query for _services._dns-sd._udp.local."""
    name = b"\x09_services\x07_dns-sd\x04_udp\x05local\x00"
    return (
        b"\x00\x00"  # transaction id
        b"\x00\x00"  # flags: standard query
        b"\x00\x01"  # 1 question
        b"\x00\x00\x00\x00\x00\x00"  # no answers/authority/additional
        + name
        + b"\x00\x0c"  # type PTR
        + b"\x00\x01"  # class IN
    )


def _mdns_scan(timeout: float = 3.0) -> list[dict]:
    """Send mDNS query and collect responding device IPs."""
    found: dict[str, dict] = {}
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        ttl = struct.pack("b", 1)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl)
        sock.settimeout(timeout)
        sock.sendto(_mdns_query(), (_MDNS_ADDR, _MDNS_PORT))
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                data, addr = sock.recvfrom(4096)
                ip = addr[0]
                if ip not in found:
                    found[ip] = {"ip": ip, "mac": _fake_mac(ip), "method": "mdns"}
            except socket.timeout:
                break
            except Exception:
                pass
        sock.close()
    except Exception as e:
        log.debug("mDNS scan failed: %s", e)
    log.info("mDNS: found %d devices", len(found))
    return list(found.values())


# ── Method 3: NetBIOS ────────────────────────────────────────────────────────

def _netbios_query() -> bytes:
    """NetBIOS Name Service broadcast query for *(any) name."""
    return (
        b"\xaa\xbb"       # transaction id
        b"\x01\x10"       # flags: broadcast query
        b"\x00\x01"       # 1 question
        b"\x00\x00\x00\x00\x00\x00"
        b"\x20"           # encoded name length
        + b"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"  # wildcard *
        + b"\x00"
        + b"\x00\x21"     # type NB
        + b"\x00\x01"     # class IN
    )


def _netbios_scan(broadcast: str = "192.168.1.255", timeout: float = 2.0) -> list[dict]:
    found: dict[str, dict] = {}
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.settimeout(timeout)
        sock.sendto(_netbios_query(), (broadcast, 137))
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                data, addr = sock.recvfrom(1024)
                ip = addr[0]
                if ip not in found:
                    found[ip] = {"ip": ip, "mac": _fake_mac(ip), "method": "netbios"}
            except socket.timeout:
                break
            except Exception:
                pass
        sock.close()
    except Exception as e:
        log.debug("NetBIOS scan failed: %s", e)
    log.info("NetBIOS: found %d devices", len(found))
    return list(found.values())


# ── Method 4: TCP port scan ───────────────────────────────────────────────────

# Ports that many home devices have open
_TCP_PORTS = [80, 443, 22, 23, 8080, 8443, 8888, 554, 7547, 53, 21, 8181, 1883]


def _tcp_probe(ip: str) -> Optional[dict]:
    for port in _TCP_PORTS:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.4)
            result = s.connect_ex((ip, port))
            s.close()
            if result in (0, 111):  # 0=connected, 111=ECONNREFUSED (host exists)
                return {"ip": ip, "mac": _fake_mac(ip), "method": "tcp", "open_port": port}
        except Exception:
            pass
    return None


def _tcp_scan(subnet: str) -> list[dict]:
    """TCP connect scan — finds any host that has at least one open/refusing port."""
    try:
        net = ipaddress.IPv4Network(subnet, strict=False)
        hosts = [str(h) for h in net.hosts()]
        if len(hosts) > 254:
            hosts = hosts[:254]
        log.info("TCP scan: probing %d hosts in %s …", len(hosts), subnet)
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as pool:
            results = [r for r in pool.map(_tcp_probe, hosts) if r is not None]
        log.info("TCP scan: found %d hosts", len(results))
        return results
    except Exception as e:
        log.warning("TCP scan error: %s", e)
        return []


# ── Method 5: ARP table (Linux / rooted Android) ─────────────────────────────

def _ip_neigh_show() -> list[dict]:
    results: dict[str, dict] = {}
    for cmd in (["ip", "neigh", "show"], ["/system/bin/ip", "neigh", "show"]):
        try:
            out = subprocess.check_output(cmd, text=True, timeout=10,
                                          stderr=subprocess.DEVNULL)
            for line in out.splitlines():
                parts = line.split()
                if "lladdr" not in parts or len(parts) < 5:
                    continue
                ip = parts[0]
                mac = parts[parts.index("lladdr") + 1]
                if _MAC_RE.match(mac):
                    results[mac.upper()] = {"ip": ip, "mac": mac.upper(), "method": "arp"}
            if results:
                break
        except FileNotFoundError:
            continue
        except Exception as e:
            log.debug("ip neigh show (%s): %s", cmd[0], e)
    return list(results.values())


def _read_proc_arp() -> list[dict]:
    results = []
    try:
        with open("/proc/net/arp") as f:
            for line in f.readlines()[1:]:
                parts = line.split()
                if len(parts) < 4:
                    continue
                ip, _, _, mac, *_ = parts
                if mac == "00:00:00:00:00:00":
                    continue
                results.append({"ip": ip, "mac": mac.upper(), "method": "arp"})
    except PermissionError:
        log.debug("/proc/net/arp: permission denied (normal on Android)")
    except Exception as e:
        log.debug("/proc/net/arp: %s", e)
    return results


# ── broadcast address helper ──────────────────────────────────────────────────

def _broadcast(subnet: str) -> str:
    try:
        net = ipaddress.IPv4Network(subnet, strict=False)
        return str(net.broadcast_address)
    except Exception:
        return "192.168.1.255"


# ── main discovery entry point ────────────────────────────────────────────────

def discover_devices(subnet: str = LOCAL_SUBNET) -> list[dict]:
    """Collect devices from all available sources and deduplicate by IP."""
    found: dict[str, dict] = {}  # keyed by IP

    def _add(entries: list[dict]):
        for e in entries:
            ip = e.get("ip", "")
            if ip and ip not in found:
                found[ip] = e
            elif ip in found and e.get("mac", "").count(":") == 5 and not e["mac"].startswith("02:00"):
                # prefer real MACs over fake ones
                found[ip] = e

    # Fast multicast methods first (parallel)
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        f_ssdp = pool.submit(_ssdp_scan)
        f_mdns = pool.submit(_mdns_scan)
        f_nb   = pool.submit(_netbios_scan, _broadcast(subnet))
        f_arp  = pool.submit(_ip_neigh_show)
        f_proc = pool.submit(_read_proc_arp)

        _add(f_arp.result())
        _add(f_proc.result())
        _add(f_ssdp.result())
        _add(f_mdns.result())
        _add(f_nb.result())

    # TCP scan fills in hosts missed by multicast
    _add(_tcp_scan(subnet))

    # Enrich with hostname and vendor
    devices = []
    for ip, entry in found.items():
        mac = entry.get("mac", _fake_mac(ip))
        hostname = entry.get("hostname") or _resolve_hostname(ip)
        # For real MACs (from ARP) use OUI lookup; for fake ones encode how we found the device
        if not mac.startswith("02:00"):
            vendor = lookup_vendor(mac, OUI_FILE)
        else:
            method = entry.get("method", "")
            port = entry.get("open_port")
            vendor = f"tcp:{port}" if method == "tcp" and port else method
        devices.append({
            "mac": mac,
            "ip": ip,
            "hostname": hostname,
            "vendor": vendor,
        })

    log.info("Scan complete — %d devices found via all methods", len(devices))
    return devices


# ── database upsert ───────────────────────────────────────────────────────────

def upsert_device(db: Session, info: dict) -> tuple:
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
                    message=f"New device: {info.get('vendor', 'Unknown')} ({info['mac']})",
                    detail=f"IP: {info.get('ip')}, Host: {info.get('hostname')}",
                )
                db.add(alert)
                db.flush()
                from services.notifier import notify_alert
                notify_alert(alert)
        db.commit()
        log.info("Scan saved — %d devices, %d new", len(devices), new_count)
    finally:
        db.close()
