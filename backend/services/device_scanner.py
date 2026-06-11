"""
Device discovery via ARP table, ping-sweep, and optional nmap.
Read-only / passive — no exploitation, no credential testing.
Requires: net-tools (arp) or access to /proc/net/arp.
Optional: nmap for richer discovery.
"""
import asyncio
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


def _read_proc_arp() -> list[dict]:
    """Read /proc/net/arp — no special privileges needed."""
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
    except Exception as e:
        log.warning("Cannot read /proc/net/arp: %s", e)
    return results


def _arp_command() -> list[dict]:
    """Fallback: parse `arp -n` output."""
    results = []
    try:
        out = subprocess.check_output(["arp", "-n"], text=True, timeout=10)
        for line in out.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 3:
                continue
            ip = parts[0]
            mac = parts[2]
            if not re.match(r"([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", mac):
                continue
            results.append({"ip": ip, "mac": mac.upper()})
    except Exception as e:
        log.warning("arp command failed: %s", e)
    return results


def _nmap_scan(subnet: str) -> list[dict]:
    """Safe nmap host-discovery only (-sn = no port scan)."""
    results = []
    try:
        out = subprocess.check_output(
            ["nmap", "-sn", "--host-timeout", "5s", subnet],
            text=True, timeout=60, stderr=subprocess.DEVNULL
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
        log.info("nmap not installed — skipping nmap scan")
    except Exception as e:
        log.warning("nmap scan failed: %s", e)
    return results


def _resolve_hostname(ip: str) -> Optional[str]:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def discover_devices(subnet: str = LOCAL_SUBNET) -> list[dict]:
    """Collect devices from all available sources and deduplicate by MAC."""
    found: dict[str, dict] = {}

    for entry in _read_proc_arp():
        found[entry["mac"]] = entry

    for entry in _arp_command():
        found.setdefault(entry["mac"], entry)

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
