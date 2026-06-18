#!/usr/bin/env python3
"""
Family Security — Remote Location Agent
Runs at each home/apartment. Scans the local network and pushes
data to the central hub over HTTPS/HTTP.

Requirements: Python 3.10+, requests, optional scapy (for DNS capture)
Install:  pip install requests scapy
Run:      python agent.py
Or:       docker compose -f docker-compose.agent.yml up
"""
import os
import re
import socket
import subprocess
import threading
import time
import logging
from datetime import datetime
from typing import Optional

import requests

# ── Config from env ────────────────────────────────────────────────────────────
HUB_URL          = os.environ["HUB_URL"]           # e.g. http://192.168.100.1:8000
API_KEY          = os.environ["API_KEY"]            # from hub /api/locations
INTERFACE        = os.environ.get("INTERFACE", "eth0")
SUBNET           = os.environ.get("SUBNET", "192.168.1.0/24")
SCAN_INTERVAL    = int(os.environ.get("SCAN_INTERVAL", "60"))
DNS_CAPTURE      = os.environ.get("DNS_CAPTURE", "false").lower() == "true"
HEARTBEAT_INTERVAL = int(os.environ.get("HEARTBEAT_INTERVAL", "30"))
BATCH_SIZE       = int(os.environ.get("DNS_BATCH_SIZE", "100"))
LOG_LEVEL        = os.environ.get("LOG_LEVEL", "INFO")

logging.basicConfig(level=LOG_LEVEL, format="%(asctime)s agent %(levelname)s %(message)s")
log = logging.getLogger("agent")

HEADERS = {"X-API-Key": API_KEY, "Content-Type": "application/json"}

# Thread-safe DNS queue
_dns_queue: list[dict] = []
_dns_lock = threading.Lock()


# ── Network helpers ────────────────────────────────────────────────────────────

def read_arp_table() -> list[dict]:
    devices = {}
    # /proc/net/arp (no root needed)
    try:
        with open("/proc/net/arp") as f:
            for line in f.readlines()[1:]:
                parts = line.split()
                if len(parts) >= 4 and parts[3] != "00:00:00:00:00:00":
                    devices[parts[3].upper()] = {"mac": parts[3].upper(), "ip": parts[0]}
    except Exception:
        pass

    # arp -n fallback
    try:
        out = subprocess.check_output(["arp", "-n"], text=True, timeout=10)
        for line in out.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 3 and re.match(r"([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", parts[2]):
                mac = parts[2].upper()
                devices.setdefault(mac, {"mac": mac, "ip": parts[0]})
    except Exception:
        pass

    # nmap -sn sweep for fuller results
    try:
        out = subprocess.check_output(
            ["nmap", "-sn", "--host-timeout", "5s", SUBNET],
            text=True, timeout=60, stderr=subprocess.DEVNULL,
        )
        current_ip = None
        for line in out.splitlines():
            m = re.search(r"Nmap scan report for (?:\S+ \()?(\d+\.\d+\.\d+\.\d+)\)?", line)
            if m:
                current_ip = m.group(1)
            m = re.search(r"MAC Address: ([0-9A-F:]{17})", line, re.I)
            if m and current_ip:
                mac = m.group(1).upper()
                devices.setdefault(mac, {"mac": mac, "ip": current_ip})
    except FileNotFoundError:
        pass
    except Exception as e:
        log.debug("nmap: %s", e)

    return list(devices.values())


def resolve_hostname(ip: str) -> Optional[str]:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


# ── Hub communication ──────────────────────────────────────────────────────────

def post_json(path: str, payload: dict, retries: int = 3) -> bool:
    url = HUB_URL.rstrip("/") + path
    for attempt in range(retries):
        try:
            r = requests.post(url, json=payload, headers=HEADERS, timeout=15)
            if r.status_code < 300:
                return True
            log.warning("Hub returned %d for %s", r.status_code, path)
        except requests.RequestException as e:
            wait = 2 ** attempt
            log.warning("Hub unreachable (%s), retry in %ds", e, wait)
            time.sleep(wait)
    return False


def send_heartbeat():
    try:
        r = requests.post(
            HUB_URL.rstrip("/") + "/api/ingest/heartbeat",
            headers=HEADERS, timeout=10,
        )
        return r.status_code < 300
    except Exception as e:
        log.debug("Heartbeat failed: %s", e)
        return False


# ── Main loops ─────────────────────────────────────────────────────────────────

def scan_loop():
    while True:
        try:
            raw_devices = read_arp_table()
            devices = []
            for d in raw_devices:
                hostname = resolve_hostname(d["ip"])
                devices.append({
                    "mac": d["mac"],
                    "ip": d["ip"],
                    "hostname": hostname,
                    "vendor": None,   # hub resolves vendor from OUI
                })

            # Drain DNS queue
            with _dns_lock:
                dns_batch = _dns_queue[:BATCH_SIZE]
                del _dns_queue[:BATCH_SIZE]

            payload = {"devices": devices, "dns_queries": dns_batch}
            ok = post_json("/api/ingest/scan", payload)
            log.info("Scan: %d devices, %d DNS queued — hub %s",
                     len(devices), len(dns_batch), "ok" if ok else "FAIL")
        except Exception as e:
            log.error("Scan loop error: %s", e)

        time.sleep(SCAN_INTERVAL)


def heartbeat_loop():
    while True:
        send_heartbeat()
        time.sleep(HEARTBEAT_INTERVAL)


def dns_capture_loop():
    """Passive DNS capture. Requires CAP_NET_RAW or root."""
    try:
        from scapy.all import sniff, DNS, DNSQR, IP  # type: ignore
    except ImportError:
        log.warning("scapy not installed — DNS capture disabled on agent")
        return

    def handle(pkt):
        if not pkt.haslayer(DNS) or not pkt.haslayer(DNSQR):
            return
        if pkt[DNS].qr != 0:
            return
        src_ip = pkt[IP].src if pkt.haslayer(IP) else None
        try:
            qname = pkt[DNS].qd.qname.decode("utf-8", errors="ignore").rstrip(".")
            if qname and qname != ".":
                with _dns_lock:
                    _dns_queue.append({
                        "device_ip": src_ip,
                        "domain": qname.lower(),
                        "query_type": "A",
                        "timestamp": datetime.utcnow().isoformat(),
                    })
        except Exception:
            pass

    try:
        log.info("DNS capture started on %s", INTERFACE)
        sniff(iface=INTERFACE, filter="udp port 53", prn=handle, store=False)
    except PermissionError:
        log.warning("No permission for DNS capture (need CAP_NET_RAW or root)")
    except Exception as e:
        log.error("DNS capture error: %s", e)


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    log.info("Family Security Agent starting → hub: %s", HUB_URL)

    # Send initial heartbeat
    if not send_heartbeat():
        log.warning("Cannot reach hub at startup — will keep retrying")

    threads = [
        threading.Thread(target=heartbeat_loop, daemon=True, name="heartbeat"),
        threading.Thread(target=scan_loop, daemon=True, name="scanner"),
    ]

    if DNS_CAPTURE:
        threads.append(threading.Thread(target=dns_capture_loop, daemon=True, name="dns"))

    for t in threads:
        t.start()

    log.info("All agent threads started. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        log.info("Agent stopped")
