"""
Zero-config network auto-detection.
Detects the best interface, gateway, local subnet and own IP
using psutil + socket — no root required.
"""
import ipaddress
import logging
import socket
import subprocess
from typing import Optional

import psutil

log = logging.getLogger("auto_config")


def _default_route_interface() -> Optional[str]:
    """Find the interface that carries the default route (Linux/macOS)."""
    try:
        out = subprocess.check_output(
            ["ip", "route", "show", "default"], text=True, timeout=5
        )
        for line in out.splitlines():
            parts = line.split()
            if "dev" in parts:
                return parts[parts.index("dev") + 1]
    except Exception:
        pass
    # Fallback: pick the interface that can reach 8.8.8.8
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        our_ip = s.getsockname()[0]
        s.close()
        for iface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET and addr.address == our_ip:
                    return iface
    except Exception:
        pass
    return None


def _get_gateway() -> Optional[str]:
    """Try multiple methods to find the default gateway (Android-safe)."""
    # 1. Termux iproute2 or system ip
    for cmd in (
        ["ip", "route", "show", "default"],
        ["/system/bin/ip", "route", "show", "default"],
        ["ip", "route", "show", "table", "all"],
        ["/system/bin/ip", "route", "show", "table", "all"],
    ):
        try:
            out = subprocess.check_output(cmd, text=True, timeout=5,
                                          stderr=subprocess.DEVNULL)
            for line in out.splitlines():
                parts = line.split()
                if "default" in line and "via" in parts:
                    return parts[parts.index("via") + 1]
        except Exception:
            pass

    # 2. Parse /proc/net/route (hex little-endian table, often readable without root)
    try:
        with open("/proc/net/route") as f:
            for line in f.readlines()[1:]:
                parts = line.split()
                if len(parts) < 3:
                    continue
                dest, gw_hex = parts[1], parts[2]
                if dest == "00000000" and gw_hex != "00000000":
                    n = int(gw_hex, 16)
                    return f"{n & 0xFF}.{(n >> 8) & 0xFF}.{(n >> 16) & 0xFF}.{(n >> 24) & 0xFF}"
    except Exception:
        pass

    # 3. Guess: same subnet, last octet = 1 (most common home router)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        our_ip = s.getsockname()[0]
        s.close()
        parts = our_ip.split(".")
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.{parts[2]}.1"
    except Exception:
        pass

    return None


def detect() -> dict:
    """
    Return {interface, my_ip, gateway, subnet} auto-detected from the OS.
    Falls back to environment variables / config defaults.
    """
    from config import NETWORK_INTERFACE, LOCAL_SUBNET

    iface = _default_route_interface() or NETWORK_INTERFACE
    my_ip: Optional[str] = None
    netmask: Optional[str] = None
    gateway: Optional[str] = None

    # Get IP + netmask for the chosen interface
    try:
        for addr in psutil.net_if_addrs().get(iface, []):
            if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                my_ip = addr.address
                netmask = addr.netmask
                break
    except Exception:
        pass

    # Derive subnet from my_ip + netmask
    subnet = LOCAL_SUBNET
    if my_ip and netmask:
        try:
            net = ipaddress.IPv4Network(f"{my_ip}/{netmask}", strict=False)
            subnet = str(net)
        except Exception:
            pass

    # Get default gateway — try several methods (Android needs multiple fallbacks)
    gateway = _get_gateway()

    result = {
        "interface": iface,
        "my_ip": my_ip or "unknown",
        "gateway": gateway or "unknown",
        "subnet": subnet,
    }
    log.info("Auto-config: %s", result)
    return result


# Module-level cache — populated once on startup
_cached: Optional[dict] = None


def get() -> dict:
    global _cached
    if _cached is None:
        _cached = detect()
    return _cached


def refresh():
    global _cached
    _cached = detect()
    return _cached
