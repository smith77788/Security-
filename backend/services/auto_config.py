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
    for addr in psutil.net_if_addrs().get(iface, []):
        if addr.family == socket.AF_INET and not addr.address.startswith("127."):
            my_ip = addr.address
            netmask = addr.netmask
            break

    # Derive subnet from my_ip + netmask
    subnet = LOCAL_SUBNET
    if my_ip and netmask:
        try:
            net = ipaddress.IPv4Network(f"{my_ip}/{netmask}", strict=False)
            subnet = str(net)
        except Exception:
            pass

    # Get default gateway
    gws = psutil.net_if_stats()
    try:
        out = subprocess.check_output(
            ["ip", "route", "show", "default"], text=True, timeout=5
        )
        for line in out.splitlines():
            parts = line.split()
            if "via" in parts:
                gateway = parts[parts.index("via") + 1]
                break
    except Exception:
        pass

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
