"""
DNS monitoring via passive packet capture.
Requires CAP_NET_RAW or root.
Falls back gracefully when permissions are unavailable.
Only captures domain names — no URL paths, no query content, no TLS SNI bodies.
"""
import logging
import threading
from datetime import datetime

log = logging.getLogger("dns_monitor")
_running = False
_thread: threading.Thread | None = None


def _capture_loop(interface: str):
    """Capture DNS queries using scapy. Runs in a background thread."""
    try:
        from scapy.all import sniff, DNS, DNSQR, IP  # type: ignore
    except ImportError:
        log.warning("scapy not installed — DNS capture disabled")
        return

    from database import SessionLocal
    from models import DNSQuery

    def handle_packet(pkt):
        if not pkt.haslayer(DNS) or not pkt.haslayer(DNSQR):
            return
        # Only log queries (qr == 0), not responses
        if pkt[DNS].qr != 0:
            return
        src_ip = pkt[IP].src if pkt.haslayer(IP) else None
        for i in range(pkt[DNS].qdcount):
            try:
                qname = pkt[DNS].qd.qname.decode("utf-8", errors="ignore").rstrip(".")
                qtype = _qtype_str(pkt[DNS].qd.qtype)
                if not qname or qname == ".":
                    continue
                db = SessionLocal()
                try:
                    # Look up MAC from IP
                    from models import Device
                    dev = db.query(Device).filter(Device.ip == src_ip).first()
                    mac = dev.mac if dev else None
                    record = DNSQuery(
                        device_mac=mac,
                        device_ip=src_ip,
                        domain=qname.lower(),
                        query_type=qtype,
                        timestamp=datetime.utcnow(),
                    )
                    db.add(record)
                    db.commit()
                finally:
                    db.close()
            except Exception as e:
                log.debug("Packet parse error: %s", e)

    try:
        log.info("Starting DNS capture on interface %s", interface)
        sniff(iface=interface, filter="udp port 53", prn=handle_packet, store=False)
    except PermissionError:
        log.warning("Insufficient privileges for packet capture. Run with sudo or grant CAP_NET_RAW.")
    except Exception as e:
        log.error("DNS capture error: %s", e)


def _qtype_str(qtype: int) -> str:
    return {1: "A", 28: "AAAA", 5: "CNAME", 15: "MX", 16: "TXT", 6: "SOA"}.get(qtype, str(qtype))


def start(interface: str):
    global _running, _thread
    if _running:
        return
    _running = True
    _thread = threading.Thread(target=_capture_loop, args=(interface,), daemon=True, name="dns-capture")
    _thread.start()
    log.info("DNS monitor thread started")


def stop():
    global _running
    _running = False
    log.info("DNS monitor stopped")
