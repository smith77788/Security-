"""
Deep Passive Network Monitor.
Uses scapy for zero-config packet capture. Extracts:
  - DNS queries/responses
  - TLS SNI (hostname from ClientHello — no decryption)
  - HTTP Host headers (plaintext HTTP)
  - DHCP fingerprints (device type from DHCP options)
  - mDNS service announcements (device names, services)
  - SSDP/UPnP announcements (smart home device types)
  - NetBIOS name announcements (Windows hostnames)
  - TCP/UDP flow metadata (IP, port, size, timing)

Privacy: payload content is NEVER stored. Only metadata.
"""
import ipaddress
import logging
import queue
import struct
import threading
from datetime import datetime
from typing import Optional

log = logging.getLogger("deep_monitor")

_running = False
_thread: Optional[threading.Thread] = None
_event_queue: queue.Queue = queue.Queue(maxsize=50_000)
_writer_thread: Optional[threading.Thread] = None

# ── TLS SNI Extraction ─────────────────────────────────────────────────────────

def _extract_sni(payload: bytes) -> Optional[str]:
    """Parse raw TCP payload, find TLS ClientHello, extract SNI extension."""
    try:
        if len(payload) < 6 or payload[0] != 0x16:   # TLS record
            return None
        if payload[5] != 0x01:                        # handshake type = ClientHello
            return None
        # ClientHello body starts at byte 9 (after record header 5B + handshake header 4B)
        pos = 9 + 2 + 32   # skip version(2) + random(32)
        if pos >= len(payload):
            return None
        sid_len = payload[pos]; pos += 1 + sid_len
        if pos + 2 > len(payload):
            return None
        cs_len = struct.unpack_from("!H", payload, pos)[0]; pos += 2 + cs_len
        if pos >= len(payload):
            return None
        cm_len = payload[pos]; pos += 1 + cm_len
        if pos + 2 > len(payload):
            return None
        ext_end = pos + 2 + struct.unpack_from("!H", payload, pos)[0]; pos += 2
        while pos + 4 <= ext_end and pos + 4 <= len(payload):
            ext_type = struct.unpack_from("!H", payload, pos)[0]
            ext_len  = struct.unpack_from("!H", payload, pos + 2)[0]
            pos += 4
            if ext_type == 0x0000 and pos + 5 <= len(payload):  # SNI
                name_len = struct.unpack_from("!H", payload, pos + 3)[0]
                end = pos + 5 + name_len
                if end <= len(payload):
                    return payload[pos + 5:end].decode("ascii", errors="ignore") or None
            pos += ext_len
    except Exception:
        pass
    return None


# ── HTTP Host Extraction ───────────────────────────────────────────────────────

def _extract_http_host(payload: bytes) -> Optional[str]:
    try:
        text = payload[:2048].decode("ascii", errors="ignore")
        for line in text.split("\r\n"):
            if line.lower().startswith("host:"):
                return line[5:].strip().split(":")[0]
    except Exception:
        pass
    return None


# ── DHCP Fingerprinting ────────────────────────────────────────────────────────

_DHCP_VENDOR_MAP = {
    b"\x64\x65\x62\x69\x61\x6e": "Linux/Debian",
    b"android":  "Android",
    b"iphone":   "iPhone/iOS",
    b"ipad":     "iPad/iOS",
    b"windows":  "Windows",
    b"MSFT":     "Windows",
    b"apple":    "Apple macOS",
    b"raspberr": "Raspberry Pi",
}

def _fingerprint_dhcp(pkt) -> dict:
    """Extract device type hints from DHCP options."""
    info: dict = {}
    try:
        from scapy.all import DHCP, BOOTP
        if not pkt.haslayer(DHCP):
            return info
        opts = dict(pkt[DHCP].options) if hasattr(pkt[DHCP], "options") else {}
        # Option 60: Vendor class identifier
        vendor_class = opts.get("vendor_class_id", b"")
        if isinstance(vendor_class, bytes):
            for sig, name in _DHCP_VENDOR_MAP.items():
                if sig.lower() in vendor_class.lower():
                    info["os_hint"] = name
                    break
        # Option 55: Parameter Request List → OS fingerprint
        prl = opts.get("param_req_list", [])
        if prl:
            info["dhcp_prl"] = str(list(prl))
        # Hostname from option 12
        hostname = opts.get("hostname", b"")
        if isinstance(hostname, bytes):
            info["hostname"] = hostname.decode("utf-8", errors="ignore")
        src_mac = pkt.src if hasattr(pkt, "src") else None
        if src_mac:
            info["mac"] = src_mac.upper()
    except Exception as e:
        log.debug("DHCP parse error: %s", e)
    return info


# ── mDNS Device Discovery ──────────────────────────────────────────────────────

def _parse_mdns(pkt) -> Optional[dict]:
    try:
        from scapy.all import DNS, DNSRR, IP
        if not pkt.haslayer(DNS):
            return None
        dns = pkt[DNS]
        src_ip = pkt[IP].src if pkt.haslayer(IP) else None
        # Look for PTR records (service announcements) and A records
        for i in range(dns.ancount):
            rr = dns.an
            while rr and i > 0:
                rr = rr.payload if hasattr(rr, "payload") else None
                i -= 1
            if rr is None:
                break
            if hasattr(rr, "rrname") and hasattr(rr, "rdata"):
                name = rr.rrname.decode("utf-8", errors="ignore").rstrip(".")
                # Common service type patterns
                svc_type = None
                if "_airplay" in name:
                    svc_type = "Apple AirPlay"
                elif "_googlecast" in name:
                    svc_type = "Google Cast"
                elif "_hap" in name:
                    svc_type = "Apple HomeKit"
                elif "_printer" in name or "_ipp" in name:
                    svc_type = "Printer"
                elif "_smb" in name or "_afpovertcp" in name:
                    svc_type = "File Server"
                elif "_sonos" in name:
                    svc_type = "Sonos Speaker"
                if svc_type:
                    return {"ip": src_ip, "service": svc_type, "mdns_name": name}
    except Exception:
        pass
    return None


# ── SSDP/UPnP Discovery ────────────────────────────────────────────────────────

_SSDP_DEVICE_TYPES = {
    "MediaRenderer":   "Smart TV / Media Renderer",
    "MediaServer":     "NAS / Media Server",
    "InternetGateway": "Router / Gateway",
    "WLANAccessPoint": "WiFi Access Point",
    "BasicDevice":     "Generic UPnP Device",
    "Printer":         "Printer",
    "Scanner":         "Scanner",
    "Robot":           "Robot Vacuum",
    "Camera":          "IP Camera",
}

def _parse_ssdp(payload: bytes, src_ip: str) -> Optional[dict]:
    try:
        text = payload.decode("utf-8", errors="ignore")
        if "NOTIFY" not in text and "HTTP/1.1 200 OK" not in text:
            return None
        for k, v in _SSDP_DEVICE_TYPES.items():
            if k in text:
                server = ""
                for line in text.splitlines():
                    if line.lower().startswith("server:"):
                        server = line[7:].strip()
                return {"ip": src_ip, "device_type": v, "ssdp_server": server}
    except Exception:
        pass
    return None


# ── Main Packet Handler ────────────────────────────────────────────────────────

def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return False


def _handle_packet(pkt):
    """
    Lightweight per-packet handler running in the capture thread.
    Classifies packets and pushes small event dicts to the queue.
    """
    try:
        from scapy.all import IP, TCP, UDP, DNS, DNSQR, Raw
        if not pkt.haslayer(IP):
            return

        src = pkt[IP].src
        dst = pkt[IP].dst
        size = len(pkt)
        ts = datetime.utcnow()

        # ── DNS query ──────────────────────────────────────────────────────────
        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR) and pkt[DNS].qr == 0:
            qname = pkt[DNS].qd.qname.decode("utf-8", errors="ignore").rstrip(".")
            if qname and qname != ".":
                _event_queue.put_nowait({
                    "type": "dns", "src": src, "dst": dst,
                    "domain": qname.lower(), "ts": ts,
                })
            return

        # ── mDNS (224.0.0.251:5353) ───────────────────────────────────────────
        if dst == "224.0.0.251":
            info = _parse_mdns(pkt)
            if info:
                _event_queue.put_nowait({"type": "mdns", "src": src, "info": info, "ts": ts})
            return

        # ── SSDP (239.255.255.250:1900) ───────────────────────────────────────
        if dst == "239.255.255.250" and pkt.haslayer(UDP) and pkt.haslayer(Raw):
            info = _parse_ssdp(bytes(pkt[Raw]), src)
            if info:
                _event_queue.put_nowait({"type": "ssdp", "src": src, "info": info, "ts": ts})
            return

        # ── DHCP ──────────────────────────────────────────────────────────────
        from scapy.all import DHCP
        if pkt.haslayer(DHCP):
            fp = _fingerprint_dhcp(pkt)
            if fp:
                _event_queue.put_nowait({"type": "dhcp", "src": src, "fp": fp, "ts": ts})
            return

        # ── TLS SNI (port 443) ─────────────────────────────────────────────────
        if pkt.haslayer(TCP) and pkt[TCP].dport == 443 and pkt.haslayer(Raw):
            sni = _extract_sni(bytes(pkt[Raw]))
            if sni:
                _event_queue.put_nowait({
                    "type": "tls_sni", "src": src, "dst": dst,
                    "sni": sni, "size": size, "ts": ts,
                })
                return  # also log as flow below

        # ── HTTP Host ──────────────────────────────────────────────────────────
        if pkt.haslayer(TCP) and pkt[TCP].dport == 80 and pkt.haslayer(Raw):
            host = _extract_http_host(bytes(pkt[Raw]))
            if host:
                _event_queue.put_nowait({
                    "type": "http_host", "src": src, "dst": dst,
                    "host": host, "size": size, "ts": ts,
                })
                return

        # ── Generic TCP/UDP flow ───────────────────────────────────────────────
        if pkt.haslayer(TCP) or pkt.haslayer(UDP):
            layer4 = pkt[TCP] if pkt.haslayer(TCP) else pkt[UDP]
            proto = "TCP" if pkt.haslayer(TCP) else "UDP"
            dport = layer4.dport
            sport = layer4.sport
            # Only log flows to/from external IPs
            if not _is_private(dst):
                _event_queue.put_nowait({
                    "type": "flow", "src": src, "dst": dst,
                    "proto": proto, "dport": dport, "sport": sport,
                    "size": size, "ts": ts,
                })
            elif not _is_private(src):
                _event_queue.put_nowait({
                    "type": "flow", "src": src, "dst": dst,
                    "proto": proto, "dport": dport, "sport": sport,
                    "size": size, "ts": ts,
                })

    except Exception as e:
        log.debug("Packet handler error: %s", e)


# ── Queue Writer ───────────────────────────────────────────────────────────────

def _writer_loop(location_id: Optional[int]):
    """Drain the event queue and persist to DB in batches."""
    from database import SessionLocal
    from models import DNSQuery, Connection, DeviceFingerprint
    from services.threat_intel import is_threat_ip, is_threat_domain
    from services.geo import lookup as geo_lookup
    from services.realtime import manager

    BATCH = 200
    SLEEP = 2.0

    while _running or not _event_queue.empty():
        events = []
        try:
            for _ in range(BATCH):
                events.append(_event_queue.get_nowait())
        except Exception:
            pass

        if not events:
            import time; time.sleep(SLEEP)
            continue

        db = SessionLocal()
        try:
            for ev in events:
                t = ev["type"]

                if t == "dns":
                    domain = ev["domain"]
                    db.add(DNSQuery(
                        location_id=location_id,
                        device_ip=ev["src"],
                        domain=domain,
                        query_type="A",
                        timestamp=ev["ts"],
                    ))
                    threat, reason = is_threat_domain(domain)
                    if threat:
                        from models import Alert
                        db.add(Alert(
                            location_id=location_id,
                            device_ip=ev["src"],
                            alert_type="suspicious_domain",
                            severity="critical",
                            message=f"DNS → подозрительный домен: {domain} ({reason})",
                            detail=f"src={ev['src']}",
                        ))

                elif t in ("flow", "tls_sni", "http_host"):
                    dst_ip = ev["dst"]
                    sni = ev.get("sni") or ev.get("host")
                    dport = ev.get("dport", 0)
                    proto = ev.get("proto", "TCP")
                    size = ev.get("size", 0)
                    threat, reason = is_threat_ip(dst_ip)
                    geo = geo_lookup(dst_ip)
                    # Upsert connection record
                    conn = db.query(Connection).filter(
                        Connection.src_ip == ev["src"],
                        Connection.dst_ip == dst_ip,
                        Connection.dst_port == dport,
                    ).first()
                    if conn is None:
                        conn = Connection(
                            location_id=location_id,
                            src_ip=ev["src"],
                            dst_ip=dst_ip,
                            dst_port=dport,
                            protocol=proto,
                            first_seen=ev["ts"],
                            last_seen=ev["ts"],
                            bytes_out=size,
                            country=geo.get("country"),
                            country_code=geo.get("country_code"),
                            asn=geo.get("asn"),
                            org=geo.get("org"),
                            is_threat=threat,
                            threat_reason=reason if threat else None,
                            tls_sni=sni,
                        )
                        db.add(conn)
                    else:
                        conn.last_seen = ev["ts"]
                        conn.bytes_out = (conn.bytes_out or 0) + size
                        if sni:
                            conn.tls_sni = sni
                        if threat and not conn.is_threat:
                            conn.is_threat = True
                            conn.threat_reason = reason

                    if threat:
                        from models import Alert
                        db.add(Alert(
                            location_id=location_id,
                            device_ip=ev["src"],
                            alert_type="threat_ip",
                            severity="critical",
                            message=f"Подключение к вредоносному IP: {dst_ip} ({reason})",
                            detail=f"SNI={sni}, port={dport}, country={geo.get('country')}",
                        ))
                        manager.emit_alert(db.query(Alert).order_by(Alert.id.desc()).first() or type('A', (), {'id':0,'location_id':location_id,'severity':'critical','alert_type':'threat_ip','message':f'Threat IP {dst_ip}','timestamp':ev['ts']})(), "")

                elif t == "dhcp":
                    fp = ev["fp"]
                    mac = fp.get("mac")
                    if mac:
                        existing = db.query(DeviceFingerprint).filter(
                            DeviceFingerprint.mac == mac
                        ).first()
                        if existing is None:
                            db.add(DeviceFingerprint(
                                mac=mac,
                                os_hint=fp.get("os_hint"),
                                hostname=fp.get("hostname"),
                                fingerprint_type="dhcp",
                                raw=str(fp),
                            ))
                        else:
                            if fp.get("os_hint"):
                                existing.os_hint = fp["os_hint"]
                            if fp.get("hostname"):
                                existing.hostname = fp["hostname"]

                elif t in ("mdns", "ssdp"):
                    info = ev.get("info", {})
                    src_ip = ev["src"]
                    # Update device fingerprint
                    svc = info.get("service") or info.get("device_type")
                    if svc:
                        fp = db.query(DeviceFingerprint).filter(
                            DeviceFingerprint.src_ip == src_ip
                        ).first()
                        if fp is None:
                            db.add(DeviceFingerprint(
                                src_ip=src_ip,
                                os_hint=svc,
                                fingerprint_type=t,
                                raw=str(info),
                            ))
                        else:
                            fp.os_hint = svc

            db.commit()
        except Exception as e:
            log.error("Writer error: %s", e)
            try:
                db.rollback()
            except Exception:
                pass
        finally:
            db.close()

        import time; time.sleep(0.1)


# ── Public API ─────────────────────────────────────────────────────────────────

def start(interface: str, location_id: Optional[int] = None):
    global _running, _thread, _writer_thread
    if _running:
        return
    _running = True

    _writer_thread = threading.Thread(
        target=_writer_loop, args=(location_id,), daemon=True, name="pkt-writer"
    )
    _writer_thread.start()

    def _capture():
        try:
            from scapy.all import sniff
            log.info("Deep monitor: capturing on %s", interface)
            sniff(
                iface=interface,
                prn=_handle_packet,
                store=False,
                filter="ip",          # only IP packets
            )
        except PermissionError:
            log.warning("Deep monitor needs CAP_NET_RAW. Run with network_mode: host + cap_add: NET_RAW")
        except Exception as e:
            log.error("Deep monitor capture error: %s", e)

    _thread = threading.Thread(target=_capture, daemon=True, name="pkt-capture")
    _thread.start()
    log.info("Deep monitor started on interface %s", interface)


def stop():
    global _running
    _running = False
