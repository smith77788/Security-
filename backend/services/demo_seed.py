"""
Multi-location demo seed with rich data:
devices, DNS, alerts, connections with GeoIP, bandwidth samples,
device fingerprints, beaconing example.
"""
import random
import secrets
from datetime import datetime, timedelta
from database import SessionLocal
from models import (
    Location, Device, DNSQuery, Alert,
    Connection, BandwidthSample, DeviceFingerprint,
)

LOCATIONS = [
    {"name": "Основной дом",      "icon": "🏠", "color": "#3b82f6", "address": "ул. Ленина, 12",    "timezone": "Europe/Moscow"},
    {"name": "Дача",              "icon": "🌲", "color": "#22c55e", "address": "Подмосковье, СНТ",  "timezone": "Europe/Moscow"},
    {"name": "Городская квартира","icon": "🏢", "color": "#a855f7", "address": "пр. Невский, 88",   "timezone": "Europe/Moscow"},
]

_DEVICES = [
    # ── Основной дом ──────────────────────────────────────────────────────────
    [
        {"mac":"AA:BB:CC:11:22:01","ip":"192.168.1.1",  "hostname":"router",       "vendor":"TP-Link", "name":"Роутер TP-Link",   "os":"RouterOS",      "dtype":"Router"},
        {"mac":"AA:BB:CC:11:22:02","ip":"192.168.1.10", "hostname":"android-dad",  "vendor":"Samsung", "name":"Телефон папы",     "os":"Android 14",    "dtype":"Smartphone"},
        {"mac":"AA:BB:CC:11:22:03","ip":"192.168.1.11", "hostname":"iphone-mom",   "vendor":"Apple",   "name":"iPhone мамы",      "os":"iOS 17",        "dtype":"Smartphone"},
        {"mac":"AA:BB:CC:11:22:04","ip":"192.168.1.20", "hostname":"laptop-home",  "vendor":"Dell",    "name":"Ноутбук",          "os":"Windows 11",    "dtype":"Laptop"},
        {"mac":"AA:BB:CC:11:22:05","ip":"192.168.1.21", "hostname":"smart-tv",     "vendor":"LG",      "name":"Телевизор LG",     "os":"WebOS",         "dtype":"Smart TV"},
        {"mac":"AA:BB:CC:11:22:06","ip":"192.168.1.30", "hostname":None,           "vendor":"Huawei",  "name":None,               "os":None,            "dtype":"Unknown"},
        {"mac":"AA:BB:CC:11:22:07","ip":"192.168.1.50", "hostname":None,           "vendor":"Unknown", "name":None,               "os":None,            "dtype":"Unknown"},
    ],
    # ── Дача ─────────────────────────────────────────────────────────────────
    [
        {"mac":"BB:CC:DD:22:33:01","ip":"192.168.2.1",  "hostname":"router-dacha", "vendor":"D-Link",  "name":"Роутер дача",      "os":"DD-WRT",        "dtype":"Router"},
        {"mac":"BB:CC:DD:22:33:02","ip":"192.168.2.10", "hostname":"ipad-dacha",   "vendor":"Apple",   "name":"iPad на даче",     "os":"iPadOS 17",     "dtype":"Tablet"},
        {"mac":"BB:CC:DD:22:33:03","ip":"192.168.2.11", "hostname":"laptop-dacha", "vendor":"Lenovo",  "name":"Ноутбук дача",     "os":"Ubuntu 22.04",  "dtype":"Laptop"},
        {"mac":"BB:CC:DD:22:33:04","ip":"192.168.2.20", "hostname":None,           "vendor":"Unknown", "name":None,               "os":None,            "dtype":"Unknown"},
    ],
    # ── Городская квартира ────────────────────────────────────────────────────
    [
        {"mac":"CC:DD:EE:33:44:01","ip":"10.0.0.1",     "hostname":"router-apt",   "vendor":"Netgear", "name":"Роутер квартира",  "os":"NetgearOS",     "dtype":"Router"},
        {"mac":"CC:DD:EE:33:44:02","ip":"10.0.0.10",    "hostname":"macbook",      "vendor":"Apple",   "name":"MacBook",          "os":"macOS Sonoma",  "dtype":"Laptop"},
        {"mac":"CC:DD:EE:33:44:03","ip":"10.0.0.11",    "hostname":"iphone-apt",   "vendor":"Apple",   "name":"iPhone квартира",  "os":"iOS 17",        "dtype":"Smartphone"},
        {"mac":"CC:DD:EE:33:44:04","ip":"10.0.0.20",    "hostname":"ps5",          "vendor":"Sony",    "name":"PlayStation 5",    "os":"PS5 OS",        "dtype":"Game Console"},
        {"mac":"CC:DD:EE:33:44:05","ip":"10.0.0.21",    "hostname":"chromecast",   "vendor":"Google",  "name":"Chromecast",       "os":"ChromecastOS",  "dtype":"Streaming Device"},
    ],
]

_DOMAINS = [
    "google.com","youtube.com","netflix.com","apple.com","icloud.com",
    "microsoft.com","amazon.com","vk.com","yandex.ru","mail.ru",
    "telegram.org","whatsapp.com","instagram.com","twitter.com",
    "spotify.com","twitch.tv","discord.com","github.com",
    "cloudflare.com","gstatic.com","fonts.googleapis.com",
    "cdn.jsdelivr.net","tiktok.com","ok.ru","steam.com",
]
_SUSPICIOUS = ["coinhive.com", "evil.example.com", "hotjar.com"]

# Geo-annotated external IPs for demo connections
_EXT_IPS = [
    {"ip":"142.250.185.78",  "country":"US","cc":"US","org":"Google LLC",      "asn":"AS15169","port":443,"sni":"youtube.com",      "threat":False},
    {"ip":"104.244.42.1",    "country":"US","cc":"US","org":"Twitter Inc",      "asn":"AS13414","port":443,"sni":"twitter.com",       "threat":False},
    {"ip":"185.60.216.35",   "country":"IE","cc":"IE","org":"Facebook Inc",     "asn":"AS32934","port":443,"sni":"instagram.com",     "threat":False},
    {"ip":"217.69.139.200",  "country":"RU","cc":"RU","org":"Mail.ru Group",    "asn":"AS47764","port":443,"sni":"mail.ru",           "threat":False},
    {"ip":"91.108.4.167",    "country":"DE","cc":"DE","org":"Telegram FZ-LLC",  "asn":"AS62041","port":443,"sni":"telegram.org",      "threat":False},
    {"ip":"23.44.229.77",    "country":"US","cc":"US","org":"Akamai",           "asn":"AS20940","port":443,"sni":"api.example.com",   "threat":False},
    # Suspicious
    {"ip":"185.220.101.47",  "country":"DE","cc":"DE","org":"Tor Relay",        "asn":"AS60729","port":443,"sni":None,               "threat":True},
    {"ip":"193.56.28.103",   "country":"RU","cc":"RU","org":"Unknown ISP",      "asn":"AS51659","port":4444,"sni":None,              "threat":True},
    {"ip":"45.95.147.236",   "country":"LT","cc":"LT","org":"C2 Infrastructure","asn":"AS211252","port":8080,"sni":None,             "threat":True},
]


def _rand_ts(days_back=7.0):
    return datetime.utcnow() - timedelta(seconds=random.uniform(0, days_back * 86400))


def seed():
    db = SessionLocal()
    try:
        if db.query(Location).count() > 0:
            return
        now = datetime.utcnow()

        # ── Locations ─────────────────────────────────────────────────────────
        locs = []
        for i, ld in enumerate(LOCATIONS):
            loc = Location(
                **ld,
                api_key=secrets.token_urlsafe(32),
                last_heartbeat=now - timedelta(minutes=random.randint(0, 3)),
                is_online=(i != 1),
                created_at=now - timedelta(days=90),
            )
            db.add(loc)
            locs.append(loc)
        db.commit()

        # ── Devices + fingerprints ────────────────────────────────────────────
        all_dev_pairs = []
        for li, loc in enumerate(locs):
            for j, d in enumerate(_DEVICES[li]):
                is_new = d["name"] is None
                first = now - timedelta(days=random.randint(7, 90) if not is_new else 0,
                                        hours=random.randint(0, 4) if is_new else 0)
                dev = Device(
                    location_id=loc.id,
                    mac=d["mac"], ip=d["ip"], hostname=d["hostname"],
                    vendor=d["vendor"], friendly_name=d["name"],
                    os_hint=d["os"], device_type=d["dtype"],
                    first_seen=first,
                    last_seen=now - timedelta(minutes=random.randint(0, 60)),
                    is_new=is_new, is_active=True,
                )
                db.add(dev)
                all_dev_pairs.append((loc, dev, d))

                if d["os"]:
                    db.add(DeviceFingerprint(
                        mac=d["mac"], src_ip=d["ip"],
                        os_hint=d["os"], device_type=d["dtype"],
                        hostname=d["hostname"],
                        fingerprint_type="dhcp",
                        updated_at=now,
                    ))
        db.commit()

        # ── DNS queries ────────────────────────────────────────────────────────
        dns_rows = []
        for loc, dev, _ in all_dev_pairs:
            for _ in range(random.randint(80, 500)):
                dns_rows.append(DNSQuery(
                    location_id=loc.id, device_mac=dev.mac, device_ip=dev.ip,
                    domain=random.choice(_DOMAINS),
                    query_type=random.choice(["A","AAAA","A","A"]),
                    timestamp=_rand_ts(7),
                ))
        # Suspicious DNS
        loc0 = locs[0]
        for dom in _SUSPICIOUS:
            mac = _DEVICES[0][1]["mac"]
            dns_rows.append(DNSQuery(
                location_id=loc0.id, device_mac=mac,
                domain=dom, query_type="A",
                timestamp=now - timedelta(hours=random.uniform(0.5, 6)),
            ))
        db.add_all(dns_rows)
        db.commit()

        # ── External connections (with GeoIP + threat) ────────────────────────
        conn_rows = []
        for loc, dev, _ in all_dev_pairs[:10]:  # top 10 devices
            for ext in random.sample(_EXT_IPS, k=random.randint(2, 6)):
                first_c = _rand_ts(1)
                conn_rows.append(Connection(
                    location_id=loc.id, src_ip=dev.ip,
                    dst_ip=ext["ip"], dst_port=ext["port"],
                    protocol="TCP",
                    bytes_out=random.randint(1000, 5_000_000),
                    bytes_in=random.randint(5000, 50_000_000),
                    first_seen=first_c,
                    last_seen=first_c + timedelta(seconds=random.randint(10, 3600)),
                    country=ext["country"], country_code=ext["cc"],
                    asn=ext["asn"], org=ext["org"],
                    is_threat=ext["threat"],
                    threat_reason="Abuse.ch / Tor" if ext["threat"] else None,
                    is_tor=("Tor" in ext["org"]),
                    tls_sni=ext["sni"],
                ))
        # Beaconing example: device connects to C2 every ~60s
        c2_ip = "45.95.147.236"
        beacon_dev = _DEVICES[0][3]
        for i in range(20):
            ts = now - timedelta(seconds=i * 62 + random.randint(-3, 3))
            conn_rows.append(Connection(
                location_id=locs[0].id, src_ip=beacon_dev["ip"],
                dst_ip=c2_ip, dst_port=8080, protocol="TCP",
                bytes_out=320, bytes_in=128,
                first_seen=ts, last_seen=ts + timedelta(seconds=1),
                country="LT", country_code="LT", asn="AS211252",
                org="C2 Infrastructure",
                is_threat=True, threat_reason="C2 beaconing detected",
                tls_sni=None,
            ))
        db.add_all(conn_rows)
        db.commit()

        # ── Bandwidth samples ────────────────────────────────────────────────
        bw_rows = []
        for loc, dev, _ in all_dev_pairs[:8]:
            for m in range(60):  # last 60 minutes
                ts = now - timedelta(minutes=m)
                bw_rows.append(BandwidthSample(
                    location_id=loc.id, device_mac=dev.mac, device_ip=dev.ip,
                    timestamp=ts,
                    bytes_up=random.randint(1000, 500_000),
                    bytes_down=random.randint(10_000, 5_000_000),
                ))
        db.add_all(bw_rows)
        db.commit()

        # ── Alerts ────────────────────────────────────────────────────────────
        d0 = _DEVICES[0]
        alerts = [
            Alert(location_id=locs[0].id, device_mac=d0[5]["mac"], device_ip=d0[5]["ip"],
                  alert_type="new_device", severity="warning",
                  message=f"Новое устройство в «{locs[0].name}»: Huawei ({d0[5]['mac']})",
                  detail="IP: 192.168.1.30", timestamp=now - timedelta(hours=2)),
            Alert(location_id=locs[0].id, device_mac=d0[6]["mac"], device_ip=d0[6]["ip"],
                  alert_type="new_device", severity="warning",
                  message=f"Новое устройство в «{locs[0].name}»: Unknown ({d0[6]['mac']})",
                  detail="IP: 192.168.1.50", timestamp=now - timedelta(hours=1)),
            Alert(location_id=locs[0].id, device_mac=d0[1]["mac"], device_ip=d0[1]["ip"],
                  alert_type="suspicious_domain", severity="critical",
                  message=f"[{locs[0].name}] DNS → coinhive.com (криптомайнер)",
                  detail="Domain: coinhive.com", timestamp=now - timedelta(hours=3)),
            Alert(location_id=locs[0].id, device_ip=d0[3]["ip"],
                  alert_type="threat_ip", severity="critical",
                  message=f"[{locs[0].name}] Подключение к вредоносному IP: 193.56.28.103",
                  detail="port=4444, country=RU, reason=C2 infrastructure",
                  timestamp=now - timedelta(hours=4)),
            Alert(location_id=locs[0].id, device_ip=d0[3]["ip"],
                  alert_type="beaconing", severity="critical",
                  message=f"[{locs[0].name}] C2 beaconing: {d0[3]['ip']} → 45.95.147.236:8080 каждые 62с (CV=0.048)",
                  detail="20 подключений за 20 минут с точным интервалом",
                  timestamp=now - timedelta(hours=1)),
            Alert(location_id=locs[0].id, device_mac=d0[0]["mac"],
                  alert_type="dns_spike", severity="warning",
                  message=f"[{locs[0].name}] Всплеск DNS: 312 запросов/час (норма 45/час)",
                  timestamp=now - timedelta(hours=5)),
            Alert(location_id=locs[1].id, device_mac=_DEVICES[1][3]["mac"],
                  alert_type="new_device", severity="warning",
                  message=f"Новое устройство в «{locs[1].name}»: Unknown",
                  timestamp=now - timedelta(hours=8)),
            Alert(location_id=locs[2].id, device_mac=_DEVICES[2][1]["mac"],
                  alert_type="unusual_time", severity="info",
                  message=f"[{locs[2].name}] MacBook активен в 03:15 UTC",
                  timestamp=now - timedelta(hours=6)),
        ]
        db.add_all(alerts)
        db.commit()
    finally:
        db.close()
