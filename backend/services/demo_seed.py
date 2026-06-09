"""
Seed the database with realistic demo data.
Run when DEMO_MODE=true so the dashboard is usable without a real network.
"""
import random
from datetime import datetime, timedelta
from database import SessionLocal
from models import Device, DNSQuery, Alert


DEMO_DEVICES = [
    {"mac": "AA:BB:CC:11:22:33", "ip": "192.168.1.1",   "hostname": "router",          "vendor": "TP-Link",      "friendly_name": "Роутер TP-Link"},
    {"mac": "AA:BB:CC:11:22:34", "ip": "192.168.1.10",  "hostname": "android-phone",   "vendor": "Samsung",      "friendly_name": "Телефон Андрей"},
    {"mac": "AA:BB:CC:11:22:35", "ip": "192.168.1.11",  "hostname": "iphone-marina",   "vendor": "Apple",        "friendly_name": "iPhone Марины"},
    {"mac": "AA:BB:CC:11:22:36", "ip": "192.168.1.20",  "hostname": "laptop-home",     "vendor": "Dell",         "friendly_name": "Ноутбук"},
    {"mac": "AA:BB:CC:11:22:37", "ip": "192.168.1.21",  "hostname": "smart-tv",        "vendor": "LG",           "friendly_name": "Телевизор LG"},
    {"mac": "AA:BB:CC:11:22:38", "ip": "192.168.1.30",  "hostname": None,              "vendor": "Huawei",       "friendly_name": None},
    {"mac": "AA:BB:CC:11:22:39", "ip": "192.168.1.50",  "hostname": None,              "vendor": "Unknown",      "friendly_name": None},
]

POPULAR_DOMAINS = [
    "google.com", "youtube.com", "netflix.com", "apple.com", "icloud.com",
    "microsoft.com", "windows.com", "amazon.com", "vk.com", "ok.ru",
    "yandex.ru", "mail.ru", "telegram.org", "whatsapp.com", "instagram.com",
    "facebook.com", "twitter.com", "tiktok.com", "spotify.com", "twitch.tv",
    "steam.com", "epicgames.com", "riot.com", "discord.com", "github.com",
    "cloudflare.com", "akamaiedge.net", "fastly.net", "cdn.jsdelivr.net",
    "fonts.googleapis.com", "gstatic.com", "doubleclick.net",
]

SUSPICIOUS = ["coinhive.com", "evil.example.com", "hotjar.com"]


def _random_time(days_back: float) -> datetime:
    base = datetime.utcnow() - timedelta(days=days_back)
    jitter = random.uniform(0, days_back * 86400)
    return base + timedelta(seconds=jitter)


def seed():
    db = SessionLocal()
    try:
        # Skip if already seeded
        if db.query(Device).count() > 0:
            return

        now = datetime.utcnow()
        devices = []
        for i, d in enumerate(DEMO_DEVICES):
            first = now - timedelta(days=random.randint(7, 90))
            dev = Device(
                mac=d["mac"],
                ip=d["ip"],
                hostname=d["hostname"],
                vendor=d["vendor"],
                friendly_name=d["friendly_name"],
                first_seen=first,
                last_seen=now - timedelta(minutes=random.randint(0, 60)),
                is_new=(i >= 5),  # last two are "new"
                is_active=True,
            )
            db.add(dev)
            devices.append(dev)
        db.commit()

        # DNS queries for past 7 days
        queries = []
        for _ in range(2000):
            dev = random.choice(devices[:5])  # active devices
            domain = random.choice(POPULAR_DOMAINS)
            queries.append(DNSQuery(
                device_mac=dev.mac,
                device_ip=dev.ip,
                domain=domain,
                query_type=random.choice(["A", "AAAA", "A"]),
                timestamp=_random_time(7),
            ))

        # Add some suspicious hits
        for domain in SUSPICIOUS:
            dev = random.choice(devices[:3])
            queries.append(DNSQuery(
                device_mac=dev.mac,
                device_ip=dev.ip,
                domain=domain,
                query_type="A",
                timestamp=_random_time(0.5),
            ))

        db.add_all(queries)
        db.commit()

        # Alerts
        alerts = [
            Alert(
                device_mac=devices[5].mac, device_ip=devices[5].ip,
                alert_type="new_device", severity="warning",
                message=f"New device joined: {devices[5].vendor} ({devices[5].mac})",
                detail=f"IP: {devices[5].ip}", timestamp=now - timedelta(hours=2),
            ),
            Alert(
                device_mac=devices[6].mac, device_ip=devices[6].ip,
                alert_type="new_device", severity="warning",
                message=f"New device joined: Unknown ({devices[6].mac})",
                detail=f"IP: {devices[6].ip}", timestamp=now - timedelta(hours=1),
            ),
            Alert(
                device_mac=devices[1].mac, device_ip=devices[1].ip,
                alert_type="suspicious_domain", severity="critical",
                message="Query to known suspicious domain: coinhive.com",
                detail="Domain: coinhive.com", timestamp=now - timedelta(hours=3),
            ),
            Alert(
                device_mac=devices[0].mac, device_ip=devices[0].ip,
                alert_type="dns_spike", severity="warning",
                message="Unusual DNS activity: 312 queries in the last hour (avg: 45/hr)",
                detail="7-day average: 45/hr, current: 312/hr", timestamp=now - timedelta(hours=5),
            ),
            Alert(
                device_mac=devices[2].mac, device_ip=devices[2].ip,
                alert_type="unusual_time", severity="info",
                message="Device 'iPhone Марины' active at unusual hours (03:14 UTC)",
                detail="Active at hour 3:00 UTC", timestamp=now - timedelta(hours=8),
            ),
        ]
        db.add_all(alerts)
        db.commit()
    finally:
        db.close()
