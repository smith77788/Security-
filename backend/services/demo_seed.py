"""
Multi-location demo data. Seeds 3 locations with realistic device/DNS/alert data.
"""
import secrets
import random
from datetime import datetime, timedelta
from database import SessionLocal
from models import Location, Device, DNSQuery, Alert


LOCATIONS = [
    {"name": "Основной дом",   "icon": "🏠", "color": "#3b82f6", "address": "ул. Ленина, 12",   "timezone": "Europe/Moscow"},
    {"name": "Дача",           "icon": "🌲", "color": "#22c55e", "address": "Подмосковье, СНТ", "timezone": "Europe/Moscow"},
    {"name": "Городская квартира", "icon": "🏢", "color": "#a855f7", "address": "пр. Невский, 88", "timezone": "Europe/Moscow"},
]

DEVICES_BY_LOCATION = [
    [   # Основной дом
        {"mac": "AA:BB:CC:11:22:01", "ip": "192.168.1.1",  "hostname": "router",       "vendor": "TP-Link",   "name": "Роутер TP-Link"},
        {"mac": "AA:BB:CC:11:22:02", "ip": "192.168.1.10", "hostname": "android-dad",  "vendor": "Samsung",   "name": "Телефон папы"},
        {"mac": "AA:BB:CC:11:22:03", "ip": "192.168.1.11", "hostname": "iphone-mom",   "vendor": "Apple",     "name": "iPhone мамы"},
        {"mac": "AA:BB:CC:11:22:04", "ip": "192.168.1.20", "hostname": "laptop-home",  "vendor": "Dell",      "name": "Ноутбук"},
        {"mac": "AA:BB:CC:11:22:05", "ip": "192.168.1.21", "hostname": "smart-tv",     "vendor": "LG",        "name": "Телевизор LG"},
        {"mac": "AA:BB:CC:11:22:06", "ip": "192.168.1.30", "hostname": None,           "vendor": "Huawei",    "name": None},   # new
        {"mac": "AA:BB:CC:11:22:07", "ip": "192.168.1.50", "hostname": None,           "vendor": "Unknown",   "name": None},   # new unknown
    ],
    [   # Дача
        {"mac": "BB:CC:DD:22:33:01", "ip": "192.168.2.1",  "hostname": "router-dacha", "vendor": "D-Link",    "name": "Роутер дача"},
        {"mac": "BB:CC:DD:22:33:02", "ip": "192.168.2.10", "hostname": "ipad-dacha",   "vendor": "Apple",     "name": "iPad на даче"},
        {"mac": "BB:CC:DD:22:33:03", "ip": "192.168.2.11", "hostname": "laptop-dacha", "vendor": "Lenovo",    "name": "Ноутбук дача"},
        {"mac": "BB:CC:DD:22:33:04", "ip": "192.168.2.20", "hostname": None,           "vendor": "Unknown",   "name": None},   # new
    ],
    [   # Городская квартира
        {"mac": "CC:DD:EE:33:44:01", "ip": "10.0.0.1",    "hostname": "router-apt",   "vendor": "Netgear",   "name": "Роутер квартира"},
        {"mac": "CC:DD:EE:33:44:02", "ip": "10.0.0.10",   "hostname": "macbook",      "vendor": "Apple",     "name": "MacBook"},
        {"mac": "CC:DD:EE:33:44:03", "ip": "10.0.0.11",   "hostname": "iphone-apt",   "vendor": "Apple",     "name": "iPhone квартира"},
        {"mac": "CC:DD:EE:33:44:04", "ip": "10.0.0.20",   "hostname": "ps5",          "vendor": "Sony",      "name": "PlayStation 5"},
        {"mac": "CC:DD:EE:33:44:05", "ip": "10.0.0.21",   "hostname": "chromecast",   "vendor": "Google",    "name": "Chromecast"},
    ],
]

POPULAR_DOMAINS = [
    "google.com", "youtube.com", "netflix.com", "apple.com", "icloud.com",
    "microsoft.com", "amazon.com", "vk.com", "yandex.ru", "mail.ru",
    "telegram.org", "whatsapp.com", "instagram.com", "twitter.com",
    "spotify.com", "twitch.tv", "discord.com", "github.com",
    "cloudflare.com", "gstatic.com", "fonts.googleapis.com",
    "cdn.jsdelivr.net", "tiktok.com", "ok.ru", "steam.com",
]

SUSPICIOUS = ["coinhive.com", "evil.example.com", "hotjar.com"]


def _rand_time(days_back: float) -> datetime:
    return datetime.utcnow() - timedelta(seconds=random.uniform(0, days_back * 86400))


def seed():
    db = SessionLocal()
    try:
        if db.query(Location).count() > 0:
            return   # already seeded

        now = datetime.utcnow()
        locations = []
        for i, ldata in enumerate(LOCATIONS):
            loc = Location(
                **ldata,
                api_key=secrets.token_urlsafe(32),
                last_heartbeat=now - timedelta(minutes=random.randint(0, 5)),
                is_online=(i != 1),   # дача — offline для демонстрации
                created_at=now - timedelta(days=90),
            )
            db.add(loc)
            locations.append(loc)
        db.commit()

        all_devices = []
        for loc_idx, loc in enumerate(locations):
            devs_data = DEVICES_BY_LOCATION[loc_idx]
            for j, d in enumerate(devs_data):
                is_new = d["name"] is None
                first = now - timedelta(days=random.randint(7, 90) if not is_new else 0,
                                        hours=random.randint(0, 5) if is_new else 0)
                dev = Device(
                    location_id=loc.id,
                    mac=d["mac"], ip=d["ip"], hostname=d["hostname"],
                    vendor=d["vendor"], friendly_name=d["name"],
                    first_seen=first,
                    last_seen=now - timedelta(minutes=random.randint(0, 120)),
                    is_new=is_new, is_active=True,
                )
                db.add(dev)
                all_devices.append((loc, dev))
        db.commit()

        # DNS queries – 7 days of traffic per location
        queries = []
        for loc, dev in all_devices:
            n = random.randint(100, 600)
            for _ in range(n):
                queries.append(DNSQuery(
                    location_id=loc.id,
                    device_mac=dev.mac, device_ip=dev.ip,
                    domain=random.choice(POPULAR_DOMAINS),
                    query_type=random.choice(["A", "AAAA", "A", "A"]),
                    timestamp=_rand_time(7),
                ))
        # Suspicious queries from location 0
        loc0 = locations[0]
        for domain in SUSPICIOUS:
            mac = DEVICES_BY_LOCATION[0][1]["mac"]
            queries.append(DNSQuery(
                location_id=loc0.id, device_mac=mac,
                domain=domain, query_type="A",
                timestamp=now - timedelta(hours=random.uniform(0.5, 6)),
            ))
        db.add_all(queries)
        db.commit()

        # Alerts
        loc0_devs = DEVICES_BY_LOCATION[0]
        loc1 = locations[1]
        loc2 = locations[2]
        alerts = [
            Alert(location_id=locations[0].id, device_mac=loc0_devs[5]["mac"], device_ip=loc0_devs[5]["ip"],
                  alert_type="new_device", severity="warning",
                  message=f"Новое устройство в «{locations[0].name}»: Huawei ({loc0_devs[5]['mac']})",
                  detail="IP: 192.168.1.30", timestamp=now - timedelta(hours=2)),
            Alert(location_id=locations[0].id, device_mac=loc0_devs[6]["mac"], device_ip=loc0_devs[6]["ip"],
                  alert_type="new_device", severity="warning",
                  message=f"Новое устройство в «{locations[0].name}»: Unknown ({loc0_devs[6]['mac']})",
                  detail="IP: 192.168.1.50", timestamp=now - timedelta(hours=1)),
            Alert(location_id=locations[0].id, device_mac=loc0_devs[1]["mac"], device_ip=loc0_devs[1]["ip"],
                  alert_type="suspicious_domain", severity="critical",
                  message=f"[{locations[0].name}] DNS к подозрительному домену: coinhive.com",
                  detail="Domain: coinhive.com", timestamp=now - timedelta(hours=3)),
            Alert(location_id=locations[0].id, device_mac=loc0_devs[0]["mac"], device_ip=loc0_devs[0]["ip"],
                  alert_type="dns_spike", severity="warning",
                  message=f"[{locations[0].name}] Всплеск DNS: 312 запросов/час (норма 45/час)",
                  detail="7-day avg: 45/hr, current: 312/hr", timestamp=now - timedelta(hours=5)),
            Alert(location_id=loc1.id, device_mac=DEVICES_BY_LOCATION[1][3]["mac"],
                  alert_type="new_device", severity="warning",
                  message=f"Новое устройство в «{loc1.name}»: Unknown",
                  detail="IP: 192.168.2.20", timestamp=now - timedelta(hours=8)),
            Alert(location_id=loc2.id, device_mac=DEVICES_BY_LOCATION[2][1]["mac"],
                  alert_type="unusual_time", severity="info",
                  message=f"[{loc2.name}] MacBook активен в 03:15 UTC",
                  detail="Unusual activity at night", timestamp=now - timedelta(hours=6)),
        ]
        db.add_all(alerts)
        db.commit()
    finally:
        db.close()
