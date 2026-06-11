import os
from pathlib import Path

BASE_DIR = Path(__file__).parent

# Автозагрузка .env файла (для запуска без Docker — Termux, прямой запуск)
_env_file = BASE_DIR / ".env"
if _env_file.exists():
    with open(_env_file) as _f:
        for _line in _f:
            _line = _line.strip()
            if _line and not _line.startswith("#") and "=" in _line:
                _key, _, _val = _line.partition("=")
                os.environ.setdefault(_key.strip(), _val.strip())
DATA_DIR = BASE_DIR.parent / "data"
DB_PATH = os.getenv("DB_PATH", str(BASE_DIR / "family_security.db"))

DEMO_MODE = os.getenv("DEMO_MODE", "true").lower() == "true"
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "changeme")
NETWORK_INTERFACE = os.getenv("NETWORK_INTERFACE", "eth0")
LOCAL_SUBNET = os.getenv("LOCAL_SUBNET", "192.168.1.0/24")
SCAN_INTERVAL_SECONDS = int(os.getenv("SCAN_INTERVAL_SECONDS", "60"))
DNS_CAPTURE_ENABLED = os.getenv("DNS_CAPTURE_ENABLED", "false").lower() == "true"
LOG_RETENTION_DAYS = int(os.getenv("LOG_RETENTION_DAYS", "30"))

# JWT authentication
JWT_SECRET = os.getenv("JWT_SECRET", "change-me-use-long-random-secret-in-production")
JWT_EXPIRE_HOURS = int(os.getenv("JWT_EXPIRE_HOURS", "168"))  # 7 days default

SUSPICIOUS_DOMAINS_FILE = str(DATA_DIR / "suspicious_domains.txt")
OUI_FILE = str(DATA_DIR / "oui.txt")

CORS_ORIGINS = os.getenv("CORS_ORIGINS", "http://localhost:5173,http://localhost:3000").split(",")

# OpenWrt router integration (optional)
OPENWRT_HOST     = os.getenv("OPENWRT_HOST", "")
OPENWRT_USER     = os.getenv("OPENWRT_USER", "root")
OPENWRT_PORT     = int(os.getenv("OPENWRT_PORT", "22"))
OPENWRT_SYSLOG_PORT = int(os.getenv("OPENWRT_SYSLOG_PORT", "5514"))
