import os
from pathlib import Path

BASE_DIR = Path(__file__).parent
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
