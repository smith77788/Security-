"""Tests for anomaly detection rules."""
import sys
import os
import pytest
from datetime import datetime, timedelta
from unittest.mock import patch

# Allow imports from the backend root
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database import Base
from models import Device, DNSQuery, Alert
from services.anomaly_detector import (
    check_suspicious_domains,
    check_dns_spike,
    check_new_domain_burst,
    check_unusual_time_activity,
)
from utils.suspicious_domains import is_suspicious, looks_like_dga


@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()


def _add_device(db, mac="AA:BB:CC:11:22:33", ip="192.168.1.10"):
    dev = Device(mac=mac, ip=ip, vendor="Test", first_seen=datetime.utcnow(), last_seen=datetime.utcnow())
    db.add(dev)
    db.commit()
    return dev


def _add_dns(db, mac, domain, minutes_ago=1, count=1):
    ts = datetime.utcnow() - timedelta(minutes=minutes_ago)
    for _ in range(count):
        db.add(DNSQuery(device_mac=mac, device_ip="192.168.1.10", domain=domain, timestamp=ts))
    db.commit()


# --- suspicious_domains utils ---

def test_is_suspicious_known_domain():
    with patch("utils.suspicious_domains.load_suspicious_domains", return_value=frozenset(["coinhive.com"])):
        assert is_suspicious("coinhive.com") is True


def test_is_suspicious_subdomain():
    with patch("utils.suspicious_domains.load_suspicious_domains", return_value=frozenset(["evil.com"])):
        assert is_suspicious("sub.evil.com") is True


def test_is_not_suspicious_legitimate():
    with patch("utils.suspicious_domains.load_suspicious_domains", return_value=frozenset(["evil.com"])):
        assert is_suspicious("google.com") is False


def test_looks_like_dga_short_domain():
    assert looks_like_dga("google.com") is False


def test_looks_like_dga_pronounceable():
    # has vowels = not DGA
    assert looks_like_dga("abcdefghijklmnopqr.com") is False


def test_looks_like_dga_high_entropy():
    # high entropy, long, consonant-heavy
    assert looks_like_dga("xkzqwvbtrmnplfsdgh.com") is True


# --- check_suspicious_domains ---

def test_check_suspicious_domains_creates_alert(db):
    dev = _add_device(db)
    _add_dns(db, dev.mac, "coinhive.com", minutes_ago=10)

    with patch("utils.suspicious_domains.load_suspicious_domains", return_value=frozenset(["coinhive.com"])):
        check_suspicious_domains(db)

    alerts = db.query(Alert).filter(Alert.alert_type == "suspicious_domain").all()
    assert len(alerts) >= 1
    assert "coinhive.com" in alerts[0].message


def test_check_suspicious_domains_no_alert_for_clean(db):
    dev = _add_device(db)
    _add_dns(db, dev.mac, "google.com", minutes_ago=10)

    with patch("utils.suspicious_domains.load_suspicious_domains", return_value=frozenset(["coinhive.com"])):
        check_suspicious_domains(db)

    alerts = db.query(Alert).filter(Alert.alert_type == "suspicious_domain").all()
    assert len(alerts) == 0


# --- check_dns_spike ---

def test_check_dns_spike_creates_alert(db):
    dev = _add_device(db)
    mac = dev.mac

    # 7-day baseline: 100 queries spread over 7 days (≈0.6/hr avg)
    for day in range(7):
        for _ in range(14):
            db.add(DNSQuery(
                device_mac=mac, domain="google.com",
                timestamp=datetime.utcnow() - timedelta(days=day+1, hours=1),
            ))
    db.commit()

    # Current hour: 300 queries (huge spike)
    _add_dns(db, mac, "google.com", minutes_ago=30, count=300)

    check_dns_spike(db)
    alerts = db.query(Alert).filter(Alert.alert_type == "dns_spike").all()
    assert len(alerts) >= 1


def test_check_dns_spike_no_alert_normal(db):
    dev = _add_device(db)
    mac = dev.mac

    # Consistent 50 queries/hour — no spike
    for hour in range(168):
        for _ in range(50):
            db.add(DNSQuery(
                device_mac=mac, domain="google.com",
                timestamp=datetime.utcnow() - timedelta(hours=hour),
            ))
    db.commit()

    check_dns_spike(db)
    alerts = db.query(Alert).filter(Alert.alert_type == "dns_spike").all()
    assert len(alerts) == 0


# --- check_new_domain_burst ---

def test_check_new_domain_burst_creates_alert(db):
    dev = _add_device(db)
    mac = dev.mac

    # Historical: only google.com
    _add_dns(db, mac, "google.com", minutes_ago=200, count=10)

    # Current hour: 40 brand-new domains
    for i in range(40):
        db.add(DNSQuery(
            device_mac=mac, domain=f"new-domain-{i}.com",
            timestamp=datetime.utcnow() - timedelta(minutes=10),
        ))
    db.commit()

    check_new_domain_burst(db)
    alerts = db.query(Alert).filter(Alert.alert_type == "new_domain_burst").all()
    assert len(alerts) >= 1


def test_check_new_domain_burst_no_alert_normal(db):
    dev = _add_device(db)
    mac = dev.mac

    # Historical: 100 different domains already seen
    for i in range(100):
        db.add(DNSQuery(
            device_mac=mac, domain=f"known-{i}.com",
            timestamp=datetime.utcnow() - timedelta(days=1),
        ))
    db.commit()

    # Current hour: same domains, not new
    for i in range(10):
        _add_dns(db, mac, f"known-{i}.com", minutes_ago=20)

    check_new_domain_burst(db)
    alerts = db.query(Alert).filter(Alert.alert_type == "new_domain_burst").all()
    assert len(alerts) == 0


# --- check_unusual_time_activity ---

def test_check_unusual_time_no_alert_outside_window(db):
    dev = _add_device(db)
    _add_dns(db, dev.mac, "google.com", minutes_ago=5)

    # Patch utcnow to a normal daytime hour (12:00)
    fake_now = datetime.utcnow().replace(hour=12, minute=0)
    with patch("services.anomaly_detector.datetime") as mock_dt:
        mock_dt.utcnow.return_value = fake_now
        mock_dt.side_effect = lambda *a, **kw: datetime(*a, **kw)
        check_unusual_time_activity(db)

    alerts = db.query(Alert).filter(Alert.alert_type == "unusual_time").all()
    assert len(alerts) == 0
