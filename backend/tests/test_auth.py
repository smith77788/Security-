"""Tests for stdlib JWT implementation and new anomaly rules."""
import sys
import os
import time
import pytest
from datetime import datetime, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database import Base
from models import Device, Connection, Alert, BlockedDevice
from services.auth_utils import create_token, decode_token


@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()


class TestJWT:
    def test_roundtrip(self):
        token = create_token()
        payload = decode_token(token)
        assert payload["sub"] == "admin"
        assert payload["exp"] > time.time()

    def test_tampered_signature_rejected(self):
        token = create_token()
        with pytest.raises(ValueError):
            decode_token(token[:-4] + "XXXX")

    def test_tampered_payload_rejected(self):
        token = create_token()
        head, body, sig = token.split(".")
        with pytest.raises(ValueError):
            decode_token(f"{head}.e30.{sig}")

    def test_malformed_rejected(self):
        with pytest.raises(ValueError):
            decode_token("not-a-token")


class TestPortScan:
    def test_port_scan_detected(self, db):
        from services.anomaly_detector import check_port_scan, PORT_SCAN_MIN_PORTS
        now = datetime.utcnow()
        db.add(Device(mac="AA:BB:CC:00:00:01", ip="192.168.1.50"))
        for port in range(1000, 1000 + PORT_SCAN_MIN_PORTS + 1):
            db.add(Connection(
                src_ip="192.168.1.50", dst_ip="192.168.1.1", dst_port=port,
                first_seen=now, last_seen=now,
            ))
        db.commit()
        check_port_scan(db)
        alerts = db.query(Alert).filter(Alert.alert_type == "port_scan").all()
        assert len(alerts) == 1
        assert alerts[0].severity == "critical"

    def test_few_ports_no_alert(self, db):
        from services.anomaly_detector import check_port_scan
        now = datetime.utcnow()
        for port in [80, 443, 8080]:
            db.add(Connection(
                src_ip="192.168.1.50", dst_ip="1.2.3.4", dst_port=port,
                first_seen=now, last_seen=now,
            ))
        db.commit()
        check_port_scan(db)
        assert db.query(Alert).filter(Alert.alert_type == "port_scan").count() == 0


class TestLargeUpload:
    def test_large_upload_detected(self, db):
        from services.anomaly_detector import check_large_upload, EXFIL_THRESHOLD_BYTES
        now = datetime.utcnow()
        db.add(Connection(
            src_ip="192.168.1.60", dst_ip="5.6.7.8", dst_port=443,
            bytes_out=EXFIL_THRESHOLD_BYTES + 1,
            first_seen=now, last_seen=now,
        ))
        db.commit()
        check_large_upload(db)
        alerts = db.query(Alert).filter(Alert.alert_type == "large_upload").all()
        assert len(alerts) == 1

    def test_normal_upload_no_alert(self, db):
        from services.anomaly_detector import check_large_upload
        now = datetime.utcnow()
        db.add(Connection(
            src_ip="192.168.1.60", dst_ip="5.6.7.8", dst_port=443,
            bytes_out=1024 * 1024,  # 1 MB
            first_seen=now, last_seen=now,
        ))
        db.commit()
        check_large_upload(db)
        assert db.query(Alert).filter(Alert.alert_type == "large_upload").count() == 0


class TestBlockedDevices:
    def test_blocked_active_device_alerts(self, db):
        from services.anomaly_detector import check_blocked_devices
        now = datetime.utcnow()
        db.add(Device(mac="AA:BB:CC:00:00:99", ip="192.168.1.99", last_seen=now))
        db.add(BlockedDevice(mac="AA:BB:CC:00:00:99", reason="test"))
        db.commit()
        check_blocked_devices(db)
        alerts = db.query(Alert).filter(Alert.alert_type == "blocked_device").all()
        assert len(alerts) == 1
        assert alerts[0].severity == "critical"

    def test_blocked_inactive_device_silent(self, db):
        from services.anomaly_detector import check_blocked_devices
        old = datetime.utcnow() - timedelta(days=2)
        db.add(Device(mac="AA:BB:CC:00:00:98", ip="192.168.1.98", last_seen=old))
        db.add(BlockedDevice(mac="AA:BB:CC:00:00:98", reason="test"))
        db.commit()
        check_blocked_devices(db)
        assert db.query(Alert).filter(Alert.alert_type == "blocked_device").count() == 0
