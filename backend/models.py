from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, Boolean, Float, Text, Index
from database import Base


class Device(Base):
    __tablename__ = "devices"

    id = Column(Integer, primary_key=True)
    mac = Column(String(17), unique=True, nullable=False, index=True)
    ip = Column(String(15))
    hostname = Column(String(255))
    vendor = Column(String(255))
    friendly_name = Column(String(255))
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    is_new = Column(Boolean, default=True)
    is_active = Column(Boolean, default=True)
    notes = Column(Text)


class DNSQuery(Base):
    __tablename__ = "dns_queries"

    id = Column(Integer, primary_key=True)
    device_mac = Column(String(17), index=True)
    device_ip = Column(String(15))
    domain = Column(String(255), index=True)
    query_type = Column(String(10), default="A")
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)

    __table_args__ = (
        Index("ix_dns_domain_ts", "domain", "timestamp"),
        Index("ix_dns_mac_ts", "device_mac", "timestamp"),
    )


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True)
    device_mac = Column(String(17), index=True)
    device_ip = Column(String(15))
    alert_type = Column(String(64), index=True)
    severity = Column(String(16), default="info")  # info | warning | critical
    message = Column(Text)
    detail = Column(Text)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    is_read = Column(Boolean, default=False)


class AppSetting(Base):
    __tablename__ = "app_settings"

    key = Column(String(64), primary_key=True)
    value = Column(Text)
    updated_at = Column(DateTime, default=datetime.utcnow)
