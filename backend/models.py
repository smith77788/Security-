from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, Boolean, Text, ForeignKey, Index
from database import Base


class Location(Base):
    __tablename__ = "locations"

    id = Column(Integer, primary_key=True)
    name = Column(String(128), nullable=False)
    address = Column(String(255))
    icon = Column(String(8), default="🏠")
    color = Column(String(7), default="#3b82f6")   # hex colour for UI card
    timezone = Column(String(64), default="UTC")
    api_key = Column(String(64), unique=True, index=True)
    last_heartbeat = Column(DateTime)
    is_online = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)


class Device(Base):
    __tablename__ = "devices"

    id = Column(Integer, primary_key=True)
    location_id = Column(Integer, ForeignKey("locations.id"), index=True)
    mac = Column(String(17), nullable=False, index=True)
    ip = Column(String(15))
    hostname = Column(String(255))
    vendor = Column(String(255))
    friendly_name = Column(String(255))
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    is_new = Column(Boolean, default=True)
    is_active = Column(Boolean, default=True)
    notes = Column(Text)

    __table_args__ = (
        Index("ix_device_loc_mac", "location_id", "mac", unique=True),
    )


class DNSQuery(Base):
    __tablename__ = "dns_queries"

    id = Column(Integer, primary_key=True)
    location_id = Column(Integer, ForeignKey("locations.id"), index=True)
    device_mac = Column(String(17), index=True)
    device_ip = Column(String(15))
    domain = Column(String(255), index=True)
    query_type = Column(String(10), default="A")
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)

    __table_args__ = (
        Index("ix_dns_domain_ts", "domain", "timestamp"),
        Index("ix_dns_mac_ts", "device_mac", "timestamp"),
        Index("ix_dns_loc_ts", "location_id", "timestamp"),
    )


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True)
    location_id = Column(Integer, ForeignKey("locations.id"), index=True)
    device_mac = Column(String(17), index=True)
    device_ip = Column(String(15))
    alert_type = Column(String(64), index=True)
    severity = Column(String(16), default="info")   # info | warning | critical
    message = Column(Text)
    detail = Column(Text)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    is_read = Column(Boolean, default=False)


class AppSetting(Base):
    __tablename__ = "app_settings"

    key = Column(String(64), primary_key=True)
    value = Column(Text)
    updated_at = Column(DateTime, default=datetime.utcnow)
