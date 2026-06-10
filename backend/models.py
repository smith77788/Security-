from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, Boolean, Text, ForeignKey, Float, BigInteger, Index
from database import Base


class Location(Base):
    __tablename__ = "locations"

    id = Column(Integer, primary_key=True)
    name = Column(String(128), nullable=False)
    address = Column(String(255))
    icon = Column(String(8), default="🏠")
    color = Column(String(7), default="#3b82f6")
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
    os_hint = Column(String(128))           # from fingerprinting
    device_type = Column(String(128))       # TV, Phone, Laptop, Printer …
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
    severity = Column(String(16), default="info")
    message = Column(Text)
    detail = Column(Text)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    is_read = Column(Boolean, default=False)


class Connection(Base):
    """Tracks all outbound TCP/UDP connections with GeoIP + threat info."""
    __tablename__ = "connections"

    id = Column(Integer, primary_key=True)
    location_id = Column(Integer, ForeignKey("locations.id"), index=True)
    src_ip = Column(String(15), index=True)
    dst_ip = Column(String(15), index=True)
    dst_port = Column(Integer)
    protocol = Column(String(8), default="TCP")
    bytes_out = Column(BigInteger, default=0)
    bytes_in = Column(BigInteger, default=0)
    first_seen = Column(DateTime, default=datetime.utcnow, index=True)
    last_seen = Column(DateTime, default=datetime.utcnow, index=True)
    # GeoIP
    country = Column(String(64))
    country_code = Column(String(8))
    asn = Column(String(32))
    org = Column(String(255))
    # Threat intel
    is_threat = Column(Boolean, default=False, index=True)
    threat_reason = Column(String(255))
    is_tor = Column(Boolean, default=False)
    # Protocol info
    tls_sni = Column(String(255))            # hostname from TLS ClientHello

    __table_args__ = (
        Index("ix_conn_src_dst", "src_ip", "dst_ip"),
        Index("ix_conn_threat", "is_threat", "last_seen"),
    )


class BandwidthSample(Base):
    """Per-device bandwidth time-series (5-minute resolution)."""
    __tablename__ = "bandwidth_samples"

    id = Column(Integer, primary_key=True)
    location_id = Column(Integer, ForeignKey("locations.id"), index=True)
    device_mac = Column(String(17), index=True)
    device_ip = Column(String(15))
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    bytes_up = Column(BigInteger, default=0)
    bytes_down = Column(BigInteger, default=0)


class DeviceFingerprint(Base):
    """Passive device identification from DHCP / mDNS / SSDP / TCP-IP."""
    __tablename__ = "device_fingerprints"

    id = Column(Integer, primary_key=True)
    mac = Column(String(17), index=True)
    src_ip = Column(String(15), index=True)
    os_hint = Column(String(128))
    device_type = Column(String(128))
    hostname = Column(String(255))
    fingerprint_type = Column(String(32))   # dhcp | mdns | ssdp | tcpip
    raw = Column(Text)
    updated_at = Column(DateTime, default=datetime.utcnow)


class GeoCache(Base):
    """SQLite cache for GeoIP/ASN lookups (7-day TTL)."""
    __tablename__ = "geo_cache"

    ip = Column(String(45), primary_key=True)
    data = Column(Text)
    expires_at = Column(DateTime, index=True)


class AppSetting(Base):
    __tablename__ = "app_settings"

    key = Column(String(64), primary_key=True)
    value = Column(Text)
    updated_at = Column(DateTime, default=datetime.utcnow)
