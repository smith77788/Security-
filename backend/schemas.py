from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel


# ── Locations ─────────────────────────────────────────────────────────────────

class LocationCreate(BaseModel):
    name: str
    address: Optional[str] = None
    icon: str = "🏠"
    color: str = "#3b82f6"
    timezone: str = "UTC"


class LocationUpdate(BaseModel):
    name: Optional[str] = None
    address: Optional[str] = None
    icon: Optional[str] = None
    color: Optional[str] = None
    timezone: Optional[str] = None


class LocationOut(BaseModel):
    id: int
    name: str
    address: Optional[str]
    icon: str
    color: str
    timezone: str
    api_key: Optional[str]
    last_heartbeat: Optional[datetime]
    is_online: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class LocationSummary(BaseModel):
    id: int
    name: str
    icon: str
    color: str
    is_online: bool
    total_devices: int
    active_devices: int
    new_devices: int
    unread_alerts: int
    critical_alerts: int
    score: int
    grade: str
    last_heartbeat: Optional[datetime]


# ── Devices ───────────────────────────────────────────────────────────────────

class DeviceBase(BaseModel):
    mac: str
    ip: Optional[str] = None
    hostname: Optional[str] = None
    vendor: Optional[str] = None
    friendly_name: Optional[str] = None
    notes: Optional[str] = None


class DeviceCreate(DeviceBase):
    location_id: Optional[int] = None


class DeviceUpdate(BaseModel):
    friendly_name: Optional[str] = None
    notes: Optional[str] = None


class DeviceOut(DeviceBase):
    id: int
    location_id: Optional[int]
    first_seen: datetime
    last_seen: datetime
    is_new: bool
    is_active: bool

    model_config = {"from_attributes": True}


# ── DNS ───────────────────────────────────────────────────────────────────────

class DNSQueryOut(BaseModel):
    id: int
    location_id: Optional[int]
    device_mac: Optional[str]
    device_ip: Optional[str]
    domain: str
    query_type: str
    timestamp: datetime

    model_config = {"from_attributes": True}


class DomainStat(BaseModel):
    domain: str
    count: int
    last_seen: datetime


class DeviceDNSStat(BaseModel):
    device_mac: str
    friendly_name: Optional[str]
    ip: Optional[str]
    count: int


# ── Alerts ────────────────────────────────────────────────────────────────────

class AlertOut(BaseModel):
    id: int
    location_id: Optional[int]
    device_mac: Optional[str]
    device_ip: Optional[str]
    alert_type: str
    severity: str
    message: str
    detail: Optional[str]
    timestamp: datetime
    is_read: bool

    model_config = {"from_attributes": True}


# ── Dashboard / Score ─────────────────────────────────────────────────────────

class NetworkScore(BaseModel):
    score: int
    grade: str
    new_devices: int
    unread_alerts: int
    critical_alerts: int
    unnamed_devices: int
    total_devices: int
    details: List[str]


# ── Assistant ─────────────────────────────────────────────────────────────────

class AssistantQuery(BaseModel):
    question: str
    location_id: Optional[int] = None


class AssistantResponse(BaseModel):
    answer: str
    data_points: List[str] = []


# ── Settings ──────────────────────────────────────────────────────────────────

class SettingOut(BaseModel):
    key: str
    value: str
    updated_at: datetime

    model_config = {"from_attributes": True}


class SettingUpdate(BaseModel):
    value: str


# ── Ingest (agent → hub) ──────────────────────────────────────────────────────

class IngestDevice(BaseModel):
    mac: str
    ip: Optional[str] = None
    hostname: Optional[str] = None
    vendor: Optional[str] = None


class IngestDNS(BaseModel):
    device_mac: Optional[str] = None
    device_ip: Optional[str] = None
    domain: str
    query_type: str = "A"
    timestamp: Optional[datetime] = None


class IngestPayload(BaseModel):
    devices: List[IngestDevice] = []
    dns_queries: List[IngestDNS] = []


# ── Real-time WebSocket events ────────────────────────────────────────────────

class WSEvent(BaseModel):
    type: str                          # alert | new_device | score_update | location_status | ping
    location_id: Optional[int] = None
    location_name: Optional[str] = None
    payload: dict = {}
