from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel


class DeviceBase(BaseModel):
    mac: str
    ip: Optional[str] = None
    hostname: Optional[str] = None
    vendor: Optional[str] = None
    friendly_name: Optional[str] = None
    notes: Optional[str] = None


class DeviceCreate(DeviceBase):
    pass


class DeviceUpdate(BaseModel):
    friendly_name: Optional[str] = None
    notes: Optional[str] = None


class DeviceOut(DeviceBase):
    id: int
    first_seen: datetime
    last_seen: datetime
    is_new: bool
    is_active: bool

    model_config = {"from_attributes": True}


class DNSQueryOut(BaseModel):
    id: int
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


class AlertOut(BaseModel):
    id: int
    device_mac: Optional[str]
    device_ip: Optional[str]
    alert_type: str
    severity: str
    message: str
    detail: Optional[str]
    timestamp: datetime
    is_read: bool

    model_config = {"from_attributes": True}


class NetworkScore(BaseModel):
    score: int
    grade: str
    new_devices: int
    unread_alerts: int
    critical_alerts: int
    unnamed_devices: int
    total_devices: int
    details: List[str]


class AssistantQuery(BaseModel):
    question: str


class AssistantResponse(BaseModel):
    answer: str
    data_points: List[str] = []


class SettingOut(BaseModel):
    key: str
    value: str
    updated_at: datetime

    model_config = {"from_attributes": True}


class SettingUpdate(BaseModel):
    value: str
