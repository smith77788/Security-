from typing import List
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from database import get_db
from models import DNSQuery, Alert, Device, AppSetting
from schemas import SettingOut, SettingUpdate
from config import LOG_RETENTION_DAYS

router = APIRouter(prefix="/api/settings", tags=["settings"])

DEFAULTS = {
    "retention_days": str(LOG_RETENTION_DAYS),
    "scan_interval_seconds": "60",
    "dns_capture_enabled": "false",
    "network_interface": "eth0",
    "local_subnet": "192.168.1.0/24",
}


def _get_or_default(db: Session, key: str) -> AppSetting:
    s = db.query(AppSetting).filter(AppSetting.key == key).first()
    if not s:
        s = AppSetting(key=key, value=DEFAULTS.get(key, ""), updated_at=datetime.utcnow())
        db.add(s)
        db.commit()
        db.refresh(s)
    return s


@router.get("", response_model=List[SettingOut])
def list_settings(db: Session = Depends(get_db)):
    return [_get_or_default(db, k) for k in DEFAULTS]


@router.put("/{key}", response_model=SettingOut)
def update_setting(key: str, body: SettingUpdate, db: Session = Depends(get_db)):
    if key not in DEFAULTS:
        raise HTTPException(status_code=404, detail="Unknown setting key")
    s = _get_or_default(db, key)
    s.value = body.value
    s.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(s)
    return s


@router.delete("/logs")
def clear_logs(db: Session = Depends(get_db)):
    """Delete all DNS logs and alerts. Devices are kept."""
    db.query(DNSQuery).delete()
    db.query(Alert).delete()
    db.commit()
    return {"ok": True, "message": "All logs and alerts cleared"}


@router.post("/apply-retention")
def apply_retention(db: Session = Depends(get_db)):
    """Prune records older than the configured retention period."""
    from datetime import timedelta
    setting = _get_or_default(db, "retention_days")
    days = int(setting.value or LOG_RETENTION_DAYS)
    cutoff = datetime.utcnow() - timedelta(days=days)
    deleted_dns = db.query(DNSQuery).filter(DNSQuery.timestamp < cutoff).delete()
    deleted_alerts = db.query(Alert).filter(Alert.timestamp < cutoff).delete()
    db.commit()
    return {"ok": True, "deleted_dns": deleted_dns, "deleted_alerts": deleted_alerts}
