from typing import List, Optional
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session
from database import get_db
from models import Device, BlockedDevice
from schemas import DeviceOut, DeviceUpdate

router = APIRouter(prefix="/api/devices", tags=["devices"])


class BlockRequest(BaseModel):
    reason: Optional[str] = None


@router.get("", response_model=List[DeviceOut])
def list_devices(
    location_id: Optional[int] = Query(None),
    active_only: bool = False,
    new_only: bool = False,
    db: Session = Depends(get_db),
):
    q = db.query(Device)
    if location_id is not None:
        q = q.filter(Device.location_id == location_id)
    if active_only:
        q = q.filter(Device.is_active == True)   # noqa: E712
    if new_only:
        q = q.filter(Device.is_new == True)      # noqa: E712
    return q.order_by(Device.last_seen.desc()).all()


@router.get("/{device_id}", response_model=DeviceOut)
def get_device(device_id: int, db: Session = Depends(get_db)):
    dev = db.query(Device).filter(Device.id == device_id).first()
    if not dev:
        raise HTTPException(status_code=404, detail="Device not found")
    return dev


@router.patch("/{device_id}", response_model=DeviceOut)
def update_device(device_id: int, body: DeviceUpdate, db: Session = Depends(get_db)):
    dev = db.query(Device).filter(Device.id == device_id).first()
    if not dev:
        raise HTTPException(status_code=404, detail="Device not found")
    if body.friendly_name is not None:
        dev.friendly_name = body.friendly_name
    if body.notes is not None:
        dev.notes = body.notes
    db.commit()
    db.refresh(dev)
    return dev


@router.post("/{device_id}/acknowledge")
def acknowledge_device(device_id: int, db: Session = Depends(get_db)):
    dev = db.query(Device).filter(Device.id == device_id).first()
    if not dev:
        raise HTTPException(status_code=404, detail="Device not found")
    dev.is_new = False
    db.commit()
    return {"ok": True}


@router.get("/blocked/list")
def list_blocked(db: Session = Depends(get_db)):
    rows = db.query(BlockedDevice).order_by(BlockedDevice.blocked_at.desc()).all()
    return [
        {
            "id": b.id, "mac": b.mac, "ip": b.ip,
            "reason": b.reason, "blocked_at": b.blocked_at,
            "location_id": b.location_id,
        }
        for b in rows
    ]


@router.post("/{device_id}/block")
def block_device(device_id: int, body: BlockRequest, db: Session = Depends(get_db)):
    """Flag a device as blocked. Monitoring-only: generates a critical alert
    whenever this device is seen on the network. Does not modify router config."""
    dev = db.query(Device).filter(Device.id == device_id).first()
    if not dev:
        raise HTTPException(status_code=404, detail="Device not found")
    existing = db.query(BlockedDevice).filter(BlockedDevice.mac == dev.mac).first()
    if existing:
        return {"ok": True, "already_blocked": True}
    db.add(BlockedDevice(
        mac=dev.mac, ip=dev.ip,
        reason=body.reason or "Заблокировано вручную",
        blocked_at=datetime.utcnow(),
        location_id=dev.location_id,
    ))
    db.commit()
    return {"ok": True}


@router.post("/{device_id}/unblock")
def unblock_device(device_id: int, db: Session = Depends(get_db)):
    dev = db.query(Device).filter(Device.id == device_id).first()
    if not dev:
        raise HTTPException(status_code=404, detail="Device not found")
    db.query(BlockedDevice).filter(BlockedDevice.mac == dev.mac).delete()
    db.commit()
    return {"ok": True}
