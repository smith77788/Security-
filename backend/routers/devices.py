from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from database import get_db
from models import Device
from schemas import DeviceOut, DeviceUpdate

router = APIRouter(prefix="/api/devices", tags=["devices"])


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
