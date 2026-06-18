import secrets
from typing import List, Optional
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import func

from database import get_db
from models import Location, Device, Alert, DNSQuery
from schemas import LocationCreate, LocationUpdate, LocationOut, LocationSummary
from services.network_score import compute_score

router = APIRouter(prefix="/api/locations", tags=["locations"])


@router.get("", response_model=List[LocationOut])
def list_locations(db: Session = Depends(get_db)):
    return db.query(Location).order_by(Location.created_at).all()


@router.get("/summary", response_model=List[LocationSummary])
def locations_summary(db: Session = Depends(get_db)):
    locations = db.query(Location).order_by(Location.created_at).all()
    result = []
    since_24h = datetime.utcnow() - timedelta(hours=24)
    for loc in locations:
        total = db.query(Device).filter(Device.location_id == loc.id).count()
        active = db.query(Device).filter(Device.location_id == loc.id, Device.is_active == True).count()  # noqa: E712
        new_dev = db.query(Device).filter(Device.location_id == loc.id, Device.is_new == True).count()  # noqa: E712
        unread = db.query(Alert).filter(Alert.location_id == loc.id, Alert.is_read == False).count()  # noqa: E712
        critical = db.query(Alert).filter(
            Alert.location_id == loc.id, Alert.severity == "critical", Alert.timestamp >= since_24h
        ).count()
        sc = compute_score(db, location_id=loc.id)
        result.append(LocationSummary(
            id=loc.id, name=loc.name, icon=loc.icon, color=loc.color,
            is_online=loc.is_online,
            total_devices=total, active_devices=active, new_devices=new_dev,
            unread_alerts=unread, critical_alerts=critical,
            score=sc.score, grade=sc.grade,
            last_heartbeat=loc.last_heartbeat,
        ))
    return result


@router.get("/{location_id}", response_model=LocationOut)
def get_location(location_id: int, db: Session = Depends(get_db)):
    loc = db.query(Location).filter(Location.id == location_id).first()
    if not loc:
        raise HTTPException(404, "Location not found")
    return loc


@router.post("", response_model=LocationOut, status_code=201)
def create_location(body: LocationCreate, db: Session = Depends(get_db)):
    loc = Location(
        **body.model_dump(),
        api_key=secrets.token_urlsafe(32),
        created_at=datetime.utcnow(),
    )
    db.add(loc)
    db.commit()
    db.refresh(loc)
    return loc


@router.patch("/{location_id}", response_model=LocationOut)
def update_location(location_id: int, body: LocationUpdate, db: Session = Depends(get_db)):
    loc = db.query(Location).filter(Location.id == location_id).first()
    if not loc:
        raise HTTPException(404, "Location not found")
    for k, v in body.model_dump(exclude_none=True).items():
        setattr(loc, k, v)
    db.commit()
    db.refresh(loc)
    return loc


@router.delete("/{location_id}", status_code=204)
def delete_location(location_id: int, db: Session = Depends(get_db)):
    loc = db.query(Location).filter(Location.id == location_id).first()
    if not loc:
        raise HTTPException(404, "Location not found")
    db.delete(loc)
    db.commit()


@router.post("/{location_id}/rotate-key", response_model=LocationOut)
def rotate_api_key(location_id: int, db: Session = Depends(get_db)):
    loc = db.query(Location).filter(Location.id == location_id).first()
    if not loc:
        raise HTTPException(404, "Location not found")
    loc.api_key = secrets.token_urlsafe(32)
    db.commit()
    db.refresh(loc)
    return loc
