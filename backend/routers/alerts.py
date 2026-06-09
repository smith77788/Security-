from typing import List, Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from datetime import datetime, timedelta

from database import get_db
from models import Alert
from schemas import AlertOut

router = APIRouter(prefix="/api/alerts", tags=["alerts"])


@router.get("", response_model=List[AlertOut])
def list_alerts(
    location_id: Optional[int] = Query(None),
    unread_only: bool = False,
    severity: Optional[str] = None,
    hours: int = Query(24, le=168),
    db: Session = Depends(get_db),
):
    since = datetime.utcnow() - timedelta(hours=hours)
    q = db.query(Alert).filter(Alert.timestamp >= since)
    if location_id is not None:
        q = q.filter(Alert.location_id == location_id)
    if unread_only:
        q = q.filter(Alert.is_read == False)   # noqa: E712
    if severity:
        q = q.filter(Alert.severity == severity)
    return q.order_by(Alert.timestamp.desc()).all()


@router.post("/{alert_id}/read")
def mark_read(alert_id: int, db: Session = Depends(get_db)):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if alert:
        alert.is_read = True
        db.commit()
    return {"ok": True}


@router.post("/read-all")
def mark_all_read(
    location_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
):
    q = db.query(Alert).filter(Alert.is_read == False)   # noqa: E712
    if location_id is not None:
        q = q.filter(Alert.location_id == location_id)
    q.update({"is_read": True})
    db.commit()
    return {"ok": True}
