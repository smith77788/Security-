from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from database import get_db
from services.network_score import compute_score
from schemas import NetworkScore

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


@router.get("/score", response_model=NetworkScore)
def network_score(db: Session = Depends(get_db)):
    return compute_score(db)
