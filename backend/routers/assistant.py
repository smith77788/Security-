from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from database import get_db
from services.assistant import answer
from schemas import AssistantQuery, AssistantResponse

router = APIRouter(prefix="/api/assistant", tags=["assistant"])


@router.post("", response_model=AssistantResponse)
def ask(body: AssistantQuery, db: Session = Depends(get_db)):
    return answer(body.question, db, location_id=body.location_id)
