from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from config import ADMIN_PASSWORD
from services.auth_utils import create_token

router = APIRouter(prefix="/api/auth", tags=["auth"])


class LoginRequest(BaseModel):
    password: str


@router.post("/login")
def login(body: LoginRequest):
    if body.password != ADMIN_PASSWORD:
        raise HTTPException(status_code=401, detail="Неверный пароль")
    return {
        "token": create_token(),
        "expires_in": 3600 * 168,  # 7 days in seconds
    }


@router.get("/me")
def me():
    return {"user": "admin", "authenticated": True}
