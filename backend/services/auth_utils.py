"""
Minimal HS256 JWT — stdlib only (hmac, hashlib, base64, json).
No external dependencies, works on any Python 3.10+, including Raspberry Pi.
"""
import base64
import hashlib
import hmac
import json
import time

from config import JWT_SECRET, JWT_EXPIRE_HOURS

_HEADER = {"alg": "HS256", "typ": "JWT"}


def _b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64decode(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def _sign(message: bytes) -> str:
    sig = hmac.new(JWT_SECRET.encode(), message, hashlib.sha256).digest()
    return _b64encode(sig)


def create_token() -> str:
    payload = {"sub": "admin", "exp": int(time.time()) + JWT_EXPIRE_HOURS * 3600}
    head = _b64encode(json.dumps(_HEADER, separators=(",", ":")).encode())
    body = _b64encode(json.dumps(payload, separators=(",", ":")).encode())
    msg = f"{head}.{body}".encode()
    return f"{head}.{body}.{_sign(msg)}"


def decode_token(token: str) -> dict:
    """Validate signature + expiry. Raises ValueError on any problem."""
    try:
        head, body, sig = token.split(".")
    except ValueError:
        raise ValueError("Malformed token")
    expected = _sign(f"{head}.{body}".encode())
    if not hmac.compare_digest(sig, expected):
        raise ValueError("Invalid signature")
    payload = json.loads(_b64decode(body))
    if payload.get("exp", 0) < time.time():
        raise ValueError("Token expired")
    return payload
