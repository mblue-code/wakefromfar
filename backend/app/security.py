from __future__ import annotations

from datetime import UTC, datetime, timedelta

import jwt
from fastapi import HTTPException, status
from passlib.context import CryptContext

from .config import get_settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, password_hash: str) -> bool:
    return pwd_context.verify(plain_password, password_hash)


def create_token(username: str, role: str, token_version: int = 0) -> tuple[str, int]:
    settings = get_settings()
    expires = datetime.now(UTC) + timedelta(seconds=settings.token_expires_seconds)
    payload = {"sub": username, "role": role, "ver": int(token_version), "exp": expires}
    token = jwt.encode(payload, settings.app_secret, algorithm="HS256")
    return token, settings.token_expires_seconds


def decode_token(token: str) -> dict:
    settings = get_settings()
    try:
        return jwt.decode(token, settings.app_secret, algorithms=["HS256"])
    except jwt.PyJWTError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token") from exc
