from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import urllib.parse
from datetime import UTC, datetime, timedelta

import jwt
from cryptography.fernet import Fernet, InvalidToken
from fastapi import HTTPException, status
from passlib.context import CryptContext

from .config import get_settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, password_hash: str) -> bool:
    return pwd_context.verify(plain_password, password_hash)


def create_token(
    username: str,
    role: str,
    token_version: int = 0,
    *,
    installation_id: str | None = None,
    app_proof_method: str | None = None,
    installation_session_version: int | None = None,
) -> tuple[str, int]:
    settings = get_settings()
    payload: dict[str, object] = {"sub": username, "role": role, "ver": int(token_version)}
    if settings.token_expires_seconds > 0:
        expires = datetime.now(UTC) + timedelta(seconds=settings.token_expires_seconds)
        payload["exp"] = expires
    if installation_id:
        payload["aid"] = installation_id
    if app_proof_method:
        payload["apm"] = app_proof_method
    if installation_session_version is not None:
        payload["asv"] = int(installation_session_version)
    token = jwt.encode(payload, settings.app_secret, algorithm="HS256")
    return token, settings.token_expires_seconds


def decode_token(token: str) -> dict:
    settings = get_settings()
    try:
        return jwt.decode(token, settings.app_secret, algorithms=["HS256"])
    except jwt.PyJWTError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token") from exc


def create_state_token(
    *,
    subject: str,
    state_type: str,
    expires_seconds: int,
    extra_claims: dict[str, object] | None = None,
) -> str:
    settings = get_settings()
    expires = datetime.now(UTC) + timedelta(seconds=expires_seconds)
    payload: dict[str, object] = {"sub": subject, "typ": state_type, "exp": expires}
    if extra_claims:
        payload.update(extra_claims)
    return jwt.encode(payload, settings.app_secret, algorithm="HS256")


def decode_state_token(token: str, *, expected_type: str) -> dict:
    settings = get_settings()
    try:
        payload = jwt.decode(token, settings.app_secret, algorithms=["HS256"])
    except jwt.PyJWTError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token") from exc
    if payload.get("typ") != expected_type:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    return payload


def create_proof_ticket(
    *,
    installation_id: str,
    platform: str,
    proof_method: str,
    installation_status: str,
    session_version: int,
    username: str | None,
    expires_seconds: int,
) -> tuple[str, int]:
    claims: dict[str, object] = {
        "installation_id": installation_id,
        "platform": platform,
        "proof_method": proof_method,
        "installation_status": installation_status,
        "session_version": int(session_version),
    }
    if username:
        claims["username"] = username
    token = create_state_token(
        subject=installation_id,
        state_type="app_proof_ticket",
        expires_seconds=expires_seconds,
        extra_claims=claims,
    )
    return token, expires_seconds


def decode_proof_ticket(token: str) -> dict:
    return decode_state_token(token, expected_type="app_proof_ticket")


def _secret_encryption_key() -> bytes:
    digest = hashlib.sha256(f"{get_settings().app_secret}:admin-mfa".encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest)


def encrypt_secret_value(secret_value: str) -> str:
    return Fernet(_secret_encryption_key()).encrypt(secret_value.encode("utf-8")).decode("utf-8")


def decrypt_secret_value(encrypted_value: str) -> str:
    try:
        return Fernet(_secret_encryption_key()).decrypt(encrypted_value.encode("utf-8")).decode("utf-8")
    except (InvalidToken, ValueError) as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid protected secret") from exc


def generate_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def _normalize_totp_secret(secret: str) -> bytes:
    normalized = "".join(ch for ch in secret.upper() if not ch.isspace())
    padding = "=" * ((8 - len(normalized) % 8) % 8)
    return base64.b32decode(normalized + padding, casefold=True)


def _totp_code(secret: str, *, for_time: datetime, time_step_seconds: int = 30, digits: int = 6) -> str:
    secret_bytes = _normalize_totp_secret(secret)
    counter = int(for_time.timestamp()) // time_step_seconds
    counter_bytes = struct.pack(">Q", counter)
    digest = hmac.new(secret_bytes, counter_bytes, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code_int = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(code_int % (10**digits)).zfill(digits)


def verify_totp_code(
    secret: str,
    code: str,
    *,
    at_time: datetime | None = None,
    window: int = 1,
    time_step_seconds: int = 30,
    digits: int = 6,
) -> bool:
    normalized_code = "".join(ch for ch in code if ch.isdigit())
    if len(normalized_code) != digits:
        return False
    current_time = at_time or datetime.now(UTC)
    for skew in range(-window, window + 1):
        candidate_time = current_time + timedelta(seconds=skew * time_step_seconds)
        if hmac.compare_digest(
            normalized_code,
            _totp_code(secret, for_time=candidate_time, time_step_seconds=time_step_seconds, digits=digits),
        ):
            return True
    return False


def generate_totp_code(secret: str, *, at_time: datetime | None = None, time_step_seconds: int = 30, digits: int = 6) -> str:
    return _totp_code(secret, for_time=at_time or datetime.now(UTC), time_step_seconds=time_step_seconds, digits=digits)


def build_totp_otpauth_uri(*, secret: str, issuer: str, account_name: str) -> str:
    label = urllib.parse.quote(f"{issuer}:{account_name}")
    query = urllib.parse.urlencode(
        {
            "secret": secret,
            "issuer": issuer,
            "algorithm": "SHA1",
            "digits": "6",
            "period": "30",
        }
    )
    return f"otpauth://totp/{label}?{query}"
