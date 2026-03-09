from __future__ import annotations

import base64
import hmac
import hashlib
import json
import struct
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import cached_property
from typing import Any, Literal

import cbor2
import httpx
import jwt
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509.oid import ObjectIdentifier
from fastapi import HTTPException, status

from .config import Settings, get_settings
from .db import (
    consume_app_proof_challenge,
    get_app_installation,
    get_ios_app_attest_key,
    issue_app_proof_challenge,
    mark_app_proof_challenge_consumed,
    record_app_installation_failure,
    record_android_attestation,
    record_ios_app_attest_enrollment,
    record_ios_app_attest_assertion,
    update_installation_after_login,
)
from .security import create_proof_ticket, decode_proof_ticket
from .telemetry import increment_counter, structured_log

APPLE_APP_ATTESTATION_ROOT_CA_PEM = """-----BEGIN CERTIFICATE-----
MIICITCCAaegAwIBAgIQC/O+DvHN0uD7jG5yH2IXmDAKBggqhkjOPQQDAzBSMSYw
JAYDVQQDDB1BcHBsZSBBcHAgQXR0ZXN0YXRpb24gUm9vdCBDQTETMBEGA1UECgwK
QXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTAeFw0yMDAzMTgxODMyNTNa
Fw00NTAzMTUwMDAwMDBaMFIxJjAkBgNVBAMMHUFwcGxlIEFwcCBBdHRlc3RhdGlv
biBSb290IENBMRMwEQYDVQQKDApBcHBsZSBBbmMuMRMwEQYDVQQIDApDYWxpZm9y
bmlhMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAERTHhmLW07ATaFQIEVwTtT4dyctdh
NbJhFs/Ii2FdCgAHGbpphY3+d8qjuDngIN3WVhQUBHAoMeQ/cLiP1sOUtgjqK9au
Yen1mMEvRq9Sk3Jm5X8U62H+xTD3FE9TgS41o0IwQDAPBgNVHRMBAf8EBTADAQH/
MB0GA1UdDgQWBBSskRBTM72+aEH/pwyp5frq5eWKoTAOBgNVHQ8BAf8EBAMCAQYw
CgYIKoZIzj0EAwMDaAAwZQIwQgFGnByvsiVbpTKwSga0kP0e8EeDS4+sQmTvb7vn
53O5+FRXgeLhpJ06ysC5PrOyAjEAp5U4xDgEgllF7En3VcE3iexZZtKeYnpqtijV
oyFraWVIyd/dganmrduC1bmTBGwD
-----END CERTIFICATE-----"""

ANDROID_PROOF_METHOD = "android_play_integrity"
IOS_PROOF_METHOD = "ios_app_attest"
APP_PROOF_TICKET_TTL_SECONDS = 300
APP_PROOF_HEADER = "x-wff-installation-id"
APP_PROOF_CANONICAL_FIELDS: tuple[str, ...] = (
    "purpose",
    "challenge_id",
    "challenge",
    "installation_id",
    "username",
)
_APPLE_NONCE_EXTENSION_OID = ObjectIdentifier("1.2.840.113635.100.8.2")
_PLAY_INTEGRITY_SCOPE = "https://www.googleapis.com/auth/playintegrity"
_PLAY_INTEGRITY_TOKEN_URI = "https://oauth2.googleapis.com/token"


class AppProofError(Exception):
    def __init__(
        self,
        *,
        status_code: int,
        detail: str,
        reason: str,
        log_event: str = "app_proof.verify_failed",
        provider_error: bool = False,
    ) -> None:
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail
        self.reason = reason
        self.log_event = log_event
        self.provider_error = provider_error

    def to_http_exception(self) -> HTTPException:
        return HTTPException(status_code=self.status_code, detail=self.detail)


@dataclass(slots=True)
class VerifiedProof:
    installation_id: str
    platform: Literal["android", "ios"]
    proof_method: str
    installation_status: str
    session_version: int
    username: str | None = None


@dataclass(slots=True)
class LoginProofDecision:
    allowed: bool
    degraded: bool = False
    degraded_reason: str | None = None
    proof: VerifiedProof | None = None


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _increment_metrics(*names: str) -> None:
    for name in names:
        increment_counter(name)


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64decode_loose(value: str) -> bytes:
    normalized = value.strip().replace("-", "+").replace("_", "/")
    padding = "=" * ((4 - len(normalized) % 4) % 4)
    return base64.b64decode(normalized + padding)


def _canonical_payload(
    *,
    purpose: str,
    challenge_id: str,
    challenge: str,
    installation_id: str,
    username: str | None,
) -> dict[str, str]:
    payload: dict[str, str] = {}
    payload["purpose"] = purpose
    payload["challenge_id"] = challenge_id
    payload["challenge"] = challenge
    payload["installation_id"] = installation_id
    if username:
        payload["username"] = username
    return payload


def canonical_json(
    *,
    purpose: str,
    challenge_id: str,
    challenge: str,
    installation_id: str,
    username: str | None,
) -> str:
    payload = _canonical_payload(
        purpose=purpose,
        challenge_id=challenge_id,
        challenge=challenge,
        installation_id=installation_id,
        username=username,
    )
    return json.dumps(payload, separators=(",", ":"))


def client_data_hash(
    *,
    purpose: str,
    challenge_id: str,
    challenge: str,
    installation_id: str,
    username: str | None,
) -> bytes:
    payload = canonical_json(
        purpose=purpose,
        challenge_id=challenge_id,
        challenge=challenge,
        installation_id=installation_id,
        username=username,
    )
    return hashlib.sha256(payload.encode("utf-8")).digest()


def request_hash_b64url(
    *,
    purpose: str,
    challenge_id: str,
    challenge: str,
    installation_id: str,
    username: str | None,
) -> str:
    return _b64url_encode(
        client_data_hash(
            purpose=purpose,
            challenge_id=challenge_id,
            challenge=challenge,
            installation_id=installation_id,
            username=username,
        )
    )


def is_mobile_bearer_login_required(*, role: str, settings: Settings) -> bool:
    if settings.app_proof_mode == "disabled":
        return False
    if role == "admin" and not settings.app_proof_require_on_admin_bearer_login:
        return False
    return True


class AppProofService:
    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()

    @cached_property
    def _apple_root_certificate(self) -> x509.Certificate:
        return x509.load_pem_x509_certificate(APPLE_APP_ATTESTATION_ROOT_CA_PEM.encode("ascii"))

    def issue_challenge(
        self,
        *,
        platform: Literal["android", "ios"],
        purpose: Literal["enroll", "login", "reauth"],
        installation_id: str,
        username: str | None,
        app_version: str | None,
        os_version: str | None,
        client_ip: str | None,
    ) -> dict[str, Any]:
        challenge_id = str(uuid.uuid4())
        challenge = _b64url_encode(hashlib.sha256(f"{challenge_id}:{time.time_ns()}".encode("utf-8")).digest())
        challenge_row = issue_app_proof_challenge(
            challenge_id=challenge_id,
            purpose=purpose,
            platform=platform,
            installation_id=installation_id,
            username_hint=username,
            challenge_nonce=challenge,
            expires_in_seconds=self.settings.app_proof_challenge_ttl_seconds,
            client_ip=client_ip,
            app_version=app_version,
            os_version=os_version,
        )
        _increment_metrics("app_proof.challenge_issued", "app_proof.challenge.issued")
        structured_log(
            "app_proof.challenge_issued",
            platform=platform,
            purpose=purpose,
            installation_id=installation_id,
            challenge_id=challenge_id,
            username=username,
            client_ip=client_ip,
        )
        return {
            "challenge_id": challenge_id,
            "challenge": challenge,
            "purpose": purpose,
            "expires_in": self.settings.app_proof_challenge_ttl_seconds,
            "binding": {"canonical_fields": list(APP_PROOF_CANONICAL_FIELDS)},
            "challenge_record": challenge_row,
        }

    def verify_android(
        self,
        *,
        challenge_id: str,
        installation_id: str,
        request_hash: str,
        integrity_token: str,
        app_version: str | None,
        os_version: str | None,
        client_ip: str | None,
    ) -> VerifiedProof:
        challenge = self._consume_challenge(
            challenge_id=challenge_id,
            platform="android",
            installation_id=installation_id,
        )
        expected_request_hash = request_hash_b64url(
            purpose=challenge["purpose"],
            challenge_id=challenge["id"],
            challenge=challenge["challenge_nonce"],
            installation_id=installation_id,
            username=challenge["username_hint"],
        )
        if not hmac_compare(request_hash, expected_request_hash):
            _increment_metrics("app_proof.invalid_nonce", "app_proof.verify_failed.reason.request_hash_mismatch")
            structured_log(
                "app_proof.invalid_nonce",
                platform="android",
                installation_id=installation_id,
                challenge_id=challenge_id,
                reason="request_hash_mismatch",
            )
            raise AppProofError(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid mobile app proof",
                reason="invalid_proof",
            )

        verdict = self._decode_android_integrity_token(integrity_token=integrity_token)
        payload = verdict.get("tokenPayloadExternal") or verdict
        request_details = payload.get("requestDetails") or {}
        app_integrity = payload.get("appIntegrity") or {}
        device_integrity = payload.get("deviceIntegrity") or {}
        account_details = payload.get("accountDetails") or {}
        package_name = str(request_details.get("requestPackageName") or "")
        provider_request_hash = str(request_details.get("requestHash") or "")
        app_verdict = str(app_integrity.get("appRecognitionVerdict") or "")
        cert_digests = [str(value).upper() for value in (app_integrity.get("certificateSha256Digest") or [])]
        device_verdicts = [str(value) for value in (device_integrity.get("deviceRecognitionVerdict") or [])]
        licensing_verdict = str(account_details.get("appLicensingVerdict") or "")

        if package_name != self.settings.app_proof_android_package_name:
            raise AppProofError(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid mobile app proof",
                reason="invalid_proof",
            )
        if not hmac_compare(provider_request_hash, expected_request_hash):
            _increment_metrics(
                "app_proof.invalid_nonce",
                "app_proof.verify_failed.reason.provider_request_hash_mismatch",
            )
            structured_log(
                "app_proof.invalid_nonce",
                platform="android",
                installation_id=installation_id,
                challenge_id=challenge_id,
                reason="provider_request_hash_mismatch",
            )
            raise AppProofError(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid mobile app proof",
                reason="invalid_proof",
            )
        if self.settings.app_proof_android_require_play_recognized and app_verdict != "PLAY_RECOGNIZED":
            raise AppProofError(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid mobile app proof",
                reason="invalid_proof",
            )
        allowed_certs = {value.upper() for value in self.settings.app_proof_android_allowed_cert_sha256_list}
        if allowed_certs and not any(cert in allowed_certs for cert in cert_digests):
            raise AppProofError(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid mobile app proof",
                reason="invalid_proof",
            )
        if self.settings.app_proof_android_require_device_integrity and "MEETS_DEVICE_INTEGRITY" not in device_verdicts:
            raise AppProofError(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid mobile app proof",
                reason="invalid_proof",
            )
        if self.settings.app_proof_android_require_licensed and licensing_verdict != "LICENSED":
            raise AppProofError(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid mobile app proof",
                reason="invalid_proof",
            )

        installation = record_android_attestation(
            installation_id=installation_id,
            app_id=package_name,
            app_version=app_version,
            os_version=os_version,
            client_ip=client_ip,
            provider_status="verified",
            provider_error=None,
            verdict_json=json.dumps(
                {
                    "appRecognitionVerdict": app_verdict,
                    "certificateSha256Digest": cert_digests,
                    "deviceRecognitionVerdict": device_verdicts,
                    "appLicensingVerdict": licensing_verdict or None,
                },
                separators=(",", ":"),
            ),
        )
        _increment_metrics("app_proof.verify_success", "app_proof.challenge.verify_success")
        structured_log(
            "app_proof.verify_success",
            platform="android",
            purpose=challenge["purpose"],
            installation_id=installation_id,
            challenge_id=challenge_id,
            proof_method=ANDROID_PROOF_METHOD,
        )
        return VerifiedProof(
            installation_id=installation_id,
            platform="android",
            proof_method=ANDROID_PROOF_METHOD,
            installation_status=str(installation["status"]),
            session_version=int(installation["session_version"] or 1),
            username=str(challenge["username_hint"]) if challenge["username_hint"] else None,
        )

    def verify_ios(
        self,
        *,
        mode: Literal["attest", "assert"],
        challenge_id: str,
        installation_id: str,
        key_id: str,
        attestation_object: str | None,
        assertion_object: str | None,
        receipt: str | None,
        app_version: str | None,
        os_version: str | None,
        client_ip: str | None,
    ) -> VerifiedProof:
        challenge = self._consume_challenge(
            challenge_id=challenge_id,
            platform="ios",
            installation_id=installation_id,
        )
        expected_client_data_hash = client_data_hash(
            purpose=challenge["purpose"],
            challenge_id=challenge["id"],
            challenge=challenge["challenge_nonce"],
            installation_id=installation_id,
            username=challenge["username_hint"],
        )

        if mode == "attest":
            if not attestation_object:
                raise AppProofError(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid mobile app proof",
                    reason="invalid_proof",
                )
            installation = self._verify_ios_attestation(
                installation_id=installation_id,
                key_id=key_id,
                attestation_object=attestation_object,
                receipt=receipt,
                client_data_hash_bytes=expected_client_data_hash,
                app_version=app_version,
                os_version=os_version,
                client_ip=client_ip,
            )
        else:
            if not assertion_object:
                raise AppProofError(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid mobile app proof",
                    reason="invalid_proof",
                )
            installation = self._verify_ios_assertion(
                installation_id=installation_id,
                key_id=key_id,
                assertion_object=assertion_object,
                client_data_hash_bytes=expected_client_data_hash,
                app_version=app_version,
                os_version=os_version,
                client_ip=client_ip,
            )

        _increment_metrics("app_proof.verify_success", "app_proof.challenge.verify_success")
        structured_log(
            "app_proof.verify_success",
            platform="ios",
            purpose=challenge["purpose"],
            installation_id=installation_id,
            challenge_id=challenge_id,
            proof_method=IOS_PROOF_METHOD,
            mode=mode,
        )
        return VerifiedProof(
            installation_id=installation_id,
            platform="ios",
            proof_method=IOS_PROOF_METHOD,
            installation_status=str(installation["status"]),
            session_version=int(installation["session_version"] or 1),
            username=str(challenge["username_hint"]) if challenge["username_hint"] else None,
        )

    def build_proof_ticket(self, proof: VerifiedProof) -> tuple[str, int]:
        return create_proof_ticket(
            installation_id=proof.installation_id,
            platform=proof.platform,
            proof_method=proof.proof_method,
            installation_status=proof.installation_status,
            session_version=proof.session_version,
            username=proof.username,
            expires_seconds=APP_PROOF_TICKET_TTL_SECONDS,
        )

    def validate_login_proof(
        self,
        *,
        username: str,
        role: str,
        installation_id: str | None,
        proof_ticket: str | None,
        client_ip: str | None,
    ) -> LoginProofDecision:
        mode = self.settings.app_proof_mode
        if not is_mobile_bearer_login_required(role=role, settings=self.settings):
            if (
                role == "admin"
                and mode != "disabled"
                and not self.settings.app_proof_require_on_admin_bearer_login
                and not (proof_ticket and installation_id)
            ):
                _increment_metrics(
                    "app_proof.admin_bearer_login_deferred_allow",
                    "app_proof.admin_bearer_login.deferred_allow",
                )
                structured_log(
                    "app_proof.admin_bearer_login_deferred_allow",
                    username=username,
                    role=role,
                    installation_id=installation_id,
                    client_ip=client_ip,
                    enforcement_mode=mode,
                )
            if proof_ticket and installation_id:
                proof = self._validate_proof_ticket(username=username, installation_id=installation_id, proof_ticket=proof_ticket)
                return LoginProofDecision(allowed=True, proof=proof)
            return LoginProofDecision(allowed=True)

        if mode == "disabled":
            if proof_ticket and installation_id:
                proof = self._validate_proof_ticket(username=username, installation_id=installation_id, proof_ticket=proof_ticket)
                return LoginProofDecision(allowed=True, proof=proof)
            return LoginProofDecision(allowed=True)

        if proof_ticket and installation_id:
            proof = self._validate_proof_ticket(username=username, installation_id=installation_id, proof_ticket=proof_ticket)
            return LoginProofDecision(allowed=True, proof=proof)

        if mode == "report_only":
            _increment_metrics(
                "app_proof.session_issued_without_proof",
                "app_proof.report_only_missing_proof",
                "app_proof.missing_proof.report_only",
            )
            structured_log(
                "app_proof.report_only_missing_proof",
                username=username,
                role=role,
                installation_id=installation_id,
                client_ip=client_ip,
                enforcement_mode=mode,
            )
            return LoginProofDecision(allowed=True)

        installation = get_app_installation(installation_id) if installation_id else None
        if mode == "soft_enforce" and self._eligible_for_degraded_login(installation):
            _increment_metrics(
                "app_proof.degraded_allow",
                "app_proof.soft_enforce_degraded_allow",
                "app_proof.soft_enforce.degraded_allow",
            )
            structured_log(
                "app_proof.soft_enforce_degraded_allow",
                username=username,
                role=role,
                installation_id=installation_id,
                client_ip=client_ip,
                degraded_reason="trusted_installation_grace",
            )
            return LoginProofDecision(
                allowed=True,
                degraded=True,
                degraded_reason="trusted_installation_grace",
                proof=VerifiedProof(
                    installation_id=str(installation["installation_id"]),
                    platform=str(installation["platform"]),
                    proof_method=str(installation["proof_method"]),
                    installation_status=str(installation["status"]),
                    session_version=int(installation["session_version"] or 1),
                    username=username,
                ),
            )

        _increment_metrics(
            "app_proof.enforcement_blocked",
            "app_proof.enforce_login_blocked",
            "app_proof.enforce_login.blocked",
        )
        structured_log(
            "app_proof.enforce_login_blocked",
            username=username,
            role=role,
            installation_id=installation_id,
            client_ip=client_ip,
            enforcement_mode=mode,
            reason="missing_proof",
        )
        return LoginProofDecision(allowed=False)

    def ensure_authenticated_installation(
        self,
        *,
        token_payload: dict[str, Any],
        presented_installation_id: str | None,
    ) -> None:
        token_installation_id = str(token_payload.get("aid") or "").strip()
        if not token_installation_id:
            return
        if not presented_installation_id or token_installation_id != presented_installation_id:
            _increment_metrics(
                "app_proof.session_mismatch",
                "app_proof.installation_session_mismatch",
                "app_proof.installation_session_mismatch.header_mismatch",
            )
            structured_log(
                "app_proof.installation_session_mismatch",
                installation_id=token_installation_id,
                presented_installation_id=presented_installation_id,
                reason="header_mismatch",
            )
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Mobile session binding is invalid")
        installation = get_app_installation(token_installation_id)
        if not installation or str(installation["status"]) == "revoked":
            _increment_metrics(
                "app_proof.installation_revoked_used",
                "app_proof.installation_revoked",
            )
            structured_log(
                "app_proof.installation_revoked",
                installation_id=token_installation_id,
            )
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Mobile session is no longer valid")
        try:
            session_version = int(token_payload.get("asv", 0))
        except (TypeError, ValueError) as exc:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token") from exc
        if session_version != int(installation["session_version"] or 0):
            _increment_metrics(
                "app_proof.session_mismatch",
                "app_proof.installation_session_mismatch",
                "app_proof.installation_session_mismatch.session_version_mismatch",
            )
            structured_log(
                "app_proof.installation_session_mismatch",
                installation_id=token_installation_id,
                reason="session_version_mismatch",
            )
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Mobile session is stale")

    def update_installation_after_login(
        self,
        *,
        installation_id: str,
        user_id: int,
        client_ip: str | None,
    ) -> dict[str, Any]:
        return dict(update_installation_after_login(installation_id=installation_id, user_id=user_id, client_ip=client_ip))

    def record_verify_error(
        self,
        *,
        platform: str,
        purpose: str | None,
        installation_id: str | None,
        challenge_id: str | None,
        reason: str,
        detail: str,
        client_ip: str | None = None,
        event: str = "app_proof.verify_failed",
    ) -> None:
        reason_metric = reason.strip().replace(" ", "_").replace("-", "_") or "unknown"
        _increment_metrics("app_proof.verify_failed", f"app_proof.verify_failed.reason.{reason_metric}")
        if event == "app_proof.verify_failed":
            structured_log(
                event,
                platform=platform,
                purpose=purpose,
                installation_id=installation_id,
                challenge_id=challenge_id,
                reason=reason,
                detail=detail,
            )
        if installation_id:
            record_app_installation_failure(
                installation_id=installation_id,
                platform=platform,
                reason=reason,
                detail=detail,
                client_ip=client_ip,
                provider_status="error" if reason.startswith("provider_") else "rejected",
                provider_error=reason,
            )

    def _validate_proof_ticket(self, *, username: str, installation_id: str, proof_ticket: str) -> VerifiedProof:
        payload = decode_proof_ticket(proof_ticket)
        if payload.get("installation_id") != installation_id:
            _increment_metrics("app_proof.verify_failed", "app_proof.verify_failed.reason.ticket_installation_mismatch")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid mobile app proof")
        ticket_username = str(payload.get("username") or "")
        if ticket_username and ticket_username != username:
            _increment_metrics("app_proof.verify_failed", "app_proof.verify_failed.reason.ticket_username_mismatch")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid mobile app proof")
        installation = get_app_installation(installation_id)
        if not installation or str(installation["status"]) == "revoked":
            _increment_metrics("app_proof.installation_revoked", "app_proof.verify_failed.reason.revoked_installation")
            structured_log(
                "app_proof.installation_revoked",
                installation_id=installation_id,
                reason="revoked_installation",
            )
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid mobile app proof")
        if int(payload.get("session_version", 0)) != int(installation["session_version"] or 0):
            _increment_metrics(
                "app_proof.installation_session_mismatch",
                "app_proof.verify_failed.reason.ticket_session_version_mismatch",
            )
            structured_log(
                "app_proof.installation_session_mismatch",
                installation_id=installation_id,
                reason="ticket_session_version_mismatch",
            )
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid mobile app proof")
        return VerifiedProof(
            installation_id=installation_id,
            platform=str(payload["platform"]),
            proof_method=str(payload["proof_method"]),
            installation_status=str(payload["installation_status"]),
            session_version=int(payload["session_version"]),
            username=ticket_username or None,
        )

    def _eligible_for_degraded_login(self, installation: Any | None) -> bool:
        if not installation or str(installation["status"]) != "trusted":
            return False
        last_verified_at = parse_iso_datetime(installation["last_verified_at"])
        if last_verified_at is None:
            return False
        age_seconds = (_utcnow() - last_verified_at).total_seconds()
        return age_seconds <= self.settings.app_proof_degraded_grace_seconds

    def _consume_challenge(
        self,
        *,
        challenge_id: str,
        platform: Literal["android", "ios"],
        installation_id: str,
    ) -> Any:
        challenge = consume_app_proof_challenge(challenge_id)
        if not challenge:
            _increment_metrics("app_proof.replay_detected", "app_proof.challenge.verify_failed")
            structured_log(
                "app_proof.replay_detected",
                platform=platform,
                installation_id=installation_id,
                challenge_id=challenge_id,
            )
            raise AppProofError(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid mobile app proof",
                reason="replayed_challenge",
                log_event="app_proof.replay_detected",
            )
        if str(challenge["platform"]) != platform or str(challenge["installation_id"]) != installation_id:
            raise AppProofError(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid mobile app proof",
                reason="invalid_proof",
            )
        expires_at = parse_iso_datetime(challenge["expires_at"])
        if expires_at is None or expires_at <= _utcnow():
            mark_app_proof_challenge_consumed(challenge_id, consume_even_if_missing=False)
            _increment_metrics("app_proof.challenge_expired", "app_proof.challenge.verify_failed")
            structured_log(
                "app_proof.challenge_expired",
                platform=platform,
                installation_id=installation_id,
                challenge_id=challenge_id,
            )
            raise AppProofError(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Mobile app proof challenge expired",
                reason="expired_challenge",
                log_event="app_proof.challenge_expired",
            )
        _increment_metrics("app_proof.challenge_consumed", "app_proof.challenge.verify_attempt")
        structured_log(
            "app_proof.challenge_consumed",
            platform=platform,
            purpose=challenge["purpose"],
            installation_id=installation_id,
            challenge_id=challenge_id,
        )
        return challenge

    def _decode_android_integrity_token(self, *, integrity_token: str) -> dict[str, Any]:
        settings = self.settings
        if not settings.app_proof_android_enabled:
            raise AppProofError(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Android mobile app proof is unavailable",
                reason="provider_error",
                provider_error=True,
            )
        service_account = settings.app_proof_android_service_account_json_dict
        if not service_account:
            raise AppProofError(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Android mobile app proof is unavailable",
                reason="provider_error",
                provider_error=True,
            )

        access_token = self._google_access_token(service_account=service_account)
        endpoint = f"https://playintegrity.googleapis.com/v1/{settings.app_proof_android_package_name}:decodeIntegrityToken"
        try:
            with httpx.Client(timeout=settings.app_proof_provider_timeout_seconds) as client:
                response = client.post(
                    endpoint,
                    headers={"Authorization": f"Bearer {access_token}"},
                    json={"integrity_token": integrity_token},
                )
        except httpx.TimeoutException as exc:
            _increment_metrics("app_proof.provider_timeout", "app_proof.provider.timeout")
            structured_log("app_proof.provider_timeout", platform="android", error=str(exc))
            raise AppProofError(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Android mobile app proof is temporarily unavailable",
                reason="provider_timeout",
                log_event="app_proof.provider_timeout",
                provider_error=True,
            ) from exc
        except httpx.HTTPError as exc:
            _increment_metrics("app_proof.provider_error", "app_proof.provider.error")
            structured_log("app_proof.provider_error", platform="android", error=str(exc))
            raise AppProofError(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Android mobile app proof is temporarily unavailable",
                reason="provider_error",
                log_event="app_proof.provider_error",
                provider_error=True,
            ) from exc

        if response.status_code >= 500:
            _increment_metrics("app_proof.provider_error", "app_proof.provider.error")
            structured_log(
                "app_proof.provider_error",
                platform="android",
                status_code=response.status_code,
                body=response.text[:200],
            )
            raise AppProofError(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Android mobile app proof is temporarily unavailable",
                reason="provider_error",
                log_event="app_proof.provider_error",
                provider_error=True,
            )
        if response.status_code == 429:
            _increment_metrics("app_proof.provider_quota", "app_proof.provider.quota")
            structured_log("app_proof.provider_quota", platform="android", body=response.text[:200])
            raise AppProofError(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Android mobile app proof is temporarily unavailable",
                reason="provider_error",
                log_event="app_proof.provider_quota",
                provider_error=True,
            )
        if response.status_code >= 400:
            raise AppProofError(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid mobile app proof",
                reason="invalid_proof",
            )
        return response.json()

    def _google_access_token(self, *, service_account: dict[str, Any]) -> str:
        client_email = str(service_account.get("client_email") or "").strip()
        private_key = str(service_account.get("private_key") or "").strip()
        token_uri = str(service_account.get("token_uri") or _PLAY_INTEGRITY_TOKEN_URI).strip()
        if not client_email or not private_key:
            raise AppProofError(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Android mobile app proof is unavailable",
                reason="provider_error",
                provider_error=True,
            )
        now = int(time.time())
        assertion = jwt.encode(
            {
                "iss": client_email,
                "sub": client_email,
                "aud": token_uri,
                "scope": _PLAY_INTEGRITY_SCOPE,
                "iat": now,
                "exp": now + 3600,
            },
            private_key,
            algorithm="RS256",
        )
        try:
            with httpx.Client(timeout=self.settings.app_proof_provider_timeout_seconds) as client:
                response = client.post(
                    token_uri,
                    data={
                        "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                        "assertion": assertion,
                    },
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
        except httpx.TimeoutException as exc:
            _increment_metrics("app_proof.provider_timeout", "app_proof.provider.timeout")
            structured_log("app_proof.provider_timeout", platform="android", stage="oauth_token", error=str(exc))
            raise AppProofError(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Android mobile app proof is temporarily unavailable",
                reason="provider_timeout",
                log_event="app_proof.provider_timeout",
                provider_error=True,
            ) from exc
        except httpx.HTTPError as exc:
            _increment_metrics("app_proof.provider_error", "app_proof.provider.error")
            structured_log("app_proof.provider_error", platform="android", stage="oauth_token", error=str(exc))
            raise AppProofError(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Android mobile app proof is temporarily unavailable",
                reason="provider_error",
                log_event="app_proof.provider_error",
                provider_error=True,
            ) from exc
        if response.status_code >= 400:
            _increment_metrics("app_proof.provider_error", "app_proof.provider.error")
            structured_log(
                "app_proof.provider_error",
                platform="android",
                stage="oauth_token",
                status_code=response.status_code,
            )
            raise AppProofError(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Android mobile app proof is unavailable",
                reason="provider_error",
                log_event="app_proof.provider_error",
                provider_error=True,
            )
        payload = response.json()
        token = str(payload.get("access_token") or "").strip()
        if not token:
            _increment_metrics("app_proof.provider_error", "app_proof.provider.error")
            structured_log("app_proof.provider_error", platform="android", stage="oauth_token", error="missing_access_token")
            raise AppProofError(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Android mobile app proof is unavailable",
                reason="provider_error",
                log_event="app_proof.provider_error",
                provider_error=True,
            )
        return token

    def _verify_ios_attestation(
        self,
        *,
        installation_id: str,
        key_id: str,
        attestation_object: str,
        receipt: str | None,
        client_data_hash_bytes: bytes,
        app_version: str | None,
        os_version: str | None,
        client_ip: str | None,
    ) -> Any:
        attestation_bytes = _b64decode_loose(attestation_object)
        attestation = cbor2.loads(attestation_bytes)
        auth_data = bytes(attestation.get("authData") or b"")
        att_stmt = attestation.get("attStmt") or {}
        certificates = [x509.load_der_x509_certificate(bytes(cert)) for cert in (att_stmt.get("x5c") or [])]
        if len(certificates) < 2:
            raise AppProofError(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid mobile app proof",
                reason="invalid_proof",
            )
        self._verify_certificate_chain(certificates)

        parsed = self._parse_authenticator_data(auth_data)
        expected_rp_id_hash = hashlib.sha256(self.settings.app_proof_ios_app_id.encode("utf-8")).digest()
        if parsed["rp_id_hash"] != expected_rp_id_hash:
            raise AppProofError(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid mobile app proof",
                reason="invalid_proof",
            )
        attested_public_key = self._public_key_from_cose(parsed["cose_key"])
        key_id_bytes = _b64decode_loose(key_id)
        if parsed["credential_id"] != key_id_bytes:
            raise AppProofError(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid mobile app proof",
                reason="invalid_proof",
            )
        nonce = hashlib.sha256(auth_data + client_data_hash_bytes).digest()
        self._verify_attestation_nonce(certificates[0], nonce)

        installation = record_ios_app_attest_enrollment(
            installation_id=installation_id,
            key_id=key_id,
            public_key_pem=attested_public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode("ascii"),
            receipt_b64=receipt,
            app_id=self.settings.app_proof_ios_bundle_id,
            app_version=app_version,
            os_version=os_version,
            client_ip=client_ip,
            provider_status="verified",
            provider_error=None,
            verdict_json=json.dumps(
                {
                    "fmt": attestation.get("fmt"),
                    "flags": parsed["flags"],
                    "sign_count": parsed["sign_count"],
                },
                separators=(",", ":"),
            ),
        )
        return installation

    def _verify_ios_assertion(
        self,
        *,
        installation_id: str,
        key_id: str,
        assertion_object: str,
        client_data_hash_bytes: bytes,
        app_version: str | None,
        os_version: str | None,
        client_ip: str | None,
    ) -> Any:
        installation = get_app_installation(installation_id)
        key_row = get_ios_app_attest_key(installation_id)
        if not installation or str(installation["status"]) == "revoked" or not key_row:
            raise AppProofError(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Mobile installation is revoked or unknown",
                reason="revoked_installation",
            )
        if str(key_row["key_id"]) != key_id:
            raise AppProofError(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid mobile app proof",
                reason="invalid_proof",
            )

        assertion_bytes = _b64decode_loose(assertion_object)
        if len(assertion_bytes) <= 37:
            raise AppProofError(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid mobile app proof",
                reason="invalid_proof",
            )
        auth_data = assertion_bytes[:37]
        signature = assertion_bytes[37:]
        parsed = self._parse_authenticator_data(auth_data)
        expected_rp_id_hash = hashlib.sha256(self.settings.app_proof_ios_app_id.encode("utf-8")).digest()
        if parsed["rp_id_hash"] != expected_rp_id_hash:
            raise AppProofError(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid mobile app proof",
                reason="invalid_proof",
            )
        previous_sign_count = int(key_row["sign_count"] or 0)
        if parsed["sign_count"] <= previous_sign_count:
            raise AppProofError(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid mobile app proof",
                reason="invalid_proof",
            )
        public_key = serialization.load_pem_public_key(str(key_row["public_key_pem"]).encode("ascii"))
        signed_payload = auth_data + client_data_hash_bytes
        try:
            public_key.verify(signature, signed_payload, ec.ECDSA(hashes.SHA256()))
        except Exception as exc:
            raise AppProofError(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid mobile app proof",
                reason="invalid_proof",
            ) from exc

        return record_ios_app_attest_assertion(
            installation_id=installation_id,
            sign_count=parsed["sign_count"],
            app_version=app_version,
            os_version=os_version,
            client_ip=client_ip,
            provider_status="verified",
            provider_error=None,
            verdict_json=json.dumps(
                {"flags": parsed["flags"], "sign_count": parsed["sign_count"]},
                separators=(",", ":"),
            ),
        )

    def _verify_certificate_chain(self, certificates: list[x509.Certificate]) -> None:
        root = self._apple_root_certificate
        chain = certificates + [root]
        for parent, child in zip(chain[1:], chain[:-1], strict=False):
            self._verify_certificate_signature(parent=parent, child=child)

    def _verify_certificate_signature(self, *, parent: x509.Certificate, child: x509.Certificate) -> None:
        public_key = parent.public_key()
        signature_hash = child.signature_hash_algorithm
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(child.signature, child.tbs_certificate_bytes, ec.ECDSA(signature_hash))
            return
        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(child.signature, child.tbs_certificate_bytes, padding.PKCS1v15(), signature_hash)
            return
        raise AppProofError(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid mobile app proof",
            reason="invalid_proof",
        )

    def _verify_attestation_nonce(self, certificate: x509.Certificate, nonce: bytes) -> None:
        try:
            extension = certificate.extensions.get_extension_for_oid(_APPLE_NONCE_EXTENSION_OID)
        except x509.ExtensionNotFound as exc:
            raise AppProofError(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid mobile app proof",
                reason="invalid_proof",
            ) from exc
        ext_value = extension.value.value
        extracted = extract_nonce_from_der_sequence(ext_value)
        if extracted != nonce:
            raise AppProofError(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid mobile app proof",
                reason="invalid_proof",
            )

    def _parse_authenticator_data(self, raw: bytes) -> dict[str, Any]:
        if len(raw) < 37:
            raise AppProofError(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid mobile app proof",
                reason="invalid_proof",
            )
        rp_id_hash = raw[:32]
        flags = raw[32]
        sign_count = struct.unpack(">I", raw[33:37])[0]
        result: dict[str, Any] = {
            "rp_id_hash": rp_id_hash,
            "flags": flags,
            "sign_count": sign_count,
        }
        if flags & 0x40:
            cursor = 37
            if len(raw) < cursor + 18:
                raise AppProofError(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid mobile app proof",
                    reason="invalid_proof",
                )
            aaguid = raw[cursor : cursor + 16]
            cursor += 16
            credential_id_length = struct.unpack(">H", raw[cursor : cursor + 2])[0]
            cursor += 2
            credential_id = raw[cursor : cursor + credential_id_length]
            cursor += credential_id_length
            cose_key = raw[cursor:]
            result.update(
                {
                    "aaguid": aaguid,
                    "credential_id": credential_id,
                    "cose_key": cose_key,
                }
            )
        return result

    def _public_key_from_cose(self, cose_key_bytes: bytes):
        cose_key = cbor2.loads(cose_key_bytes)
        if int(cose_key.get(1, 0)) != 2 or int(cose_key.get(3, 0)) != -7 or int(cose_key.get(-1, 0)) != 1:
            raise AppProofError(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid mobile app proof",
                reason="invalid_proof",
            )
        x_coord = bytes(cose_key.get(-2) or b"")
        y_coord = bytes(cose_key.get(-3) or b"")
        if len(x_coord) != 32 or len(y_coord) != 32:
            raise AppProofError(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid mobile app proof",
                reason="invalid_proof",
            )
        public_numbers = ec.EllipticCurvePublicNumbers(
            int.from_bytes(x_coord, "big"),
            int.from_bytes(y_coord, "big"),
            ec.SECP256R1(),
        )
        return public_numbers.public_key()


def parse_iso_datetime(value: Any) -> datetime | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def hmac_compare(left: str, right: str) -> bool:
    left_bytes = left.strip().encode("utf-8")
    right_bytes = right.strip().encode("utf-8")
    if not left_bytes or not right_bytes:
        return False
    return hmac.compare_digest(left_bytes, right_bytes)


def extract_nonce_from_der_sequence(raw: bytes) -> bytes:
    if len(raw) < 4 or raw[0] != 0x30:
        raise AppProofError(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid mobile app proof",
            reason="invalid_proof",
        )
    seq_length, cursor = _read_der_length(raw, 1)
    end = cursor + seq_length
    if end > len(raw) or cursor >= len(raw) or raw[cursor] != 0x04:
        raise AppProofError(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid mobile app proof",
            reason="invalid_proof",
        )
    octet_length, cursor = _read_der_length(raw, cursor + 1)
    inner = raw[cursor : cursor + octet_length]
    if cursor + octet_length != end:
        raise AppProofError(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid mobile app proof",
            reason="invalid_proof",
        )
    if len(inner) > 2 and inner[0] == 0x04:
        nested_length, nested_cursor = _read_der_length(inner, 1)
        nested = inner[nested_cursor : nested_cursor + nested_length]
        if nested_cursor + nested_length == len(inner):
            return nested
    return inner


def _read_der_length(raw: bytes, cursor: int) -> tuple[int, int]:
    first = raw[cursor]
    cursor += 1
    if first < 0x80:
        return first, cursor
    count = first & 0x7F
    if count == 0 or count > 4 or cursor + count > len(raw):
        raise AppProofError(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid mobile app proof",
            reason="invalid_proof",
        )
    value = int.from_bytes(raw[cursor : cursor + count], "big")
    return value, cursor + count
