from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

from app.app_proof import AppProofError, AppProofService, request_hash_b64url
from app.db import (
    create_device_membership,
    create_host,
    create_user,
    get_app_installation,
    get_conn,
    record_ios_app_attest_enrollment,
    revoke_app_installation,
)
from app.security import decode_token, hash_password
from app.telemetry import get_counters

from .conftest import admin_ui_login, auth_headers, login


def _create_user(username: str = "alice", password: str = "password123456") -> int:
    return create_user(username=username, password_hash=hash_password(password), role="user")


def _issue_challenge(client, *, platform: str, purpose: str, installation_id: str, username: str | None = None) -> dict:
    response = client.post(
        "/auth/app-proof/challenge",
        json={
            "platform": platform,
            "purpose": purpose,
            "installation_id": installation_id,
            "username": username,
            "app_version": "1.0.0",
            "os_version": "test-os",
        },
    )
    assert response.status_code == 200, response.text
    return response.json()


def test_challenge_issuance(client):
    payload = _issue_challenge(client, platform="android", purpose="login", installation_id="android-install-1", username="alice")
    assert payload["purpose"] == "login"
    assert payload["expires_in"] == 300
    assert payload["binding"]["canonical_fields"] == [
        "purpose",
        "challenge_id",
        "challenge",
        "installation_id",
        "username",
    ]


def test_expired_challenge_rejected(client_factory):
    with client_factory(
        env_overrides={
            "APP_PROOF_MODE": "report_only",
            "APP_PROOF_CHALLENGE_TTL_SECONDS": "300",
        }
    ) as client:
        challenge = _issue_challenge(
            client,
            platform="android",
            purpose="login",
            installation_id="android-install-expired",
            username="alice",
        )
        with get_conn() as conn:
            conn.execute(
                "UPDATE app_proof_challenges SET expires_at = ? WHERE id = ?",
                ((datetime.now(UTC) - timedelta(seconds=1)).isoformat(), challenge["challenge_id"]),
            )
        response = client.post(
            "/auth/app-proof/verify/android",
            json={
                "challenge_id": challenge["challenge_id"],
                "installation_id": "android-install-expired",
                "request_hash": request_hash_b64url(
                    purpose="login",
                    challenge_id=challenge["challenge_id"],
                    challenge=challenge["challenge"],
                    installation_id="android-install-expired",
                    username="alice",
                ),
                "integrity_token": "unused-integrity-token",
            },
        )
        assert response.status_code == 400
        assert response.json()["detail"] == "Mobile app proof challenge expired"


def test_android_attestation_success(client_factory, monkeypatch):
    with client_factory(env_overrides={"APP_PROOF_MODE": "report_only"}) as client:
        challenge = _issue_challenge(
            client,
            platform="android",
            purpose="login",
            installation_id="android-install-success",
            username="alice",
        )
        expected_hash = request_hash_b64url(
            purpose="login",
            challenge_id=challenge["challenge_id"],
            challenge=challenge["challenge"],
            installation_id="android-install-success",
            username="alice",
        )

        def fake_decode(self, *, integrity_token: str):
            return {
                "tokenPayloadExternal": {
                    "requestDetails": {
                        "requestPackageName": self.settings.app_proof_android_package_name,
                        "requestHash": expected_hash,
                    },
                    "appIntegrity": {
                        "appRecognitionVerdict": "PLAY_RECOGNIZED",
                        "certificateSha256Digest": [self.settings.app_proof_android_allowed_cert_sha256_list[0]],
                    },
                    "deviceIntegrity": {
                        "deviceRecognitionVerdict": ["MEETS_DEVICE_INTEGRITY"],
                    },
                    "accountDetails": {
                        "appLicensingVerdict": "UNSPECIFIED",
                    },
                }
            }

        monkeypatch.setattr(AppProofService, "_decode_android_integrity_token", fake_decode)
        response = client.post(
            "/auth/app-proof/verify/android",
            json={
                "challenge_id": challenge["challenge_id"],
                "installation_id": "android-install-success",
                "request_hash": expected_hash,
                "integrity_token": "integrity-token-123",
                "app_version": "1.1.0",
                "os_version": "android-15",
            },
        )
        assert response.status_code == 200, response.text
        data = response.json()
        assert data["installation_status"] == "trusted"
        installation = get_app_installation("android-install-success")
        assert installation is not None
        assert installation["platform"] == "android"
        assert installation["status"] == "trusted"


def test_android_attestation_failure(client_factory, monkeypatch):
    with client_factory(env_overrides={"APP_PROOF_MODE": "report_only"}) as client:
        challenge = _issue_challenge(
            client,
            platform="android",
            purpose="login",
            installation_id="android-install-fail",
            username="alice",
        )
        expected_hash = request_hash_b64url(
            purpose="login",
            challenge_id=challenge["challenge_id"],
            challenge=challenge["challenge"],
            installation_id="android-install-fail",
            username="alice",
        )

        def fake_decode(self, *, integrity_token: str):
            return {
                "tokenPayloadExternal": {
                    "requestDetails": {
                        "requestPackageName": "wrong.package",
                        "requestHash": expected_hash,
                    },
                    "appIntegrity": {
                        "appRecognitionVerdict": "UNRECOGNIZED_VERSION",
                        "certificateSha256Digest": [],
                    },
                    "deviceIntegrity": {"deviceRecognitionVerdict": []},
                }
            }

        monkeypatch.setattr(AppProofService, "_decode_android_integrity_token", fake_decode)
        response = client.post(
            "/auth/app-proof/verify/android",
            json={
                "challenge_id": challenge["challenge_id"],
                "installation_id": "android-install-fail",
                "request_hash": expected_hash,
                "integrity_token": "integrity-token-123",
            },
        )
        assert response.status_code == 400
        assert response.json()["detail"] == "Invalid mobile app proof"


def test_ios_attestation_success(client_factory, monkeypatch):
    with client_factory(env_overrides={"APP_PROOF_MODE": "report_only"}) as client:
        challenge = _issue_challenge(
            client,
            platform="ios",
            purpose="enroll",
            installation_id="ios-install-success",
        )

        def fake_verify_ios_attestation(
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
        ):
            return record_ios_app_attest_enrollment(
                installation_id=installation_id,
                key_id=key_id,
                public_key_pem="-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==\n-----END PUBLIC KEY-----\n",
                receipt_b64=receipt,
                app_id=self.settings.app_proof_ios_bundle_id,
                app_version=app_version,
                os_version=os_version,
                client_ip=client_ip,
                provider_status="verified",
                provider_error=None,
                verdict_json=json.dumps({"mode": "attest"}),
            )

        monkeypatch.setattr(AppProofService, "_verify_ios_attestation", fake_verify_ios_attestation)
        response = client.post(
            "/auth/app-proof/verify/ios",
            json={
                "mode": "attest",
                "challenge_id": challenge["challenge_id"],
                "installation_id": "ios-install-success",
                "key_id": "a2V5LWlkLXRlc3Q",
                "attestation_object": "ZHVtbXk",
                "receipt": "cmVjZWlwdA",
                "app_version": "1.0.0",
                "os_version": "ios-18.3",
            },
        )
        assert response.status_code == 200, response.text
        assert response.json()["installation_status"] == "trusted"
        installation = get_app_installation("ios-install-success")
        assert installation is not None
        assert installation["platform"] == "ios"


def test_ios_attestation_failure(client_factory, monkeypatch):
    with client_factory(env_overrides={"APP_PROOF_MODE": "report_only"}) as client:
        challenge = _issue_challenge(
            client,
            platform="ios",
            purpose="enroll",
            installation_id="ios-install-fail",
        )

        def fake_verify_ios_attestation(self, **kwargs):
            raise AppProofError(
                status_code=400,
                detail="Invalid mobile app proof",
                reason="invalid_proof",
            )

        monkeypatch.setattr(AppProofService, "_verify_ios_attestation", fake_verify_ios_attestation)
        response = client.post(
            "/auth/app-proof/verify/ios",
            json={
                "mode": "attest",
                "challenge_id": challenge["challenge_id"],
                "installation_id": "ios-install-fail",
                "key_id": "a2V5LWlkLXRlc3Q",
                "attestation_object": "ZHVtbXk",
            },
        )
        assert response.status_code == 400
        assert response.json()["detail"] == "Invalid mobile app proof"


def test_login_allowed_in_disabled_mode(client):
    _create_user()
    response = client.post("/auth/login", json={"username": "alice", "password": "password123456"})
    assert response.status_code == 200, response.text


def test_login_allowed_and_logged_in_report_only(client_factory):
    with client_factory(env_overrides={"APP_PROOF_MODE": "report_only"}) as client:
        _create_user()
        response = client.post("/auth/login", json={"username": "alice", "password": "password123456"})
        assert response.status_code == 200, response.text
        assert get_counters()["app_proof.session_issued_without_proof"] == 1
        assert get_counters()["app_proof.report_only_missing_proof"] == 1

        admin_h = auth_headers(login(client, "admin", "adminpass123456"))
        security_status = client.get("/admin/security-status", headers=admin_h)
        assert security_status.status_code == 200, security_status.text
        payload = security_status.json()
        assert payload["app_proof_mode"] == "report_only"
        assert any(item["name"] == "app_proof.report_only_missing_proof" and item["value"] == 1 for item in payload["security_counters"])
        assert {item["code"] for item in payload["warnings"]} >= {
            "app_proof_report_only",
            "admin_bearer_login_app_proof_deferred",
        }
        assert {item["code"] for item in payload["deferrals"]} >= {
            "all_request_proof_of_possession_deferred",
            "mtls_deferred",
            "devicecheck_not_enforcement",
        }
        assert "test-secret-value-1234-abcdef-5678" not in security_status.text
        assert "integrity-token-123" not in security_status.text


def test_login_blocked_in_enforce_login_without_valid_proof(client_factory):
    with client_factory(env_overrides={"APP_PROOF_MODE": "enforce_login"}) as client:
        _create_user()
        response = client.post("/auth/login", json={"username": "alice", "password": "password123456"})
        assert response.status_code == 403
        assert response.json()["detail"] == "Valid mobile app proof is required"
        assert get_counters()["app_proof.enforce_login.blocked"] == 1

        admin_h = auth_headers(login(client, "admin", "adminpass123456"))
        security_status = client.get("/admin/security-status", headers=admin_h)
        assert security_status.status_code == 200, security_status.text
        categories = {item["category"]: item["count"] for item in security_status.json()["recent_app_proof_failures"]}
        assert categories["missing_proof_enforce_login"] == 1


def test_login_succeeds_in_enforce_login_with_valid_proof(client_factory, monkeypatch):
    with client_factory(env_overrides={"APP_PROOF_MODE": "enforce_login"}) as client:
        user_id = _create_user()
        challenge = _issue_challenge(
            client,
            platform="android",
            purpose="login",
            installation_id="android-login-success",
            username="alice",
        )
        expected_hash = request_hash_b64url(
            purpose="login",
            challenge_id=challenge["challenge_id"],
            challenge=challenge["challenge"],
            installation_id="android-login-success",
            username="alice",
        )

        def fake_decode(self, *, integrity_token: str):
            return {
                "tokenPayloadExternal": {
                    "requestDetails": {
                        "requestPackageName": self.settings.app_proof_android_package_name,
                        "requestHash": expected_hash,
                    },
                    "appIntegrity": {
                        "appRecognitionVerdict": "PLAY_RECOGNIZED",
                        "certificateSha256Digest": [self.settings.app_proof_android_allowed_cert_sha256_list[0]],
                    },
                    "deviceIntegrity": {
                        "deviceRecognitionVerdict": ["MEETS_DEVICE_INTEGRITY"],
                    },
                }
            }

        monkeypatch.setattr(AppProofService, "_decode_android_integrity_token", fake_decode)
        verify_response = client.post(
            "/auth/app-proof/verify/android",
            json={
                "challenge_id": challenge["challenge_id"],
                "installation_id": "android-login-success",
                "request_hash": expected_hash,
                "integrity_token": "integrity-token-123",
            },
        )
        assert verify_response.status_code == 200, verify_response.text
        proof_ticket = verify_response.json()["proof_ticket"]

        login_response = client.post(
            "/auth/login",
            json={
                "username": "alice",
                "password": "password123456",
                "installation_id": "android-login-success",
                "proof_ticket": proof_ticket,
            },
        )
        assert login_response.status_code == 200, login_response.text
        token_payload = decode_token(login_response.json()["token"])
        assert token_payload["aid"] == "android-login-success"
        assert token_payload["apm"] == "android_play_integrity"
        assert token_payload["asv"] == 1
        installation = get_app_installation("android-login-success")
        assert installation["user_id"] == user_id
        assert installation["last_login_at"] is not None


def test_installation_session_binding_required_on_authenticated_requests(client_factory, monkeypatch):
    with client_factory(env_overrides={"APP_PROOF_MODE": "enforce_login"}) as client:
        user_id = _create_user()
        create_host(
            name="Office Mac",
            mac="AA:BB:CC:DD:EE:FF",
            group_name=None,
            broadcast=None,
            subnet_cidr=None,
            udp_port=9,
            interface=None,
            source_ip=None,
            host_id="office-mac",
        )
        create_device_membership(user_id=user_id, device_id="office-mac")
        challenge = _issue_challenge(
            client,
            platform="android",
            purpose="login",
            installation_id="android-bound-session",
            username="alice",
        )
        expected_hash = request_hash_b64url(
            purpose="login",
            challenge_id=challenge["challenge_id"],
            challenge=challenge["challenge"],
            installation_id="android-bound-session",
            username="alice",
        )

        def fake_decode(self, *, integrity_token: str):
            return {
                "tokenPayloadExternal": {
                    "requestDetails": {
                        "requestPackageName": self.settings.app_proof_android_package_name,
                        "requestHash": expected_hash,
                    },
                    "appIntegrity": {
                        "appRecognitionVerdict": "PLAY_RECOGNIZED",
                        "certificateSha256Digest": [self.settings.app_proof_android_allowed_cert_sha256_list[0]],
                    },
                    "deviceIntegrity": {
                        "deviceRecognitionVerdict": ["MEETS_DEVICE_INTEGRITY"],
                    },
                }
            }

        monkeypatch.setattr(AppProofService, "_decode_android_integrity_token", fake_decode)
        verify_response = client.post(
            "/auth/app-proof/verify/android",
            json={
                "challenge_id": challenge["challenge_id"],
                "installation_id": "android-bound-session",
                "request_hash": expected_hash,
                "integrity_token": "integrity-token-123",
            },
        )
        proof_ticket = verify_response.json()["proof_ticket"]
        login_response = client.post(
            "/auth/login",
            json={
                "username": "alice",
                "password": "password123456",
                "installation_id": "android-bound-session",
                "proof_ticket": proof_ticket,
            },
        )
        token = login_response.json()["token"]

        without_header = client.get("/me/devices", headers=auth_headers(token))
        assert without_header.status_code == 401

        with_header = client.get(
            "/me/devices",
            headers={**auth_headers(token), "x-wff-installation-id": "android-bound-session"},
        )
        assert with_header.status_code == 200, with_header.text


def test_revoked_installation_cannot_log_in_under_enforcement(client_factory, monkeypatch):
    with client_factory(env_overrides={"APP_PROOF_MODE": "enforce_login"}) as client:
        _create_user()
        challenge = _issue_challenge(
            client,
            platform="android",
            purpose="login",
            installation_id="android-revoked",
            username="alice",
        )
        expected_hash = request_hash_b64url(
            purpose="login",
            challenge_id=challenge["challenge_id"],
            challenge=challenge["challenge"],
            installation_id="android-revoked",
            username="alice",
        )

        def fake_decode(self, *, integrity_token: str):
            return {
                "tokenPayloadExternal": {
                    "requestDetails": {
                        "requestPackageName": self.settings.app_proof_android_package_name,
                        "requestHash": expected_hash,
                    },
                    "appIntegrity": {
                        "appRecognitionVerdict": "PLAY_RECOGNIZED",
                        "certificateSha256Digest": [self.settings.app_proof_android_allowed_cert_sha256_list[0]],
                    },
                    "deviceIntegrity": {
                        "deviceRecognitionVerdict": ["MEETS_DEVICE_INTEGRITY"],
                    },
                }
            }

        monkeypatch.setattr(AppProofService, "_decode_android_integrity_token", fake_decode)
        verify_response = client.post(
            "/auth/app-proof/verify/android",
            json={
                "challenge_id": challenge["challenge_id"],
                "installation_id": "android-revoked",
                "request_hash": expected_hash,
                "integrity_token": "integrity-token-123",
            },
        )
        assert verify_response.status_code == 200, verify_response.text
        revoke_app_installation("android-revoked", reason="operator-test")
        login_response = client.post(
            "/auth/login",
            json={
                "username": "alice",
                "password": "password123456",
                "installation_id": "android-revoked",
                "proof_ticket": verify_response.json()["proof_ticket"],
            },
        )
        assert login_response.status_code == 401
        assert login_response.json()["detail"] == "Invalid mobile app proof"


def test_replayed_or_mismatched_challenge_fails(client_factory, monkeypatch):
    with client_factory(env_overrides={"APP_PROOF_MODE": "report_only"}) as client:
        challenge = _issue_challenge(
            client,
            platform="android",
            purpose="login",
            installation_id="android-replay",
            username="alice",
        )
        expected_hash = request_hash_b64url(
            purpose="login",
            challenge_id=challenge["challenge_id"],
            challenge=challenge["challenge"],
            installation_id="android-replay",
            username="alice",
        )

        def fake_decode(self, *, integrity_token: str):
            return {
                "tokenPayloadExternal": {
                    "requestDetails": {
                        "requestPackageName": self.settings.app_proof_android_package_name,
                        "requestHash": expected_hash,
                    },
                    "appIntegrity": {
                        "appRecognitionVerdict": "PLAY_RECOGNIZED",
                        "certificateSha256Digest": [self.settings.app_proof_android_allowed_cert_sha256_list[0]],
                    },
                    "deviceIntegrity": {
                        "deviceRecognitionVerdict": ["MEETS_DEVICE_INTEGRITY"],
                    },
                }
            }

        monkeypatch.setattr(AppProofService, "_decode_android_integrity_token", fake_decode)
        first = client.post(
            "/auth/app-proof/verify/android",
            json={
                "challenge_id": challenge["challenge_id"],
                "installation_id": "android-replay",
                "request_hash": expected_hash,
                "integrity_token": "integrity-token-123",
            },
        )
        assert first.status_code == 200, first.text

        replay = client.post(
            "/auth/app-proof/verify/android",
            json={
                "challenge_id": challenge["challenge_id"],
                "installation_id": "android-replay",
                "request_hash": expected_hash,
                "integrity_token": "integrity-token-123",
            },
        )
        assert replay.status_code == 400
        assert replay.json()["detail"] == "Invalid mobile app proof"


def test_admin_installation_listing_is_protected_and_filterable(client_factory, monkeypatch):
    with client_factory(env_overrides={"APP_PROOF_MODE": "report_only"}) as client:
        _create_user()
        challenge = _issue_challenge(
            client,
            platform="android",
            purpose="login",
            installation_id="android-admin-listing",
            username="alice",
        )
        expected_hash = request_hash_b64url(
            purpose="login",
            challenge_id=challenge["challenge_id"],
            challenge=challenge["challenge"],
            installation_id="android-admin-listing",
            username="alice",
        )

        def fake_decode(self, *, integrity_token: str):
            return {
                "tokenPayloadExternal": {
                    "requestDetails": {
                        "requestPackageName": self.settings.app_proof_android_package_name,
                        "requestHash": expected_hash,
                    },
                    "appIntegrity": {
                        "appRecognitionVerdict": "PLAY_RECOGNIZED",
                        "certificateSha256Digest": [self.settings.app_proof_android_allowed_cert_sha256_list[0]],
                    },
                    "deviceIntegrity": {
                        "deviceRecognitionVerdict": ["MEETS_DEVICE_INTEGRITY"],
                    },
                }
            }

        monkeypatch.setattr(AppProofService, "_decode_android_integrity_token", fake_decode)
        verify_response = client.post(
            "/auth/app-proof/verify/android",
            json={
                "challenge_id": challenge["challenge_id"],
                "installation_id": "android-admin-listing",
                "request_hash": expected_hash,
                "integrity_token": "integrity-token-123",
                "app_version": "1.2.3",
                "os_version": "android-15",
            },
        )
        assert verify_response.status_code == 200, verify_response.text

        user_h = auth_headers(login(client, "alice", "password123456"))
        forbidden = client.get("/admin/app-installations", headers=user_h)
        assert forbidden.status_code == 403

        admin_h = auth_headers(login(client, "admin", "adminpass123456"))
        listing = client.get(
            "/admin/app-installations?platform=android&status=trusted&limit=1",
            headers=admin_h,
        )
        assert listing.status_code == 200, listing.text
        payload = listing.json()
        assert len(payload) == 1
        assert payload[0]["installation_id"] == "android-admin-listing"
        assert payload[0]["platform"] == "android"
        assert payload[0]["status"] == "trusted"
        assert payload[0]["last_failure_reason"] is None
        assert "integrity-token-123" not in listing.text


def test_browser_admin_ui_flow_still_works(client):
    response = admin_ui_login(client, follow_redirects=False)
    assert response.status_code == 303
