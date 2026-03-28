from __future__ import annotations

from app.security import decode_token


def test_login_issues_non_expiring_token_when_expiry_disabled(client_factory):
    with client_factory(env_overrides={"TOKEN_EXPIRES_SECONDS": "0"}) as client:
        response = client.post("/auth/login", json={"username": "admin", "password": "adminpass123456"})

    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["expires_in"] == 0

    token_payload = decode_token(payload["token"])
    assert token_payload["sub"] == "admin"
    assert "exp" not in token_payload
