from __future__ import annotations

MIN_USER_PASSWORD_LENGTH = 6
MIN_ADMIN_PASSWORD_LENGTH = 12
MIN_APP_SECRET_LENGTH = 32


def min_password_length_for_role(role: str) -> int:
    return MIN_ADMIN_PASSWORD_LENGTH if role == "admin" else MIN_USER_PASSWORD_LENGTH


def validate_password_for_role(password: str, role: str) -> None:
    required = min_password_length_for_role(role)
    if len(password) < required:
        raise ValueError(f"Password must be at least {required} characters for role '{role}'.")
