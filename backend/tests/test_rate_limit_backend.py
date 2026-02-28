from __future__ import annotations

from app.rate_limit import InMemoryRateLimiter


def test_in_memory_check_and_record_blocks_after_limit() -> None:
    limiter = InMemoryRateLimiter()
    scope = "wake"
    key = "user@example"

    assert limiter.check_and_record(scope, key, limit=2, window_seconds=60) is False
    assert limiter.check_and_record(scope, key, limit=2, window_seconds=60) is False
    assert limiter.check_and_record(scope, key, limit=2, window_seconds=60) is True


def test_in_memory_failed_login_pattern() -> None:
    limiter = InMemoryRateLimiter()
    scope = "login"
    key = "100.64.0.1"

    assert limiter.is_limited(scope, key, limit=1, window_seconds=60) is False
    limiter.record_attempt(scope, key, window_seconds=60)
    assert limiter.is_limited(scope, key, limit=1, window_seconds=60) is True
