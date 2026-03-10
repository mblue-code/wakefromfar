from __future__ import annotations

import secrets
import time
from collections import defaultdict, deque
from threading import Lock
from typing import Protocol

from .config import Settings

try:
    from redis import Redis
except Exception:  # pragma: no cover
    Redis = None


class RateLimiter(Protocol):
    def is_limited(self, scope: str, key: str, limit: int, window_seconds: int = 60) -> bool: ...

    def record_attempt(self, scope: str, key: str, window_seconds: int = 60) -> None: ...

    def check_and_record(self, scope: str, key: str, limit: int, window_seconds: int = 60) -> bool: ...

    def clear(self) -> None: ...


class InMemoryRateLimiter:
    def __init__(self) -> None:
        self._attempts: dict[tuple[str, str], deque[float]] = defaultdict(deque)
        self._lock = Lock()

    def _prune(self, bucket: deque[float], now: float, window_seconds: int) -> None:
        while bucket and (now - bucket[0]) > window_seconds:
            bucket.popleft()

    def is_limited(self, scope: str, key: str, limit: int, window_seconds: int = 60) -> bool:
        now = time.time()
        entry_key = (scope, key)
        with self._lock:
            bucket = self._attempts[entry_key]
            self._prune(bucket, now, window_seconds)
            return len(bucket) >= limit

    def record_attempt(self, scope: str, key: str, window_seconds: int = 60) -> None:
        now = time.time()
        entry_key = (scope, key)
        with self._lock:
            bucket = self._attempts[entry_key]
            self._prune(bucket, now, window_seconds)
            bucket.append(now)

    def check_and_record(self, scope: str, key: str, limit: int, window_seconds: int = 60) -> bool:
        now = time.time()
        entry_key = (scope, key)
        with self._lock:
            bucket = self._attempts[entry_key]
            self._prune(bucket, now, window_seconds)
            if len(bucket) >= limit:
                return True
            bucket.append(now)
            return False

    def clear(self) -> None:
        with self._lock:
            self._attempts.clear()


class RedisRateLimiter:
    def __init__(self, redis_url: str, key_prefix: str = "wff:rl") -> None:
        if Redis is None:  # pragma: no cover
            raise RuntimeError("RATE_LIMIT_BACKEND=redis requires redis package installed")
        self._client = Redis.from_url(redis_url, decode_responses=True)
        self._key_prefix = key_prefix
        self._client.ping()
        self._script_is_limited = self._client.register_script(
            """
            local key = KEYS[1]
            local now_ms = tonumber(ARGV[1])
            local window_ms = tonumber(ARGV[2])
            local limit = tonumber(ARGV[3])

            redis.call("ZREMRANGEBYSCORE", key, 0, now_ms - window_ms)
            local count = redis.call("ZCARD", key)
            redis.call("EXPIRE", key, math.floor(window_ms / 1000) + 5)
            if count >= limit then
              return 1
            end
            return 0
            """
        )
        self._script_record = self._client.register_script(
            """
            local key = KEYS[1]
            local now_ms = tonumber(ARGV[1])
            local window_ms = tonumber(ARGV[2])
            local member = ARGV[3]

            redis.call("ZREMRANGEBYSCORE", key, 0, now_ms - window_ms)
            redis.call("ZADD", key, now_ms, member)
            redis.call("EXPIRE", key, math.floor(window_ms / 1000) + 5)
            return 1
            """
        )
        self._script_check_and_record = self._client.register_script(
            """
            local key = KEYS[1]
            local now_ms = tonumber(ARGV[1])
            local window_ms = tonumber(ARGV[2])
            local limit = tonumber(ARGV[3])
            local member = ARGV[4]

            redis.call("ZREMRANGEBYSCORE", key, 0, now_ms - window_ms)
            local count = redis.call("ZCARD", key)
            if count >= limit then
              redis.call("EXPIRE", key, math.floor(window_ms / 1000) + 5)
              return 1
            end
            redis.call("ZADD", key, now_ms, member)
            redis.call("EXPIRE", key, math.floor(window_ms / 1000) + 5)
            return 0
            """
        )

    def _redis_key(self, scope: str, key: str) -> str:
        return f"{self._key_prefix}:{scope}:{key}"

    def _now_ms(self) -> int:
        return int(time.time() * 1000)

    def _member(self, now_ms: int) -> str:
        return f"{now_ms}:{secrets.token_hex(8)}"

    def is_limited(self, scope: str, key: str, limit: int, window_seconds: int = 60) -> bool:
        now_ms = self._now_ms()
        window_ms = window_seconds * 1000
        redis_key = self._redis_key(scope, key)
        result = self._script_is_limited(keys=[redis_key], args=[now_ms, window_ms, limit])
        return bool(int(result))

    def record_attempt(self, scope: str, key: str, window_seconds: int = 60) -> None:
        now_ms = self._now_ms()
        window_ms = window_seconds * 1000
        redis_key = self._redis_key(scope, key)
        self._script_record(keys=[redis_key], args=[now_ms, window_ms, self._member(now_ms)])

    def check_and_record(self, scope: str, key: str, limit: int, window_seconds: int = 60) -> bool:
        now_ms = self._now_ms()
        window_ms = window_seconds * 1000
        redis_key = self._redis_key(scope, key)
        result = self._script_check_and_record(
            keys=[redis_key],
            args=[now_ms, window_ms, limit, self._member(now_ms)],
        )
        return bool(int(result))

    def clear(self) -> None:
        pattern = f"{self._key_prefix}:*"
        cursor = 0
        while True:
            cursor, keys = self._client.scan(cursor=cursor, match=pattern, count=200)
            if keys:
                self._client.delete(*keys)
            if cursor == 0:
                break


_RATE_LIMITER: RateLimiter | None = None


def configure_rate_limiter(settings: Settings) -> None:
    global _RATE_LIMITER
    backend = settings.rate_limit_backend.strip().lower()
    if backend == "redis":
        _RATE_LIMITER = RedisRateLimiter(settings.rate_limit_redis_url)
        return
    if backend == "memory":
        _RATE_LIMITER = InMemoryRateLimiter()
        return
    raise RuntimeError("Unsupported RATE_LIMIT_BACKEND. Use 'memory' or 'redis'.")


def get_rate_limiter() -> RateLimiter:
    global _RATE_LIMITER
    if _RATE_LIMITER is None:
        _RATE_LIMITER = InMemoryRateLimiter()
    return _RATE_LIMITER


def reset_rate_limiter_for_tests() -> None:
    global _RATE_LIMITER
    if _RATE_LIMITER is not None:
        _RATE_LIMITER.clear()
    _RATE_LIMITER = None
