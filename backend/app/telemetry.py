from __future__ import annotations

import json
import logging
from collections import Counter
from collections import deque
from datetime import UTC, datetime
from threading import Lock
from typing import Any

_LOG = logging.getLogger("wakefromfar")
_COUNTERS = Counter()
_RECENT_EVENTS = deque(maxlen=512)
_LOCK = Lock()


def _ensure_logger() -> None:
    if _LOG.handlers:
        return
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(message)s"))
    _LOG.addHandler(handler)
    _LOG.setLevel(logging.INFO)
    _LOG.propagate = False


def structured_log(event: str, **fields: Any) -> None:
    _ensure_logger()
    payload = {
        "ts": datetime.now(UTC).isoformat(),
        "event": event,
        **fields,
    }
    with _LOCK:
        _RECENT_EVENTS.append(dict(payload))
    _LOG.info(json.dumps(payload, separators=(",", ":"), default=str))


def increment_counter(name: str, amount: int = 1) -> int:
    with _LOCK:
        _COUNTERS[name] += amount
        return _COUNTERS[name]


def get_counters() -> dict[str, int]:
    with _LOCK:
        return dict(_COUNTERS)


def get_recent_events(*, limit: int = 100, event_prefix: str | None = None) -> list[dict[str, Any]]:
    with _LOCK:
        items = list(_RECENT_EVENTS)
    if event_prefix:
        items = [item for item in items if str(item.get("event") or "").startswith(event_prefix)]
    if limit <= 0:
        return []
    return items[-limit:]


def reset_counters() -> None:
    with _LOCK:
        _COUNTERS.clear()
        _RECENT_EVENTS.clear()
