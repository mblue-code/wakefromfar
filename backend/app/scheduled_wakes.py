from __future__ import annotations

import json
from datetime import UTC, datetime, time, timedelta
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

DAY_ORDER = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
DAY_TO_WEEKDAY = {day: index for index, day in enumerate(DAY_ORDER)}


def normalize_days_of_week(days_of_week: list[str]) -> list[str]:
    normalized: list[str] = []
    seen: set[str] = set()
    for raw_day in days_of_week:
        day = str(raw_day).strip().lower()
        if day not in DAY_TO_WEEKDAY:
            raise ValueError("days_of_week must contain only mon,tue,wed,thu,fri,sat,sun")
        if day not in seen:
            normalized.append(day)
            seen.add(day)
    if not normalized:
        raise ValueError("days_of_week must contain at least one day")
    return sorted(normalized, key=DAY_ORDER.index)


def normalize_local_time(local_time: str) -> str:
    value = str(local_time).strip()
    parts = value.split(":")
    if len(parts) != 2 or any(not part.isdigit() for part in parts):
        raise ValueError("local_time must use HH:MM")
    hour = int(parts[0])
    minute = int(parts[1])
    if not (0 <= hour <= 23 and 0 <= minute <= 59):
        raise ValueError("local_time must use HH:MM")
    return f"{hour:02d}:{minute:02d}"


def validate_timezone_name(timezone_name: str) -> str:
    value = str(timezone_name).strip()
    if not value:
        raise ValueError("timezone is required")
    try:
        ZoneInfo(value)
    except ZoneInfoNotFoundError as exc:
        raise ValueError("Invalid timezone") from exc
    return value


def normalize_schedule_definition(
    *,
    timezone_name: str,
    days_of_week: list[str],
    local_time: str,
) -> tuple[str, list[str], str]:
    return (
        validate_timezone_name(timezone_name),
        normalize_days_of_week(days_of_week),
        normalize_local_time(local_time),
    )


def compute_next_run_at(
    *,
    timezone_name: str,
    days_of_week: list[str],
    local_time: str,
    now_utc: datetime,
) -> datetime:
    normalized_timezone, normalized_days, normalized_time = normalize_schedule_definition(
        timezone_name=timezone_name,
        days_of_week=days_of_week,
        local_time=local_time,
    )
    zone = ZoneInfo(normalized_timezone)
    local_now = now_utc.astimezone(zone)
    hour, minute = [int(part) for part in normalized_time.split(":")]
    allowed_days = {DAY_TO_WEEKDAY[day] for day in normalized_days}

    for offset in range(0, 14):
        candidate_date = local_now.date() + timedelta(days=offset)
        if candidate_date.weekday() not in allowed_days:
            continue
        candidate_local = datetime.combine(candidate_date, time(hour=hour, minute=minute), zone)
        if candidate_local > local_now:
            return candidate_local.astimezone(UTC)
    raise RuntimeError("Could not compute next scheduled wake run")


def compute_next_run_at_iso(
    *,
    timezone_name: str,
    days_of_week: list[str],
    local_time: str,
    now_utc: datetime,
) -> str:
    return compute_next_run_at(
        timezone_name=timezone_name,
        days_of_week=days_of_week,
        local_time=local_time,
        now_utc=now_utc,
    ).isoformat()


def parse_days_of_week_json(days_of_week_json: str) -> list[str]:
    try:
        parsed = json.loads(days_of_week_json)
    except (TypeError, ValueError) as exc:
        raise ValueError("Invalid stored days_of_week_json") from exc
    if not isinstance(parsed, list):
        raise ValueError("Invalid stored days_of_week_json")
    return normalize_days_of_week([str(item) for item in parsed])
