from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.db import record_scheduled_wake_run

from .conftest import auth_headers, create_device_membership, login

DAY_NAMES = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")


def _create_device(client, admin_headers: dict[str, str], *, name: str = "NAS") -> str:
    response = client.post(
        "/admin/devices",
        headers=admin_headers,
        json={
            "name": name,
            "display_name": f"{name} Display",
            "mac": "AA:BB:CC:DD:EE:FF",
            "broadcast": "192.168.1.255",
            "source_ip": "192.168.1.2",
            "udp_port": 9,
            "check_method": "tcp",
            "check_target": "192.168.1.10",
            "check_port": 22,
        },
    )
    assert response.status_code == 201, response.text
    return response.json()["id"]


def _future_schedule_payload(device_id: str, *, label: str = "Weekday boot") -> dict[str, object]:
    now = datetime.now(UTC) + timedelta(minutes=5)
    return {
        "device_id": device_id,
        "label": label,
        "enabled": True,
        "timezone": "UTC",
        "days_of_week": [DAY_NAMES[now.weekday()]],
        "local_time": now.strftime("%H:%M"),
    }


def test_create_and_list_scheduled_wake_jobs(client):
    admin_token = login(client, "admin", "adminpass123456")
    admin_headers = auth_headers(admin_token)
    device_id = _create_device(client, admin_headers)

    create_response = client.post(
        "/admin/scheduled-wakes",
        headers=admin_headers,
        json=_future_schedule_payload(device_id),
    )
    assert create_response.status_code == 201, create_response.text
    created = create_response.json()
    assert created["device_id"] == device_id
    assert created["device_name"] == "NAS"
    assert created["enabled"] is True
    assert created["days_of_week"]
    assert created["next_run_at"] is not None
    assert created["last_run_at"] is None

    list_response = client.get("/admin/scheduled-wakes", headers=admin_headers)
    assert list_response.status_code == 200, list_response.text
    jobs = list_response.json()
    assert any(job["id"] == created["id"] and job["label"] == "Weekday boot" for job in jobs)


def test_update_and_delete_scheduled_wake_job(client):
    admin_token = login(client, "admin", "adminpass123456")
    admin_headers = auth_headers(admin_token)
    device_id = _create_device(client, admin_headers)

    create_response = client.post(
        "/admin/scheduled-wakes",
        headers=admin_headers,
        json=_future_schedule_payload(device_id, label="Morning"),
    )
    assert create_response.status_code == 201, create_response.text
    job_id = create_response.json()["id"]

    update_response = client.patch(
        f"/admin/scheduled-wakes/{job_id}",
        headers=admin_headers,
        json={"label": "Paused morning", "enabled": False},
    )
    assert update_response.status_code == 200, update_response.text
    updated = update_response.json()
    assert updated["label"] == "Paused morning"
    assert updated["enabled"] is False
    assert updated["next_run_at"] is None

    delete_response = client.delete(f"/admin/scheduled-wakes/{job_id}", headers=admin_headers)
    assert delete_response.status_code == 200, delete_response.text
    assert delete_response.json() == {"ok": True}

    list_response = client.get("/admin/scheduled-wakes", headers=admin_headers)
    assert list_response.status_code == 200, list_response.text
    assert all(job["id"] != job_id for job in list_response.json())


def test_reject_invalid_scheduled_wake_payloads(client):
    admin_token = login(client, "admin", "adminpass123456")
    admin_headers = auth_headers(admin_token)
    device_id = _create_device(client, admin_headers)
    base_payload = _future_schedule_payload(device_id)

    invalid_timezone = client.post(
        "/admin/scheduled-wakes",
        headers=admin_headers,
        json={**base_payload, "timezone": "Mars/Olympus"},
    )
    assert invalid_timezone.status_code == 400
    assert invalid_timezone.json()["detail"] == "Invalid timezone"

    invalid_day = client.post(
        "/admin/scheduled-wakes",
        headers=admin_headers,
        json={**base_payload, "days_of_week": ["funday"]},
    )
    assert invalid_day.status_code == 400
    assert "days_of_week" in invalid_day.json()["detail"]

    invalid_time = client.post(
        "/admin/scheduled-wakes",
        headers=admin_headers,
        json={**base_payload, "local_time": "25:61"},
    )
    assert invalid_time.status_code == 400
    assert invalid_time.json()["detail"] == "local_time must use HH:MM"


def test_reject_unknown_device_id_for_scheduled_wakes(client):
    admin_token = login(client, "admin", "adminpass123456")
    admin_headers = auth_headers(admin_token)
    device_id = _create_device(client, admin_headers)

    create_response = client.post(
        "/admin/scheduled-wakes",
        headers=admin_headers,
        json=_future_schedule_payload("missing-device"),
    )
    assert create_response.status_code == 404
    assert create_response.json()["detail"] == "Device not found"

    existing_job = client.post(
        "/admin/scheduled-wakes",
        headers=admin_headers,
        json=_future_schedule_payload(device_id),
    )
    assert existing_job.status_code == 201, existing_job.text
    job_id = existing_job.json()["id"]

    update_response = client.patch(
        f"/admin/scheduled-wakes/{job_id}",
        headers=admin_headers,
        json={"device_id": "missing-device"},
    )
    assert update_response.status_code == 404
    assert update_response.json()["detail"] == "Device not found"


def test_list_scheduled_wake_run_history(client):
    admin_token = login(client, "admin", "adminpass123456")
    admin_headers = auth_headers(admin_token)
    device_id = _create_device(client, admin_headers)

    job_response = client.post(
        "/admin/scheduled-wakes",
        headers=admin_headers,
        json=_future_schedule_payload(device_id),
    )
    assert job_response.status_code == 201, job_response.text
    job_id = job_response.json()["id"]

    started_at = datetime.now(UTC)
    record_scheduled_wake_run(
        job_id=job_id,
        device_id=device_id,
        started_at=started_at.isoformat(),
        finished_at=(started_at + timedelta(seconds=2)).isoformat(),
        result="sent",
        detail="magic_packet_sent",
        wake_log_id=123,
    )

    history_response = client.get("/admin/scheduled-wakes/runs", headers=admin_headers)
    assert history_response.status_code == 200, history_response.text
    runs = history_response.json()
    assert any(run["job_id"] == job_id and run["result"] == "sent" and run["wake_log_id"] == 123 for run in runs)

    filtered_response = client.get(
        f"/admin/scheduled-wakes/runs?job_id={job_id}",
        headers=admin_headers,
    )
    assert filtered_response.status_code == 200, filtered_response.text
    filtered_runs = filtered_response.json()
    assert filtered_runs
    assert all(run["job_id"] == job_id for run in filtered_runs)


def test_me_devices_includes_scheduled_wake_summary(client):
    admin_token = login(client, "admin", "adminpass123456")
    admin_headers = auth_headers(admin_token)
    device_id = _create_device(client, admin_headers, name="Media")

    create_user_response = client.post(
        "/admin/users",
        headers=admin_headers,
        json={"username": "schedule-user", "password": "scheduleuser123", "role": "user"},
    )
    assert create_user_response.status_code == 201, create_user_response.text
    user_id = create_user_response.json()["id"]
    create_device_membership(client, admin_headers, user_id=user_id, device_id=device_id)

    enabled_response = client.post(
        "/admin/scheduled-wakes",
        headers=admin_headers,
        json=_future_schedule_payload(device_id, label="Enabled Wake"),
    )
    assert enabled_response.status_code == 201, enabled_response.text
    enabled_job = enabled_response.json()

    disabled_response = client.post(
        "/admin/scheduled-wakes",
        headers=admin_headers,
        json={**_future_schedule_payload(device_id, label="Disabled Wake"), "enabled": False},
    )
    assert disabled_response.status_code == 201, disabled_response.text

    user_token = login(client, "schedule-user", "scheduleuser123")
    me_devices = client.get("/me/devices", headers=auth_headers(user_token))
    assert me_devices.status_code == 200, me_devices.text
    payload = me_devices.json()
    device = next(row for row in payload if row["id"] == device_id)
    summary = device["scheduled_wake_summary"]
    assert summary == {
        "total_count": 2,
        "enabled_count": 1,
        "next_run_at": enabled_job["next_run_at"],
    }
