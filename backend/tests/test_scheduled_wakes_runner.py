from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.db import claim_scheduled_wake_job, get_scheduled_wake_job, update_scheduled_wake_job
from app.main import run_scheduled_wake_runner_cycle
from app.power import PowerCheckResult

from .conftest import auth_headers, login

DAY_NAMES = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")


def _create_device(client, admin_headers: dict[str, str], *, name: str = "Workstation") -> str:
    response = client.post(
        "/admin/devices",
        headers=admin_headers,
        json={
            "name": name,
            "display_name": f"{name} Display",
            "mac": "10:20:30:40:50:60",
            "broadcast": "10.0.0.255",
            "source_ip": "10.0.0.2",
            "udp_port": 9,
            "check_method": "tcp",
            "check_target": "10.0.0.10",
            "check_port": 3389,
        },
    )
    assert response.status_code == 201, response.text
    return response.json()["id"]


def _create_job(client, admin_headers: dict[str, str], device_id: str, *, enabled: bool = True) -> str:
    future = datetime.now(UTC) + timedelta(minutes=10)
    response = client.post(
        "/admin/scheduled-wakes",
        headers=admin_headers,
        json={
            "device_id": device_id,
            "label": "Auto boot",
            "enabled": enabled,
            "timezone": "UTC",
            "days_of_week": [DAY_NAMES[future.weekday()]],
            "local_time": future.strftime("%H:%M"),
        },
    )
    assert response.status_code == 201, response.text
    return response.json()["id"]


def _mark_due(job_id: str) -> str:
    due_at = (datetime.now(UTC) - timedelta(minutes=1)).isoformat()
    row = update_scheduled_wake_job(job_id, {"next_run_at": due_at})
    assert row is not None
    return due_at


def test_runner_sends_wake_for_due_offline_device(client, monkeypatch):
    admin_token = login(client, "admin", "adminpass123456")
    admin_headers = auth_headers(admin_token)
    device_id = _create_device(client, admin_headers)
    job_id = _create_job(client, admin_headers, device_id)
    _mark_due(job_id)

    monkeypatch.setattr(
        "app.main.run_power_check",
        lambda *_args, **_kwargs: PowerCheckResult(method="tcp", result="off", detail="timeout", latency_ms=45),
    )
    sent_calls: list[tuple[str, str, int, str | None, str | None]] = []

    def fake_send_magic_packet(
        mac: str,
        target_ip: str,
        udp_port: int = 9,
        interface: str | None = None,
        source_ip: str | None = None,
    ) -> None:
        sent_calls.append((mac, target_ip, udp_port, interface, source_ip))

    monkeypatch.setattr("app.main.send_magic_packet", fake_send_magic_packet)

    processed = run_scheduled_wake_runner_cycle()
    assert processed == 1
    assert len(sent_calls) == 1

    runs_response = client.get("/admin/scheduled-wakes/runs", headers=admin_headers)
    assert runs_response.status_code == 200, runs_response.text
    run = runs_response.json()[0]
    assert run["job_id"] == job_id
    assert run["result"] == "sent"
    assert run["detail"] == "magic_packet_sent"

    jobs_response = client.get("/admin/scheduled-wakes", headers=admin_headers)
    assert jobs_response.status_code == 200, jobs_response.text
    job = next(item for item in jobs_response.json() if item["id"] == job_id)
    assert job["last_run_at"] is not None
    assert job["next_run_at"] is not None
    assert job["next_run_at"] > job["last_run_at"]


def test_runner_records_already_on_without_sending_packet(client, monkeypatch):
    admin_token = login(client, "admin", "adminpass123456")
    admin_headers = auth_headers(admin_token)
    device_id = _create_device(client, admin_headers)
    job_id = _create_job(client, admin_headers, device_id)
    _mark_due(job_id)

    monkeypatch.setattr(
        "app.main.run_power_check",
        lambda *_args, **_kwargs: PowerCheckResult(method="tcp", result="on", detail="connected", latency_ms=3),
    )

    def fail_if_send_called(*_args, **_kwargs):
        raise AssertionError("send_magic_packet must not run when the device is already on")

    monkeypatch.setattr("app.main.send_magic_packet", fail_if_send_called)

    processed = run_scheduled_wake_runner_cycle()
    assert processed == 1

    runs_response = client.get("/admin/scheduled-wakes/runs", headers=admin_headers)
    assert runs_response.status_code == 200, runs_response.text
    assert runs_response.json()[0]["result"] == "already_on"
    assert runs_response.json()[0]["detail"] == "device_already_on"


def test_runner_records_failed_when_wake_send_fails(client, monkeypatch):
    admin_token = login(client, "admin", "adminpass123456")
    admin_headers = auth_headers(admin_token)
    device_id = _create_device(client, admin_headers)
    job_id = _create_job(client, admin_headers, device_id)
    _mark_due(job_id)

    monkeypatch.setattr(
        "app.main.run_power_check",
        lambda *_args, **_kwargs: PowerCheckResult(method="tcp", result="unknown", detail="dns_resolution_failed", latency_ms=None),
    )

    def failing_send_magic_packet(*_args, **_kwargs):
        raise OSError("simulated send failure")

    monkeypatch.setattr("app.main.send_magic_packet", failing_send_magic_packet)

    processed = run_scheduled_wake_runner_cycle()
    assert processed == 1

    runs_response = client.get("/admin/scheduled-wakes/runs", headers=admin_headers)
    assert runs_response.status_code == 200, runs_response.text
    run = runs_response.json()[0]
    assert run["job_id"] == job_id
    assert run["result"] == "failed"
    assert run["detail"] == "simulated send failure"


def test_runner_does_not_execute_disabled_jobs(client, monkeypatch):
    admin_token = login(client, "admin", "adminpass123456")
    admin_headers = auth_headers(admin_token)
    device_id = _create_device(client, admin_headers)
    job_id = _create_job(client, admin_headers, device_id, enabled=False)
    update_scheduled_wake_job(job_id, {"next_run_at": (datetime.now(UTC) - timedelta(minutes=1)).isoformat()})

    monkeypatch.setattr(
        "app.main.run_power_check",
        lambda *_args, **_kwargs: PowerCheckResult(method="tcp", result="off", detail="timeout", latency_ms=45),
    )
    monkeypatch.setattr("app.main.send_magic_packet", lambda *_args, **_kwargs: None)

    processed = run_scheduled_wake_runner_cycle()
    assert processed == 0

    runs_response = client.get("/admin/scheduled-wakes/runs", headers=admin_headers)
    assert runs_response.status_code == 200, runs_response.text
    assert runs_response.json() == []


def test_claim_scheduled_wake_job_is_single_winner(client):
    admin_token = login(client, "admin", "adminpass123456")
    admin_headers = auth_headers(admin_token)
    device_id = _create_device(client, admin_headers)
    job_id = _create_job(client, admin_headers, device_id)
    due_at = _mark_due(job_id)

    first_claim = claim_scheduled_wake_job(
        job_id=job_id,
        expected_next_run_at=due_at,
        claimed_next_run_at=(datetime.now(UTC) + timedelta(days=1)).isoformat(),
        claimed_at=datetime.now(UTC).isoformat(),
    )
    second_claim = claim_scheduled_wake_job(
        job_id=job_id,
        expected_next_run_at=due_at,
        claimed_next_run_at=(datetime.now(UTC) + timedelta(days=2)).isoformat(),
        claimed_at=datetime.now(UTC).isoformat(),
    )

    assert first_claim is not None
    assert second_claim is None


def test_runner_skips_missing_device_jobs(client):
    admin_token = login(client, "admin", "adminpass123456")
    admin_headers = auth_headers(admin_token)
    device_id = _create_device(client, admin_headers)
    job_id = _create_job(client, admin_headers, device_id)
    _mark_due(job_id)

    delete_response = client.delete(f"/admin/devices/{device_id}", headers=admin_headers)
    assert delete_response.status_code == 200, delete_response.text

    processed = run_scheduled_wake_runner_cycle()
    assert processed == 1

    runs_response = client.get("/admin/scheduled-wakes/runs", headers=admin_headers)
    assert runs_response.status_code == 200, runs_response.text
    run = runs_response.json()[0]
    assert run["job_id"] == job_id
    assert run["result"] == "skipped"
    assert run["detail"] == "scheduled device not found"

    job = get_scheduled_wake_job(job_id)
    assert job is not None
    assert job["last_run_at"] is not None
