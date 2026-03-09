from __future__ import annotations

import re

from app.power import PowerCheckResult

from .conftest import admin_ui_login, admin_ui_post, auth_headers, login


def test_discovery_api_run_validate_and_import(client, monkeypatch):
    admin_token = login(client, "admin", "adminpass123456")
    admin_h = auth_headers(admin_token)
    existing_res = client.post(
        "/admin/devices",
        headers=admin_h,
        json={
            "name": "Existing-NAS",
            "mac": "aa:bb:cc:dd:ee:ff",
            "broadcast": "192.168.1.255",
            "source_ip": "192.168.1.2",
            "check_method": "tcp",
            "check_target": "192.168.1.50",
            "check_port": 22,
        },
    )
    assert existing_res.status_code == 201, existing_res.text
    existing_id = existing_res.json()["id"]

    monkeypatch.setattr(
        "app.main.discover_sender_bindings",
        lambda: [
            {
                "network_cidr": "192.168.1.0/24",
                "source_ip": "192.168.1.2",
                "interface": "eth0",
                "broadcast_ip": "192.168.1.255",
            }
        ],
    )
    monkeypatch.setattr(
        "app.main.collect_discovery_candidates",
        lambda **_kwargs: (
            [
                {
                    "hostname": "nas.local",
                    "mac": "aabbccddeeff",
                    "ip": "192.168.1.50",
                    "source_interface": "eth0",
                    "source_ip": "192.168.1.2",
                    "source_network_cidr": "192.168.1.0/24",
                    "broadcast_ip": "192.168.1.255",
                    "wol_confidence": "high",
                    "power_check_method": "tcp",
                    "power_check_target": "192.168.1.50",
                    "power_check_port": 22,
                    "power_data_source": "inferred",
                    "notes_json": {"seen_via": "test"},
                },
                {
                    "hostname": "pc.local",
                    "mac": "001122334455",
                    "ip": "192.168.1.60",
                    "source_interface": "eth0",
                    "source_ip": "192.168.1.2",
                    "source_network_cidr": "192.168.1.0/24",
                    "broadcast_ip": "192.168.1.255",
                    "wol_confidence": "high",
                    "power_check_method": "tcp",
                    "power_check_target": "192.168.1.60",
                    "power_check_port": 3389,
                    "power_data_source": "inferred",
                    "notes_json": {"seen_via": "test"},
                }
            ],
            [],
        ),
    )

    run_res = client.post("/admin/discovery/runs", headers=admin_h, json={})
    assert run_res.status_code == 202, run_res.text
    run_id = run_res.json()["id"]

    runs_res = client.get("/admin/discovery/runs", headers=admin_h)
    assert runs_res.status_code == 200, runs_res.text
    assert any(row["id"] == run_id for row in runs_res.json())

    candidates_res = client.get(f"/admin/discovery/runs/{run_id}/candidates", headers=admin_h)
    assert candidates_res.status_code == 200, candidates_res.text
    assert len(candidates_res.json()) == 2
    by_mac = {row["mac"]: row for row in candidates_res.json()}
    assert by_mac["aabbccddeeff"]["suggested_host_id"] == existing_id
    candidate_id = by_mac["aabbccddeeff"]["id"]

    monkeypatch.setattr("app.main.send_magic_packet", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        "app.main.run_power_check",
        lambda *_args, **_kwargs: PowerCheckResult(method="tcp", result="on", detail="connected", latency_ms=7),
    )
    validate_res = client.post(f"/admin/discovery/candidates/{candidate_id}/validate-wake", headers=admin_h)
    assert validate_res.status_code == 200, validate_res.text
    assert validate_res.json()["result"] == "validated"

    bulk_res = client.post(
        f"/admin/discovery/runs/{run_id}/import-bulk",
        headers=admin_h,
        json={"mode": "auto_merge_by_mac", "apply_power_settings": True},
    )
    assert bulk_res.status_code == 200, bulk_res.text
    assert bulk_res.json()["imported"] == 2
    assert bulk_res.json()["merged"] == 1
    assert bulk_res.json()["created"] == 1
    assert bulk_res.json()["failed"] == 0

    devices_res = client.get("/admin/devices", headers=admin_h)
    assert devices_res.status_code == 200
    rows = devices_res.json()
    merged_host = [row for row in rows if row["id"] == existing_id][0]
    assert merged_host["provisioning_source"] == "discovery"
    assert merged_host["source_network_cidr"] == "192.168.1.0/24"
    created_host = [row for row in rows if row["mac"] == "001122334455"]
    assert created_host
    assert created_host[0]["name"] == "pc.local"


def test_admin_ui_discovery_page_and_actions(client, monkeypatch):
    login_res = admin_ui_login(client, next_path="/admin/ui/discovery")
    assert login_res.status_code == 303

    monkeypatch.setattr(
        "app.admin_ui.discover_sender_bindings",
        lambda: [
            {
                "network_cidr": "10.0.0.0/24",
                "source_ip": "10.0.0.2",
                "interface": "eth0",
                "broadcast_ip": "10.0.0.255",
            }
        ],
    )
    admin_token = login(client, "admin", "adminpass123456")
    admin_h = auth_headers(admin_token)
    existing_res = client.post(
        "/admin/devices",
        headers=admin_h,
        json={
            "name": "Known-Box",
            "mac": "00:11:22:33:44:55",
            "broadcast": "10.0.0.255",
            "source_ip": "10.0.0.2",
            "check_method": "tcp",
            "check_target": "10.0.0.10",
            "check_port": 3389,
        },
    )
    assert existing_res.status_code == 201, existing_res.text

    from app.db import complete_discovery_run, create_discovery_candidate, create_discovery_run

    run_id = create_discovery_run(requested_by="admin", options_json="{}")
    candidate_id = create_discovery_candidate(
        run_id=run_id,
        hostname="ws.local",
        mac="001122334455",
        ip="10.0.0.10",
        source_interface="eth0",
        source_ip="10.0.0.2",
        source_network_cidr="10.0.0.0/24",
        broadcast_ip="10.0.0.255",
        wol_confidence="high",
        power_check_method="tcp",
        power_check_target="10.0.0.10",
        power_check_port=3389,
        power_data_source="inferred",
        notes_json='{"seen_via":"test"}',
    )
    create_discovery_candidate(
        run_id=run_id,
        hostname="fresh.local",
        mac="aabbccddee01",
        ip="10.0.0.20",
        source_interface="eth0",
        source_ip="10.0.0.2",
        source_network_cidr="10.0.0.0/24",
        broadcast_ip="10.0.0.255",
        wol_confidence="high",
        power_check_method="tcp",
        power_check_target="10.0.0.20",
        power_check_port=22,
        power_data_source="inferred",
        notes_json='{"seen_via":"test"}',
    )
    complete_discovery_run(run_id=run_id, summary_json='{"candidate_count":1}')

    page = client.get(f"/admin/ui/discovery?run_id={run_id}")
    assert page.status_code == 200
    assert "Discovery Candidates" in page.text
    assert "ws.local" in page.text
    assert "Merge Suggested" in page.text

    candidate_match = re.search(r"/admin/ui/discovery/candidates/([^/\"]+)/validate-wake", page.text)
    assert candidate_match is not None
    assert candidate_match.group(1) == candidate_id

    monkeypatch.setattr("app.admin_ui.send_magic_packet", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        "app.admin_ui.run_power_check",
        lambda *_args, **_kwargs: PowerCheckResult(method="tcp", result="on", detail="connected", latency_ms=8),
    )

    validate_res = admin_ui_post(
        client,
        f"/admin/ui/discovery/candidates/{candidate_id}/validate-wake",
        form_page_path=f"/admin/ui/discovery?run_id={run_id}",
        follow_redirects=False,
    )
    assert validate_res.status_code == 303

    import_res = admin_ui_post(
        client,
        f"/admin/ui/discovery/candidates/{candidate_id}/import",
        form_page_path=f"/admin/ui/discovery?run_id={run_id}",
        data={"mode": "auto_merge_by_mac", "apply_power_settings": "1"},
        follow_redirects=False,
    )
    assert import_res.status_code == 303

    bulk_res = admin_ui_post(
        client,
        f"/admin/ui/discovery/runs/{run_id}/import-bulk",
        form_page_path=f"/admin/ui/discovery?run_id={run_id}",
        data={"mode": "auto_merge_by_mac", "apply_power_settings": "1", "skip_without_mac": "1"},
        follow_redirects=False,
    )
    assert bulk_res.status_code == 303

    devices_page = client.get("/admin/ui/devices")
    assert devices_page.status_code == 200
    assert "Known-Box" in devices_page.text
    assert "fresh.local" in devices_page.text
