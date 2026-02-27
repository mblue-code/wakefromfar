from __future__ import annotations

import hashlib
import html
import secrets
from datetime import UTC, datetime, timedelta
from urllib.parse import quote_plus, urlencode

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from .diagnostics import device_diagnostic_hints
from .db import (
    assign_device_to_user,
    count_admin_users,
    create_host,
    create_invite_token,
    create_user,
    delete_host,
    delete_user,
    get_host_by_id,
    get_user_by_id,
    get_user_by_username,
    list_admin_audit_logs,
    list_assignments,
    list_hosts,
    list_invite_tokens,
    list_power_check_logs,
    list_successful_wakes,
    list_users,
    list_wake_logs,
    log_admin_action,
    log_power_check,
    remove_assignment,
    revoke_invite,
    update_host,
    update_host_power_state,
    update_user_password_by_id,
    update_user_role,
)
from .power import run_power_check
from .security import create_token, decode_token, hash_password, verify_password
from .telemetry import get_counters
from .wol import normalize_mac

router = APIRouter(prefix="/admin/ui", tags=["admin-ui"])


def _esc(value: object | None) -> str:
    if value is None:
        return ""
    return html.escape(str(value))


def _admin_from_cookie(request: Request):
    token = request.cookies.get("admin_session")
    if not token:
        return None
    try:
        payload = decode_token(token)
    except Exception:
        return None
    if payload.get("role") != "admin":
        return None
    username = payload.get("sub", "")
    user = get_user_by_username(username)
    if not user or user["role"] != "admin":
        return None
    return user


def _require_admin_or_redirect(request: Request):
    user = _admin_from_cookie(request)
    if user:
        return user
    next_path = request.url.path
    if request.url.query:
        next_path = f"{next_path}?{request.url.query}"
    return RedirectResponse(f"/admin/ui/login?{urlencode({'next': next_path})}", status_code=303)


def _layout(title: str, body: str, admin_username: str, message: str | None = None, error: str | None = None) -> HTMLResponse:
    notice = ""
    if message:
        notice = f'<div style="padding:10px;border:1px solid #5aa469;background:#edf9ef;margin-bottom:12px;">{_esc(message)}</div>'
    if error:
        notice = f'{notice}<div style="padding:10px;border:1px solid #b74a4a;background:#fdeeee;margin-bottom:12px;">{_esc(error)}</div>'
    nav = """
    <nav style="display:flex;gap:12px;flex-wrap:wrap;margin-bottom:16px;">
      <a href="/admin/ui">Dashboard</a>
      <a href="/admin/ui/users">Users</a>
      <a href="/admin/ui/devices">Devices</a>
      <a href="/admin/ui/assignments">Assignments</a>
      <a href="/admin/ui/invites">Invites</a>
      <a href="/admin/ui/diagnostics">Diagnostics</a>
      <a href="/admin/ui/wake-logs">Wake Logs</a>
      <a href="/admin/ui/power-check-logs">Power Logs</a>
      <a href="/admin/ui/audit-logs">Audit Logs</a>
      <a href="/admin/ui/metrics">Metrics</a>
      <a href="/admin/ui/pilot-metrics">Pilot Metrics</a>
      <a href="/admin/ui/logout">Logout</a>
    </nav>
    """
    page = f"""<!doctype html>
<html><head><meta charset="utf-8"><title>{_esc(title)}</title></head>
<body style="font-family:ui-sans-serif,system-ui,sans-serif;max-width:1200px;margin:20px auto;padding:0 16px;">
  <header style="display:flex;justify-content:space-between;align-items:center;">
    <h1 style="margin:0 0 12px 0;">{_esc(title)}</h1>
    <div>Signed in as <strong>{_esc(admin_username)}</strong></div>
  </header>
  {nav}
  {notice}
  {body}
</body></html>"""
    return HTMLResponse(page)


def _redirect(path: str, message: str | None = None, error: str | None = None) -> RedirectResponse:
    params: dict[str, str] = {}
    if message:
        params["message"] = message
    if error:
        params["error"] = error
    location = path if not params else f"{path}?{urlencode(params)}"
    return RedirectResponse(location, status_code=303)


def _msg(request: Request) -> tuple[str | None, str | None]:
    return request.query_params.get("message"), request.query_params.get("error")


@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request, next: str = "/admin/ui", error: str | None = None):
    user = _admin_from_cookie(request)
    if user:
        return RedirectResponse(next or "/admin/ui", status_code=303)
    page = f"""<!doctype html>
<html><head><meta charset="utf-8"><title>Admin Login</title></head>
<body style="font-family:ui-sans-serif,system-ui,sans-serif;max-width:480px;margin:40px auto;padding:0 16px;">
  <h1>Admin Login</h1>
  {"<div style='padding:10px;border:1px solid #b74a4a;background:#fdeeee;margin-bottom:12px;'>" + _esc(error) + "</div>" if error else ""}
  <form method="post" action="/admin/ui/login" style="display:grid;gap:10px;">
    <input type="hidden" name="next" value="{_esc(next)}" />
    <label>Username <input required name="username" /></label>
    <label>Password <input required type="password" name="password" /></label>
    <button type="submit">Login</button>
  </form>
</body></html>"""
    return HTMLResponse(page)


@router.post("/login")
def login_submit(
    username: str = Form(...),
    password: str = Form(...),
    next: str = Form("/admin/ui"),
):
    user = get_user_by_username(username)
    if not user or user["role"] != "admin" or not verify_password(password, user["password_hash"]):
        return RedirectResponse(
            f"/admin/ui/login?{urlencode({'next': next, 'error': 'Invalid admin credentials'})}",
            status_code=303,
        )
    token, _ = create_token(username=user["username"], role=user["role"])
    response = RedirectResponse(next or "/admin/ui", status_code=303)
    response.set_cookie("admin_session", token, httponly=True, samesite="lax")
    return response


@router.get("/logout")
def logout():
    response = RedirectResponse("/admin/ui/login", status_code=303)
    response.delete_cookie("admin_session")
    return response


@router.get("", response_class=HTMLResponse)
def dashboard(request: Request):
    user = _require_admin_or_redirect(request)
    if isinstance(user, RedirectResponse):
        return user
    users = list_users()
    devices = list_hosts()
    assignments = list_assignments()
    wake_logs = list_wake_logs(limit=10)
    power_logs = list_power_check_logs(limit=10)
    message, error = _msg(request)
    body = f"""
    <section style="display:grid;grid-template-columns:repeat(4,minmax(120px,1fr));gap:12px;margin-bottom:16px;">
      <div style="padding:12px;border:1px solid #ddd;"><div>Users</div><strong>{len(users)}</strong></div>
      <div style="padding:12px;border:1px solid #ddd;"><div>Devices</div><strong>{len(devices)}</strong></div>
      <div style="padding:12px;border:1px solid #ddd;"><div>Assignments</div><strong>{len(assignments)}</strong></div>
      <div style="padding:12px;border:1px solid #ddd;"><div>Invites</div><strong>{len(list_invite_tokens(limit=500))}</strong></div>
    </section>
    <h2>Recent Wake Logs</h2>
    <table border="1" cellpadding="6" cellspacing="0"><tr><th>ID</th><th>Device</th><th>Actor</th><th>Result</th><th>Time</th></tr>
      {"".join(f"<tr><td>{row['id']}</td><td>{_esc(row['host_id'])}</td><td>{_esc(row['actor_username'])}</td><td>{_esc(row['result'])}</td><td>{_esc(row['created_at'])}</td></tr>" for row in wake_logs)}
    </table>
    <h2>Recent Power Checks</h2>
    <table border="1" cellpadding="6" cellspacing="0"><tr><th>ID</th><th>Device</th><th>Method</th><th>Result</th><th>Time</th></tr>
      {"".join(f"<tr><td>{row['id']}</td><td>{_esc(row['device_id'])}</td><td>{_esc(row['method'])}</td><td>{_esc(row['result'])}</td><td>{_esc(row['created_at'])}</td></tr>" for row in power_logs)}
    </table>
    """
    return _layout("Admin Dashboard", body, user["username"], message=message, error=error)


@router.get("/users", response_class=HTMLResponse)
def users_page(request: Request):
    user = _require_admin_or_redirect(request)
    if isinstance(user, RedirectResponse):
        return user
    rows = list_users()
    message, error = _msg(request)
    table_rows = "".join(
        f"""
        <tr>
          <td>{row['id']}</td><td>{_esc(row['username'])}</td><td>{_esc(row['role'])}</td><td>{_esc(row['created_at'])}</td>
          <td>
            <form method="post" action="/admin/ui/users/{row['id']}/update" style="display:flex;gap:6px;flex-wrap:wrap;">
              <select name="role">
                <option value="user" {"selected" if row['role']=="user" else ""}>user</option>
                <option value="admin" {"selected" if row['role']=="admin" else ""}>admin</option>
              </select>
              <input name="password" type="password" placeholder="new password (optional)" />
              <button type="submit">Save</button>
            </form>
          </td>
          <td>
            <form method="post" action="/admin/ui/users/{row['id']}/delete">
              <button type="submit">Delete</button>
            </form>
          </td>
        </tr>
        """
        for row in rows
    )
    body = f"""
    <h2>Create User</h2>
    <form method="post" action="/admin/ui/users/create" style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px;">
      <input required name="username" placeholder="username" />
      <input required name="password" type="password" placeholder="password (>=12)" />
      <select name="role"><option value="user">user</option><option value="admin">admin</option></select>
      <button type="submit">Create</button>
    </form>
    <h2>Users</h2>
    <table border="1" cellpadding="6" cellspacing="0">
      <tr><th>ID</th><th>Username</th><th>Role</th><th>Created</th><th>Update</th><th>Delete</th></tr>
      {table_rows}
    </table>
    """
    return _layout("Users", body, user["username"], message=message, error=error)


@router.post("/users/create")
def users_create(request: Request, username: str = Form(...), password: str = Form(...), role: str = Form("user")):
    user = _require_admin_or_redirect(request)
    if isinstance(user, RedirectResponse):
        return user
    if role not in {"admin", "user"}:
        return _redirect("/admin/ui/users", error="Invalid role")
    if len(password) < 12:
        return _redirect("/admin/ui/users", error="Password must be at least 12 characters")
    if get_user_by_username(username):
        return _redirect("/admin/ui/users", error="Username already exists")
    user_id = create_user(username=username, password_hash=hash_password(password), role=role)
    log_admin_action(
        actor_username=user["username"],
        action="ui_create_user",
        target_type="user",
        target_id=str(user_id),
        detail=f"username={username}",
    )
    return _redirect("/admin/ui/users", message=f"User '{username}' created")


@router.post("/users/{user_id}/update")
def users_update(request: Request, user_id: int, role: str = Form(...), password: str = Form("")):
    admin = _require_admin_or_redirect(request)
    if isinstance(admin, RedirectResponse):
        return admin
    target = get_user_by_id(user_id)
    if not target:
        return _redirect("/admin/ui/users", error="User not found")
    if role not in {"admin", "user"}:
        return _redirect("/admin/ui/users", error="Invalid role")
    if target["role"] == "admin" and role != "admin" and count_admin_users() <= 1:
        return _redirect("/admin/ui/users", error="Cannot demote last admin")
    update_user_role(user_id, role)
    if password:
        if len(password) < 12:
            return _redirect("/admin/ui/users", error="Password must be at least 12 characters")
        update_user_password_by_id(user_id, hash_password(password))
    log_admin_action(
        actor_username=admin["username"],
        action="ui_update_user",
        target_type="user",
        target_id=str(user_id),
        detail=f"role={role}",
    )
    return _redirect("/admin/ui/users", message=f"Updated user '{target['username']}'")


@router.post("/users/{user_id}/delete")
def users_delete(request: Request, user_id: int):
    admin = _require_admin_or_redirect(request)
    if isinstance(admin, RedirectResponse):
        return admin
    target = get_user_by_id(user_id)
    if not target:
        return _redirect("/admin/ui/users", error="User not found")
    if target["role"] == "admin" and count_admin_users() <= 1:
        return _redirect("/admin/ui/users", error="Cannot delete last admin")
    delete_user(user_id)
    log_admin_action(
        actor_username=admin["username"],
        action="ui_delete_user",
        target_type="user",
        target_id=str(user_id),
        detail=f"username={target['username']}",
    )
    return _redirect("/admin/ui/users", message=f"Deleted user '{target['username']}'")


@router.get("/devices", response_class=HTMLResponse)
def devices_page(request: Request):
    admin = _require_admin_or_redirect(request)
    if isinstance(admin, RedirectResponse):
        return admin
    rows = list_hosts()
    message, error = _msg(request)
    table_rows = "".join(
        f"""
        <tr>
          <td>{_esc(row['id'])}</td><td>{_esc(row['name'])}</td><td>{_esc(row['display_name'])}</td><td>{_esc(row['mac'])}</td>
          <td>{_esc(row['check_method'])}</td><td>{_esc(row['check_target'])}</td><td>{_esc(row['check_port'])}</td>
          <td>{_esc(row['last_power_state'])}</td><td>{_esc(row['last_power_checked_at'])}</td>
          <td>{"<br/>".join(_esc(hint) for hint in device_diagnostic_hints(dict(row)))}</td>
          <td>
            <form method="post" action="/admin/ui/devices/{_esc(row['id'])}/update" style="display:grid;gap:4px;">
              <input name="name" value="{_esc(row['name'])}" />
              <input name="display_name" value="{_esc(row['display_name'])}" placeholder="display name" />
              <input name="mac" value="{_esc(row['mac'])}" />
              <input name="check_target" value="{_esc(row['check_target'])}" placeholder="check target" />
              <input name="check_port" value="{_esc(row['check_port'])}" placeholder="check port" />
              <select name="check_method">
                <option value="tcp" {"selected" if row['check_method']=="tcp" else ""}>tcp</option>
                <option value="icmp" {"selected" if row['check_method']=="icmp" else ""}>icmp</option>
              </select>
              <button type="submit">Save</button>
            </form>
          </td>
          <td>
            <form method="post" action="/admin/ui/devices/{_esc(row['id'])}/test-power-check"><button type="submit">Test Power Check</button></form>
            <form method="post" action="/admin/ui/devices/{_esc(row['id'])}/delete"><button type="submit">Delete</button></form>
          </td>
        </tr>
        """
        for row in rows
    )
    body = f"""
    <h2>Create Device</h2>
    <form method="post" action="/admin/ui/devices/create" style="display:grid;grid-template-columns:repeat(4,minmax(160px,1fr));gap:8px;margin-bottom:16px;">
      <input required name="name" placeholder="name" />
      <input name="display_name" placeholder="display name" />
      <input required name="mac" placeholder="AA:BB:CC:DD:EE:FF" />
      <input name="group_name" placeholder="group" />
      <input name="broadcast" placeholder="broadcast ip" />
      <input name="subnet_cidr" placeholder="subnet cidr" />
      <input name="udp_port" value="9" placeholder="udp port" />
      <input name="interface" placeholder="interface" />
      <select name="check_method"><option value="tcp">tcp</option><option value="icmp">icmp</option></select>
      <input name="check_target" placeholder="check target" />
      <input name="check_port" placeholder="check port" />
      <button type="submit">Create</button>
    </form>
    <h2>Devices</h2>
    <table border="1" cellpadding="6" cellspacing="0">
      <tr><th>ID</th><th>Name</th><th>Display</th><th>MAC</th><th>Method</th><th>Target</th><th>Port</th><th>State</th><th>Checked At</th><th>Diagnostics</th><th>Update</th><th>Actions</th></tr>
      {table_rows}
    </table>
    """
    return _layout("Devices", body, admin["username"], message=message, error=error)


@router.post("/devices/create")
def devices_create(
    request: Request,
    name: str = Form(...),
    display_name: str = Form(""),
    mac: str = Form(...),
    group_name: str = Form(""),
    broadcast: str = Form(""),
    subnet_cidr: str = Form(""),
    udp_port: int = Form(9),
    interface: str = Form(""),
    check_method: str = Form("tcp"),
    check_target: str = Form(""),
    check_port: str = Form(""),
):
    admin = _require_admin_or_redirect(request)
    if isinstance(admin, RedirectResponse):
        return admin
    try:
        normalized_mac = normalize_mac(mac)
    except ValueError as exc:
        return _redirect("/admin/ui/devices", error=str(exc))
    if check_method not in {"tcp", "icmp"}:
        return _redirect("/admin/ui/devices", error="Invalid check_method")
    port_value = int(check_port) if check_port.strip() else None
    device_id = create_host(
        host_id=None,
        name=name,
        display_name=display_name or None,
        mac=normalized_mac,
        group_name=group_name or None,
        broadcast=broadcast or None,
        subnet_cidr=subnet_cidr or None,
        udp_port=udp_port,
        interface=interface or None,
        check_method=check_method,
        check_target=check_target or None,
        check_port=port_value,
    )
    log_admin_action(
        actor_username=admin["username"],
        action="ui_create_device",
        target_type="device",
        target_id=device_id,
        detail=f"name={name}",
    )
    return _redirect("/admin/ui/devices", message=f"Created device {device_id}")


@router.post("/devices/{device_id}/update")
def devices_update(
    request: Request,
    device_id: str,
    name: str = Form(...),
    display_name: str = Form(""),
    mac: str = Form(...),
    check_method: str = Form("tcp"),
    check_target: str = Form(""),
    check_port: str = Form(""),
):
    admin = _require_admin_or_redirect(request)
    if isinstance(admin, RedirectResponse):
        return admin
    current = get_host_by_id(device_id)
    if not current:
        return _redirect("/admin/ui/devices", error="Device not found")
    try:
        normalized_mac = normalize_mac(mac)
    except ValueError as exc:
        return _redirect("/admin/ui/devices", error=str(exc))
    if check_method not in {"tcp", "icmp"}:
        return _redirect("/admin/ui/devices", error="Invalid check_method")
    try:
        port_value = int(check_port) if check_port.strip() else None
    except ValueError:
        return _redirect("/admin/ui/devices", error="check_port must be integer")
    update_host(
        device_id,
        {
            "name": name,
            "display_name": display_name or None,
            "mac": normalized_mac,
            "check_method": check_method,
            "check_target": check_target or None,
            "check_port": port_value,
        },
    )
    log_admin_action(
        actor_username=admin["username"],
        action="ui_update_device",
        target_type="device",
        target_id=device_id,
        detail=f"name={name}",
    )
    return _redirect("/admin/ui/devices", message=f"Updated device {device_id}")


@router.post("/devices/{device_id}/delete")
def devices_delete(request: Request, device_id: str):
    admin = _require_admin_or_redirect(request)
    if isinstance(admin, RedirectResponse):
        return admin
    existing = get_host_by_id(device_id)
    if not delete_host(device_id):
        return _redirect("/admin/ui/devices", error="Device not found")
    log_admin_action(
        actor_username=admin["username"],
        action="ui_delete_device",
        target_type="device",
        target_id=device_id,
        detail=f"name={existing['name']}" if existing else None,
    )
    return _redirect("/admin/ui/devices", message=f"Deleted device {device_id}")


@router.post("/devices/{device_id}/test-power-check")
def devices_test_power_check(request: Request, device_id: str):
    admin = _require_admin_or_redirect(request)
    if isinstance(admin, RedirectResponse):
        return admin
    host = get_host_by_id(device_id)
    if not host:
        return _redirect("/admin/ui/devices", error="Device not found")
    result = run_power_check(
        method=host["check_method"] or "tcp",
        target=host["check_target"],
        port=host["check_port"],
    )
    checked_at = datetime.now(UTC).isoformat()
    update_host_power_state(device_id, result.result, checked_at)
    log_power_check(
        device_id=device_id,
        method=result.method,
        result=result.result,
        detail=result.detail,
        latency_ms=result.latency_ms,
    )
    log_admin_action(
        actor_username=admin["username"],
        action="ui_test_power_check",
        target_type="device",
        target_id=device_id,
        detail=f"result={result.result}",
    )
    return _redirect("/admin/ui/devices", message=f"Power check {result.result} ({result.detail})")


@router.get("/assignments", response_class=HTMLResponse)
def assignments_page(request: Request):
    admin = _require_admin_or_redirect(request)
    if isinstance(admin, RedirectResponse):
        return admin
    users = list_users()
    devices = list_hosts()
    assignments = list_assignments()
    message, error = _msg(request)
    user_opts = "".join(f'<option value="{row["id"]}">{_esc(row["username"])} ({row["id"]})</option>' for row in users)
    device_opts = "".join(f'<option value="{_esc(row["id"])}">{_esc(row["name"])} ({_esc(row["id"])})</option>' for row in devices)
    rows = "".join(
        f"""
        <tr>
          <td>{row['user_id']}</td><td>{_esc(row['username'])}</td><td>{_esc(row['device_id'])}</td><td>{_esc(row['device_name'])}</td><td>{_esc(row['created_at'])}</td>
          <td><form method="post" action="/admin/ui/assignments/{row['user_id']}/{_esc(row['device_id'])}/delete"><button type="submit">Remove</button></form></td>
        </tr>
        """
        for row in assignments
    )
    body = f"""
    <h2>Create Assignment</h2>
    <form method="post" action="/admin/ui/assignments/create" style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px;">
      <select name="user_id">{user_opts}</select>
      <select name="device_id">{device_opts}</select>
      <button type="submit">Assign</button>
    </form>
    <h2>Assignments</h2>
    <table border="1" cellpadding="6" cellspacing="0">
      <tr><th>User ID</th><th>Username</th><th>Device ID</th><th>Device</th><th>Created</th><th>Action</th></tr>
      {rows}
    </table>
    """
    return _layout("Assignments", body, admin["username"], message=message, error=error)


@router.post("/assignments/create")
def assignments_create(request: Request, user_id: int = Form(...), device_id: str = Form(...)):
    admin = _require_admin_or_redirect(request)
    if isinstance(admin, RedirectResponse):
        return admin
    if not get_user_by_id(user_id):
        return _redirect("/admin/ui/assignments", error="User not found")
    if not get_host_by_id(device_id):
        return _redirect("/admin/ui/assignments", error="Device not found")
    assign_device_to_user(user_id, device_id)
    log_admin_action(
        actor_username=admin["username"],
        action="ui_create_assignment",
        target_type="assignment",
        target_id=f"{user_id}:{device_id}",
        detail=None,
    )
    return _redirect("/admin/ui/assignments", message="Assignment saved")


@router.post("/assignments/{user_id}/{device_id}/delete")
def assignments_delete(request: Request, user_id: int, device_id: str):
    admin = _require_admin_or_redirect(request)
    if isinstance(admin, RedirectResponse):
        return admin
    if not remove_assignment(user_id, device_id):
        return _redirect("/admin/ui/assignments", error="Assignment not found")
    log_admin_action(
        actor_username=admin["username"],
        action="ui_delete_assignment",
        target_type="assignment",
        target_id=f"{user_id}:{device_id}",
        detail=None,
    )
    return _redirect("/admin/ui/assignments", message="Assignment removed")


def _render_invites_page(
    admin_username: str,
    message: str | None,
    error: str | None,
    created_token: str | None = None,
    created_link: str | None = None,
):
    invites = list_invite_tokens(limit=300)
    rows = "".join(
        f"""
        <tr>
          <td>{_esc(row['id'])}</td><td>{_esc(row['username'])}</td><td>{_esc(row['backend_url_hint'])}</td>
          <td>{_esc(row['expires_at'])}</td><td>{_esc(row['claimed_at'])}</td><td>{_esc(row['created_by'])}</td>
          <td><form method="post" action="/admin/ui/invites/{_esc(row['id'])}/revoke"><button type="submit">Revoke</button></form></td>
        </tr>
        """
        for row in invites
    )
    created_section = ""
    if created_token and created_link:
        qr_url = f"https://quickchart.io/qr?size=240&text={quote_plus(created_link)}"
        created_section = f"""
        <section style="padding:12px;border:1px solid #ddd;margin-bottom:16px;">
          <h3>New Invite</h3>
          <div><strong>Token:</strong> <code>{_esc(created_token)}</code></div>
          <div><strong>Link:</strong> <code>{_esc(created_link)}</code></div>
          <div style="margin-top:8px;"><img src="{_esc(qr_url)}" alt="Invite QR Code" /></div>
        </section>
        """
    users = list_users()
    user_opts = "".join(f'<option value="{_esc(row["username"])}">{_esc(row["username"])}</option>' for row in users)
    body = f"""
    {created_section}
    <h2>Create Invite</h2>
    <form method="post" action="/admin/ui/invites/create" style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px;">
      <select name="username">{user_opts}</select>
      <input name="backend_url_hint" placeholder="backend url hint (optional)" />
      <input name="expires_in_hours" value="72" placeholder="hours" />
      <button type="submit">Create Invite</button>
    </form>
    <h2>Invites</h2>
    <table border="1" cellpadding="6" cellspacing="0">
      <tr><th>ID</th><th>Username</th><th>Backend Hint</th><th>Expires At</th><th>Claimed At</th><th>Created By</th><th>Action</th></tr>
      {rows}
    </table>
    """
    return _layout("Invites", body, admin_username, message=message, error=error)


@router.get("/invites", response_class=HTMLResponse)
def invites_page(request: Request):
    admin = _require_admin_or_redirect(request)
    if isinstance(admin, RedirectResponse):
        return admin
    message, error = _msg(request)
    return _render_invites_page(admin["username"], message, error)


@router.post("/invites/create", response_class=HTMLResponse)
def invites_create(
    request: Request,
    username: str = Form(...),
    backend_url_hint: str = Form(""),
    expires_in_hours: int = Form(72),
):
    admin = _require_admin_or_redirect(request)
    if isinstance(admin, RedirectResponse):
        return admin
    user = get_user_by_username(username)
    if not user:
        return _render_invites_page(admin["username"], None, "Username not found")
    if expires_in_hours < 1 or expires_in_hours > 24 * 30:
        return _render_invites_page(admin["username"], None, "expires_in_hours out of range")
    raw_token = secrets.token_urlsafe(24)
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    invite_id = secrets.token_hex(16)
    expires_at = datetime.now(UTC) + timedelta(hours=expires_in_hours)
    create_invite_token(
        invite_id=invite_id,
        token_hash=token_hash,
        username=username,
        backend_url_hint=backend_url_hint or None,
        expires_at=expires_at.isoformat(),
        created_by=admin["username"],
    )
    log_admin_action(
        actor_username=admin["username"],
        action="ui_create_invite",
        target_type="invite",
        target_id=invite_id,
        detail=f"username={username}",
    )
    hint = backend_url_hint.strip() or f"{request.url.scheme}://{request.url.netloc}"
    link = f"wakefromfar://claim?token={quote_plus(raw_token)}&backend_url_hint={quote_plus(hint)}"
    return _render_invites_page(
        admin["username"],
        message=f"Invite created for {username}",
        error=None,
        created_token=raw_token,
        created_link=link,
    )


@router.post("/invites/{invite_id}/revoke")
def invites_revoke(request: Request, invite_id: str):
    admin = _require_admin_or_redirect(request)
    if isinstance(admin, RedirectResponse):
        return admin
    if not revoke_invite(invite_id):
        return _redirect("/admin/ui/invites", error="Invite not found or already claimed")
    log_admin_action(
        actor_username=admin["username"],
        action="ui_revoke_invite",
        target_type="invite",
        target_id=invite_id,
        detail=None,
    )
    return _redirect("/admin/ui/invites", message="Invite revoked")


@router.get("/wake-logs", response_class=HTMLResponse)
def wake_logs_page(
    request: Request,
    limit: int = 100,
    result: str = "",
    actor: str = "",
    host_id: str = "",
):
    admin = _require_admin_or_redirect(request)
    if isinstance(admin, RedirectResponse):
        return admin
    limit = max(1, min(limit, 500))
    rows = list_wake_logs(limit=limit)
    if result:
        rows = [row for row in rows if row["result"] == result]
    if actor:
        rows = [row for row in rows if actor.lower() in str(row["actor_username"]).lower()]
    if host_id:
        rows = [row for row in rows if host_id.lower() in str(row["host_id"]).lower()]
    message, error = _msg(request)
    body_rows = "".join(
        f"<tr><td>{row['id']}</td><td>{_esc(row['host_id'])}</td><td>{_esc(row['actor_username'])}</td><td>{_esc(row['result'])}</td><td>{_esc(row['precheck_state'])}</td><td>{_esc(row['error_detail'])}</td><td>{_esc(row['created_at'])}</td></tr>"
        for row in rows
    )
    body = f"""
    <h2>Wake Logs</h2>
    <form method="get" style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px;">
      <input name="host_id" value="{_esc(host_id)}" placeholder="host id filter" />
      <input name="actor" value="{_esc(actor)}" placeholder="actor filter" />
      <select name="result">
        <option value="" {"selected" if not result else ""}>all results</option>
        <option value="sent" {"selected" if result=="sent" else ""}>sent</option>
        <option value="already_on" {"selected" if result=="already_on" else ""}>already_on</option>
        <option value="failed" {"selected" if result=="failed" else ""}>failed</option>
      </select>
      <input name="limit" value="{limit}" />
      <button type="submit">Filter</button>
    </form>
    <table border="1" cellpadding="6" cellspacing="0">
      <tr><th>ID</th><th>Host ID</th><th>Actor</th><th>Result</th><th>Precheck</th><th>Error</th><th>Created</th></tr>
      {body_rows}
    </table>
    """
    return _layout("Wake Logs", body, admin["username"], message=message, error=error)


@router.get("/power-check-logs", response_class=HTMLResponse)
def power_logs_page(
    request: Request,
    limit: int = 100,
    result: str = "",
    method: str = "",
    device_id: str = "",
):
    admin = _require_admin_or_redirect(request)
    if isinstance(admin, RedirectResponse):
        return admin
    limit = max(1, min(limit, 500))
    rows = list_power_check_logs(limit=limit)
    if result:
        rows = [row for row in rows if row["result"] == result]
    if method:
        rows = [row for row in rows if row["method"] == method]
    if device_id:
        rows = [row for row in rows if device_id.lower() in str(row["device_id"]).lower()]
    message, error = _msg(request)
    body_rows = "".join(
        f"<tr><td>{row['id']}</td><td>{_esc(row['device_id'])}</td><td>{_esc(row['method'])}</td><td>{_esc(row['result'])}</td><td>{_esc(row['detail'])}</td><td>{_esc(row['latency_ms'])}</td><td>{_esc(row['created_at'])}</td></tr>"
        for row in rows
    )
    body = f"""
    <h2>Power Check Logs</h2>
    <form method="get" style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px;">
      <input name="device_id" value="{_esc(device_id)}" placeholder="device id filter" />
      <select name="method">
        <option value="" {"selected" if not method else ""}>all methods</option>
        <option value="tcp" {"selected" if method=="tcp" else ""}>tcp</option>
        <option value="icmp" {"selected" if method=="icmp" else ""}>icmp</option>
      </select>
      <select name="result">
        <option value="" {"selected" if not result else ""}>all results</option>
        <option value="on" {"selected" if result=="on" else ""}>on</option>
        <option value="off" {"selected" if result=="off" else ""}>off</option>
        <option value="unknown" {"selected" if result=="unknown" else ""}>unknown</option>
      </select>
      <input name="limit" value="{limit}" />
      <button type="submit">Filter</button>
    </form>
    <table border="1" cellpadding="6" cellspacing="0">
      <tr><th>ID</th><th>Device ID</th><th>Method</th><th>Result</th><th>Detail</th><th>Latency ms</th><th>Created</th></tr>
      {body_rows}
    </table>
    """
    return _layout("Power Check Logs", body, admin["username"], message=message, error=error)


@router.get("/diagnostics", response_class=HTMLResponse)
def diagnostics_page(request: Request):
    admin = _require_admin_or_redirect(request)
    if isinstance(admin, RedirectResponse):
        return admin
    rows = []
    for host in list_hosts():
        rows.append(
            f"<tr><td>{_esc(host['id'])}</td><td>{_esc(host['name'])}</td><td>{'<br/>'.join(_esc(h) for h in device_diagnostic_hints(dict(host)))}</td></tr>"
        )
    body = f"""
    <h2>Device Diagnostics Hints</h2>
    <table border="1" cellpadding="6" cellspacing="0">
      <tr><th>Device ID</th><th>Name</th><th>Hints</th></tr>
      {''.join(rows)}
    </table>
    """
    message, error = _msg(request)
    return _layout("Diagnostics", body, admin["username"], message=message, error=error)


@router.get("/audit-logs", response_class=HTMLResponse)
def audit_logs_page(request: Request):
    admin = _require_admin_or_redirect(request)
    if isinstance(admin, RedirectResponse):
        return admin
    rows = list_admin_audit_logs(limit=500)
    body_rows = "".join(
        f"<tr><td>{row['id']}</td><td>{_esc(row['actor_username'])}</td><td>{_esc(row['action'])}</td><td>{_esc(row['target_type'])}</td><td>{_esc(row['target_id'])}</td><td>{_esc(row['detail'])}</td><td>{_esc(row['created_at'])}</td></tr>"
        for row in rows
    )
    body = f"""
    <h2>Admin Audit Logs</h2>
    <table border="1" cellpadding="6" cellspacing="0">
      <tr><th>ID</th><th>Actor</th><th>Action</th><th>Target Type</th><th>Target ID</th><th>Detail</th><th>Created</th></tr>
      {body_rows}
    </table>
    """
    message, error = _msg(request)
    return _layout("Audit Logs", body, admin["username"], message=message, error=error)


@router.get("/metrics", response_class=HTMLResponse)
def metrics_page(request: Request):
    admin = _require_admin_or_redirect(request)
    if isinstance(admin, RedirectResponse):
        return admin
    counters = get_counters()
    rows = "".join(
        f"<tr><td>{_esc(name)}</td><td>{value}</td></tr>" for name, value in sorted(counters.items(), key=lambda kv: kv[0])
    )
    body = f"""
    <h2>Runtime Counters</h2>
    <table border="1" cellpadding="6" cellspacing="0">
      <tr><th>Counter</th><th>Value</th></tr>
      {rows}
    </table>
    """
    message, error = _msg(request)
    return _layout("Metrics", body, admin["username"], message=message, error=error)


@router.get("/pilot-metrics", response_class=HTMLResponse)
def pilot_metrics_page(request: Request):
    admin = _require_admin_or_redirect(request)
    if isinstance(admin, RedirectResponse):
        return admin
    claimed_invites = [row for row in list_invite_tokens(limit=5000) if row["claimed_at"]]
    successful_wakes = list_successful_wakes(limit=20000)

    first_success_by_user: dict[str, str] = {}
    for row in successful_wakes:
        actor = str(row["actor_username"])
        if actor not in first_success_by_user:
            first_success_by_user[actor] = str(row["created_at"])

    total_claimed = len(claimed_invites)
    within_two_minutes = 0
    details_rows: list[str] = []
    for invite in claimed_invites:
        username = str(invite["username"])
        claimed_at = datetime.fromisoformat(str(invite["claimed_at"]))
        if claimed_at.tzinfo is None:
            claimed_at = claimed_at.replace(tzinfo=UTC)
        first_success_raw = first_success_by_user.get(username)
        duration = None
        within = False
        if first_success_raw:
            first_success = datetime.fromisoformat(first_success_raw)
            if first_success.tzinfo is None:
                first_success = first_success.replace(tzinfo=UTC)
            duration = (first_success - claimed_at).total_seconds()
            within = duration <= 120
            if within:
                within_two_minutes += 1
        details_rows.append(
            f"<tr><td>{_esc(username)}</td><td>{_esc(invite['claimed_at'])}</td><td>{_esc(first_success_raw)}</td><td>{_esc(duration)}</td><td>{'yes' if within else 'no'}</td></tr>"
        )

    rate = (within_two_minutes / total_claimed) if total_claimed else 0.0
    body = f"""
    <h2>Pilot Metrics</h2>
    <p>Total claimed users: <strong>{total_claimed}</strong></p>
    <p>Users with first successful wake within 2 min: <strong>{within_two_minutes}</strong></p>
    <p>Completion rate within 2 min: <strong>{rate:.2%}</strong> (target: 90%)</p>
    <table border="1" cellpadding="6" cellspacing="0">
      <tr><th>Username</th><th>Claimed At</th><th>First Successful Wake</th><th>Seconds</th><th>Within 2m</th></tr>
      {''.join(details_rows)}
    </table>
    """
    message, error = _msg(request)
    return _layout("Pilot Metrics", body, admin["username"], message=message, error=error)
