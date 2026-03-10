from __future__ import annotations

import argparse

from .db import create_host, create_user, disable_user_mfa_by_username, get_user_by_username, init_db, list_hosts
from .password_policy import min_password_length_for_role
from .security import hash_password
from .wol import normalize_mac


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="WoL relay admin CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    add_user = sub.add_parser("add-user", help="Create a user")
    add_user.add_argument("username")
    add_user.add_argument("password")
    add_user.add_argument("--role", choices=["admin", "user"], default="user")

    add_host = sub.add_parser("add-host", help="Create a host")
    add_host.add_argument("--id")
    add_host.add_argument("--name", required=True)
    add_host.add_argument("--mac", required=True)
    add_host.add_argument("--group-name")
    add_host.add_argument("--broadcast")
    add_host.add_argument("--subnet-cidr")
    add_host.add_argument("--udp-port", type=int, default=9)
    add_host.add_argument("--interface")
    add_host.add_argument("--source-ip")

    sub.add_parser("list-hosts", help="List configured hosts")

    disable_mfa = sub.add_parser("admin-disable-mfa", help="Disable MFA for an admin user")
    disable_mfa.add_argument("--username", required=True)

    return parser


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    init_db()

    if args.command == "add-user":
        if get_user_by_username(args.username):
            raise SystemExit(f"User '{args.username}' already exists")
        min_len = min_password_length_for_role(args.role)
        if len(args.password) < min_len:
            raise SystemExit(f"Password for role '{args.role}' must be at least {min_len} characters")
        create_user(args.username, hash_password(args.password), args.role)
        print(f"Created user '{args.username}' ({args.role})")
        return

    if args.command == "add-host":
        host_id = create_host(
            host_id=args.id,
            name=args.name,
            mac=normalize_mac(args.mac),
            group_name=args.group_name,
            broadcast=args.broadcast,
            subnet_cidr=args.subnet_cidr,
            udp_port=args.udp_port,
            interface=args.interface,
            source_ip=args.source_ip,
        )
        print(f"Created host '{args.name}' with id {host_id}")
        return

    if args.command == "list-hosts":
        for host in list_hosts():
            print(
                f"{host['id']} | {host['name']} | {host['mac']} | "
                f"{host['broadcast'] or host['subnet_cidr'] or '255.255.255.255'}:{host['udp_port']}"
            )
        return

    if args.command == "admin-disable-mfa":
        user = get_user_by_username(args.username)
        if not user:
            raise SystemExit(f"User '{args.username}' not found")
        if user["role"] != "admin":
            raise SystemExit(f"User '{args.username}' is not an admin")
        if not disable_user_mfa_by_username(args.username):
            raise SystemExit(f"Failed to disable MFA for '{args.username}'")
        print(f"Disabled MFA for admin '{args.username}'")
        return


if __name__ == "__main__":
    main()
