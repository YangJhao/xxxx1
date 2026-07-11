#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import ipaddress
import pathlib
import subprocess


APP_DIR = pathlib.Path(os.environ.get("APP_DIR", "/opt/42IPwin"))
STATE_FILES = [
    APP_DIR / "data" / "macvlan_current.json",
    APP_DIR / "data" / "macvlan_current_211.230.223.67.json",
]


def run(args: list[str], check: bool = False) -> subprocess.CompletedProcess:
    proc = subprocess.run(args, text=True, capture_output=True)
    if check and proc.returncode != 0:
        message = ((proc.stdout or "") + (proc.stderr or "")).strip()
        raise SystemExit(f"command failed {proc.returncode}: {' '.join(args)}\n{message}")
    return proc


def exists(iface: str) -> bool:
    return pathlib.Path("/sys/class/net", iface).exists()


def read_mac(iface: str) -> str:
    try:
        return pathlib.Path("/sys/class/net", iface, "address").read_text().strip().lower()
    except Exception:
        return ""


def current_cidrs(iface: str) -> list[str]:
    proc = run(["ip", "-br", "-4", "addr", "show", "dev", iface])
    cidrs: list[str] = []
    for token in (proc.stdout or "").split():
        if "/" in token and token[0].isdigit():
            cidrs.append(token)
    return cidrs


def delete_source_rules(ip: str):
    for _ in range(20):
        proc = run(["ip", "rule", "del", "from", f"{ip}/32"])
        if proc.returncode != 0:
            break


def default_gateway_for_iface(iface: str, ip: str) -> str:
    proc = run(["ip", "route", "show", "default", "dev", iface])
    for line in (proc.stdout or "").splitlines():
        words = line.split()
        if "via" in words:
            return words[words.index("via") + 1]
    proc = run(["ip", "route", "get", "1.1.1.1", "from", ip, "oif", iface])
    words = (proc.stdout or "").split()
    if "via" in words:
        return words[words.index("via") + 1]
    return ""


def restore_source_route(row: dict):
    iface = row.get("iface") or ""
    ip = row.get("ip") or ""
    table = row.get("table") or ""
    priority = row.get("priority") or ""
    if not iface or not ip or not table or not priority:
        return False
    router = row.get("router") or default_gateway_for_iface(iface, ip)
    if not router:
        print(f"[restore-macvlans] skip route {iface} {ip}: no gateway")
        return False
    run(["ip", "route", "flush", "table", str(table)])
    network = row.get("network") or ""
    if not network and row.get("prefix"):
        try:
            network = str(ipaddress.ip_network(f"{ip}/{row.get('prefix')}", strict=False))
        except Exception:
            network = ""
    if network:
        run(["ip", "route", "replace", network, "dev", iface, "src", ip, "table", str(table)])
    proc = run(["ip", "route", "replace", "default", "via", router, "dev", iface, "src", ip, "table", str(table)])
    if proc.returncode != 0:
        run(["ip", "route", "replace", "default", "via", router, "dev", iface, "src", ip, "table", str(table), "onlink"], check=True)
    delete_source_rules(ip)
    run(["ip", "rule", "add", "from", f"{ip}/32", "priority", str(priority), "table", str(table)], check=True)
    return True


def load_state() -> dict:
    for path in STATE_FILES:
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
    print("[restore-macvlans] no state file")
    return {"rows": []}


def ensure_link(row: dict):
    iface = row.get("iface") or ""
    parent = row.get("parent") or ""
    mac = (row.get("mac") or "").lower()
    if not iface or not parent:
        return False
    if not exists(parent):
        print(f"[restore-macvlans] skip {iface}: parent {parent} missing")
        return False
    if not exists(iface):
        if not mac:
            print(f"[restore-macvlans] skip {iface}: no saved mac")
            return False
        run(["ip", "link", "add", "link", parent, "name", iface, "address", mac, "type", "macvlan", "mode", "bridge"], check=True)
        print(f"[restore-macvlans] created {iface} on {parent} {mac}")
    elif mac and read_mac(iface) != mac:
        run(["ip", "link", "set", "dev", iface, "down"])
        run(["ip", "link", "set", "dev", iface, "address", mac], check=True)
        print(f"[restore-macvlans] refreshed mac {iface} {mac}")
    run(["ip", "link", "set", "dev", iface, "up"], check=True)
    return True


def restore_row(row: dict):
    if not ensure_link(row):
        return False
    iface = row.get("iface") or ""
    internal_ip = row.get("internal_ip") or ""
    internal_prefix = row.get("internal_prefix") or 32
    if internal_ip:
        run(["ip", "addr", "replace", f"{internal_ip}/{internal_prefix}", "dev", iface], check=True)
    restore_source_route(row)
    return True


def restore() -> int:
    payload = load_state()
    rows = payload.get("rows") or []
    restored = 0
    for row in rows:
        if restore_row(row):
            restored += 1
    run(["ip", "route", "flush", "cache"])
    public_count = len([row for row in rows if row.get("ip")])
    print(f"[restore-macvlans] restored {restored}/{len(rows)}, public {public_count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(restore())
