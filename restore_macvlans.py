#!/usr/bin/env python3
from __future__ import annotations

import json
import os
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
    ip = row.get("ip") or ""
    prefix = row.get("prefix") or ""
    table = str(row.get("table") or "")
    router = row.get("router") or ""
    network = row.get("network") or ""
    priority = str(row.get("priority") or "")
    if not ip or not prefix:
        for cidr in current_cidrs(iface):
            run(["ip", "addr", "del", cidr, "dev", iface])
        return True
    wanted = f"{ip}/{prefix}"
    for cidr in current_cidrs(iface):
        if cidr != wanted:
            run(["ip", "addr", "del", cidr, "dev", iface])
    run(["ip", "addr", "replace", wanted, "dev", iface], check=True)
    if table:
        run(["ip", "route", "flush", "table", table])
        if network:
            run(["ip", "route", "replace", network, "dev", iface, "src", ip, "table", table], check=True)
        if router:
            run(["ip", "route", "replace", "default", "via", router, "dev", iface, "src", ip, "table", table], check=True)
        delete_source_rules(ip)
        if priority:
            run(["ip", "rule", "add", "from", f"{ip}/32", "table", table, "priority", priority], check=True)
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
