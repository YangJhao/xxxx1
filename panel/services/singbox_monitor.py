"""Runtime monitor for per-line sing-box instances."""
import json
import os
import re
import time
import urllib.request
from datetime import datetime
from pathlib import Path

import psutil

from config import PROJECT_DIR
from models import Line, ProxyUser, get_session


INSTANCE_ROOT = Path(os.environ.get("IPWIN42_SINGBOX_INSTANCE_DIR") or (PROJECT_DIR / "sing-box" / "instances"))
CONTROLLER_BASE_PORT = int(os.environ.get("IPWIN42_SINGBOX_INSTANCE_CONTROLLER_BASE", "19090"))
STATE_PATH = Path(PROJECT_DIR) / "data" / "singbox_monitor_state.json"
_last_rates: dict[int, dict] = {}


def _controller_port(line_id: int) -> int:
    return CONTROLLER_BASE_PORT + int(line_id)


def _instance_config_path(line_id: int) -> str:
    return str(INSTANCE_ROOT / f"line-{int(line_id)}" / "config.json")


def _read_json(path: Path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def _write_json(path: Path, payload) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception:
        pass


def _process_map() -> dict[int, dict]:
    rows = {}
    pattern = re.compile(r"instances[\\/]+line-(\d+)[\\/]+config\.json", re.I)
    for proc in psutil.process_iter(["pid", "name", "cmdline", "create_time"]):
        try:
            name = proc.info.get("name") or ""
            if name.lower() not in {"sing-box.exe", "sing-box"}:
                continue
            cmdline = " ".join(proc.info.get("cmdline") or [])
            match = pattern.search(cmdline)
            if not match:
                continue
            pid = int(proc.info["pid"])
            rows[int(match.group(1))] = {
                "pid": pid,
                "create_time": datetime.fromtimestamp(proc.info.get("create_time") or 0).strftime("%Y-%m-%d %H:%M:%S"),
                "cmdline": cmdline,
            }
        except (psutil.Error, OSError, ValueError):
            continue
    return rows


def _listen_count(pid: int | None) -> int:
    if not pid:
        return 0
    count = 0
    try:
        for conn in psutil.net_connections(kind="tcp"):
            if conn.pid == pid and str(conn.status).upper() == "LISTEN":
                count += 1
    except Exception:
        return 0
    return count


def _fetch_connections(line_id: int, timeout: float = 0.45) -> tuple[list[dict], str]:
    url = f"http://127.0.0.1:{_controller_port(line_id)}/connections"
    try:
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="ignore"))
        return data.get("connections") or [], ""
    except Exception as exc:
        return [], str(exc)


def _line_rates(line_id: int, upload_total: int, download_total: int) -> tuple[int, int]:
    now = time.time()
    prev = _last_rates.get(line_id)
    _last_rates[line_id] = {"time": now, "upload": upload_total, "download": download_total}
    if not prev:
        return 0, 0
    elapsed = max(now - float(prev.get("time") or now), 0.001)
    up = max(0, int((upload_total - int(prev.get("upload") or 0)) / elapsed))
    down = max(0, int((download_total - int(prev.get("download") or 0)) / elapsed))
    return up, down


def _update_pid_state(lines: list[Line], processes: dict[int, dict]) -> dict[str, dict]:
    state = _read_json(STATE_PATH, {})
    changed = False
    now_text = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    for line in lines:
        key = str(line.id)
        pid = int((processes.get(line.id) or {}).get("pid") or 0)
        item = state.setdefault(key, {"pid": 0, "changes": 0, "last_changed_at": ""})
        old_pid = int(item.get("pid") or 0)
        if pid and old_pid and pid != old_pid:
            item["changes"] = int(item.get("changes") or 0) + 1
            item["last_changed_at"] = now_text
            changed = True
        if pid != old_pid:
            item["pid"] = pid
            changed = True
    if changed:
        _write_json(STATE_PATH, state)
    return state


def instance_status() -> dict:
    session = get_session()
    try:
        lines = session.query(Line).filter(Line.status == 1).order_by(Line.id).all()
        users = session.query(ProxyUser).all()
        users_by_line: dict[int, list[ProxyUser]] = {}
        for user in users:
            users_by_line.setdefault(int(user.line_id), []).append(user)
    finally:
        session.close()

    processes = _process_map()
    state = _update_pid_state(lines, processes)
    rows = []
    totals = {
        "instances": len(lines),
        "running": 0,
        "connections": 0,
        "upload_bps": 0,
        "download_bps": 0,
        "bytes_in": 0,
        "bytes_out": 0,
        "pid_changes": 0,
    }

    for line in lines:
        process = processes.get(line.id) or {}
        pid = process.get("pid")
        line_users = users_by_line.get(line.id, [])
        active_users = [u for u in line_users if int(u.status or 0) == 1]
        bytes_in = sum(int(u.bytes_in or 0) for u in line_users)
        bytes_out = sum(int(u.bytes_out or 0) for u in line_users)
        connections, conn_error = _fetch_connections(line.id) if pid else ([], "not running")
        active_upload = sum(int(c.get("upload") or 0) for c in connections)
        active_download = sum(int(c.get("download") or 0) for c in connections)
        upload_bps, download_bps = _line_rates(line.id, active_upload, active_download)
        monitor_state = state.get(str(line.id), {})
        listen_count = _listen_count(pid)
        running = bool(pid and listen_count > 0)
        if running:
            totals["running"] += 1
        totals["connections"] += len(connections)
        totals["upload_bps"] += upload_bps
        totals["download_bps"] += download_bps
        totals["bytes_in"] += bytes_in
        totals["bytes_out"] += bytes_out
        totals["pid_changes"] += int(monitor_state.get("changes") or 0)
        rows.append({
            "line_id": line.id,
            "name": line.name,
            "public_ip": line.public_ip,
            "pid": pid,
            "running": running,
            "status": "running" if running else "down",
            "listen_count": listen_count,
            "controller_port": _controller_port(line.id),
            "connections": len(connections),
            "upload_bps": upload_bps,
            "download_bps": download_bps,
            "bytes_in": bytes_in,
            "bytes_out": bytes_out,
            "active_users": len(active_users),
            "total_users": len(line_users),
            "pid_changes": int(monitor_state.get("changes") or 0),
            "last_changed_at": monitor_state.get("last_changed_at") or "",
            "started_at": process.get("create_time") or "",
            "config": _instance_config_path(line.id),
            "error": "" if running else conn_error,
        })

    return {
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "state_path": str(STATE_PATH),
        "totals": totals,
        "rows": rows,
    }
