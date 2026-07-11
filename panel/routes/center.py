"""Center API for 42IP control center."""
import base64
import subprocess
import time
from functools import wraps

import psutil
from flask import Blueprint, jsonify, request
from sqlalchemy.orm import joinedload, selectinload

from models import AdminUser, Line, ProxyUser, get_session
from routes.users import _create_user_v3
from services.traffic_collector import snapshot_connections

bp = Blueprint("center", __name__, url_prefix="/api/center")
_probe_last = {"time": 0.0, "recv": 0, "sent": 0}
_conn_count_cache = {"time": 0.0, "count": 0}


def _basic_credentials():
    header = request.headers.get("Authorization", "")
    if not header.lower().startswith("basic "):
        return "", ""
    try:
        raw = base64.b64decode(header.split(" ", 1)[1]).decode("utf-8", "replace")
        username, password = raw.split(":", 1)
        return username.strip(), password
    except Exception:
        return "", ""


def center_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        username, password = _basic_credentials()
        if not username:
            data = request.get_json(silent=True) or {}
            username = (data.get("username") or "").strip()
            password = data.get("password") or ""
        s = get_session()
        try:
            admin = s.query(AdminUser).filter_by(username=username).first()
            if not admin or not admin.check_password(password) or not admin.status:
                return jsonify({"ok": False, "error": "center auth failed"}), 401
        finally:
            s.close()
        return func(*args, **kwargs)

    return wrapper


def _system_connection_count() -> int:
    now = time.time()
    if now - float(_conn_count_cache.get("time") or 0) < 15:
        return int(_conn_count_cache.get("count") or 0)
    try:
        if psutil.WINDOWS:
            proc = subprocess.run(
                ["netstat", "-ano", "-p", "tcp"],
                capture_output=True,
                text=True,
                timeout=2,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            count = sum(1 for line in proc.stdout.splitlines() if line.lstrip().startswith("TCP"))
        else:
            proc = subprocess.run(["ss", "-Htun"], capture_output=True, text=True, timeout=2)
            count = sum(1 for line in proc.stdout.splitlines() if line.strip())
        _conn_count_cache.update({"time": now, "count": count})
        return count
    except Exception:
        return int(_conn_count_cache.get("count") or 0)


@bp.route("/status", methods=["GET", "POST"])
@center_required
def status():
    s = get_session()
    try:
        return jsonify({"ok": True, "data": {
            "lines": s.query(Line).count(),
            "nodes": s.query(ProxyUser).count(),
            "active_lines": s.query(Line).filter_by(status=1).count(),
            "active_nodes": s.query(ProxyUser).filter_by(status=1).count(),
        }})
    finally:
        s.close()


@bp.route("/probe", methods=["GET", "POST"])
@center_required
def probe():
    global _probe_last
    now = time.time()
    net = psutil.net_io_counters()
    elapsed = max(now - float(_probe_last.get("time") or 0), 0.001)
    if not _probe_last.get("time"):
        rx_bps = 0
        tx_bps = 0
    else:
        rx_bps = max(0, int((net.bytes_recv - int(_probe_last.get("recv") or 0)) / elapsed))
        tx_bps = max(0, int((net.bytes_sent - int(_probe_last.get("sent") or 0)) / elapsed))
    _probe_last = {"time": now, "recv": net.bytes_recv, "sent": net.bytes_sent}
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage("/")
    connections = _system_connection_count()
    return jsonify({"ok": True, "data": {
        "cpu_percent": psutil.cpu_percent(interval=0.05),
        "memory_percent": mem.percent,
        "memory_used": mem.used,
        "memory_total": mem.total,
        "disk_percent": disk.percent,
        "disk_used": disk.used,
        "disk_total": disk.total,
        "connections": connections,
        "net_rx_bps": rx_bps,
        "net_tx_bps": tx_bps,
    }})


@bp.route("/nodes", methods=["GET"])
@center_required
def nodes():
    s = get_session()
    try:
        live_map = snapshot_connections()
        rows = []
        for user in s.query(ProxyUser).options(joinedload(ProxyUser.line)).order_by(ProxyUser.id.desc()).all():
            item = user.to_dict()
            live = live_map.get(user.id, {})
            item["connections"] = int(live.get("connections") or 0)
            item["live_upload"] = int(live.get("upload") or 0)
            item["live_download"] = int(live.get("download") or 0)
            rows.append(item)
        return jsonify({"ok": True, "data": rows})
    finally:
        s.close()


@bp.route("/nodes", methods=["POST"])
@center_required
def create_node():
    return _create_user_v3()


@bp.route("/lines", methods=["GET", "POST"])
@center_required
def lines():
    s = get_session()
    try:
        live_map = snapshot_connections()
        rows = []
        for line in s.query(Line).options(selectinload(Line.users)).order_by(Line.name, Line.id).all():
            item = line.to_dict()
            active_users = [user for user in (line.users or []) if int(user.status or 0) == 1]
            item["node_count"] = len(active_users)
            item["connection_count"] = sum(
                int((live_map.get(user.id) or {}).get("connections") or 0)
                for user in active_users
            )
            rows.append(item)
        return jsonify({"ok": True, "data": rows})
    finally:
        s.close()
