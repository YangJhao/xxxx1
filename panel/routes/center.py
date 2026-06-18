"""Center API for 42IP control center."""
import base64
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
    try:
        connections = len(psutil.net_connections(kind="inet"))
    except Exception:
        connections = 0
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


@bp.route("/nodes", methods=["GET", "POST"])
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
            item["node_count"] = len(line.users)
            item["connection_count"] = sum(
                int((live_map.get(user.id) or {}).get("connections") or 0)
                for user in line.users
            )
            rows.append(item)
        return jsonify({"ok": True, "data": rows})
    finally:
        s.close()
