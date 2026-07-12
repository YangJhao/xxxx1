"""Monitoring, statistics, and panel settings APIs."""
import os
import shutil
import subprocess
import sys
import threading
import time
import urllib.request
import zipfile
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

import psutil
from flask import Blueprint, jsonify, request, send_file

from config import PANEL_CFG_FILE, PANEL_PORT, PROXY_LOG_DIR, PROJECT_DIR, SING_BOX_CFG, get_panel_bind_ip, set_panel_bind_ip
from models import AdminUser, DB_PATH, Line, ProxyUser, TrafficLog, get_session
from routes.auth import login_required
from services import proxy_manager
from services.singbox_monitor import instance_status
from services.system_info import (
    clear_cache as clear_sys_cache,
    get_all_proxy_connections,
    get_internal_ips,
    get_ip_region,
    get_public_ip,
    get_system_info,
)
from services.traffic_collector import collect_once, collector_status

bp = Blueprint("monitor", __name__, url_prefix="/api")

LOG_TAIL_LINES = 200
_probe_last = {"time": 0.0, "recv": 0, "sent": 0}
BACKUP_DIR = Path(PROJECT_DIR) / "data" / "backups"
RESTORE_DIR = Path(PROJECT_DIR) / "data" / "restore_uploads"
UPGRADE_DIR = Path(PROJECT_DIR) / "data" / "upgrade_uploads"
UPGRADE_SKIP_PREFIXES = (
    ".git/",
    ".agents/",
    ".codex/",
    "data/",
    "panel/__pycache__/",
    "panel/routes/__pycache__/",
    "panel/services/__pycache__/",
    "3proxy/logs/",
)
UPGRADE_SKIP_NAMES = {
    "data/panel.db",
    "data/panel_cfg.json",
    "sing-box/sing-box.log",
    "3proxy/3proxy.pid",
    "sing-box/sing-box.pid",
}
DEFAULT_GIT_UPGRADE_URL = os.environ.get(
    "IPWIN42_UPGRADE_URL",
    "https://codeload.github.com/YangJhao/xxxx1/zip/refs/heads/lite33-protect-buttons",
)


def _timestamp() -> str:
    return datetime.now().strftime("%Y%m%d-%H%M%S")


def _safe_backup_name(prefix: str, suffix: str) -> str:
    return f"{prefix}-{_timestamp()}{suffix}"


def _backup_items() -> list[tuple[Path, str]]:
    items = [(Path(DB_PATH), "data/panel.db")]
    optional = [
        (Path(PANEL_CFG_FILE), "data/panel_cfg.json"),
        (Path(SING_BOX_CFG), "sing-box/config.json"),
    ]
    for src, arc in optional:
        if src.exists():
            items.append((src, arc))
    return items


def _create_backup_zip() -> Path:
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    target = BACKUP_DIR / _safe_backup_name("42IPwin-data", ".zip")
    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for src, arc in _backup_items():
            if src.exists():
                zf.write(src, arc)
        zf.writestr("backup_info.txt", f"42IPwin data backup\ncreated_at={datetime.now().isoformat()}\n")
    return target


def _safe_zip_members(zf: zipfile.ZipFile) -> list[zipfile.ZipInfo]:
    raw_names = [info.filename.replace("\\", "/").lstrip("/") for info in zf.infolist()]
    roots = {name.split("/", 1)[0] for name in raw_names if "/" in name and name.split("/", 1)[0]}
    strip_root = next(iter(roots)) if len(roots) == 1 else ""
    members = []
    for info in zf.infolist():
        name = info.filename.replace("\\", "/").lstrip("/")
        parts = [p for p in name.split("/") if p]
        if not parts or any(p == ".." for p in parts):
            continue
        if parts[0].lower() in {"42ipwin", "42ipwin-main", "42ipwin-windows-deploy"} or parts[0] == strip_root:
            name = "/".join(parts[1:])
        if not name or name.endswith("/"):
            continue
        info.filename = name
        members.append(info)
    return members


def _should_skip_upgrade_member(name: str) -> bool:
    norm = name.replace("\\", "/").lstrip("/")
    if norm in UPGRADE_SKIP_NAMES:
        return True
    return any(norm.startswith(prefix) for prefix in UPGRADE_SKIP_PREFIXES)


def _backup_program_files(paths: list[Path]) -> Path:
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    target = BACKUP_DIR / _safe_backup_name("before-upgrade-program", ".zip")
    root = Path(PROJECT_DIR).resolve()
    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path in paths:
            if path.exists() and path.is_file():
                zf.write(path, path.resolve().relative_to(root).as_posix())
        zf.writestr("backup_info.txt", f"42IPwin program backup\ncreated_at={datetime.now().isoformat()}\n")
    return target


def _apply_upgrade_zip(src: Path) -> dict:
    if not zipfile.is_zipfile(src):
        raise ValueError("升级包格式错误，只支持 .zip")
    root = Path(PROJECT_DIR).resolve()
    applied = []
    skipped = []
    tasks = []
    with zipfile.ZipFile(src, "r") as zf:
        members = _safe_zip_members(zf)
        for info in members:
            name = info.filename
            if _should_skip_upgrade_member(name):
                skipped.append(name)
                continue
            target = (root / name).resolve()
            if root not in target.parents and target != root:
                skipped.append(name)
                continue
            tasks.append((info, target))
        targets = [target for _, target in tasks]
        backup_path = _backup_program_files(targets)
        for info, target in tasks:
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as rf, open(target, "wb") as wf:
                shutil.copyfileobj(rf, wf)
            applied.append(info.filename)
    return {
        "applied_count": len(applied),
        "skipped_count": len(skipped),
        "applied": applied[:80],
        "skipped": skipped[:80],
        "backup": str(backup_path),
        "restart_required": True,
    }


def _download_upgrade_package(url: str) -> Path:
    if not url.lower().startswith(("http://", "https://")):
        raise ValueError("升级地址必须以 http:// 或 https:// 开头")
    UPGRADE_DIR.mkdir(parents=True, exist_ok=True)
    target = UPGRADE_DIR / _safe_backup_name("upgrade-url", ".zip")
    req = urllib.request.Request(url, headers={"User-Agent": "42IPwin-updater/1.0"})
    with urllib.request.urlopen(req, timeout=60) as resp, open(target, "wb") as wf:
        shutil.copyfileobj(resp, wf)
    if target.stat().st_size <= 0:
        raise ValueError("下载到的升级包为空")
    return target


def _schedule_panel_restart(delay: float = 1.0):
    raise RuntimeError("网页重启已禁用，请使用服务器守护脚本或 WinRM 重启面板")


def _restore_from_db_file(src: Path):
    if not src.exists() or src.stat().st_size <= 0:
        raise ValueError("数据库文件无效")
    if src.suffix.lower() not in (".db", ".sqlite", ".sqlite3"):
        raise ValueError("只支持 panel.db / sqlite 数据库文件")
    shutil.copy2(DB_PATH, BACKUP_DIR / _safe_backup_name("before-restore-panel", ".db"))
    shutil.copy2(src, DB_PATH)


def _restore_from_zip(src: Path):
    if not zipfile.is_zipfile(src):
        raise ValueError("备份包格式错误")
    shutil.copy2(_create_backup_zip(), BACKUP_DIR / _safe_backup_name("before-restore-data", ".zip"))
    with zipfile.ZipFile(src, "r") as zf:
        names = set(zf.namelist())
        db_name = "data/panel.db" if "data/panel.db" in names else "panel.db" if "panel.db" in names else ""
        if not db_name:
            raise ValueError("备份包里没有 data/panel.db")
        extract_map = {
            db_name: Path(DB_PATH),
            "data/panel_cfg.json": Path(PANEL_CFG_FILE),
            "sing-box/config.json": Path(SING_BOX_CFG),
        }
        for member, target in extract_map.items():
            if member not in names:
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(member) as rf, open(target, "wb") as wf:
                shutil.copyfileobj(rf, wf)


def _disk_probe(path):
    try:
        usage = psutil.disk_usage(path)
        return {
            "path": path,
            "percent": usage.percent,
            "used": usage.used,
            "total": usage.total,
            "free": usage.free,
        }
    except Exception:
        return None


@bp.route("/status", methods=["GET"])
@login_required
def status():
    return jsonify({"ok": True, "data": proxy_manager.health_check()})


@bp.route("/proxy/start", methods=["POST"])
@login_required
def start_proxy():
    try:
        pid = proxy_manager.start()
        return jsonify({"ok": True, "data": {"pid": pid}})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@bp.route("/proxy/stop", methods=["POST"])
@login_required
def stop_proxy():
    ok = proxy_manager.stop()
    return jsonify({"ok": ok})


@bp.route("/proxy/reload", methods=["POST"])
@login_required
def reload_proxy():
    try:
        data = request.get_json(silent=True) or {}
        force = bool(data.get("force"))
        if force:
            pid = proxy_manager.restart_config()
            return jsonify({"ok": True, "data": {"pid": pid, "restarted": True}})
        status = proxy_manager.reload_config_no_restart()
        return jsonify({"ok": bool(status.get("ok")), "data": status})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@bp.route("/stats/overview", methods=["GET"])
@login_required
def overview():
    s = get_session()
    try:
        line_count = s.query(Line).count()
        line_active = s.query(Line).filter_by(status=1).count()
        user_count = s.query(ProxyUser).count()
        user_active = s.query(ProxyUser).filter_by(status=1).count()
        admin_count = s.query(AdminUser).count()

        try:
            collect_once()
        except Exception:
            pass

        now_dt = datetime.now()
        soon_dt = now_dt + timedelta(days=3)
        node_unsold = s.query(ProxyUser).filter_by(status=1).count()
        node_sold = 0
        node_disabled = s.query(ProxyUser).filter_by(status=0).count()
        node_expiring = (
            s.query(ProxyUser)
            .filter(ProxyUser.expire_at.isnot(None), ProxyUser.expire_at >= now_dt, ProxyUser.expire_at <= soon_dt)
            .count()
        )
        node_expired = (
            s.query(ProxyUser)
            .filter(ProxyUser.expire_at.isnot(None), ProxyUser.expire_at < now_dt)
            .count()
        )

        today_prefix = datetime.now().strftime("%Y-%m-%d")
        today_logs = s.query(TrafficLog).filter(TrafficLog.hour.like(f"{today_prefix}%")).all()
        per_user_today = defaultdict(lambda: [0, 0])
        for row in today_logs:
            if row.bytes_in > per_user_today[row.user_id][0]:
                per_user_today[row.user_id][0] = row.bytes_in
            if row.bytes_out > per_user_today[row.user_id][1]:
                per_user_today[row.user_id][1] = row.bytes_out
        today_in = sum(v[0] for v in per_user_today.values())
        today_out = sum(v[1] for v in per_user_today.values())

        now = datetime.now().replace(minute=0, second=0, microsecond=0)
        hours = [(now - timedelta(hours=i)).strftime("%Y-%m-%d %H") for i in range(23, -1, -1)]
        trend_in = []
        trend_out = []
        for hour in hours:
            logs = s.query(TrafficLog).filter_by(hour=hour).all()
            trend_in.append(max((row.bytes_in for row in logs), default=0))
            trend_out.append(max((row.bytes_out for row in logs), default=0))

        line_stats = []
        for line in s.query(Line).all():
            bytes_in = sum((u.bytes_in or 0) for u in line.users)
            bytes_out = sum((u.bytes_out or 0) for u in line.users)
            line_stats.append({
                "id": line.id,
                "name": line.name,
                "public_ip": line.public_ip,
                "socks_port": line.socks_port,
                "status": line.status,
                "bytes_in": bytes_in,
                "bytes_out": bytes_out,
            })

        return jsonify({"ok": True, "data": {
            "line_count": line_count,
            "line_active": line_active,
            "user_count": user_count,
            "user_active": user_active,
            "admin_count": admin_count,
            "customer_count": admin_count,
            "sale_total": 0,
            "node_unsold": node_unsold,
            "node_sold": node_sold,
            "node_disabled": node_disabled,
            "node_expiring": node_expiring,
            "node_expired": node_expired,
            "today_in": today_in,
            "today_out": today_out,
            "trend_hours": hours,
            "trend_in": trend_in,
            "trend_out": trend_out,
            "line_stats": line_stats,
        }})
    finally:
        s.close()


@bp.route("/probe", methods=["GET"])
@login_required
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
    project_root = os.path.abspath(str(PROJECT_DIR))
    system_root = os.environ.get("SystemDrive", "C:") + "\\"
    project_drive = os.path.splitdrive(project_root)[0]
    project_disk_path = (project_drive + "\\") if project_drive else project_root
    disk_system = _disk_probe(system_root)
    disk_project = _disk_probe(project_disk_path)
    try:
        conn_rows = psutil.net_connections(kind="inet")
        connections = len(conn_rows)
        established_connections = sum(1 for conn in conn_rows if str(conn.status).upper() == "ESTABLISHED")
        listen_connections = sum(1 for conn in conn_rows if str(conn.status).upper() == "LISTEN")
        time_wait_connections = sum(1 for conn in conn_rows if str(conn.status).upper() == "TIME_WAIT")
    except Exception:
        connections = 0
        established_connections = 0
        listen_connections = 0
        time_wait_connections = 0
    cpu_percent = psutil.cpu_percent(interval=0.05)

    return jsonify({"ok": True, "data": {
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "cpu_percent": cpu_percent,
        "memory_percent": mem.percent,
        "memory_used": mem.used,
        "memory_total": mem.total,
        "memory_available": mem.available,
        "connections": connections,
        "machine_connections_total": connections,
        "machine_connections_established": established_connections,
        "machine_connections_listen": listen_connections,
        "machine_connections_time_wait": time_wait_connections,
        "net_rx_bps": rx_bps,
        "net_tx_bps": tx_bps,
        "net_bytes_recv": net.bytes_recv,
        "net_bytes_sent": net.bytes_sent,
        "disk_system": disk_system,
        "disk_project": disk_project,
        "disk_percent": (disk_project or disk_system or {}).get("percent", 0),
        "disk_used": (disk_project or disk_system or {}).get("used", 0),
        "disk_total": (disk_project or disk_system or {}).get("total", 0),
    }})


@bp.route("/singbox/instances", methods=["GET"])
@login_required
def singbox_instances():
    try:
        return jsonify({"ok": True, "data": instance_status()})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


@bp.route("/stats/log", methods=["GET"])
@login_required
def tail_log():
    n = request.args.get("n", LOG_TAIL_LINES, type=int)
    log_path = os.path.join(PROXY_LOG_DIR, "3proxy.log")
    if not os.path.exists(log_path):
        log_path = os.path.join(PROJECT_DIR, "sing-box", "sing-box.log")
    if not os.path.exists(log_path):
        return jsonify({"ok": True, "data": []})
    try:
        with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
        return jsonify({"ok": True, "data": lines[-n:]})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@bp.route("/traffic/status", methods=["GET"])
@login_required
def traffic_status():
    return jsonify({"ok": True, "data": collector_status()})


@bp.route("/stats/user/<int:uid>", methods=["GET"])
@login_required
def user_traffic(uid):
    s = get_session()
    try:
        user = s.query(ProxyUser).get(uid)
        if not user:
            return jsonify({"ok": False, "error": "节点不存在"}), 404
        logs = s.query(TrafficLog).filter_by(user_id=uid).order_by(TrafficLog.hour.desc()).limit(168).all()
        logs.reverse()
        return jsonify({"ok": True, "data": {
            "user": user.to_dict(hide_password=True),
            "hours": [row.hour for row in logs],
            "in": [row.bytes_in for row in logs],
            "out": [row.bytes_out for row in logs],
        }})
    finally:
        s.close()


@bp.route("/system/info", methods=["GET"])
@login_required
def system_info():
    return jsonify({"ok": True, "data": get_system_info(cached=True)})


@bp.route("/system/public-ip", methods=["GET"])
@login_required
def public_ip():
    return jsonify({"ok": True, "data": get_public_ip()})


@bp.route("/system/internal-ips", methods=["GET"])
@login_required
def internal_ips():
    return jsonify({"ok": True, "data": get_internal_ips()})


@bp.route("/system/region", methods=["GET"])
@login_required
def region_info():
    ip = request.args.get("ip")
    data = get_ip_region(ip) if ip else {}
    return jsonify({"ok": True, "data": data})


@bp.route("/system/connections", methods=["GET"])
@login_required
def connection_count():
    return jsonify({"ok": True, "data": get_all_proxy_connections()})


@bp.route("/system/refresh", methods=["POST"])
@login_required
def refresh_system_info():
    clear_sys_cache()
    return jsonify({"ok": True, "data": get_system_info(cached=False)})


@bp.route("/settings/info", methods=["GET"])
@login_required
def settings_info():
    internal_ips = get_internal_ips()
    pub_ip_data = get_public_ip()
    bind_ip = get_panel_bind_ip()
    return jsonify({"ok": True, "data": {
        "bind_ip": bind_ip,
        "panel_port": PANEL_PORT,
        "internal_ips": internal_ips,
        "public_ip": pub_ip_data,
    }})


@bp.route("/settings/bind-ip", methods=["POST"])
@login_required
def settings_bind_ip():
    data = request.get_json(silent=True) or {}
    ip = (data.get("bind_ip") or "0.0.0.0").strip()
    set_panel_bind_ip(ip)
    return jsonify({"ok": True, "data": {"bind_ip": ip}})


@bp.route("/settings/restart-panel", methods=["POST"])
@login_required
def restart_panel():
    try:
        _schedule_panel_restart()
        return jsonify({"ok": True, "data": {"message": "???????? 3-5 ???????"}})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


@bp.route("/settings/backup", methods=["GET"])
@login_required
def settings_backup():
    try:
        path = _create_backup_zip()
        return send_file(path, as_attachment=True, download_name=path.name, mimetype="application/zip")
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


@bp.route("/settings/export-db", methods=["GET"])
@login_required
def settings_export_db():
    try:
        if not Path(DB_PATH).exists():
            return jsonify({"ok": False, "error": "数据库不存在"}), 404
        return send_file(DB_PATH, as_attachment=True, download_name=_safe_backup_name("panel", ".db"), mimetype="application/octet-stream")
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


@bp.route("/settings/restore", methods=["POST"])
@login_required
def settings_restore():
    file = request.files.get("file")
    if not file or not file.filename:
        return jsonify({"ok": False, "error": "请选择备份文件"}), 400
    filename = os.path.basename(file.filename)
    ext = Path(filename).suffix.lower()
    if ext not in (".zip", ".db", ".sqlite", ".sqlite3"):
        return jsonify({"ok": False, "error": "只支持 .zip 或 .db 备份文件"}), 400
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    RESTORE_DIR.mkdir(parents=True, exist_ok=True)
    upload_path = RESTORE_DIR / f"{_timestamp()}-{filename}"
    try:
        file.save(upload_path)
        if ext == ".zip":
            _restore_from_zip(upload_path)
        else:
            _restore_from_db_file(upload_path)
        return jsonify({"ok": True, "data": {"message": "数据已恢复，请重启面板或刷新页面后使用。"}})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


@bp.route("/settings/upgrade", methods=["POST"])
@login_required
def settings_upgrade_upload():
    file = request.files.get("file")
    if not file or not file.filename:
        return jsonify({"ok": False, "error": "请选择升级包"}), 400
    filename = os.path.basename(file.filename)
    if Path(filename).suffix.lower() != ".zip":
        return jsonify({"ok": False, "error": "升级包只支持 .zip 文件"}), 400
    UPGRADE_DIR.mkdir(parents=True, exist_ok=True)
    upload_path = UPGRADE_DIR / f"{_timestamp()}-{filename}"
    try:
        file.save(upload_path)
        result = _apply_upgrade_zip(upload_path)
        return jsonify({"ok": True, "data": result})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


@bp.route("/settings/upgrade-url", methods=["POST"])
@login_required
def settings_upgrade_url():
    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()
    if not url:
        return jsonify({"ok": False, "error": "请输入升级包 URL"}), 400
    try:
        package = _download_upgrade_package(url)
        result = _apply_upgrade_zip(package)
        result["package"] = str(package)
        return jsonify({"ok": True, "data": result})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


@bp.route("/settings/upgrade-git", methods=["POST"])
@login_required
def settings_upgrade_git():
    try:
        package = _download_upgrade_package(DEFAULT_GIT_UPGRADE_URL)
        result = _apply_upgrade_zip(package)
        result["package"] = str(package)
        result["url"] = DEFAULT_GIT_UPGRADE_URL
        return jsonify({"ok": True, "data": result})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


@bp.route("/settings/backups", methods=["GET"])
@login_required
def settings_backups():
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    rows = []
    for path in sorted(BACKUP_DIR.glob("*"), key=lambda p: p.stat().st_mtime, reverse=True)[:30]:
        if not path.is_file():
            continue
        rows.append({
            "name": path.name,
            "size": path.stat().st_size,
            "created_at": datetime.fromtimestamp(path.stat().st_mtime).isoformat(),
        })
    return jsonify({"ok": True, "data": rows})
