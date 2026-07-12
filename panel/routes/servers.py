"""Managed server APIs for the lightweight control page."""
import os
import csv
import json
import http.cookiejar
import posixpath
import re
import shlex
import socket
import tarfile
import tempfile
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace

from flask import Blueprint, jsonify, request, session

from models import Line, ManagedServer, ProxyUser, get_session
from routes.auth import login_required
from services.audit_logger import write_operation_log

bp = Blueprint("servers", __name__, url_prefix="/api/servers")

IP_SPLIT_RE = re.compile(r"[\s,;，；]+")
PROJECT_DIR = Path(__file__).resolve().parents[2]
INSTALL_SCRIPT = PROJECT_DIR / "install_lite.sh"
TAR_EXCLUDES = {".git", "__pycache__", "data/backups", "control_center", "control_center_old_20260702-013419"}
TAR_INCLUDE_ROOTS = ("panel", "install_lite.sh", "restore_macvlans.py", "sing-box/sing-box")


def _operator():
    return (session.get("admin_name") or "admin").strip() or "admin"


def _log(action, detail):
    write_operation_log(_operator(), "服务器管理", action, detail, request.remote_addr or "")


def _parse_ips(value):
    if isinstance(value, list):
        raw_items = value
    else:
        raw_items = IP_SPLIT_RE.split(str(value or ""))
    seen = set()
    ips = []
    for item in raw_items:
        ip = str(item or "").strip()
        if not ip or ip in seen:
            continue
        seen.add(ip)
        ips.append(ip)
    return ips


def _truthy(value) -> bool:
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in {"1", "true", "yes", "on", "y"}


def _server_counts(session, ip: str) -> dict:
    text = (ip or "").strip()
    if not text:
        return {"line_count": 0, "inbound_count": 0, "line_ids": [], "inbound_assignments": []}
    lines = session.query(Line).filter(Line.public_ip == text).all()
    line_ids = [line.id for line in lines]
    inbound_count = 0
    assignments = []
    if line_ids:
        users = (
            session.query(ProxyUser)
            .filter(ProxyUser.line_id.in_(line_ids))
            .order_by(ProxyUser.id.desc())
            .all()
        )
        inbound_count = len(users)
        seen = set()
        for user in users:
            owner = (user.owner_name or user.username or "-").strip()
            project = (user.project_name or "-").strip()
            label = f"{owner}|{project}"
            if label in seen:
                continue
            seen.add(label)
            assignments.append(label)
            if len(assignments) >= 1000:
                break
    return {
        "line_count": len(line_ids),
        "inbound_count": inbound_count,
        "line_ids": line_ids,
        "inbound_assignments": assignments,
    }


def _local_server_ips() -> set[str]:
    ips = {"127.0.0.1", "localhost"}
    try:
        hostname = socket.gethostname()
        ips.add(socket.gethostbyname(hostname))
        for item in socket.getaddrinfo(hostname, None, socket.AF_INET):
            ips.add(item[4][0])
    except Exception:
        pass
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            ips.add(sock.getsockname()[0])
    except Exception:
        pass
    for key in ("PUBLIC_IP", "IPWIN42_PUBLIC_IP", "SERVER_PUBLIC_IP"):
        value = (os.environ.get(key) or "").strip()
        if value:
            ips.add(value)
    return ips


def _split_server_import_line(line: str) -> list[str]:
    text = (line or "").strip()
    if not text:
        return []
    if "|" in text:
        return [part.strip() for part in text.split("|")]
    if "," in text:
        return [part.strip() for part in next(csv.reader([text]))]
    return re.split(r"\s+", text)


def _parse_server_import_rows(text: str, defaults: dict) -> tuple[list[dict], list[str]]:
    rows = []
    errors = []
    seen = set()
    default_port = int(defaults.get("port") or defaults.get("ssh_port") or 22)
    default_username = (defaults.get("username") or defaults.get("account") or "root").strip() or "root"
    default_password = str(defaults.get("password") or "")
    default_group = str(defaults.get("group_name") or defaults.get("group") or "").strip()
    default_note = str(defaults.get("note") or "")
    for line_no, raw_line in enumerate((text or "").splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = _split_server_import_line(line)
        if not parts:
            continue
        first = (parts[0] or "").strip().lower()
        if first in {"ip", "server", "server_ip", "服务器ip", "服务器"}:
            continue
        ip = (parts[0] if len(parts) > 0 else "").strip()
        if not ip:
            errors.append(f"第 {line_no} 行缺少 IP")
            continue
        try:
            port = int((parts[1] if len(parts) > 1 and parts[1] else default_port) or 22)
        except Exception:
            errors.append(f"第 {line_no} 行端口不是数字")
            continue
        if port < 1 or port > 65535:
            errors.append(f"第 {line_no} 行端口超出 1-65535")
            continue
        row = {
            "ip": ip,
            "ssh_port": port,
            "username": (parts[2] if len(parts) > 2 and parts[2] else default_username).strip() or "root",
            "password": str(parts[3] if len(parts) > 3 and parts[3] else default_password),
            "group_name": str(parts[4] if len(parts) > 4 and parts[4] else default_group).strip(),
            "note": str(parts[5] if len(parts) > 5 and parts[5] else default_note).strip(),
        }
        key = (row["ip"], row["ssh_port"])
        if key in seen:
            continue
        seen.add(key)
        rows.append(row)
    return rows, errors


def _remote_server_counts(server) -> dict:
    if server.install_status != "installed" or getattr(server, "is_local", False):
        return {}
    base = f"http://{server.ip}:18080"
    cj = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

    def post_json(url, body):
        req = urllib.request.Request(
            url,
            data=json.dumps(body).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with opener.open(req, timeout=4) as resp:
            return json.loads(resp.read().decode("utf-8", "replace"))

    login = post_json(f"{base}/api/login", {"username": "admin", "password": "admin123"})
    if not login.get("ok"):
        raise RuntimeError(login.get("error") or "login failed")
    with opener.open(f"{base}/api/users?local_only=1", timeout=4) as resp:
        users = json.loads(resp.read().decode("utf-8", "replace")).get("data") or []
    assignments = []
    seen = set()
    for user in users:
        owner = (user.get("owner_name") or user.get("username") or "-").strip()
        project = (user.get("project_name") or "-").strip()
        label = f"{owner}|{project}"
        if label in seen:
            continue
        seen.add(label)
        assignments.append(label)
        if len(assignments) >= 1000:
            break
    return {
        "inbound_count": len(users),
        "inbound_assignments": assignments,
        "remote_count_ok": True,
    }


def _server_counts_from_users(users) -> dict:
    assignments = []
    seen = set()
    for user in users or []:
        owner = (user.get("owner_name") or user.get("username") or "-").strip()
        project = (user.get("project_name") or "-").strip()
        label = f"{owner}|{project}"
        if label in seen:
            continue
        seen.add(label)
        assignments.append(label)
        if len(assignments) >= 1000:
            break
    return {
        "inbound_count": len(users or []),
        "inbound_assignments": assignments,
        "remote_count_ok": True,
        "remote_count_source": "live",
    }


def _remote_server_counts_via_ssh(server) -> dict:
    ssh = _ssh_connect(server, timeout=12)
    try:
        command = r"""python3 - <<'PY'
import http.cookiejar
import json
import urllib.request

base = 'http://127.0.0.1:18080'
cj = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

def post(path, body):
    raw = json.dumps(body).encode('utf-8')
    req = urllib.request.Request(base + path, data=raw, headers={'Content-Type': 'application/json'}, method='POST')
    with opener.open(req, timeout=12) as resp:
        return json.loads(resp.read().decode('utf-8', 'replace'))

login = post('/api/login', {'username': 'admin', 'password': 'admin123'})
if not login.get('ok'):
    raise SystemExit('login failed: ' + (login.get('error') or 'unknown'))
with opener.open(base + '/api/users?local_only=1', timeout=12) as resp:
    print(resp.read().decode('utf-8', 'replace'))
PY"""
        code, out, err = _run(ssh, command, timeout=35)
        if code != 0:
            raise RuntimeError((err or out or f"ssh count exit {code}")[-1200:])
        payload = json.loads(out.strip() or "{}")
        return _server_counts_from_users(payload.get("data") or [])
    finally:
        ssh.close()


def _detect_lite_install(row) -> tuple[str, str, str, dict]:
    status = "error"
    install_status = "idle"
    messages = []
    counts = {}

    try:
        ssh = _ssh_connect(row, timeout=12)
        try:
            code, out, err = _run(
                ssh,
                "test -f /opt/42IPwin/panel/app.py && "
                "systemctl is-active 42ipwin 2>/dev/null || true; "
                "curl -sS -o /dev/null -w 'HTTP:%{http_code}' --max-time 6 http://127.0.0.1:18080/login || true",
                timeout=30,
            )
            text = f"{out}\n{err}".strip()
            messages.append(text)
            if "/opt/42IPwin" in text or "active" in text or "HTTP:200" in text or "HTTP:302" in text:
                status = "online"
            if "active" in text and ("HTTP:200" in text or "HTTP:302" in text):
                install_status = "installed"
        finally:
            ssh.close()
    except Exception as exc:
        messages.append(f"ssh: {exc}")

    if install_status == "installed":
        try:
            counts = _remote_server_counts(row)
        except Exception as exc:
            messages.append(f"panel: {exc}")
            counts = {}

    detail = "; ".join(part for part in messages if part).strip()
    if install_status == "installed":
        detail = "已检测到 42 轻量面板，入站映射已刷新"
    return status, install_status, detail[-1200:], counts


def _ssh_connect(server, timeout=12):
    try:
        import paramiko
    except Exception as exc:
        raise RuntimeError(f"缺少 SSH 依赖 paramiko：{exc}") from exc

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        server.ip,
        port=int(server.ssh_port or 22),
        username=server.username or "root",
        password=server.password or "",
        timeout=timeout,
        banner_timeout=timeout,
        auth_timeout=timeout,
        look_for_keys=False,
        allow_agent=False,
    )
    return client


def _run(ssh, command, timeout=900):
    stdin, stdout, stderr = ssh.exec_command(command, timeout=timeout)
    out = stdout.read().decode("utf-8", "replace")
    err = stderr.read().decode("utf-8", "replace")
    code = stdout.channel.recv_exit_status()
    return code, out, err


def _run_quick(ssh, command, timeout=30):
    stdin, stdout, stderr = ssh.exec_command(command, timeout=timeout)
    code = stdout.channel.recv_exit_status()
    out = stdout.read().decode("utf-8", "replace")
    err = stderr.read().decode("utf-8", "replace")
    return code, out, err


def _verify_lite_ready(ssh, timeout=900, interval=8):
    deadline = time.time() + timeout
    last_output = ""
    check_command = r"""
active=$(systemctl is-active 42ipwin 2>/dev/null || true)
http=0
python3 - <<'PY' >/tmp/42ipwin-lite-http-check 2>/dev/null
import urllib.request
try:
    urllib.request.urlopen('http://127.0.0.1:18080/login', timeout=3).read(1)
    print('1')
except Exception:
    print('0')
PY
http=$(cat /tmp/42ipwin-lite-http-check 2>/dev/null || echo 0)
echo "STATUS:${active}:${http}"
"""
    while time.time() < deadline:
        time.sleep(interval)
        code, out, err = _run_quick(ssh, check_command, timeout=30)
        last_output = (out or err or last_output)[-1200:]
        if "STATUS:active:1" in out or "STATUS:active:" in out:
            return last_output
    raise RuntimeError(last_output or "install verification timeout")


def _make_project_archive():
    fd, name = tempfile.mkstemp(prefix="42ipwin-lite-", suffix=".tar.gz")
    os.close(fd)
    archive_path = Path(name)
    with tarfile.open(archive_path, "w:gz") as tar:
        for root_name in TAR_INCLUDE_ROOTS:
            root = PROJECT_DIR / root_name
            if not root.exists():
                continue
            if root.is_file():
                tar.add(root, arcname=root_name)
                continue
            for path in root.rglob("*"):
                rel = path.relative_to(PROJECT_DIR).as_posix()
                if any(rel == item or rel.startswith(item + "/") for item in TAR_EXCLUDES):
                    continue
                if path.is_file():
                    tar.add(path, arcname=rel)
    return archive_path


@bp.route("", methods=["GET"])
@login_required
def list_servers():
    s = get_session()
    try:
        rows = s.query(ManagedServer).order_by(ManagedServer.id.desc()).all()
        servers = []
        include_counts = str(request.args.get("include_counts") or "").strip().lower() in {"1", "true", "yes", "on"}
        local_ips = _local_server_ips()
        host_ip = (request.host or "").split(":", 1)[0].strip()
        if host_ip:
            local_ips.add(host_ip)
        local_display_ip = host_ip if host_ip and host_ip not in {"127.0.0.1", "localhost", "0.0.0.0"} else ""
        if not local_display_ip:
            local_display_ip = next((ip for ip in sorted(local_ips) if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", ip) and not ip.startswith("127.")), "")
        for row in rows:
            data = row.to_dict()
            data["is_local"] = row.ip in local_ips
            if data["is_local"]:
                data.update(_server_counts(s, row.ip))
            servers.append(data)
        if include_counts:
            by_id = {item["id"]: item for item in servers}
            with ThreadPoolExecutor(max_workers=min(8, max(1, len(rows)))) as executor:
                future_map = {
                    executor.submit(_remote_server_counts, row): row.id
                    for row in rows
                    if not by_id.get(row.id, {}).get("is_local")
                }
                for future in as_completed(future_map):
                    row_id = future_map[future]
                    try:
                        remote_counts = future.result()
                    except Exception as exc:
                        row = next((item for item in rows if item.id == row_id), None)
                        if row is None:
                            by_id[row_id]["remote_count_ok"] = False
                            by_id[row_id]["remote_count_error"] = str(exc)
                            continue
                        try:
                            remote_counts = _remote_server_counts_via_ssh(row)
                        except Exception as ssh_exc:
                            by_id[row_id]["remote_count_ok"] = False
                            by_id[row_id]["remote_count_error"] = f"{exc}; ssh: {ssh_exc}"
                            continue
                    by_id[row_id].update(remote_counts)
                    row = next((item for item in rows if item.id == row_id), None)
                    if row is not None:
                        row.inbound_count_cache = int(remote_counts.get("inbound_count") or 0)
                        row.inbound_assignments_cache = "\n".join(remote_counts.get("inbound_assignments") or [])
                        row.updated_at = datetime.utcnow()
            s.commit()
        return jsonify({"ok": True, "servers": servers, "local_ip": local_display_ip})
    finally:
        s.close()


@bp.route("", methods=["POST"])
@login_required
def add_servers():
    data = request.json or {}
    ips = _parse_ips(data.get("ips") or data.get("ip"))
    if not ips:
        return jsonify({"ok": False, "error": "请填写服务器 IP"}), 400
    try:
        port = int(data.get("port") or data.get("ssh_port") or 22)
    except Exception:
        return jsonify({"ok": False, "error": "端口必须是数字"}), 400
    if port < 1 or port > 65535:
        return jsonify({"ok": False, "error": "端口范围必须是 1-65535"}), 400
    username = (data.get("username") or data.get("account") or "root").strip() or "root"
    password = str(data.get("password") or "")
    group_name = str(data.get("group_name") or data.get("group") or "").strip()
    note = str(data.get("note") or "")

    s = get_session()
    try:
        created = []
        for ip in ips:
            row = ManagedServer(
                ip=ip,
                ssh_port=port,
                username=username,
                password=password,
                group_name=group_name,
                status="unknown",
                install_status="idle",
                note=note,
            )
            s.add(row)
            created.append(row)
        s.commit()
        _log("批量添加服务器", f"添加 {len(created)} 台：{', '.join(ips[:10])}")
        return jsonify({"ok": True, "servers": [row.to_dict() for row in created], "count": len(created)})
    finally:
        s.close()


@bp.route("/<int:server_id>", methods=["PUT"])
@login_required
def update_server(server_id):
    data = request.json or {}
    s = get_session()
    try:
        row = s.query(ManagedServer).get(server_id)
        if not row:
            return jsonify({"ok": False, "error": "服务器不存在"}), 404
        if "ip" in data:
            ip = str(data.get("ip") or "").strip()
            if not ip:
                return jsonify({"ok": False, "error": "IP 不能为空"}), 400
            row.ip = ip
        if "port" in data or "ssh_port" in data:
            try:
                port = int(data.get("port") or data.get("ssh_port") or row.ssh_port or 22)
            except Exception:
                return jsonify({"ok": False, "error": "端口必须是数字"}), 400
            if port < 1 or port > 65535:
                return jsonify({"ok": False, "error": "端口范围必须是 1-65535"}), 400
            row.ssh_port = port
        if "username" in data or "account" in data:
            row.username = (data.get("username") or data.get("account") or "root").strip() or "root"
        if "password" in data:
            password = str(data.get("password") or "")
            if password:
                row.password = password
        if "group_name" in data or "group" in data:
            row.group_name = str(data.get("group_name") or data.get("group") or "").strip()
        if "silent_group" in data:
            row.silent_group = 1 if _truthy(data.get("silent_group")) else 0
        if "note" in data:
            row.note = str(data.get("note") or "")
        row.updated_at = datetime.utcnow()
        s.commit()
        _log("编辑服务器", f"{row.ip}:{row.ssh_port}")
        return jsonify({"ok": True, "server": row.to_dict()})
    finally:
        s.close()


@bp.route("/<int:server_id>", methods=["DELETE"])
@login_required
def delete_server(server_id):
    s = get_session()
    try:
        row = s.query(ManagedServer).get(server_id)
        if not row:
            return jsonify({"ok": False, "error": "服务器不存在"}), 404
        detail = f"{row.ip}:{row.ssh_port}"
        s.delete(row)
        s.commit()
        _log("删除服务器", detail)
        return jsonify({"ok": True})
    finally:
        s.close()


@bp.route("/batch-delete", methods=["POST"])
@login_required
def batch_delete_servers():
    ids = [int(x) for x in (request.json or {}).get("ids", []) if str(x).isdigit()]
    if not ids:
        return jsonify({"ok": False, "error": "请选择服务器"}), 400
    s = get_session()
    try:
        rows = s.query(ManagedServer).filter(ManagedServer.id.in_(ids)).all()
        count = len(rows)
        details = [f"{row.ip}:{row.ssh_port}" for row in rows[:10]]
        for row in rows:
            s.delete(row)
        s.commit()
        _log("批量删除服务器", f"删除 {count} 台：{', '.join(details)}")
        return jsonify({"ok": True, "deleted": count})
    finally:
        s.close()


@bp.route("/batch-group", methods=["POST"])
@login_required
def batch_group_servers():
    data = request.json or {}
    ids = [int(x) for x in data.get("ids", []) if str(x).isdigit()]
    group_name = str(data.get("group_name") or data.get("group") or "").strip()
    has_silent = "silent_group" in data
    silent_group = 1 if _truthy(data.get("silent_group")) else 0
    if not ids:
        return jsonify({"ok": False, "error": "请选择服务器"}), 400
    s = get_session()
    try:
        rows = s.query(ManagedServer).filter(ManagedServer.id.in_(ids)).all()
        for row in rows:
            row.group_name = group_name
            if has_silent:
                row.silent_group = silent_group
            row.updated_at = datetime.utcnow()
        s.commit()
        _log("批量分组服务器", f"{len(rows)} 台 -> {group_name or '未分组'}")
        return jsonify({"ok": True, "updated": len(rows)})
    finally:
        s.close()


@bp.route("/test", methods=["POST"])
@login_required
def test_servers():
    ids = [int(x) for x in (request.json or {}).get("ids", []) if str(x).isdigit()]
    if not ids:
        return jsonify({"ok": False, "error": "请选择服务器"}), 400
    s = get_session()
    results = []
    try:
        rows = s.query(ManagedServer).filter(ManagedServer.id.in_(ids)).all()
        for row in rows:
            try:
                ssh = _ssh_connect(row)
                try:
                    code, out, err = _run(ssh, "uname -srm", timeout=20)
                finally:
                    ssh.close()
                row.status = "online" if code == 0 else "error"
                row.last_error = "" if code == 0 else (err or out)[-500:]
            except Exception as exc:
                row.status = "error"
                row.last_error = str(exc)[-500:]
            row.updated_at = datetime.utcnow()
            results.append(row.to_dict())
        s.commit()
        _log("测试服务器", f"测试 {len(results)} 台")
        return jsonify({"ok": True, "servers": results})
    finally:
        s.close()


@bp.route("/group-silent", methods=["POST"])
@login_required
def set_group_silent():
    data = request.json or {}
    group_name = str(data.get("group_name") or data.get("group") or "").strip()
    silent_group = 1 if _truthy(data.get("silent_group")) else 0
    if not group_name:
        return jsonify({"ok": False, "error": "请选择分组"}), 400
    s = get_session()
    try:
        rows = s.query(ManagedServer).filter(ManagedServer.group_name == group_name).all()
        for row in rows:
            row.silent_group = silent_group
            row.updated_at = datetime.utcnow()
        s.commit()
        _log("设置静默组" if silent_group else "取消静默组", f"{group_name}: {len(rows)} 台")
        return jsonify({"ok": True, "updated": len(rows), "group_name": group_name, "silent_group": bool(silent_group)})
    finally:
        s.close()


@bp.route("/import", methods=["POST"])
@login_required
def import_servers():
    data = request.json or {}
    text = str(data.get("text") or data.get("servers") or data.get("content") or "")
    rows, errors = _parse_server_import_rows(text, data)
    if not rows:
        return jsonify({"ok": False, "error": errors[0] if errors else "请粘贴要导入的服务器"}), 400
    s = get_session()
    try:
        existing = {
            (row.ip, int(row.ssh_port or 22))
            for row in s.query(ManagedServer).all()
        }
        created = []
        skipped = 0
        for item in rows:
            key = (item["ip"], int(item["ssh_port"] or 22))
            if key in existing:
                skipped += 1
                continue
            row = ManagedServer(
                ip=item["ip"],
                ssh_port=item["ssh_port"],
                username=item["username"],
                password=item["password"],
                group_name=item["group_name"],
                status="unknown",
                install_status="idle",
                note=item["note"],
            )
            s.add(row)
            created.append(row)
            existing.add(key)
        s.commit()
        _log("导入服务器", f"导入 {len(created)} 台，跳过 {skipped} 台")
        return jsonify({
            "ok": True,
            "count": len(created),
            "skipped": skipped,
            "errors": errors[:20],
            "servers": [row.to_dict() for row in created],
        })
    finally:
        s.close()


@bp.route("/detect-lite", methods=["POST"])
@login_required
def detect_lite_servers():
    ids = [int(x) for x in (request.json or {}).get("ids", []) if str(x).isdigit()]
    if not ids:
        return jsonify({"ok": False, "error": "请选择服务器"}), 400
    s = get_session()
    results = []
    try:
        rows = s.query(ManagedServer).filter(ManagedServer.id.in_(ids)).all()
        for row in rows:
            status, install_status, message, counts = _detect_lite_install(row)
            row.status = status
            row.install_status = install_status
            if status != "online":
                row.install_status = "failed" if row.install_status in {"installed", "installing", "failed"} else (row.install_status or "idle")
            row.last_error = message
            if counts:
                row.inbound_count_cache = int(counts.get("inbound_count") or 0)
                row.inbound_assignments_cache = "\n".join(counts.get("inbound_assignments") or [])
            row.updated_at = datetime.utcnow()
            data = row.to_dict()
            if counts:
                data.update(counts)
            results.append(data)
        s.commit()
        _log("检测轻量安装", f"检测 {len(results)} 台")
        return jsonify({"ok": True, "servers": results})
    finally:
        s.close()


@bp.route("/sync-inbounds", methods=["POST"])
@login_required
def sync_server_inbounds():
    ids = [int(x) for x in (request.json or {}).get("ids", []) if str(x).isdigit()]
    if not ids:
        return jsonify({"ok": False, "error": "请选择服务器"}), 400
    s = get_session()
    results = []
    try:
        rows = s.query(ManagedServer).filter(ManagedServer.id.in_(ids)).all()
        local_ips = _local_server_ips()
        host_ip = (request.host or "").split(":", 1)[0].strip()
        if host_ip:
            local_ips.add(host_ip)

        jobs = [
            SimpleNamespace(
                id=row.id,
                ip=row.ip,
                ssh_port=row.ssh_port,
                username=row.username,
                password=row.password,
                install_status=row.install_status,
                is_local=row.ip in local_ips,
            )
            for row in rows
        ]

        def sync_one(snapshot):
            try:
                if snapshot.is_local:
                    local_session = get_session()
                    try:
                        counts = _server_counts(local_session, snapshot.ip)
                    finally:
                        local_session.close()
                else:
                    try:
                        counts = _remote_server_counts(snapshot)
                    except Exception:
                        counts = _remote_server_counts_via_ssh(snapshot)
                return snapshot.id, "online", "installed", "入站同步完成", counts
            except Exception as exc:
                return snapshot.id, "error", "failed", str(exc)[-1200:], {}

        with ThreadPoolExecutor(max_workers=min(10, max(1, len(jobs)))) as executor:
            futures = [executor.submit(sync_one, job) for job in jobs]
            for future in as_completed(futures):
                row_id, status, install_status, message, counts = future.result()
                row = s.query(ManagedServer).get(row_id)
                if not row:
                    continue
                row.status = status
                if install_status:
                    row.install_status = install_status
                row.last_error = message
                if counts:
                    row.inbound_count_cache = int(counts.get("inbound_count") or 0)
                    row.inbound_assignments_cache = "\n".join(counts.get("inbound_assignments") or [])
                row.updated_at = datetime.utcnow()
                data = row.to_dict()
                if counts:
                    data.update(counts)
                results.append(data)
        s.commit()
        _log("同步入站", f"同步 {len(results)} 台服务器入站")
        return jsonify({"ok": True, "servers": results, "count": len(results)})
    finally:
        s.close()


def _install_one(row):
    if not INSTALL_SCRIPT.exists():
        raise RuntimeError(f"安装脚本不存在：{INSTALL_SCRIPT}")
    archive_path = _make_project_archive()
    ssh = _ssh_connect(row, timeout=20)
    try:
        stamp = int(time.time())
        remote_archive = f"/tmp/42ipwin-lite-src-{stamp}.tar.gz"
        remote_dir = f"/tmp/42ipwin-lite-src-{stamp}"
        sftp = ssh.open_sftp()
        try:
            sftp.put(str(archive_path), remote_archive)
        finally:
            sftp.close()
        command = (
            f"rm -rf {shlex.quote(remote_dir)} && mkdir -p {shlex.quote(remote_dir)} && "
            f"tar -xzf {shlex.quote(remote_archive)} -C {shlex.quote(remote_dir)} && "
            f"cd {shlex.quote(remote_dir)} && "
            f"nohup env DEBIAN_FRONTEND=noninteractive PANEL_PORT=18080 "
            f"bash install_lite.sh > /tmp/42ipwin-lite-install-{stamp}.log 2>&1 < /dev/null & "
            f"echo $!"
        )
        code, out, err = _run_quick(ssh, command, timeout=60)
        if code != 0:
            raise RuntimeError((err or out or f"install exit {code}")[-1200:])
        pid = (out or "").strip().splitlines()[-1] if (out or "").strip() else ""
        output = _verify_lite_ready(ssh)
        return (f"install started pid={pid}\n{output}")[-1200:]
    finally:
        ssh.close()
        try:
            archive_path.unlink()
        except Exception:
            pass


def _upgrade_one(row):
    archive_path = _make_project_archive()
    ssh = _ssh_connect(row, timeout=20)
    try:
        stamp = int(time.time())
        remote_archive = f"/tmp/42ipwin-lite-upgrade-{stamp}.tar.gz"
        remote_backup = f"/opt/42IPwin/data/backups/before-upgrade-center-push-{stamp}.tar.gz"
        sftp = ssh.open_sftp()
        try:
            sftp.put(str(archive_path), remote_archive)
        finally:
            sftp.close()
        command = f"""
set -e
APP_DIR=/opt/42IPwin
test -d "$APP_DIR"
mkdir -p "$APP_DIR/data/backups"
tar -C "$APP_DIR" -czf {shlex.quote(remote_backup)} panel install_lite.sh restore_macvlans.py sing-box/sing-box 2>/dev/null || true
tar -xzf {shlex.quote(remote_archive)} -C "$APP_DIR"
rm -f {shlex.quote(remote_archive)}
python3 -m py_compile "$APP_DIR/panel/routes/users.py" "$APP_DIR/panel/routes/servers.py" "$APP_DIR/panel/services/proxy_manager.py"
systemctl restart 42ipwin
sleep 2
systemctl is-active 42ipwin
python3 - <<'PY'
import pathlib
import re
root = pathlib.Path('/opt/42IPwin')
conf = (root / 'panel/config.py').read_text(encoding='utf-8', errors='replace')
match = re.search(r"APP_VERSION\\s*=\\s*['\\\"]([^'\\\"]+)", conf)
print('APP_VERSION=' + (match.group(1) if match else 'missing'))
print('HAS_WG_NODE_UI=' + str('wgNodeCount' in (root / 'panel/templates/users.html').read_text(encoding='utf-8', errors='replace')))
print('HAS_WG_BACKEND=' + str('target_node_count' in (root / 'panel/routes/users.py').read_text(encoding='utf-8', errors='replace')))
print('BACKUP={remote_backup}')
PY
"""
        code, out, err = _run(ssh, command, timeout=300)
        if code != 0:
            raise RuntimeError((err or out or f"upgrade exit {code}")[-1200:])
        return (out or err)[-1200:]
    finally:
        ssh.close()
        try:
            archive_path.unlink()
        except Exception:
            pass


def _uninstall_lite_one(row):
    ssh = _ssh_connect(row, timeout=20)
    try:
        stamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
        command = rf"""
set +e
systemctl stop 42ipwin 42ipwin-macvlans 2>/dev/null || true
systemctl disable 42ipwin 42ipwin-macvlans 2>/dev/null || true
rm -f /etc/systemd/system/42ipwin.service /etc/systemd/system/42ipwin-macvlans.service
systemctl daemon-reload 2>/dev/null || true
python3 - <<'PY'
import os, signal
roots = ("/opt/42IPwin", "/root/42IPwin")
for pid in [p for p in os.listdir("/proc") if p.isdigit()]:
    try:
        with open(f"/proc/{{pid}}/cmdline", "rb") as f:
            cmd = f.read().replace(b"\0", b" ").decode("utf-8", "ignore")
        if any(root in cmd for root in roots) or "IPWIN42_PANEL_PORT=18080" in cmd:
            os.kill(int(pid), signal.SIGTERM)
            print("KILLED", pid, cmd[:180])
    except Exception:
        pass
PY
sleep 1
for dir in /opt/42IPwin /root/42IPwin; do
  if [ -d "$dir" ]; then
    dest="${{dir}}.uninstalled-{stamp}"
    mv "$dir" "$dest"
    echo MOVED "$dest"
  fi
done
python3 - <<'PY'
import os, signal, time
roots = ("/opt/42IPwin", "/root/42IPwin")
time.sleep(0.5)
for pid in [p for p in os.listdir("/proc") if p.isdigit()]:
    try:
        with open(f"/proc/{{pid}}/cmdline", "rb") as f:
            cmd = f.read().replace(b"\0", b" ").decode("utf-8", "ignore")
        if any(root in cmd for root in roots) or "IPWIN42_PANEL_PORT=18080" in cmd:
            os.kill(int(pid), signal.SIGKILL)
            print("KILLED_FORCE", pid, cmd[:180])
    except Exception:
        pass
PY
echo PANEL $(systemctl is-active 42ipwin 2>/dev/null || true)
echo MACVLANS $(systemctl is-active 42ipwin-macvlans 2>/dev/null || true)
echo REMOVED_OPT $(test ! -d /opt/42IPwin && echo yes || echo no)
echo REMOVED_ROOT $(test ! -d /root/42IPwin && echo yes || echo no)
echo LISTEN
ss -lntup 2>/dev/null | grep -E ':18080\b|:9090\b' || true
"""
        code, out, err = _run(ssh, command, timeout=180)
        text = (out + "\n" + err).strip()
        if code != 0:
            raise RuntimeError(text[-1200:] or f"uninstall exit {code}")
        if ":18080" in out or ":9090" in out:
            raise RuntimeError(text[-1200:] or "uninstall left panel ports listening")
        if "REMOVED_OPT yes" not in out:
            raise RuntimeError(text[-1200:] or "uninstall did not remove /opt/42IPwin")
        return text[-1200:]
    finally:
        ssh.close()


@bp.route("/install", methods=["POST"])
@login_required
def install_servers():
    ids = [int(x) for x in (request.json or {}).get("ids", []) if str(x).isdigit()]
    if not ids:
        return jsonify({"ok": False, "error": "请选择服务器"}), 400
    s = get_session()
    try:
        rows = s.query(ManagedServer).filter(ManagedServer.id.in_(ids)).all()
        jobs = []
        for row in rows:
            row.install_status = "installing"
            row.last_error = "安装任务已提交，后台并发执行中..."
            row.updated_at = datetime.utcnow()
            jobs.append(SimpleNamespace(
                id=row.id,
                ip=row.ip,
                ssh_port=row.ssh_port,
                username=row.username,
                password=row.password,
            ))
        s.commit()
        results = [row.to_dict() for row in rows]

        def install_row(job):
            try:
                output = _install_one(job)
                return job.id, "online", "installed", output
            except Exception as exc:
                return job.id, "error", "failed", str(exc)[-1200:]

        def run_background_install(jobs_to_run):
            bg_session = get_session()
            try:
                with ThreadPoolExecutor(max_workers=min(10, max(1, len(jobs_to_run)))) as executor:
                    futures = [executor.submit(install_row, job) for job in jobs_to_run]
                    for future in as_completed(futures):
                        row_id, status, install_status, message = future.result()
                        row = bg_session.query(ManagedServer).get(row_id)
                        if not row:
                            continue
                        row.status = status
                        row.install_status = install_status
                        row.last_error = message
                        row.updated_at = datetime.utcnow()
                        bg_session.commit()
            finally:
                bg_session.close()

        threading.Thread(target=run_background_install, args=(jobs,), daemon=True).start()
        _log("一键安装42轻量", f"后台并发安装 {len(results)} 台")
        return jsonify({"ok": True, "servers": results})
    finally:
        s.close()


@bp.route("/upgrade", methods=["POST"])
@login_required
def upgrade_servers():
    ids = [int(x) for x in (request.json or {}).get("ids", []) if str(x).isdigit()]
    if not ids:
        return jsonify({"ok": False, "error": "请选择服务器"}), 400
    s = get_session()
    try:
        rows = s.query(ManagedServer).filter(ManagedServer.id.in_(ids)).all()
        jobs = []
        for row in rows:
            row.last_error = "升级任务已提交，后台并发执行中..."
            row.updated_at = datetime.utcnow()
            jobs.append(SimpleNamespace(
                id=row.id,
                ip=row.ip,
                ssh_port=row.ssh_port,
                username=row.username,
                password=row.password,
            ))
        s.commit()
        results = [row.to_dict() for row in rows]

        def upgrade_row(job):
            try:
                output = _upgrade_one(job)
                return job.id, "online", "installed", output
            except Exception as exc:
                return job.id, "error", "failed", str(exc)[-1200:]

        def run_background_upgrade(jobs_to_run):
            bg_session = get_session()
            try:
                with ThreadPoolExecutor(max_workers=min(3, max(1, len(jobs_to_run)))) as executor:
                    futures = [executor.submit(upgrade_row, job) for job in jobs_to_run]
                    for future in as_completed(futures):
                        row_id, status, install_status, message = future.result()
                        row = bg_session.query(ManagedServer).get(row_id)
                        if not row:
                            continue
                        row.status = status
                        row.install_status = install_status
                        row.last_error = message
                        row.updated_at = datetime.utcnow()
                        bg_session.commit()
            finally:
                bg_session.close()

        threading.Thread(target=run_background_upgrade, args=(jobs,), daemon=True).start()
        _log("一键升级42轻量", f"后台并发升级 {len(results)} 台")
        return jsonify({"ok": True, "servers": results})
    finally:
        s.close()


@bp.route("/uninstall-lite", methods=["POST"])
@login_required
def uninstall_lite_servers():
    ids = [int(x) for x in (request.json or {}).get("ids", []) if str(x).isdigit()]
    if not ids:
        return jsonify({"ok": False, "error": "请选择服务器"}), 400
    s = get_session()
    try:
        rows = s.query(ManagedServer).filter(ManagedServer.id.in_(ids)).all()
        jobs = []
        for row in rows:
            row.install_status = "uninstalling"
            row.last_error = "卸载任务已提交，后台并发执行中..."
            row.updated_at = datetime.utcnow()
            jobs.append(SimpleNamespace(
                id=row.id,
                ip=row.ip,
                ssh_port=row.ssh_port,
                username=row.username,
                password=row.password,
            ))
        s.commit()
        results = [row.to_dict() for row in rows]

        def uninstall_row(job):
            try:
                output = _uninstall_lite_one(job)
                return job.id, "offline", "idle", output
            except Exception as exc:
                return job.id, "error", "failed", str(exc)[-1200:]

        def run_background_uninstall(jobs_to_run):
            bg_session = get_session()
            try:
                with ThreadPoolExecutor(max_workers=min(8, max(1, len(jobs_to_run)))) as executor:
                    futures = [executor.submit(uninstall_row, job) for job in jobs_to_run]
                    for future in as_completed(futures):
                        row_id, status, install_status, message = future.result()
                        row = bg_session.query(ManagedServer).get(row_id)
                        if not row:
                            continue
                        row.status = status
                        row.install_status = install_status
                        row.inbound_count_cache = 0
                        row.inbound_assignments_cache = ""
                        row.last_error = message
                        row.updated_at = datetime.utcnow()
                        bg_session.commit()
            finally:
                bg_session.close()

        threading.Thread(target=run_background_uninstall, args=(jobs,), daemon=True).start()
        _log("一键卸载42轻量", f"后台并发卸载 {len(results)} 台")
        return jsonify({"ok": True, "servers": results, "count": len(results)})
    finally:
        s.close()
