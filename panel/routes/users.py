"""Proxy user management APIs."""
import heapq
import ipaddress
import base64
import os
import re
import secrets
import socket
import struct
import string
import threading
import time
import uuid
import io
import zipfile
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
import urllib.request
import urllib.error
import urllib.parse
import http.cookiejar
import subprocess
import tempfile

import psutil
from flask import Blueprint, Response, jsonify, request, session
from sqlalchemy import func
from sqlalchemy.orm import joinedload

try:
    from config import SING_BOX_EXE, is_lite_mode
except ImportError:
    SING_BOX_EXE = ""
    def is_lite_mode() -> bool:
        return os.environ.get("IPWIN42_LITE") == "1" or os.environ.get("42IPWIN_LITE") == "1"
from models import Line, ManagedServer, PROTOCOL_TYPES, ProxyUser, SS_METHODS, get_session
from routes.auth import login_required
try:
    from services.audit_logger import add_operation_log
except ModuleNotFoundError:
    def add_operation_log(*args, **kwargs):
        return None
from services import proxy_manager
from services import inbound_instance_manager
try:
    from services.proxy_manager import _pop_auto_restore_marker
except ImportError:
    def _pop_auto_restore_marker(note):
        return None, note
from services.cfg_generator import parse_size_to_bytes, write_cfg
from services.fast_speed import fast_socks5_speed
from services.limit_manager import apply_limit, clear_limit, parse_speed_to_bps, sync_limits
try:
    from services.traffic_collector import collect_once, snapshot_connections_status
except ImportError:
    from services.traffic_collector import collect_once, snapshot_connections as snapshot_connections_status
try:
    from services import wireguard_manager
except ImportError:
    class _MissingWireGuardManager:
        @staticmethod
        def available():
            return False

        @staticmethod
        def create_client_material(*args, **kwargs):
            return None

        @staticmethod
        def reload_service(*args, **kwargs):
            return False

        @staticmethod
        def transfer_snapshot(*args, **kwargs):
            return {}

        @staticmethod
        def client_conf(*args, **kwargs):
            return ""

    wireguard_manager = _MissingWireGuardManager()

bp = Blueprint("users", __name__, url_prefix="/api/users")
_limit_worker_lock = threading.Lock()

USERNAME_RE = re.compile(r"^[A-Za-z0-9_\-]{3,48}$")
TESTABLE_UDP_PROTOCOLS = {"socks5", "ss", "hysteria2"}
RANDOM_PORT_MIN = 10000
RANDOM_PORT_MAX = 60000
WINDOWS_EXCLUDED_PORT_CACHE = {"time": 0.0, "ports": set()}
DEFAULT_SPEED_LIMIT = "20m"
DEFAULT_TRAFFIC_LIMIT = "130g"
DEFAULT_LITE_LINE_NAME = "本机公网"


def current_operator_name() -> str:
    name = (session.get("admin_name") or "").strip()
    return name or "admin"


def _log_client_ip() -> str:
    return request.headers.get("X-Forwarded-For", "").split(",", 1)[0].strip() or request.remote_addr or ""


def _format_log_user_detail(user_or_item, server_ip: str | None = None) -> str:
    if isinstance(user_or_item, dict):
        item = user_or_item
        ip = server_ip or item.get("managed_server_ip") or item.get("line_ip") or item.get("server") or item.get("ip") or "-"
        port = item.get("listen_port") or item.get("port") or "-"
        protocol = item.get("protocol") or "-"
        username = item.get("username") or item.get("account") or "-"
        owner = item.get("owner_name") or item.get("owner") or "-"
        project = item.get("project_name") or item.get("project") or "-"
        uid = item.get("local_id") or item.get("id") or "-"
        expire_at = item.get("expire_at") or item.get("expire_date") or "-"
    else:
        user = user_or_item
        line = getattr(user, "line", None)
        ip = server_ip or (line.public_ip if line else "-")
        port = user.listen_port or (line.get_port_by_protocol(user.protocol) if line else "-")
        protocol = user.protocol or "-"
        username = user.username or "-"
        owner = user.owner_name or "-"
        project = user.project_name or "-"
        uid = user.id or "-"
        expire_at = user.expire_at.date().isoformat() if user.expire_at else "-"
    return (
        f"server={ip} protocol={protocol} port={port} user={username} "
        f"owner={owner} project={project} expire={expire_at} id={uid}"
    )


def _add_user_operation_log(db_session, action: str, detail: str) -> None:
    add_operation_log(
        db_session,
        current_operator_name(),
        "入站管理",
        action,
        detail[:4000],
        _log_client_ip(),
    )


def _compact_log_details(details: list[str], max_items: int = 12) -> str:
    if len(details) <= max_items:
        return "; ".join(details)
    return "; ".join(details[:max_items]) + f"; ... more={len(details) - max_items}"


def _gen_password(n: int = 12) -> str:
    chars = string.ascii_letters + string.digits
    return "".join(secrets.choice(chars) for _ in range(n))


def _selected_lines(session, line_id):
    def only_public(rows):
        return [line for line in rows if _is_public_ip(line.public_ip or "")]

    if str(line_id).lower() == "all":
        rows = session.query(Line).filter(Line.status == 1).order_by(Line.id).all()
        return only_public(rows)
    line = session.query(Line).get(int(line_id))
    return [line] if line and _is_public_ip(line.public_ip or "") else []


def _sort_lines_by_inbound_count(session, lines: list[Line]) -> list[Line]:
    if not lines:
        return []
    counts = {
        line_id: total
        for line_id, total in (
            session.query(ProxyUser.line_id, func.count(ProxyUser.id))
            .filter(ProxyUser.line_id.in_([line.id for line in lines]))
            .group_by(ProxyUser.line_id)
            .all()
        )
    }
    return sorted(lines, key=lambda line: (int(counts.get(line.id, 0)), str(line.public_ip or ""), int(line.id or 0)))


def _target_lines(session, line_id, count: int):
    lines = _selected_lines(session, line_id)
    if str(line_id).lower() == "all":
        return _sort_lines_by_inbound_count(session, lines)
    return lines[:1]


def _target_lines_by_ids(session, line_ids) -> list[Line]:
    ids = []
    for value in line_ids or []:
        try:
            item = int(value)
        except Exception:
            continue
        if item not in ids:
            ids.append(item)
    if not ids:
        return []
    rows = session.query(Line).filter(Line.id.in_(ids)).order_by(Line.id).all()
    by_id = {row.id: row for row in rows}
    selected = [by_id[item] for item in ids if item in by_id and _is_public_ip(by_id[item].public_ip or "")]
    return _sort_lines_by_inbound_count(session, selected)


def _parse_int_ids(values) -> list[int]:
    ids = []
    for value in values or []:
        try:
            item = int(str(value).strip())
        except Exception:
            continue
        if item > 0 and item not in ids:
            ids.append(item)
    return ids


def _parse_remote_user_id(value: str) -> tuple[int, int] | None:
    parts = str(value or "").split(":")
    if len(parts) != 3 or parts[0] != "remote":
        return None
    try:
        server_id = int(parts[1])
        user_id = int(parts[2])
    except Exception:
        return None
    if server_id <= 0 or user_id <= 0:
        return None
    return server_id, user_id


def _remote_item_local_id(item: dict) -> int:
    raw = item.get("local_id") or item.get("id")
    remote_id = _parse_remote_user_id(str(raw))
    if remote_id:
        raw = remote_id[1]
    try:
        user_id = int(str(raw).strip())
    except Exception as exc:
        raise ValueError(f"invalid remote inbound id: {raw}") from exc
    if user_id <= 0:
        raise ValueError(f"invalid remote inbound id: {raw}")
    return user_id


def _remote_panel_post(server: ManagedServer, path: str, payload: dict, timeout: int = 45) -> dict:
    base = f"http://{server.ip}:18080"
    cj = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

    def post_json(url: str, body: dict):
        raw = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=raw,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with opener.open(req, timeout=timeout) as resp:
                text = resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            text = exc.read().decode("utf-8", "replace")
            try:
                body = json.loads(text)
                message = body.get("error") or body.get("message") or text[:300]
            except Exception:
                plain = re.sub(r"<[^>]+>", " ", text or "")
                plain = re.sub(r"\s+", " ", plain).strip()
                if exc.code >= 500:
                    message = "子机内部错误，请查看该服务器日志"
                else:
                    message = plain[:160] or exc.reason
            raise RuntimeError(f"HTTP {exc.code}: {message}") from exc
        try:
            return json.loads(text)
        except Exception as exc:
            raise RuntimeError(f"返回不是 JSON: {text[:200]}") from exc

    login = post_json(f"{base}/api/login", {"username": "admin", "password": "admin123"})
    if not login.get("ok"):
        raise RuntimeError(login.get("error") or "远程轻量面板登录失败")
    result = post_json(f"{base}{path}", payload)
    if not result.get("ok"):
        raise RuntimeError(result.get("error") or "远程创建失败")
    return result


def _remote_panel_get(server: ManagedServer, path: str, timeout: int = 6) -> dict:
    base = f"http://{server.ip}:18080"
    cj = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

    def post_json(url: str, body: dict):
        raw = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(url, data=raw, headers={"Content-Type": "application/json"}, method="POST")
        with opener.open(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8", "replace"))

    login = post_json(f"{base}/api/login", {"username": "admin", "password": "admin123"})
    if not login.get("ok"):
        raise RuntimeError(login.get("error") or "远程轻量面板登录失败")
    req = urllib.request.Request(f"{base}{path}", method="GET")
    with opener.open(req, timeout=timeout) as resp:
        text = resp.read().decode("utf-8", "replace")
    try:
        return json.loads(text)
    except Exception as exc:
        raise RuntimeError(f"返回不是 JSON: {text[:200]}") from exc



def _ssh_connect_managed_server(server: ManagedServer, timeout: int = 12):
    try:
        import paramiko
    except Exception as exc:
        raise RuntimeError(f"缺少 SSH 依赖 paramiko: {exc}") from exc

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


def _ssh_run(ssh, command: str, timeout: int = 45) -> tuple[int, str, str]:
    stdin, stdout, stderr = ssh.exec_command(command, timeout=timeout)
    out = stdout.read().decode("utf-8", "replace")
    err = stderr.read().decode("utf-8", "replace")
    code = stdout.channel.recv_exit_status()
    return code, out, err


def _remote_panel_get_via_ssh(server: ManagedServer, path: str, timeout: int = 12) -> dict:
    safe_path = json.dumps(path)
    command = f"""python3 - <<'PY'
import http.cookiejar
import json
import urllib.request

base = 'http://127.0.0.1:18080'
path = {safe_path}
cj = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

def post(path, body):
    raw = json.dumps(body).encode('utf-8')
    req = urllib.request.Request(base + path, data=raw, headers={{'Content-Type': 'application/json'}}, method='POST')
    with opener.open(req, timeout={int(timeout)}) as resp:
        return json.loads(resp.read().decode('utf-8', 'replace'))

login = post('/api/login', {{'username': 'admin', 'password': 'admin123'}})
if not login.get('ok'):
    raise SystemExit('login failed: ' + (login.get('error') or 'unknown'))
req = urllib.request.Request(base + path, method='GET')
with opener.open(req, timeout={int(timeout)}) as resp:
    print(resp.read().decode('utf-8', 'replace'))
PY"""
    ssh = _ssh_connect_managed_server(server, timeout=max(timeout, 12))
    try:
        code, out, err = _ssh_run(ssh, command, timeout=max(timeout + 20, 35))
    finally:
        ssh.close()
    if code != 0:
        raise RuntimeError((err or out or f"ssh panel get exit {code}")[-1200:])
    try:
        return json.loads(out.strip() or "{}")
    except Exception as exc:
        raise RuntimeError(f"SSH 返回不是 JSON: {out[:200]}") from exc


def _remote_panel_download(server: ManagedServer, path: str, timeout: int = 20) -> tuple[bytes, str]:
    base = f"http://{server.ip}:18080"
    cj = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

    def post_json(url: str, body: dict):
        raw = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(url, data=raw, headers={"Content-Type": "application/json"}, method="POST")
        with opener.open(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8", "replace"))

    login = post_json(f"{base}/api/login", {"username": "admin", "password": "admin123"})
    if not login.get("ok"):
        raise RuntimeError(login.get("error") or "remote login failed")
    req = urllib.request.Request(f"{base}{path}", method="GET")
    with opener.open(req, timeout=timeout) as resp:
        data = resp.read()
        disposition = resp.headers.get("Content-Disposition") or ""
    filename = ""
    match = re.search(r'filename="?([^";]+)"?', disposition)
    if match:
        filename = match.group(1)
    return data, filename


def _remote_panel_delete(server: ManagedServer, path: str, timeout: int = 20) -> dict:
    base = f"http://{server.ip}:18080"
    cj = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

    def request_json(url: str, method: str = "GET", body: dict | None = None):
        data = None if body is None else json.dumps(body).encode("utf-8")
        headers = {"Content-Type": "application/json"} if body is not None else {}
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        with opener.open(req, timeout=timeout) as resp:
            text = resp.read().decode("utf-8", "replace")
        return json.loads(text) if text else {}

    login = request_json(f"{base}/api/login", "POST", {"username": "admin", "password": "admin123"})
    if not login.get("ok"):
        raise RuntimeError(login.get("error") or "remote login failed")
    result = request_json(f"{base}{path}", "DELETE")
    if result and not result.get("ok", True):
        raise RuntimeError(result.get("error") or "remote delete failed")
    return result or {"ok": True}


def _local_server_ips() -> set[str]:
    ips = {"127.0.0.1", "localhost"}
    host_ip = (request.host or "").split(":", 1)[0].strip()
    if host_ip:
        ips.add(host_ip)
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


def _remote_users_from_managed_servers(session) -> list[dict]:
    local_ips = _local_server_ips()
    servers = (
        session.query(ManagedServer)
        .filter(
            ManagedServer.install_status == "installed",
            (ManagedServer.silent_group.is_(None)) | (ManagedServer.silent_group == 0),
        )
        .order_by(ManagedServer.id.desc())
        .all()
    )
    servers = [server for server in servers if server.ip not in local_ips]

    def fetch_server(server: ManagedServer) -> list[dict]:
        server_rows = []
        try:
            try:
                result = _remote_panel_get(server, "/api/users?local_only=1", timeout=6)
            except Exception:
                result = _remote_panel_get_via_ssh(server, "/api/users?local_only=1", timeout=12)
            for item in result.get("data") or []:
                item = dict(item)
                item["local_id"] = item.get("id")
                item["id"] = f"remote:{server.id}:{item.get('id')}"
                item["managed_server_id"] = server.id
                item["managed_server_ip"] = server.ip
                item["line_ip"] = item.get("line_ip") or server.ip
                item["line_name"] = item.get("line_name") or server.ip
                item["note"] = item.get("note") or ""
                item["traffic_available"] = item.get("traffic_available", False)
                item["traffic_source"] = item.get("traffic_source") or "远程服务器实时统计"
                server_rows.append(item)
        except Exception:
            return []
        return server_rows

    if not servers:
        return []

    rows = []
    with ThreadPoolExecutor(max_workers=min(8, len(servers))) as executor:
        futures = [executor.submit(fetch_server, server) for server in servers]
        for future in as_completed(futures):
            rows.extend(future.result())
    return rows


def _dedupe_user_rows(rows: list[dict]) -> list[dict]:
    deduped = []
    seen = set()
    for item in rows:
        key = (
            str(item.get("line_ip") or item.get("managed_server_ip") or "").strip(),
            str(item.get("listen_port") or "").strip(),
            str(item.get("protocol") or "").strip().lower(),
        )
        if key[0] and key[1] and key[2]:
            if key in seen:
                continue
            seen.add(key)
        deduped.append(item)
    return deduped


def _server_ip_sort_key(server: ManagedServer):
    try:
        return (0, int(ipaddress.ip_address(str(server.ip or "").strip())))
    except Exception:
        return (1, str(server.ip or ""))


def _managed_server_inbound_count(server: ManagedServer) -> int:
    try:
        result = _remote_panel_get(server, "/api/users?local_only=1", timeout=8)
        return len(result.get("data") or [])
    except Exception:
        return 10**9


def _least_inbound_targets(servers: list[ManagedServer], count: int) -> list[ManagedServer]:
    heap = []
    unique_servers = []
    seen_ids = set()
    for server in servers:
        if server.id in seen_ids:
            continue
        seen_ids.add(server.id)
        unique_servers.append(server)
        if server.install_status != "installed":
            continue
        inbound_count = _managed_server_inbound_count(server)
        heapq.heappush(heap, (inbound_count, _server_ip_sort_key(server), server.id, server))
    if not heap:
        heap = [(0, _server_ip_sort_key(server), server.id, server) for server in unique_servers]
        heapq.heapify(heap)

    targets = []
    for _ in range(max(0, count)):
        if not heap:
            break
        inbound_count, sort_key, server_id, server = heapq.heappop(heap)
        targets.append(server)
        heapq.heappush(heap, (inbound_count + 1, sort_key, server_id, server))
    return targets


def _least_inbound_unique_targets(servers: list[ManagedServer], count: int) -> list[ManagedServer]:
    targets = _least_inbound_targets(servers, count)
    deduped = []
    seen_ids = set()
    for server in targets:
        if server.id in seen_ids:
            continue
        seen_ids.add(server.id)
        deduped.append(server)
    return deduped


def _verify_remote_created_item(item: dict, timeout: int = 12) -> tuple[bool, str]:
    protocol = (item.get("protocol") or "").strip().lower()
    if protocol != "ss":
        return True, "not verified for this protocol"
    if not SING_BOX_EXE or not os.path.exists(SING_BOX_EXE):
        return True, "sing-box client not available on center"
    host = (item.get("managed_server_ip") or item.get("line_ip") or "").strip()
    try:
        port = int(item.get("listen_port") or item.get("port") or 0)
    except Exception:
        port = 0
    method = (item.get("ss_method") or "aes-256-gcm").strip()
    password = (item.get("ss_password") or item.get("password") or "").strip()
    if not host or not port or not password:
        return False, "missing ss connection fields"
    socks_port = 31000 + secrets.randbelow(20000)
    cfg = {
        "log": {"level": "warn"},
        "inbounds": [{"type": "socks", "tag": "socks", "listen": "127.0.0.1", "listen_port": socks_port}],
        "outbounds": [{"type": "shadowsocks", "tag": "ss", "server": host, "server_port": port, "method": method, "password": password}],
        "route": {"rules": [{"inbound": ["socks"], "outbound": "ss"}]},
    }
    cfg_path = None
    proc = None
    try:
        fd, cfg_path = tempfile.mkstemp(prefix="42ipwin-ss-verify-", suffix=".json")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(cfg, fh)
        proc = subprocess.Popen([SING_BOX_EXE, "run", "-c", cfg_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(0.8)
        if proc.poll() is not None:
            return False, "verify client exited"
        errors = []
        verify_urls = (
            "http://api.ipify.org",
            "http://ifconfig.me/ip",
            "https://api.ipify.org",
            "https://ifconfig.me/ip",
        )
        for url in verify_urls:
            curl = subprocess.run(
                [
                    "curl",
                    "-sS",
                    "--socks5-hostname",
                    f"127.0.0.1:{socks_port}",
                    "--max-time",
                    str(max(3, int(timeout))),
                    url,
                ],
                capture_output=True,
                text=True,
                timeout=max(5, int(timeout) + 3),
            )
            body = (curl.stdout or "").strip()
            if curl.returncode == 0 and body:
                return True, f"verified outbound {body} via {url}"
            errors.append(f"{url}: {(curl.stderr or curl.stdout or f'curl exit {curl.returncode}')[-160:]}")
        return False, " | ".join(errors)[-400:] or "empty verify response"
    except Exception as exc:
        return False, str(exc)[-300:]
    finally:
        if proc is not None and proc.poll() is None:
            try:
                proc.terminate()
                proc.wait(timeout=2)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        if cfg_path:
            try:
                os.unlink(cfg_path)
            except Exception:
                pass


def _create_on_managed_servers(session, server_ids: list[int], data: dict, count: int) -> dict | None:
    ids = []
    seen_ids = set()
    for item in _parse_int_ids(server_ids):
        if item in seen_ids:
            continue
        seen_ids.add(item)
        ids.append(item)
    if not ids:
        return None
    rows = (
        session.query(ManagedServer)
        .filter(ManagedServer.id.in_(ids), (ManagedServer.silent_group.is_(None)) | (ManagedServer.silent_group == 0))
        .order_by(ManagedServer.id)
        .all()
    )
    by_id = {row.id: row for row in rows}
    servers = [by_id[item] for item in ids if item in by_id]
    if not servers:
        raise ValueError("请选择有效服务器")

    created = []
    errors = []
    skipped = []
    base_custom_port = None
    if data.get("custom_port") not in (None, "", 0, "0"):
        try:
            base_custom_port = int(data.get("custom_port"))
        except Exception:
            base_custom_port = None
    if base_custom_port is not None:
        targets = _least_inbound_unique_targets(servers, count)
        if len(targets) < max(0, int(count or 0)):
            skipped.append(f"固定端口批量创建时每台服务器只创建 1 个，已按可用服务器数创建 {len(targets)} 个")
    else:
        targets = _least_inbound_targets(servers, count)

    def create_remote(index_server):
        index, server = index_server
        payload = dict(data)
        payload.pop("server_ids", None)
        payload["line_id"] = "lite"
        payload["line_ids"] = []
        payload["count"] = 1
        payload["public_ip"] = server.ip
        if base_custom_port is not None:
            payload["custom_port"] = base_custom_port
            payload["listen_port"] = base_custom_port
        try:
            result = _remote_panel_post(server, "/api/users", payload)
            result_data = result.get("data") or {}
            rows = result_data.get("created") or ([result_data] if result_data.get("id") else [])
            server_created = []
            for item in rows:
                item = dict(item)
                item["local_id"] = item.get("id")
                item["id"] = f"remote:{server.id}:{item.get('id')}"
                item["managed_server_id"] = server.id
                item["managed_server_ip"] = server.ip
                ok, verify_message = _verify_remote_created_item(item)
                item["verify_ok"] = ok
                item["verify_message"] = verify_message
                if False and not ok:
                    return [], f"{server.ip}: 创建后出网验证失败：{verify_message}"
                if not ok:
                    try:
                        _remote_panel_delete(server, f"/api/users/{_remote_item_local_id(item)}")
                    except Exception:
                        pass
                    return [], f"{server.ip}: 创建后出网验证失败，已回滚本次创建：{verify_message}"
                server_created.append(item)
            return server_created, None
        except Exception as exc:
            return [], f"{server.ip}: {exc}"

    with ThreadPoolExecutor(max_workers=min(8, max(1, len(targets)))) as executor:
        futures = [executor.submit(create_remote, pair) for pair in enumerate(targets, 1)]
        for future in as_completed(futures):
            server_created, error = future.result()
            created.extend(server_created)
            if error:
                errors.append(error)
    if created:
        for item in created:
            server_id = item.get("managed_server_id")
            row = by_id.get(server_id)
            if not row:
                continue
            row.inbound_count_cache = int(row.inbound_count_cache or 0) + 1
            existing = [x for x in (row.inbound_assignments_cache or "").splitlines() if x]
            owner = (item.get("owner_name") or item.get("username") or "-").strip()
            project = (item.get("project_name") or "-").strip()
            label = f"{owner}|{project}"
            if label not in existing:
                existing.append(label)
            row.inbound_assignments_cache = "\n".join(existing[:1000])
            row.status = "online"
            row.install_status = "installed"
            row.last_error = f"创建成功，入站缓存已更新：{row.inbound_count_cache}"
            row.updated_at = datetime.utcnow()

    return {
        "created": created,
        "created_count": len(created),
        "skipped": skipped,
        "skipped_count": 0,
        "errors": errors,
        "limits": [],
        "limit_queued": 0,
        "apply_status": {
            "applied": bool(created),
            "restarted": False,
            "message": f"已在服务器管理中创建 {len(created)} 个，失败 {len(errors)} 个",
        },
    }


def _line_project_used(session, line_id: int, project_name: str) -> bool:
    project = (project_name or "").strip()
    q = session.query(ProxyUser).filter(ProxyUser.line_id == line_id)
    if project:
        q = q.filter(ProxyUser.project_name == project)
    else:
        q = q.filter((ProxyUser.project_name.is_(None)) | (ProxyUser.project_name == ""))
    return q.first() is not None


def _assignment_label(owner_name: str, username: str) -> str:
    owner = (owner_name or "").strip()
    if owner:
        return owner
    return (username or "").strip()


def _used_listen_ports(session) -> set[int]:
    ports = set()
    for row in session.query(ProxyUser.listen_port).filter(ProxyUser.listen_port.isnot(None)).all():
        if row[0]:
            ports.add(int(row[0]))
    for line in session.query(Line).all():
        for value in (
            line.socks_port,
            line.http_port,
            line.ss_port,
            line.get_port_by_protocol("vless"),
            line.get_port_by_protocol("trojan"),
            line.get_port_by_protocol("hysteria2"),
        ):
            if value:
                ports.add(int(value))
    return ports


def _port_available_on_host(port: int) -> bool:
    try:
        port = int(port)
    except Exception:
        return False
    if _is_windows_excluded_port(port):
        return False
    for family, sock_type in ((socket.AF_INET, socket.SOCK_STREAM), (socket.AF_INET, socket.SOCK_DGRAM)):
        sock = socket.socket(family, sock_type)
        try:
            sock.bind(("0.0.0.0", port))
        except OSError:
            return False
        finally:
            sock.close()
    return True


def _windows_excluded_ports() -> set[int]:
    if os.name != "nt":
        return set()
    now = time.time()
    cached = WINDOWS_EXCLUDED_PORT_CACHE
    if cached["ports"] and now - cached["time"] < 300:
        return set(cached["ports"])
    ports: set[int] = set()
    for protocol in ("tcp", "udp"):
        try:
            proc = subprocess.run(
                ["netsh", "interface", "ipv4", "show", "excludedportrange", f"protocol={protocol}"],
                capture_output=True,
                text=True,
                timeout=5,
            )
        except Exception:
            continue
        for line in (proc.stdout or "").splitlines():
            numbers = re.findall(r"\d+", line)
            if len(numbers) < 2:
                continue
            start, end = int(numbers[0]), int(numbers[1])
            if 0 < start <= end <= 65535:
                ports.update(range(start, end + 1))
    cached["time"] = now
    cached["ports"] = ports
    return set(ports)


def _is_windows_excluded_port(port: int) -> bool:
    try:
        port = int(port)
    except Exception:
        return True
    return port in _windows_excluded_ports()


def _random_available_port(session, used_ports: set[int] | None = None) -> int:
    used_ports = used_ports if used_ports is not None else _used_listen_ports(session)
    for _ in range(3000):
        port = secrets.randbelow(RANDOM_PORT_MAX - RANDOM_PORT_MIN + 1) + RANDOM_PORT_MIN
        if port not in used_ports and _port_available_on_host(port):
            used_ports.add(port)
            return port
    for port in range(RANDOM_PORT_MIN, RANDOM_PORT_MAX + 1):
        if port not in used_ports and _port_available_on_host(port):
            used_ports.add(port)
            return port
    raise ValueError("没有可用端口")


def _is_public_ip(ip: str) -> bool:
    try:
        import ipaddress
        addr = ipaddress.ip_address(ip)
        return not (addr.is_loopback or addr.is_private or addr.is_link_local or addr.is_multicast or addr.is_unspecified)
    except Exception:
        return False


def _detect_public_ip() -> str:
    env_ip = (os.environ.get("IPWIN42_PUBLIC_IP") or os.environ.get("PUBLIC_IP") or "").strip()
    if _is_public_ip(env_ip):
        return env_ip
    for url in ("https://api.ipify.org", "https://ifconfig.me/ip"):
        try:
            with urllib.request.urlopen(url, timeout=5) as resp:
                ip = resp.read(64).decode("utf-8", "replace").strip()
                if _is_public_ip(ip):
                    return ip
        except Exception:
            pass
    try:
        for rows in psutil.net_if_addrs().values():
            for addr in rows:
                if addr.family == socket.AF_INET and _is_public_ip(addr.address):
                    return addr.address
    except Exception:
        pass
    return ""


def _ensure_lite_line(session, preferred_public_ip: str = "") -> Line:
    preferred_public_ip = (preferred_public_ip or "").strip()
    public_ip = preferred_public_ip if _is_public_ip(preferred_public_ip) else _detect_public_ip()
    if not public_ip:
        raise ValueError("无法自动获取本机公网 IP，请设置环境变量 IPWIN42_PUBLIC_IP")
    line = session.query(Line).filter(Line.public_ip == public_ip).first()
    if line:
        if line.status != 1:
            line.status = 1
        if not line.name:
            line.name = DEFAULT_LITE_LINE_NAME
        return line
    used = _used_listen_ports(session)
    socks_port = 10801
    while socks_port in used:
        socks_port += 1
    line = Line(
        name=DEFAULT_LITE_LINE_NAME,
        public_ip=public_ip,
        internal_ip="0.0.0.0",
        socks_port=socks_port,
        http_port=socks_port + 10,
        ss_port=socks_port + 20,
        status=1,
        note="lite-auto",
    )
    session.add(line)
    session.flush()
    return line


def _normalize_protocol(value: str) -> str:
    proto = (value or "socks5").strip().lower()
    aliases = {
        "socks": "socks5",
        "sk5": "socks5",
        "sock5": "socks5",
        "shadowsocks": "ss",
        "shadow": "ss",
        "hy": "hysteria2",
        "hysteria": "hysteria2",
        "hysteria-2": "hysteria2",
        "vm": "vmess",
        "vmess": "vmess",
        "wg": "wireguard",
        "wireguard": "wireguard",
    }
    return aliases.get(proto, proto)


def _parse_expire(value):
    if not value:
        return None
    text = str(value).strip()
    if re.fullmatch(r"\d{8}", text):
        try:
            return datetime.strptime(text, "%Y%m%d")
        except Exception:
            return None
    try:
        return datetime.fromisoformat(text.replace("/", "-"))
    except Exception:
        return None


def _format_size_limit_text(total_bytes: int) -> str:
    total = max(0, int(total_bytes or 0))
    units = [("t", 1000**4), ("g", 1000**3), ("m", 1000**2), ("k", 1000)]
    for suffix, size in units:
        if total >= size and total % size == 0:
            return f"{total // size}{suffix}"
    if total >= 1000**3:
        return f"{total / 1000**3:.2f}g".rstrip("0").rstrip(".")
    if total >= 1000**2:
        return f"{total / 1000**2:.2f}m".rstrip("0").rstrip(".")
    return f"{total}b"


def _hysteria2_name(line: Line, expire_at, index: int | None = None, total: int = 1) -> str:
    expire_text = expire_at.date().isoformat() if expire_at else "long"
    name = f"{line.public_ip}-{expire_text}"
    if total > 1 and index is not None:
        return f"{name}-{index:03d}"
    return name


def _safe_conf_name(value: str) -> str:
    text = re.sub(r"[^A-Za-z0-9_.\-\u4e00-\u9fff]+", "-", str(value or "")).strip("-")
    return text or "wireguard"


def _wireguard_conf_filename(user: ProxyUser) -> str:
    ip = user.line.public_ip if user.line else ""
    expire = user.expire_at.date().isoformat() if user.expire_at else ""
    parts = [ip, user.project_name or "", user.owner_name or user.username or "", expire]
    base = "-".join(_safe_conf_name(part) for part in parts if part)
    return f"{base or f'wg-{user.id}'}.conf"


def _download_disposition(filename: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "-", str(filename or "download.conf")).strip("-")
    if not safe:
        safe = "download.conf"
    encoded = urllib.parse.quote(str(filename or safe), safe="")
    return f"attachment; filename=\"{safe}\"; filename*=UTF-8''{encoded}"


def _normalize_speed_limit(value: str | None, default: str | None = None) -> str:
    text = str(value or "").strip().lower().replace(" ", "")
    if not text:
        return default or ""
    if re.fullmatch(r"\d+(?:\.\d+)?", text):
        return f"{text}m"
    return text


def _normalize_traffic_limit(value: str | None, default: str | None = None) -> str:
    text = str(value or "").strip().lower().replace(" ", "")
    if not text:
        return default or ""
    if re.fullmatch(r"\d+(?:\.\d+)?", text):
        return f"{text}g"
    return text


def _reload_proxy(session=None, line_ids=None):
    return proxy_manager.reload_config_with_listener_sync(session, reason="user-inbound-change", line_ids=line_ids)


def _is_inbound_instance(user: ProxyUser | None) -> bool:
    return inbound_instance_manager.is_instance_user(user)


def _apply_runtime_after_create(session, users: list[ProxyUser]) -> dict:
    instance_users = [user for user in users if _is_inbound_instance(user)]
    legacy_users = [user for user in users if not _is_inbound_instance(user)]
    result = {"ok": True, "instance": [], "legacy": {}}
    if legacy_users:
        _reload_proxy(session, [user.line_id for user in legacy_users])
        result["legacy"] = _ensure_created_applied(legacy_users)
        result["ok"] = bool(result["legacy"].get("applied", result["legacy"].get("ok", True)))
    for user in instance_users:
        item = inbound_instance_manager.start_user(user)
        item["user_id"] = user.id
        result["instance"].append(item)
        if not item.get("ok"):
            result["ok"] = False
    result["applied"] = result["ok"]
    result["restarted"] = any(item.get("restarted") for item in result["instance"]) or bool(result["legacy"].get("restarted"))
    return result


def _apply_runtime_after_delete(session, users: list[ProxyUser], affected_line_ids: list[int]) -> dict:
    instance_users = [user for user in users if _is_inbound_instance(user)]
    legacy_line_ids = [line_id for user, line_id in zip(users, affected_line_ids) if not _is_inbound_instance(user)]
    result = {"ok": True, "instance": [], "legacy": {}}
    for user in instance_users:
        item = inbound_instance_manager.remove_user(user)
        item["user_id"] = user.id
        result["instance"].append(item)
        if not item.get("ok"):
            result["ok"] = False
    if legacy_line_ids:
        result["legacy"] = _reload_proxy(session, legacy_line_ids)
        result["ok"] = result["ok"] and bool(result["legacy"].get("ok", True))
    return result


def _apply_runtime_for_user(session, user: ProxyUser, affected_line_ids: list[int] | None = None) -> dict:
    if _is_inbound_instance(user):
        return inbound_instance_manager.apply_user(user)
    return _reload_proxy(session, affected_line_ids or [user.line_id])


def _parse_inbound_field(text: str) -> dict:
    raw = str(text or "").strip()
    if not raw:
        raise ValueError("请输入原完整入站")
    if raw.lower().startswith("vmess://"):
        parts = raw.split("|")
        link_part = parts[0]
        suffix_parts = [part.strip() for part in parts[1:] if part.strip()]
        payload = link_part[8:].split("#", 1)[0].split("?", 1)[0].strip()
        payload += "=" * (-len(payload) % 4)
        try:
            vm = json.loads(base64.urlsafe_b64decode(payload.encode()).decode("utf-8", "replace"))
        except Exception as exc:
            raise ValueError("VMess 链接解析失败") from exc
        ip = str(vm.get("add") or vm.get("host") or "").strip()
        if suffix_parts:
            try:
                socket.inet_aton(suffix_parts[0])
                ip = suffix_parts[0]
            except Exception:
                pass
        try:
            port = int(suffix_parts[1] if len(suffix_parts) >= 2 and suffix_parts[1].isdigit() else (vm.get("port") or 0))
        except Exception as exc:
            raise ValueError("VMess 端口格式错误") from exc
        password = str(vm.get("id") or "").strip()
        if not ip or not port or not password:
            raise ValueError("VMess 链接缺少 IP、端口或 UUID")
        username = str(vm.get("ps") or "").strip() or "vmess"
        expire_candidate = next((part for part in reversed(suffix_parts) if _parse_expire(part)), "")
        expire = expire_candidate or (username if _parse_expire(username) else "")
        return {
            "raw": raw,
            "ip": ip,
            "port": port,
            "protocol": "vmess",
            "username": username,
            "password": password,
            "ss_method": None,
            "ss_password": None,
            "expire_at": expire,
            "vmess_payload": vm,
        }
    parts = [part.strip() for part in raw.split("|")]
    if len(parts) < 4:
        raise ValueError("入站格式错误，至少需要 IP|端口|账号/方法|密码")
    ip = parts[0]
    try:
        socket.inet_aton(ip)
    except Exception as exc:
        raise ValueError("入站 IP 格式错误") from exc
    try:
        port = int(parts[1])
    except Exception as exc:
        raise ValueError("入站端口格式错误") from exc
    if not (0 < port <= 65535):
        raise ValueError("入站端口范围错误")
    third = parts[2]
    fourth = parts[3]
    expire = ""
    for value in reversed(parts[4:]):
        if _parse_expire(value):
            expire = value
            break
    protocol = "ss" if third in SS_METHODS else "socks5"
    data = {
        "raw": raw,
        "ip": ip,
        "port": port,
        "protocol": protocol,
        "username": "ss_user" if protocol == "ss" else third,
        "password": fourth,
        "ss_method": third if protocol == "ss" else None,
        "ss_password": fourth if protocol == "ss" else None,
        "expire_at": expire,
    }
    return data


def _user_matches_inbound(user: ProxyUser, spec: dict) -> bool:
    if not user.line:
        return False
    if str(user.line.public_ip or "") != str(spec.get("ip") or ""):
        return False
    if int(user.listen_port or user.line.get_port_by_protocol(user.protocol)) != int(spec.get("port") or 0):
        return False
    if (user.protocol or "socks5").lower() != spec.get("protocol"):
        return False
    if spec.get("protocol") == "ss":
        return (user.ss_method or "aes-256-gcm") == spec.get("ss_method") and (user.ss_password or user.password or "") == spec.get("ss_password")
    if spec.get("protocol") == "vmess":
        return (user.password or "") == spec.get("password")
    return (user.username or "") == spec.get("username") and (user.password or "") == spec.get("password")


def _find_remote_inbound(session, spec: dict) -> tuple[ManagedServer | None, dict | None]:
    servers = session.query(ManagedServer).filter(ManagedServer.ip == spec["ip"]).all()
    for server in servers:
        try:
            rows = (_remote_panel_get(server, "/api/users", timeout=8).get("data") or [])
        except Exception:
            continue
        for item in rows:
            try:
                port = int(item.get("listen_port") or item.get("port") or 0)
            except Exception:
                port = 0
            if port != spec["port"]:
                continue
            if (item.get("protocol") or "socks5").lower() != spec["protocol"]:
                continue
            if spec["protocol"] == "ss":
                if (item.get("ss_method") or "aes-256-gcm") != spec["ss_method"]:
                    continue
                if (item.get("ss_password") or item.get("password") or "") != spec["ss_password"]:
                    continue
            elif spec["protocol"] == "vmess":
                if (item.get("password") or "") != spec["password"]:
                    continue
            else:
                if (item.get("username") or "") != spec["username"] or (item.get("password") or "") != spec["password"]:
                    continue
            return server, item
    return None, None


def _change_ip_output(spec: dict, new_ip: str) -> str:
    expire = spec.get("expire_at") or ""
    if spec["protocol"] == "ss":
        return f"{new_ip}|{spec['port']}|{spec['ss_method']}|{spec['ss_password']}|{expire}".rstrip("|")
    if spec["protocol"] == "vmess":
        vm = dict(spec.get("vmess_payload") or {})
        vm["add"] = new_ip
        vm["port"] = str(spec["port"])
        vm["id"] = spec["password"]
        raw = json.dumps(vm, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        link = "vmess://" + base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
        return f"{link}|{new_ip}|{spec['port']}|{expire}".rstrip("|")
    return f"{new_ip}|{spec['port']}|{spec['username']}|{spec['password']}|{expire}".rstrip("|")


def _remote_has_assignment(server: ManagedServer, owner_name: str, project_name: str) -> bool:
    owner_need = (owner_name or "").strip()
    project_need = (project_name or "").strip()
    if not owner_need and not project_need:
        return False
    try:
        rows = (_remote_panel_get(server, "/api/users", timeout=8).get("data") or [])
    except Exception:
        return True
    for item in rows:
        owner = (item.get("owner_name") or item.get("username") or "").strip()
        project = (item.get("project_name") or "").strip()
        if owner_need and project_need:
            if owner == owner_need and project == project_need:
                return True
        elif owner_need and owner == owner_need:
            return True
        elif project_need and project == project_need:
            return True
    return False


def _select_change_ip_target(session, old_ip: str, requested_ip: str, owner_name: str, project_name: str) -> ManagedServer | None:
    q = session.query(ManagedServer).filter(
        ManagedServer.install_status == "installed",
        (ManagedServer.silent_group.is_(None)) | (ManagedServer.silent_group == 0),
        ManagedServer.ip != old_ip,
    )
    if requested_ip:
        q = q.filter(ManagedServer.ip == requested_ip)
    servers = q.order_by(ManagedServer.id).all()
    best = None
    best_count = None
    for server in servers:
        if _remote_has_assignment(server, owner_name, project_name):
            continue
        count = 0
        try:
            rows = (_remote_panel_get(server, "/api/users", timeout=8).get("data") or [])
            count = len(rows)
        except Exception:
            continue
        if best is None or count < best_count:
            best = server
            best_count = count
    return best


def _apply_user_limit(user):
    if not parse_speed_to_bps(user.speed_limit):
        return {"ok": True, "limited": False, "bps": None, "skipped": True, "output": ""}
    if not user.line:
        return {"ok": False, "output": "line missing"}
    port = user.listen_port or user.line.get_port_by_protocol(user.protocol)
    return apply_limit(user, port, user.protocol)


def _apply_user_limits_background(user_ids: list[int]):
    ids = [int(x) for x in user_ids if x]
    if not ids:
        return

    def worker():
        if not _limit_worker_lock.acquire(blocking=False):
            return
        session = get_session()
        try:
            users = session.query(ProxyUser).filter(ProxyUser.id.in_(ids), ProxyUser.status == 1).all()
            for user in users:
                try:
                    _apply_user_limit(user)
                except Exception as exc:
                    print(f"[limit] apply failed for user {user.id}: {exc}")
        finally:
            session.close()
            _limit_worker_lock.release()

    threading.Thread(target=worker, daemon=True).start()


def _clear_user_limits_background(user_ids: list[int]):
    ids = [int(x) for x in user_ids if x]
    if not ids:
        return

    def worker():
        if not _limit_worker_lock.acquire(blocking=False):
            return
        try:
            for uid in ids:
                try:
                    clear_limit(uid)
                except Exception as exc:
                    print(f"[limit] clear failed for user {uid}: {exc}")
        finally:
            _limit_worker_lock.release()

    threading.Thread(target=worker, daemon=True).start()


def _apply_traffic_limits(session):
    disabled = []
    for user in session.query(ProxyUser).filter_by(status=1).all():
        limit = parse_size_to_bytes(user.traffic_limit)
        if not limit:
            continue
        used = int(user.bytes_in or 0) + int(user.bytes_out or 0)
        if used >= limit:
            user.status = 0
            host = user.line.public_ip if user.line else "-"
            port = user.listen_port or (user.line.get_port_by_protocol(user.protocol) if user.line else "-")
            add_operation_log(
                session,
                "system",
                "自动保护",
                "自动停用节点",
                (
                    f"自动停用原因=流量用完；节点={host}:{port}；协议={user.protocol or '-'}；"
                    f"用户={user.owner_name or user.username or '-'}；项目={user.project_name or '-'}；"
                    f"已用={used} bytes；上限={limit} bytes；流量套餐={user.traffic_limit or '-'}"
                ),
                str(host),
            )
            disabled.append(user.username)
    if disabled:
        session.commit()
    return disabled


def _apply_expire_limits(session):
    disabled = []
    now = datetime.now()
    users = (
        session.query(ProxyUser)
        .filter(ProxyUser.status == 1, ProxyUser.expire_at.isnot(None), ProxyUser.expire_at <= now)
        .all()
    )
    for user in users:
        user.status = 0
        host = user.line.public_ip if user.line else "-"
        port = user.listen_port or (user.line.get_port_by_protocol(user.protocol) if user.line else "-")
        add_operation_log(
            session,
            "system",
            "自动保护",
            "自动停用节点",
            (
                f"自动停用原因=到期；节点={host}:{port}；协议={user.protocol or '-'}；"
                f"用户={user.owner_name or user.username or '-'}；项目={user.project_name or '-'}；"
                f"到期时间={user.expire_at.isoformat() if user.expire_at else '-'}"
            ),
            str(host),
        )
        disabled.append(user.username)
    if disabled:
        session.commit()
        _clear_user_limits_background([user.id for user in users])
    return disabled


def _format_bps(bytes_per_second: int) -> str:
    units = ["B/s", "KB/s", "MB/s", "GB/s", "TB/s"]
    value = float(max(0, bytes_per_second or 0))
    idx = 0
    while value >= 1024 and idx < len(units) - 1:
        value /= 1024
        idx += 1
    return f"{value:.2f} {units[idx]}"


def _is_port_listening(port: int, protocol: str | None = None) -> bool:
    if (protocol or "").lower() == "hysteria2":
        try:
            for conn in psutil.net_connections(kind="udp"):
                if conn.laddr and conn.laddr.port == int(port):
                    return True
        except Exception:
            pass
        return False
    try:
        for conn in psutil.net_connections(kind="tcp"):
            if conn.status == psutil.CONN_LISTEN and conn.laddr and conn.laddr.port == int(port):
                return True
    except Exception:
        pass
    return False


def _is_tcp_listening_on(host: str, port: int) -> bool:
    host = (host or "").strip()
    try:
        for conn in psutil.net_connections(kind="tcp"):
            if conn.status != psutil.CONN_LISTEN or not conn.laddr:
                continue
            if int(conn.laddr.port) != int(port):
                continue
            listen_host = getattr(conn.laddr, "ip", "") or conn.laddr[0]
            if not host or listen_host in {host, "0.0.0.0", "::"}:
                return True
    except Exception:
        pass
    return False


def _user_listen_target(user: ProxyUser) -> tuple[str, int, str]:
    protocol = (user.protocol or "socks5").lower()
    line = user.line
    host = (line.public_ip if line else "") or ""
    port = int(user.listen_port or (line.get_port_by_protocol(protocol) if line else 0) or 0)
    return host, port, protocol


def _ensure_user_runtime_applied(session, user: ProxyUser, expected_enabled: bool, apply_status: dict | None = None) -> dict:
    host, port, protocol = _user_listen_target(user)
    status = dict(apply_status or {})
    if not port:
        status.update({"applied": False, "message": "missing listen port"})
        return status

    is_listening = _is_tcp_listening_on(host, port)
    if (expected_enabled and is_listening) or ((not expected_enabled) and not is_listening):
        status.setdefault("applied", True)
        status.setdefault("restarted", False)
        status.setdefault("message", "runtime listener verified")
        status["listen"] = f"{host}:{port}" if host else str(port)
        return status

    status.update({
        "applied": False,
        "restarted": False,
        "listen": f"{host}:{port}" if host else str(port),
        "message": "runtime listener state not changed by hot reload; sing-box was not restarted",
    })
    return status


def _created_apply_status(users: list[ProxyUser]) -> dict:
    ports = sorted({int(u.listen_port or u.line.get_port_by_protocol(u.protocol)) for u in users if u.line})
    missing = []
    for port in ports:
        sample = next((u for u in users if int(u.listen_port or u.line.get_port_by_protocol(u.protocol)) == port), None)
        if sample and not _is_port_listening(port, sample.protocol):
            missing.append(port)
    return {
        "applied": not missing,
        "missing_ports": missing,
        "restarted": False,
        "message": "已自动应用，端口已监听" if not missing else f"端口 {', '.join(map(str, missing[:8]))} 尚未监听",
    }


def _ensure_created_applied(users: list[ProxyUser]) -> dict:
    status = _created_apply_status(users)
    if status["applied"]:
        return status
    missing_before = list(status.get("missing_ports") or [])
    status["applied"] = False
    status["restarted"] = False
    status["message"] = (
        "hot reload did not expose every listener; sing-box was not restarted automatically: "
        + ", ".join(map(str, missing_before[:8]))
    )
    return status


def _interface_for_line(line: Line) -> str | None:
    candidates = [line.note, line.name]
    addrs = psutil.net_if_addrs()
    for candidate in candidates:
        if candidate and candidate in addrs:
            return candidate
    for iface, rows in addrs.items():
        for addr in rows:
            if addr.family == socket.AF_INET and addr.address in {line.public_ip, line.internal_ip}:
                return iface
    return None


def _line_bandwidth(line: Line) -> dict:
    iface = _interface_for_line(line)
    empty = {"interface": iface or "", "speed_mbps": 0, "speed": "未知", "rx_bps": 0, "tx_bps": 0, "rx": "0 B/s", "tx": "0 B/s"}
    if not iface:
        return empty

    try:
        stat = psutil.net_if_stats().get(iface)
        speed_mbps = int(stat.speed or 0) if stat else 0
    except Exception:
        speed_mbps = 0

    first = psutil.net_io_counters(pernic=True).get(iface)
    if not first:
        empty.update({"speed_mbps": speed_mbps, "speed": f"{speed_mbps} Mbps" if speed_mbps else "未知"})
        return empty
    start = time.time()
    time.sleep(0.35)
    second = psutil.net_io_counters(pernic=True).get(iface)
    if not second:
        empty.update({"speed_mbps": speed_mbps, "speed": f"{speed_mbps} Mbps" if speed_mbps else "未知"})
        return empty

    elapsed = max(time.time() - start, 0.001)
    rx_bps = max(0, int((second.bytes_recv - first.bytes_recv) / elapsed))
    tx_bps = max(0, int((second.bytes_sent - first.bytes_sent) / elapsed))
    return {
        "interface": iface,
        "speed_mbps": speed_mbps,
        "speed": f"{speed_mbps} Mbps" if speed_mbps else "未知",
        "rx_bps": rx_bps,
        "tx_bps": tx_bps,
        "rx": _format_bps(rx_bps),
        "tx": _format_bps(tx_bps),
    }


def _tcp_test(host: str, port: int) -> dict:
    result = {"ok": False, "message": "TCP 不通"}
    try:
        with socket.create_connection((host, int(port)), timeout=2.0):
            result.update({"ok": True, "message": "TCP 通"})
            return result
    except Exception as exc:
        result["error"] = str(exc)

    try:
        for conn in psutil.net_connections(kind="tcp"):
            if not conn.laddr or conn.status != psutil.CONN_LISTEN:
                continue
            if conn.laddr.port != int(port):
                continue
            listen_ip = conn.laddr.ip or ""
            if listen_ip in {"0.0.0.0", "::", host}:
                result.update({"ok": True, "message": "TCP 已监听"})
                result.pop("error", None)
                return result
    except Exception:
        pass
    return result


def _read_exact(sock, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise OSError("连接提前关闭")
        data += chunk
    return data


def _parse_socks_addr(sock, atyp: int | None = None) -> tuple[str, int]:
    if atyp is None:
        atyp = _read_exact(sock, 1)[0]
    if atyp == 1:
        host = socket.inet_ntoa(_read_exact(sock, 4))
    elif atyp == 3:
        size = _read_exact(sock, 1)[0]
        host = _read_exact(sock, size).decode("utf-8", errors="ignore")
    elif atyp == 4:
        host = socket.inet_ntop(socket.AF_INET6, _read_exact(sock, 16))
    else:
        raise OSError(f"未知地址类型 {atyp}")
    port = struct.unpack("!H", _read_exact(sock, 2))[0]
    return host, port


def _dns_query_packet() -> bytes:
    query_id = secrets.randbits(16)
    header = struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0)
    question = b"\x01a\x0croot-servers\x03net\x00" + struct.pack("!HH", 1, 1)
    return header + question


def _socks5_udp_associate_test(host: str, port: int, username: str, password: str) -> dict:
    try:
        with socket.create_connection((host, int(port)), timeout=3.0) as tcp:
            tcp.settimeout(3.0)
            tcp.sendall(b"\x05\x01\x02")
            if _read_exact(tcp, 2) != b"\x05\x02":
                return {"ok": False, "message": "SK5 UDP 认证方式不匹配"}

            user_b = username.encode("utf-8")
            pass_b = password.encode("utf-8")
            if len(user_b) > 255 or len(pass_b) > 255:
                return {"ok": False, "message": "SK5 账号或密码过长"}
            tcp.sendall(b"\x01" + bytes([len(user_b)]) + user_b + bytes([len(pass_b)]) + pass_b)
            if _read_exact(tcp, 2) != b"\x01\x00":
                return {"ok": False, "message": "SK5 认证失败"}

            udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                udp.settimeout(4.0)
                udp.bind(("0.0.0.0", 0))
                udp_host, udp_port = udp.getsockname()
                tcp.sendall(b"\x05\x03\x00\x01" + socket.inet_aton(udp_host) + struct.pack("!H", udp_port))
                head = _read_exact(tcp, 4)
                if head[:2] != b"\x05\x00":
                    return {"ok": False, "message": f"SK5 UDP Associate 失败({head[1] if len(head) > 1 else '-'})"}
                relay_host, relay_port = _parse_socks_addr(tcp, head[3])
                if relay_host in {"0.0.0.0", "::"}:
                    relay_host = host

                packet = b"\x00\x00\x00\x01" + socket.inet_aton("1.1.1.1") + struct.pack("!H", 53) + _dns_query_packet()
                udp.sendto(packet, (relay_host, relay_port))
                data, _ = udp.recvfrom(4096)
                if len(data) > 10 and data[:3] == b"\x00\x00\x00":
                    return {"ok": True, "message": "SK5 UDP 通"}
                return {"ok": False, "message": "SK5 UDP 返回异常"}
            finally:
                udp.close()
    except Exception as exc:
        return {"ok": False, "message": "SK5 UDP 不通", "error": str(exc)}


def _udp_test(host: str, port: int, protocol: str, user: ProxyUser | None = None) -> dict:
    if protocol not in TESTABLE_UDP_PROTOCOLS:
        return {"ok": True, "message": "该协议无 UDP 入站"}
    if protocol == "socks5" and user:
        return _socks5_udp_associate_test(host, port, user.username, user.password)
    try:
        for conn in psutil.net_connections(kind="udp"):
            if not conn.laddr or conn.laddr.port != int(port):
                continue
            listen_ip = conn.laddr.ip or ""
            if listen_ip in {"0.0.0.0", "::", host}:
                return {"ok": True, "message": "UDP 已监听"}
    except Exception as exc:
        return {"ok": False, "message": "UDP 检测失败", "error": str(exc)}
    return {"ok": False, "message": "UDP 未监听"}


def _node_ok(protocol: str, tcp: dict, udp: dict) -> bool:
    if protocol == "hysteria2":
        return bool(udp.get("ok"))
    if protocol in {"socks5", "ss"}:
        return bool(tcp.get("ok") and udp.get("ok"))
    return bool(tcp.get("ok"))


def _fast_speed_for_user(user: ProxyUser) -> dict | None:
    if (user.protocol or "").lower() != "socks5" or not user.line:
        return None
    return fast_socks5_speed({
        "type": "socks5",
        "host": user.line.public_ip,
        "port": user.listen_port or user.line.get_port_by_protocol("socks5"),
        "username": user.username,
        "password": user.password,
    })


def _create_user_v3():
    data = request.get_json(silent=True) or {}
    base_username = (data.get("username") or data.get("account") or "user").strip()
    password = (data.get("password") or "").strip()
    protocol = _normalize_protocol(data.get("protocol"))
    ss_method = (data.get("ss_method") or "aes-256-gcm").strip()
    line_id = data.get("line_id") or data.get("ip") or data.get("ip_select") or ("lite" if is_lite_mode() else "all")
    line_ids = data.get("line_ids") or []
    server_ids = data.get("server_ids") or []
    expire_at_str = data.get("expire_at") or ""
    speed_limit = _normalize_speed_limit(data.get("speed_limit"), DEFAULT_SPEED_LIMIT)
    traffic_limit = _normalize_traffic_limit(data.get("traffic_limit"), DEFAULT_TRAFFIC_LIMIT)
    owner_name = (data.get("owner_name") or data.get("owner") or "").strip()
    operator = current_operator_name()
    project_name = (data.get("project_name") or data.get("project") or "").strip()
    custom_port = data.get("custom_port")
    count = min(max(int(data.get("count") or 1), 1), 500)
    local_count = min(max(int(data.get("local_count") or 0), 0), count)
    remote_count = min(max(int(data.get("remote_count") or 0), 0), count)
    skip_existing = True
    note = data.get("note", "")

    if protocol == "wireguard":
        base_username = base_username if base_username != "user" else "wg"
    if protocol == "ss":
        base_username = "ss_user"
    if protocol == "hysteria2":
        base_username = "hy2"
    if protocol not in PROTOCOL_TYPES:
        return jsonify({"ok": False, "error": f"协议必须是 {', '.join(PROTOCOL_TYPES)}"}), 400
    if protocol == "ss" and ss_method not in SS_METHODS:
        return jsonify({"ok": False, "error": f"SS 加密方式必须是 {', '.join(SS_METHODS)}"}), 400
    if protocol != "hysteria2" and not USERNAME_RE.match(base_username):
        return jsonify({"ok": False, "error": "用户名格式错误：3-48 位字母、数字、下划线或横线"}), 400
    if not project_name and not is_lite_mode():
        return jsonify({"ok": False, "error": "请选择项目"}), 400
    if not project_name:
        project_name = (data.get("project") or "default").strip() or "default"

    if protocol == "hysteria2":
        password = _gen_password(16)
    elif not password:
        password = str(uuid.uuid4()) if protocol in {"vless", "vmess"} else _gen_password(12)
    elif protocol in {"vless", "vmess"}:
        try:
            password = str(uuid.UUID(password))
        except ValueError:
            return jsonify({"ok": False, "error": "VLESS 密码必须是 UUID，留空可自动生成"}), 400
    ss_password = (data.get("ss_password") or "").strip() or password or _gen_password(12)

    expire_at = _parse_expire(expire_at_str)
    if expire_at_str and expire_at is None:
        return jsonify({"ok": False, "error": "到期时间格式错误"}), 400

    if protocol == "wireguard" and not wireguard_manager.available():
        return jsonify({"ok": False, "error": "WireGuard tools not installed: install wireguard-tools first"}), 400

    s = get_session()
    try:
        remote_create_count = remote_count if (local_count or str(line_id).lower() == "lite") else count
        remote_result = _create_on_managed_servers(s, server_ids, data, remote_create_count)
        remote_created = remote_result.get("created", []) if remote_result else []
        if remote_result is not None and not (str(line_id).lower() == "lite" and local_count):
            if not remote_result.get("created"):
                detail = "；".join((remote_result.get("errors") or [])[:3]) or "远程服务器没有创建成功"
                return jsonify({"ok": False, "error": f"未创建任何节点：{detail}", "data": remote_result}), 400
            log_details = [_format_log_user_detail(item) for item in remote_result.get("created", [])]
            _add_user_operation_log(
                s,
                "新增入站",
                f"count={len(log_details)} scope=remote; {_compact_log_details(log_details)}",
            )
            s.commit()
            return jsonify({"ok": True, "data": remote_result})

        line_key = str(line_id).lower()
        lite_create = False
        batch_selected_lines = bool(line_ids)
        if line_ids:
            selected_lines = _target_lines_by_ids(s, line_ids)
            lines = []
            while len(lines) < count and selected_lines:
                lines.extend(selected_lines)
            lines = lines[:count]
        elif line_key == "all":
            lines = _target_lines(s, line_id, count)
        elif is_lite_mode() or line_key == "lite":
            lite_create = True
            lite_line = _ensure_lite_line(s, data.get("public_ip") or data.get("line_ip") or data.get("managed_server_ip") or "")
            lines = [lite_line for _ in range(local_count or count)]
        else:
            lines = _target_lines(s, line_id, count)
        if not lines:
            return jsonify({"ok": False, "error": "线路不存在"}), 400

        forced_port = None
        used_ports = _used_listen_ports(s)
        if protocol != "hysteria2" and custom_port not in (None, "", 0, "0"):
            forced_port = int(custom_port)
            if not (1024 < forced_port < 65536):
                return jsonify({"ok": False, "error": "端口范围错误"}), 400
            if _is_windows_excluded_port(forced_port):
                return jsonify({"ok": False, "error": f"端口 {forced_port} 被 Windows 系统保留，请换一个端口"}), 400
            if not _port_available_on_host(forced_port):
                return jsonify({"ok": False, "error": f"端口 {forced_port} 已被系统进程占用"}), 400
            if str(line_id).lower() != "all":
                exists = (
                    s.query(ProxyUser)
                    .filter(
                        ProxyUser.line_id == lines[0].id,
                        ProxyUser.protocol == protocol,
                        ProxyUser.listen_port == forced_port,
                    )
                    .first()
                )
                if exists:
                    if remote_created:
                        forced_port = None
                    else:
                        return jsonify({"ok": False, "error": "该线路端口已被占用"}), 400

        created = []
        skipped = []
        errors = []
        assignment_owner = _assignment_label(owner_name, base_username)
        for line in lines:
            if len(created) >= count:
                break
            if not lite_create and not batch_selected_lines and _line_project_used(s, line.id, project_name):
                skipped.append(f"{line.name} / {line.public_ip}: 项目 {project_name or '-'} 已占用该节点，已跳过")
                continue
            if protocol == "hysteria2":
                username = _hysteria2_name(line, expire_at, len(created) + 1, count)
            else:
                username = base_username if len(lines) == 1 else f"{base_username}{len(created) + 1:03d}"

            if forced_port:
                exists = (
                    s.query(ProxyUser)
                    .filter(
                        ProxyUser.line_id == line.id,
                        ProxyUser.protocol == protocol,
                        ProxyUser.listen_port == forced_port,
                    )
                    .first()
                )
                if exists:
                    skipped.append(f"{line.name} / {line.public_ip}: 端口 {forced_port} 已被该线路占用，已跳过")
                    continue
                listen_port = forced_port
            else:
                listen_port = _random_available_port(s, used_ports)
            user_password = str(uuid.uuid4()) if protocol in {"vless", "vmess"} and not data.get("password") else password
            if protocol == "wireguard":
                user_password = "pending-wireguard-key"
            user = ProxyUser(
                username=username,
                password=user_password,
                ss_password=ss_password if protocol == "ss" else None,
                line_id=line.id,
                protocol=protocol,
                listen_port=listen_port,
                ss_method=ss_method if protocol == "ss" else None,
                operator=operator,
                owner_name=assignment_owner or None,
                project_name=project_name or None,
                speed_limit=speed_limit or None,
                traffic_limit=traffic_limit or None,
                runtime_mode="inbound_instance" if protocol != "wireguard" else None,
                expire_at=expire_at,
                note=note,
            )
            s.add(user)
            if protocol == "wireguard":
                s.flush()
                wireguard_manager.create_client_material(s, user, line.public_ip)
            created.append(user)

        local_target_count = len(lines)
        if len(created) < local_target_count:
            errors.append(f"节点不足：需要 {local_target_count} 个，实际创建 {len(created)} 个，缺少 {local_target_count - len(created)} 个")

        if not created and not remote_created:
            details = errors or skipped
            detail = "；".join(details[:3]) if details else "没有可用线路"
            if skipped and not errors and skip_existing:
                return jsonify({"ok": True, "data": {
                    "created": [],
                    "created_count": 0,
                    "skipped": skipped,
                    "skipped_count": len(skipped),
                    "errors": [],
                    "limits": [],
                    "limit_queued": 0,
                    "apply_status": {"applied": True, "missing_ports": [], "restarted": False, "message": "all matched nodes already exist; skipped"},
                }})
            return jsonify({"ok": False, "error": f"未创建任何节点：{detail}"}), 400

        s.commit()
        for user in created:
            s.refresh(user)
        try:
            if protocol == "wireguard":
                apply_status = wireguard_manager.reload_service(s)
            else:
                apply_status = _apply_runtime_after_create(s, created)
        except Exception as exc:
            created_ids = [user.id for user in created]
            for user in created:
                s.delete(user)
            s.commit()
            if protocol == "wireguard":
                try:
                    wireguard_manager.reload_service(s)
                except Exception:
                    pass
            else:
                try:
                    _apply_runtime_after_delete(s, created, [user.line_id for user in created])
                except Exception:
                    pass
            detail = str(exc)
            return jsonify({"ok": False, "error": f"自动应用配置失败，已回滚本次创建：{detail}", "data": {"rolled_back_ids": created_ids}}), 400
        limited_ids = [u.id for u in created if parse_speed_to_bps(u.speed_limit)]
        _apply_user_limits_background(limited_ids)
        log_details = [_format_log_user_detail(item) for item in remote_created]
        log_details.extend(_format_log_user_detail(user) for user in created)
        if log_details:
            _add_user_operation_log(
                s,
                "新增入站",
                f"count={len(log_details)} protocol={protocol}; {_compact_log_details(log_details)}",
            )
            s.commit()
        result = {
            "created": remote_created + [u.to_dict() for u in created],
            "created_count": len(remote_created) + len(created),
            "skipped": skipped,
            "skipped_count": len(skipped),
            "errors": (remote_result.get("errors", []) if remote_result else []) + errors,
            "limits": [{"ok": True, "queued": True, "user_id": uid} for uid in limited_ids],
            "limit_queued": len(limited_ids),
            "apply_status": apply_status,
        }
        if len(created) == 1:
            result.update(created[0].to_dict())
        return jsonify({"ok": True, "data": result})
    finally:
        s.close()


def _limit_info_for_user(user: ProxyUser, measured_mbps=None) -> dict:
    bps = parse_speed_to_bps(user.speed_limit)
    if not bps:
        return {"enabled": False, "raw": user.speed_limit or "", "message": "未设置限速"}
    limit_mbps = round(bps / 1000 / 1000, 2)
    policy = apply_limit(user, user.listen_port or user.line.get_port_by_protocol(user.protocol), user.protocol) if user.line else {}
    bypass_hint = bool(measured_mbps and measured_mbps > limit_mbps * 1.3)
    return {
        "enabled": True,
        "raw": user.speed_limit,
        "bps": bps,
        "mbps": limit_mbps,
        "policy_ok": bool(policy.get("ok")),
        "policy_output": policy.get("output") or "",
        "self_test_bypassed": bypass_hint,
        "message": (
            "本机 Fast 自测会绕过 Windows 端口 QoS，显示的是原始出口速度；"
            "外部客户端连接节点时才会命中限速策略。"
            if bypass_hint else
            "限速策略已下发，外部客户端连接节点时生效。"
        ),
    }


@bp.route("", methods=["GET"])
@login_required
def list_users():
    s = get_session()
    try:
        local_only = str(request.args.get("local_only") or "").lower() in {"1", "true", "yes"}
        include_remote = str(request.args.get("include_remote") or "").lower() in {"1", "true", "yes"}
        refresh_stats = str(request.args.get("refresh_stats") or "").lower() in {"1", "true", "yes"}
        if refresh_stats:
            try:
                collect_once()
            except Exception:
                pass
        if refresh_stats:
            connection_status = snapshot_connections_status()
        else:
            connection_status = {"ok": False, "data": {}, "port_counter_users": set(), "error": "fast list mode"}
        connection_snapshot = connection_status.get("data") or {}
        port_counter_users = connection_status.get("port_counter_users") or set()
        wg_totals = wireguard_manager.transfer_snapshot(s) if refresh_stats else {}
        expired = _apply_expire_limits(s)
        traffic_disabled = _apply_traffic_limits(s)
        if expired or traffic_disabled:
            _reload_proxy(s)
        q = s.query(ProxyUser)
        line_id = request.args.get("line_id", type=int)
        if line_id:
            q = q.filter(ProxyUser.line_id == line_id)
        users = q.options(joinedload(ProxyUser.line)).order_by(ProxyUser.id.desc()).all()
        rows = []
        for user in users:
            item = user.to_dict()
            live = connection_snapshot.get(user.id, {})
            item["connections"] = int(live.get("connections") or 0)
            item["live_upload"] = int(live.get("upload") or 0)
            item["live_download"] = int(live.get("download") or 0)
            item["traffic_available"] = bool(connection_status.get("ok"))
            if connection_status.get("ok"):
                if user.id in port_counter_users:
                    item["traffic_source"] = "系统端口累计统计"
                else:
                    item["traffic_source"] = "sing-box 实时连接统计"
            else:
                item["traffic_source"] = f"sing-box 连接读取失败，已清零: {connection_status.get('error') or 'unknown'}"
            if (user.protocol or "").lower() == "wireguard" and user.id in wg_totals:
                wg_rx, wg_tx = wg_totals.get(user.id) or (0, 0)
                item["bytes_in"] = max(int(item.get("bytes_in") or 0), int(wg_tx or 0))
                item["bytes_out"] = max(int(item.get("bytes_out") or 0), int(wg_rx or 0))
                item["connections"] = 1 if int(wg_rx or 0) or int(wg_tx or 0) else 0
                item["traffic_available"] = True
                item["traffic_source"] = "WireGuard 实时统计"
            rows.append(item)
        if include_remote and not local_only:
            rows.extend(_remote_users_from_managed_servers(s))
            rows = _dedupe_user_rows(rows)
        return jsonify({"ok": True, "data": rows})
    finally:
        s.close()


@bp.route("", methods=["POST"])
@login_required
def create_user():
    return _create_user_v3()


@bp.route("/sync", methods=["POST"])
@login_required
def sync_users():
    traffic = collect_once()
    s = get_session()
    try:
        expired = _apply_expire_limits(s)
        disabled = _apply_traffic_limits(s)
        limit_results = sync_limits(s)
        if expired or disabled:
            _reload_proxy(s)
        return jsonify({"ok": True, "data": {"traffic": traffic, "expired": expired, "disabled": disabled, "limits": limit_results}})
    finally:
        s.close()


@bp.route("/clean-expired", methods=["POST"])
@login_required
def clean_expired():
    s = get_session()
    try:
        now = datetime.utcnow()
        users = s.query(ProxyUser).filter(ProxyUser.expire_at.isnot(None), ProxyUser.expire_at < now).all()
        count = len(users)
        limit_ids = [user.id for user in users]
        affected_line_ids = [user.line_id for user in users]
        for user in users:
            s.delete(user)
        s.commit()
        _reload_proxy(s, affected_line_ids)
        _clear_user_limits_background(limit_ids)
        return jsonify({"ok": True, "data": {"deleted": count, "limit_clear_queued": len(limit_ids)}})
    finally:
        s.close()


@bp.route("/batch-delete", methods=["POST"])
@login_required
def batch_delete():
    raw_ids = (request.get_json(silent=True) or {}).get("ids") or []
    ids = []
    remote_ids = []
    for value in raw_ids:
        remote_id = _parse_remote_user_id(value)
        if remote_id and remote_id not in remote_ids:
            remote_ids.append(remote_id)
            continue
        if str(value).isdigit():
            uid = int(value)
            if uid not in ids:
                ids.append(uid)
    if not ids and not remote_ids:
        return jsonify({"ok": False, "error": "请选择要删除的节点"}), 400
    s = get_session()
    try:
        users = s.query(ProxyUser).filter(ProxyUser.id.in_(ids)).all() if ids else []
        count = len(users)
        limit_ids = [user.id for user in users]
        affected_line_ids = [user.line_id for user in users]
        local_log_details = [_format_log_user_detail(user) for user in users]
        apply_status = _apply_runtime_after_delete(s, users, affected_line_ids) if users else {}
        for user in users:
            s.delete(user)
        s.commit()
        if users:
            _clear_user_limits_background(limit_ids)

        errors = []
        if remote_ids:
            server_ids = sorted({server_id for server_id, _ in remote_ids})
            servers = {server.id: server for server in s.query(ManagedServer).filter(ManagedServer.id.in_(server_ids)).all()}
            def delete_remote(remote_pair):
                server_id, user_id = remote_pair
                server = servers.get(server_id)
                if not server:
                    return False, f"server {server_id} not found", ""
                detail = f"server={server.ip} remote_id={user_id}"
                try:
                    try:
                        remote_rows = (_remote_panel_get(server, "/api/users", timeout=8).get("data") or [])
                        for item in remote_rows:
                            if str(item.get("id")) == str(user_id):
                                detail = _format_log_user_detail(item, server.ip)
                                break
                    except Exception:
                        pass
                    _remote_panel_delete(server, f"/api/users/{user_id}")
                    return True, "", detail
                except Exception as exc:
                    return False, f"{server.ip}:{user_id} {exc}", detail

            with ThreadPoolExecutor(max_workers=min(10, len(remote_ids))) as executor:
                futures = [executor.submit(delete_remote, item) for item in remote_ids]
                for future in as_completed(futures):
                    ok, error, detail = future.result()
                    if ok:
                        count += 1
                        if detail:
                            local_log_details.append(detail)
                    elif error:
                        errors.append(error)
        if local_log_details:
            _add_user_operation_log(
                s,
                "删除入站",
                f"count={len(local_log_details)}; {_compact_log_details(local_log_details)}",
            )
            s.commit()
        return jsonify({"ok": True, "data": {"deleted": count, "errors": errors, "limit_clear_queued": len(limit_ids), "apply_status": apply_status}})
    finally:
        s.close()


@bp.route("/batch-stop", methods=["POST"])
@login_required
def batch_stop():
    ids = (request.get_json(silent=True) or {}).get("ids") or []
    ids = [int(x) for x in ids if str(x).isdigit()]
    if not ids:
        return jsonify({"ok": False, "error": "请选择要停止的节点"}), 400
    s = get_session()
    try:
        users = s.query(ProxyUser).filter(ProxyUser.id.in_(ids)).all()
        changed = []
        affected_line_ids = []
        apply_status = {"ok": True, "instance": [], "legacy": {}}
        for user in users:
            if user.status:
                user.status = 0
                changed.append(user.id)
                affected_line_ids.append(user.line_id)
        s.commit()
        if changed:
            _clear_user_limits_background(changed)
            changed_users = [user for user in users if user.id in changed]
            instance_users = [user for user in changed_users if _is_inbound_instance(user)]
            legacy_line_ids = [user.line_id for user in changed_users if not _is_inbound_instance(user)]
            for user in instance_users:
                item = inbound_instance_manager.stop_user(user)
                item["user_id"] = user.id
                apply_status["instance"].append(item)
                if not item.get("ok"):
                    apply_status["ok"] = False
            if legacy_line_ids:
                apply_status["legacy"] = _reload_proxy(s, legacy_line_ids)
        return jsonify({"ok": True, "data": {"updated": len(changed), "matched": len(users), "limit_clear_queued": len(changed), "apply_status": apply_status}})
    finally:
        s.close()


@bp.route("/batch-assign-user", methods=["POST"])
@login_required
def batch_assign_user():
    data = request.get_json(silent=True) or {}
    ids = [int(x) for x in (data.get("ids") or []) if str(x).isdigit()]
    owner_name = (data.get("owner_name") or data.get("username") or "").strip()
    if not ids:
        return jsonify({"ok": False, "error": "请选择节点"}), 400
    if not owner_name:
        return jsonify({"ok": False, "error": "请输入归属用户"}), 400
    s = get_session()
    try:
        users = s.query(ProxyUser).filter(ProxyUser.id.in_(ids)).all()
        for user in users:
            user.owner_name = owner_name
        s.commit()
        return jsonify({"ok": True, "data": {"updated": len(users)}})
    finally:
        s.close()


@bp.route("/batch-assign-operator", methods=["POST"])
@login_required
def batch_assign_operator():
    data = request.get_json(silent=True) or {}
    ids = [int(x) for x in (data.get("ids") or []) if str(x).isdigit()]
    operator = (data.get("operator") or data.get("operator_name") or "").strip()
    if not ids:
        return jsonify({"ok": False, "error": "请选择节点"}), 400
    if not operator:
        return jsonify({"ok": False, "error": "操作人必填"}), 400
    s = get_session()
    try:
        users = s.query(ProxyUser).filter(ProxyUser.id.in_(ids)).all()
        for user in users:
            user.operator = operator
        s.commit()
        return jsonify({"ok": True, "data": {"updated": len(users)}})
    finally:
        s.close()


@bp.route("/batch-assign-project", methods=["POST"])
@login_required
def batch_assign_project():
    data = request.get_json(silent=True) or {}
    ids = [int(x) for x in (data.get("ids") or []) if str(x).isdigit()]
    project_name = (data.get("project_name") or data.get("project") or "").strip()
    if not ids:
        return jsonify({"ok": False, "error": "请选择节点"}), 400
    if not project_name:
        return jsonify({"ok": False, "error": "请输入项目"}), 400
    s = get_session()
    try:
        users = s.query(ProxyUser).filter(ProxyUser.id.in_(ids)).all()
        for user in users:
            user.project_name = project_name
        s.commit()
        return jsonify({"ok": True, "data": {"updated": len(users)}})
    finally:
        s.close()


@bp.route("/batch-edit-limits", methods=["POST"])
@login_required
def batch_edit_limits():
    data = request.get_json(silent=True) or {}
    raw_ids = data.get("ids") or []
    ids = []
    for value in raw_ids:
        if str(value).isdigit():
            uid = int(value)
            if uid > 0 and uid not in ids:
                ids.append(uid)
    speed_limit = _normalize_speed_limit(data.get("speed_limit"))
    set_traffic = _normalize_traffic_limit(data.get("set_traffic") or data.get("add_traffic"))
    if not ids:
        return jsonify({"ok": False, "error": "请选择节点"}), 400
    if not speed_limit and not set_traffic:
        return jsonify({"ok": False, "error": "请输入限速或设置流量"}), 400
    set_bytes = None
    if set_traffic:
        set_bytes = parse_size_to_bytes(set_traffic)
        if not set_bytes:
            return jsonify({"ok": False, "error": "设置流量格式不正确，例如 20g"}), 400
    s = get_session()
    try:
        users = s.query(ProxyUser).filter(ProxyUser.id.in_(ids)).all()
        if len(users) != len(ids):
            found_ids = {user.id for user in users}
            missing_ids = [uid for uid in ids if uid not in found_ids]
            return jsonify({"ok": False, "error": f"部分节点不存在: {missing_ids[:10]}"}), 400
        affected_line_ids = [user.line_id for user in users]
        limit_ids = []
        clear_ids = []
        for user in users:
            old_limit_enabled = bool(parse_speed_to_bps(user.speed_limit))
            if speed_limit:
                user.speed_limit = speed_limit
            if set_bytes:
                user.traffic_limit = _format_size_limit_text(set_bytes)
            if old_limit_enabled:
                clear_ids.append(user.id)
            if user.status and parse_speed_to_bps(user.speed_limit):
                limit_ids.append(user.id)
        s.commit()
        _reload_proxy(s, affected_line_ids)
        _clear_user_limits_background(clear_ids)
        _apply_user_limits_background(limit_ids)
        return jsonify({"ok": True, "data": {"updated": len(users), "updated_ids": ids, "limit_queued": len(limit_ids)}})
    finally:
        s.close()


@bp.route("/batch-renew", methods=["POST"])
@login_required
def batch_renew():
    data = request.get_json(silent=True) or {}
    ids = []
    remote_ids = []
    for value in data.get("ids") or []:
        remote_id = _parse_remote_user_id(value)
        if remote_id and remote_id not in remote_ids:
            remote_ids.append(remote_id)
            continue
        if str(value).isdigit():
            uid = int(value)
            if uid not in ids:
                ids.append(uid)
    try:
        days = max(1, int(data.get("days") or 0))
    except Exception:
        days = 0
    expire_at = _parse_expire(data.get("expire_at") or "")
    if not ids and not remote_ids:
        return jsonify({"ok": False, "error": "请选择节点"}), 400
    if not days and not expire_at:
        return jsonify({"ok": False, "error": "请输入有效到期时间"}), 400
    s = get_session()
    try:
        users = s.query(ProxyUser).filter(ProxyUser.id.in_(ids)).all() if ids else []
        affected_line_ids = [user.line_id for user in users]
        limit_ids = []
        for user in users:
            if days:
                base = user.expire_at or datetime.now()
                user.expire_at = base + timedelta(days=days)
            else:
                user.expire_at = expire_at
            user.bytes_in = 0
            user.bytes_out = 0
            if user.status == 0:
                user.status = 1
                if parse_speed_to_bps(user.speed_limit):
                    limit_ids.append(user.id)
        s.commit()
        for user in users:
            s.refresh(user)
        if users:
            _reload_proxy(s, affected_line_ids)
            _apply_user_limits_background(limit_ids)

        remote_updated = 0
        remote_users = []
        remote_errors = []
        if remote_ids:
            server_ids = sorted({server_id for server_id, _ in remote_ids})
            remote_servers = {
                server.id: server
                for server in s.query(ManagedServer).filter(ManagedServer.id.in_(server_ids)).all()
            }
            grouped = {}
            for server_id, user_id in remote_ids:
                grouped.setdefault(server_id, []).append(user_id)

            def renew_remote(server_id, user_ids):
                server = remote_servers.get(server_id)
                if not server:
                    return 0, [], [f"server {server_id} not found"]
                result = _remote_panel_post(
                    server,
                    "/api/users/batch-renew",
                    {"ids": user_ids, "days": days, "expire_at": data.get("expire_at") or ""},
                    timeout=45,
                )
                payload = result.get("data") or {}
                rows = payload.get("users") or []
                for item in rows:
                    item["id"] = f"remote:{server.id}:{item.get('id')}"
                    item["managed_server_id"] = server.id
                    item["managed_server_ip"] = server.ip
                    item["line_ip"] = server.ip
                return int(payload.get("updated") or len(rows) or 0), rows, []

            with ThreadPoolExecutor(max_workers=min(8, max(1, len(grouped)))) as executor:
                futures = [executor.submit(renew_remote, server_id, user_ids) for server_id, user_ids in grouped.items()]
                for future in as_completed(futures):
                    try:
                        count, rows, errors = future.result()
                        remote_updated += count
                        remote_users.extend(rows)
                        remote_errors.extend(errors)
                    except Exception as exc:
                        remote_errors.append(str(exc))

        result_users = [u.to_dict() for u in users] + remote_users
        return jsonify({
            "ok": True,
            "data": {
                "updated": len(users) + remote_updated,
                "users": result_users,
                "errors": remote_errors,
            },
        })
    finally:
        s.close()


@bp.route("/<int:uid>", methods=["DELETE"])
@login_required
def delete_user(uid):
    s = get_session()
    try:
        user = s.query(ProxyUser).get(uid)
        if not user:
            return jsonify({"ok": False, "error": "用户不存在"}), 404
        limit_ids = [user.id]
        affected_line_ids = [user.line_id]
        log_detail = _format_log_user_detail(user)
        apply_status = _apply_runtime_after_delete(s, [user], affected_line_ids)
        s.delete(user)
        s.commit()
        _clear_user_limits_background(limit_ids)
        _add_user_operation_log(s, "删除入站", log_detail)
        s.commit()
        return jsonify({"ok": True, "data": {"apply_status": apply_status}})
    finally:
        s.close()


@bp.route("/<int:uid>", methods=["PUT"])
@login_required
def update_user(uid):
    data = request.get_json(silent=True) or {}
    s = get_session()
    try:
        user = s.query(ProxyUser).get(uid)
        if not user:
            return jsonify({"ok": False, "error": "节点不存在"}), 404

        if data.get("edit_limits_only"):
            old_limit_enabled = bool(parse_speed_to_bps(user.speed_limit))
            affected_line_ids = [user.line_id]
            speed_limit = _normalize_speed_limit(data.get("speed_limit"))
            set_traffic = _normalize_traffic_limit(data.get("set_traffic") or data.get("add_traffic"))

            if speed_limit:
                user.speed_limit = speed_limit

            if set_traffic:
                set_bytes = parse_size_to_bytes(set_traffic)
                if not set_bytes:
                    return jsonify({"ok": False, "error": "设置流量格式不正确，例如 20g"}), 400
                user.traffic_limit = _format_size_limit_text(set_bytes)

            s.commit()
            s.refresh(user)
            _apply_runtime_for_user(s, user, affected_line_ids)
            if old_limit_enabled:
                _clear_user_limits_background([user.id])
            if user.status and parse_speed_to_bps(user.speed_limit):
                _apply_user_limits_background([user.id])
            return jsonify({"ok": True, "data": user.to_dict()})

        proto = _normalize_protocol(data.get("protocol") or user.protocol)
        if proto not in PROTOCOL_TYPES:
            return jsonify({"ok": False, "error": "不支持的协议"}), 400

        line_id = data.get("line_id", user.line_id)
        try:
            line_id = int(line_id)
        except Exception:
            return jsonify({"ok": False, "error": "请选择有效线路"}), 400
        line = s.query(Line).get(line_id)
        if not line:
            return jsonify({"ok": False, "error": "线路不存在"}), 404

        listen_port = data.get("custom_port", data.get("listen_port", user.listen_port))
        if listen_port in ("", None):
            listen_port = user.listen_port or line.get_port_by_protocol(proto)
        try:
            listen_port = int(listen_port)
        except Exception:
            return jsonify({"ok": False, "error": "端口不正确"}), 400
        if listen_port < 1 or listen_port > 65535:
            return jsonify({"ok": False, "error": "端口范围必须是 1-65535"}), 400
        if _is_windows_excluded_port(listen_port):
            return jsonify({"ok": False, "error": f"端口 {listen_port} 被 Windows 系统保留，请换一个端口"}), 400
        exists = s.query(ProxyUser).filter(ProxyUser.id != uid, ProxyUser.listen_port == listen_port).first()
        if exists:
            return jsonify({"ok": False, "error": f"端口 {listen_port} 已被其他节点使用"}), 400

        username = (data.get("username") or user.username or "").strip()
        password = (data.get("password") or user.password or "").strip()
        if proto == "ss":
            username = username or "ss"
            ss_method = (data.get("ss_method") or user.ss_method or SS_METHODS[0]).strip()
            if ss_method not in SS_METHODS:
                return jsonify({"ok": False, "error": "不支持的 SS 加密方式"}), 400
            ss_password = (data.get("ss_password") or password or user.ss_password or user.password or "").strip()
            if not ss_password:
                return jsonify({"ok": False, "error": "请输入 SS 密码"}), 400
            user.ss_method = ss_method
            user.ss_password = ss_password
            password = ss_password
        else:
            if not username:
                return jsonify({"ok": False, "error": "请输入账号"}), 400
            if not password:
                return jsonify({"ok": False, "error": "请输入密码"}), 400
            if proto in {"vless", "vmess"}:
                try:
                    password = str(uuid.UUID(password))
                except ValueError:
                    return jsonify({"ok": False, "error": f"{proto.upper()} password must be UUID"}), 400
            user.ss_method = None
            user.ss_password = None

        old_limit_enabled = bool(parse_speed_to_bps(user.speed_limit))
        old_line_id = user.line_id
        user.line_id = line.id
        user.protocol = proto
        user.listen_port = listen_port
        user.username = username
        user.password = password
        user.operator = (data.get("operator") or user.operator or current_operator_name()).strip()
        user.owner_name = (data.get("owner_name") or "").strip()
        user.project_name = (data.get("project_name") or "").strip()
        user.speed_limit = _normalize_speed_limit(data.get("speed_limit"), DEFAULT_SPEED_LIMIT)
        user.traffic_limit = _normalize_traffic_limit(data.get("traffic_limit"), DEFAULT_TRAFFIC_LIMIT)
        user.note = (data.get("note") or "").strip()
        user.expire_at = _parse_expire(data.get("expire_at")) if data.get("expire_at") else None

        s.commit()
        s.refresh(user)
        if _is_inbound_instance(user):
            inbound_instance_manager.stop_user(user.id)
            inbound_instance_manager.apply_user(user)
        else:
            _reload_proxy(s, [old_line_id, user.line_id])
        if old_limit_enabled:
            _clear_user_limits_background([user.id])
        if user.status and parse_speed_to_bps(user.speed_limit):
            _apply_user_limits_background([user.id])
        return jsonify({"ok": True, "data": user.to_dict()})
    finally:
        s.close()


@bp.route("/<int:uid>/toggle", methods=["POST"])
@login_required
def toggle_user(uid):
    s = get_session()
    try:
        user = s.query(ProxyUser).get(uid)
        if not user:
            return jsonify({"ok": False, "error": "用户不存在"}), 404
        affected_line_ids = [user.line_id]
        user.status = 0 if user.status else 1
        if user.status:
            _, user.note = _pop_auto_restore_marker(user.note)
        if user.status and (user.note or "").startswith("自动停用：连接数"):
            lines = [line for line in (user.note or "").splitlines() if not line.startswith("自动停用：连接数")]
            user.note = "\n".join(lines).strip()
        s.commit()
        if user.status:
            _apply_user_limits_background([user.id])
        else:
            _clear_user_limits_background([user.id])
        apply_status = _apply_runtime_for_user(s, user, affected_line_ids)
        if not _is_inbound_instance(user):
            apply_status = _ensure_user_runtime_applied(s, user, bool(user.status), apply_status)
        data = user.to_dict()
        data["apply_status"] = apply_status
        return jsonify({"ok": True, "data": data})
    finally:
        s.close()


@bp.route("/gen-password", methods=["GET"])
@login_required
def gen_password():
    length = request.args.get("len", 12, type=int)
    kind = request.args.get("kind", "")
    if kind == "uuid":
        return jsonify({"ok": True, "data": str(uuid.uuid4())})
    return jsonify({"ok": True, "data": _gen_password(min(max(length, 6), 32))})


@bp.route("/<int:uid>/connection-info", methods=["GET"])
@login_required
def connection_info(uid):
    s = get_session()
    try:
        user = s.query(ProxyUser).get(uid)
        if not user:
            return jsonify({"ok": False, "error": "用户不存在"}), 404
        if user.expire_at and user.expire_at <= datetime.now():
            user.status = 0
            s.commit()
            _clear_user_limits_background([user.id])
            _reload_proxy(s, [user.line_id])
            return jsonify({"ok": False, "error": "节点已到期并停用"}), 410
        if not user.status:
            return jsonify({"ok": False, "error": "节点已停用"}), 410
        return jsonify({"ok": True, "data": user.get_connection_info()})
    finally:
        s.close()


def _change_inbound_ip_one(s, data: dict, spec: dict, requested_ip: str = "") -> dict:
    if requested_ip:
        socket.inet_aton(requested_ip)
    if requested_ip == spec["ip"]:
        raise ValueError("新 IP 和原 IP 一样")

    source = "local"
    deleted_detail = ""
    old_remote_server = None
    old_remote_item = None
    owner_name = ""
    project_name = ""
    speed_limit = data.get("speed_limit") or DEFAULT_SPEED_LIMIT
    traffic_limit = data.get("traffic_limit") or DEFAULT_TRAFFIC_LIMIT
    note = data.get("note") or f"换IP自 {spec['ip']}"
    old_user = (
        s.query(ProxyUser)
        .join(Line)
        .filter(Line.public_ip == spec["ip"], ProxyUser.listen_port == spec["port"], ProxyUser.protocol == spec["protocol"])
        .all()
    )
    old_user = next((user for user in old_user if _user_matches_inbound(user, spec)), None)
    if old_user:
        deleted_detail = _format_log_user_detail(old_user)
        owner_name = old_user.owner_name or old_user.username or spec["username"]
        project_name = old_user.project_name or ""
        speed_limit = data.get("speed_limit") or old_user.speed_limit or DEFAULT_SPEED_LIMIT
        traffic_limit = data.get("traffic_limit") or old_user.traffic_limit or DEFAULT_TRAFFIC_LIMIT
        note = data.get("note") or old_user.note or note
    else:
        source = "remote"
        old_remote_server, old_remote_item = _find_remote_inbound(s, spec)
        if not old_remote_server or not old_remote_item:
            raise LookupError("没有找到要删除的原入站，请确认 IP、端口、协议和密码一致")
        deleted_detail = _format_log_user_detail(old_remote_item, old_remote_server.ip)
        owner_name = old_remote_item.get("owner_name") or old_remote_item.get("username") or spec["username"]
        project_name = old_remote_item.get("project_name") or ""
        speed_limit = data.get("speed_limit") or old_remote_item.get("speed_limit") or DEFAULT_SPEED_LIMIT
        traffic_limit = data.get("traffic_limit") or old_remote_item.get("traffic_limit") or DEFAULT_TRAFFIC_LIMIT
        note = data.get("note") or old_remote_item.get("note") or note

    owner_name = data.get("owner_name") or owner_name or spec["username"]
    project_name = data.get("project_name") or project_name or "换IP"
    target_server = _select_change_ip_target(s, spec["ip"], requested_ip, owner_name, project_name)
    if not target_server:
        if requested_ip:
            raise ValueError(f"新 IP {requested_ip} 不可用，或已经有 {owner_name}|{project_name} 的入站")
        raise ValueError(f"没有符合排除规则的可用新 IP：排除 {owner_name}|{project_name}")
    new_ip = target_server.ip

    create_payload = {
        "protocol": spec["protocol"],
        "custom_port": spec["port"],
        "count": 1,
        "server_ids": [target_server.id],
        "remote_count": 1,
        "line_id": "",
        "line_ids": [],
        "username": spec["username"],
        "password": spec["password"],
        "ss_method": spec.get("ss_method") or "aes-256-gcm",
        "ss_password": spec.get("ss_password") or spec["password"],
        "expire_at": spec.get("expire_at") or "",
        "owner_name": owner_name,
        "project_name": project_name,
        "speed_limit": speed_limit,
        "traffic_limit": traffic_limit,
        "note": note,
    }
    created = _create_on_managed_servers(s, [target_server.id], create_payload, 1)
    created_rows = (created or {}).get("created") or []
    if not created_rows:
        error = "；".join(((created or {}).get("errors") or [])[:3]) or "新 IP 创建失败"
        raise RuntimeError(f"新入站创建失败，原入站未删除：{error}")

    if old_user:
        limit_ids = [old_user.id]
        affected_line_ids = [old_user.line_id]
        s.delete(old_user)
        s.commit()
        _reload_proxy(s, affected_line_ids)
        _clear_user_limits_background(limit_ids)
    else:
        _remote_panel_delete(old_remote_server, f"/api/users/{_remote_item_local_id(old_remote_item)}")

    output = _change_ip_output(spec, new_ip)
    created_detail = _format_log_user_detail(created_rows[0], new_ip)
    _add_user_operation_log(
        s,
        "一键换IP",
        f"source={source}; old_deleted={deleted_detail}; new_created={created_detail}; output={output}",
    )
    s.commit()
    return {
        "old_deleted": spec["raw"],
        "new_created": output,
        "copy_text": f"原删除：{spec['raw']}\n新成功更换：{output}",
        "created": created_rows,
        "source": source,
        "target_ip": new_ip,
    }


@bp.route("/change-ip", methods=["POST"])
@login_required
def change_inbound_ip():
    data = request.get_json(silent=True) or {}
    old_lines = [
        line.strip()
        for line in re.split(r"[\r\n]+", str(data.get("old_inbound") or data.get("old") or ""))
        if line.strip()
    ]
    if not old_lines:
        return jsonify({"ok": False, "error": "请输入原完整入站"}), 400
    raw_ip_text = str(data.get("new_ip") or data.get("ip") or "").strip()
    requested_ips = [part.strip() for part in re.split(r"[\s,，\r\n]+", raw_ip_text) if part.strip()]
    s = get_session()
    try:
        successes = []
        errors = []
        for index, old_text in enumerate(old_lines):
            requested_ip = ""
            if len(requested_ips) == 1:
                requested_ip = requested_ips[0]
            elif index < len(requested_ips):
                requested_ip = requested_ips[index]
            try:
                spec = _parse_inbound_field(old_text)
                successes.append(_change_inbound_ip_one(s, data, spec, requested_ip))
            except Exception as exc:
                errors.append({"old": old_text, "error": str(exc)})
        copy_lines = []
        for item in successes:
            copy_lines.append(f"原删除：{item['old_deleted']}")
            copy_lines.append(f"新成功更换：{item['new_created']}")
        if errors:
            copy_lines.append("失败：")
            copy_lines.extend(f"{item['old']} => {item['error']}" for item in errors)
        if not successes:
            return jsonify({"ok": False, "error": errors[0]["error"] if errors else "批量换 IP 失败", "data": {"errors": errors}}), 400
        return jsonify({"ok": True, "data": {
            "changed": len(successes),
            "failed": len(errors),
            "results": successes,
            "errors": errors,
            "copy_text": "\n".join(copy_lines),
        }})
    finally:
        s.close()


@bp.route("/remote-connection-info", methods=["GET"])
@login_required
def remote_connection_info():
    remote_id = _parse_remote_user_id(request.args.get("id") or "")
    if not remote_id:
        return jsonify({"ok": False, "error": "remote id invalid"}), 400
    server_id, user_id = remote_id
    s = get_session()
    try:
        server = s.query(ManagedServer).get(server_id)
        if not server:
            return jsonify({"ok": False, "error": "server not found"}), 404
        return jsonify(_remote_panel_get(server, f"/api/users/{user_id}/connection-info", timeout=15))
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500
    finally:
        s.close()


@bp.route("/<int:uid>/wireguard.conf", methods=["GET"])
@login_required
def wireguard_conf(uid):
    s = get_session()
    try:
        user = s.query(ProxyUser).get(uid)
        if not user:
            return jsonify({"ok": False, "error": "用户不存在"}), 404
        if (user.protocol or "").lower() != "wireguard":
            return jsonify({"ok": False, "error": "该节点不是 WireGuard"}), 400
        text = wireguard_manager.client_conf(user)
        filename = _wireguard_conf_filename(user)
        return Response(
            text,
            mimetype="text/plain; charset=utf-8",
            headers={"Content-Disposition": _download_disposition(filename)},
        )
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500
    finally:
        s.close()


@bp.route("/remote-wireguard.conf", methods=["GET"])
@login_required
def remote_wireguard_conf():
    remote_id = _parse_remote_user_id(request.args.get("id") or "")
    if not remote_id:
        return jsonify({"ok": False, "error": "remote id invalid"}), 400
    server_id, user_id = remote_id
    s = get_session()
    try:
        server = s.query(ManagedServer).get(server_id)
        if not server:
            return jsonify({"ok": False, "error": "server not found"}), 404
        data, filename = _remote_panel_download(server, f"/api/users/{user_id}/wireguard.conf")
        filename = filename or f"{server.ip}-{user_id}.conf"
        return Response(
            data,
            mimetype="text/plain; charset=utf-8",
            headers={"Content-Disposition": _download_disposition(filename)},
        )
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500
    finally:
        s.close()


@bp.route("/wireguard.zip", methods=["GET"])
@login_required
def wireguard_zip():
    raw_ids = request.args.get("ids") or ""
    ids = []
    remote_ids = []
    for value in raw_ids.split(","):
        value = value.strip()
        remote_id = _parse_remote_user_id(value)
        if remote_id and remote_id not in remote_ids:
            remote_ids.append(remote_id)
            continue
        if value.isdigit():
            uid = int(value)
            if uid and uid not in ids:
                ids.append(uid)
    if not ids and not remote_ids:
        return jsonify({"ok": False, "error": "请选择要下载的 WireGuard 节点"}), 400

    s = get_session()
    try:
        users = []
        if ids:
            users = (
                s.query(ProxyUser)
                .filter(ProxyUser.id.in_(ids), ProxyUser.protocol == "wireguard")
                .order_by(ProxyUser.id)
                .all()
            )
        remote_servers = {}
        if remote_ids:
            server_ids = sorted({server_id for server_id, _ in remote_ids})
            remote_servers = {
                server.id: server
                for server in s.query(ManagedServer).filter(ManagedServer.id.in_(server_ids)).all()
            }
        if not users and not remote_ids:
            return jsonify({"ok": False, "error": "没有可下载的 WireGuard 配置"}), 404
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            used_names = set()
            for user in users:
                text = wireguard_manager.client_conf(user)
                name = _wireguard_conf_filename(user)
                if name in used_names:
                    stem = name[:-5] if name.endswith(".conf") else name
                    name = f"{stem}-{user.id}.conf"
                used_names.add(name)
                zf.writestr(name, text)
            for server_id, user_id in remote_ids:
                server = remote_servers.get(server_id)
                if not server:
                    continue
                data, name = _remote_panel_download(server, f"/api/users/{user_id}/wireguard.conf")
                name = name or f"{server.ip}-{user_id}.conf"
                if name in used_names:
                    stem = name[:-5] if name.endswith(".conf") else name
                    name = f"{stem}-{server_id}-{user_id}.conf"
                used_names.add(name)
                zf.writestr(name, data)
        buf.seek(0)
        return Response(
            buf.getvalue(),
            mimetype="application/zip",
            headers={"Content-Disposition": 'attachment; filename="wireguard-confs.zip"'},
        )
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500
    finally:
        s.close()


@bp.route("/<int:uid>/test", methods=["POST"])
@login_required
def test_user(uid):
    s = get_session()
    try:
        user = s.query(ProxyUser).get(uid)
        if not user or not user.line:
            return jsonify({"ok": False, "error": "用户不存在"}), 404
        if user.expire_at and user.expire_at <= datetime.now():
            user.status = 0
            s.commit()
            _clear_user_limits_background([user.id])
            _reload_proxy(s, [user.line_id])
            return jsonify({"ok": False, "error": "节点已到期并停用"}), 410
        if not user.status:
            return jsonify({"ok": False, "error": "节点已停用"}), 410
        protocol = user.protocol or "socks5"
        host = user.line.public_ip
        port = user.listen_port or user.line.get_port_by_protocol(protocol)
        tcp = _tcp_test(host, port)
        udp = _udp_test(host, port, protocol, user)
        bandwidth = _line_bandwidth(user.line)
        speedtest = None
        speed_error = None
        if protocol == "socks5" and tcp.get("ok"):
            try:
                speedtest = _fast_speed_for_user(user)
            except Exception as exc:
                speed_error = str(exc)
        measured_mbps = speedtest.get("mbps") if speedtest else None
        limit_info = _limit_info_for_user(user, measured_mbps)
        ok = _node_ok(protocol, tcp, udp)
        speed_text = f" / Fast {speedtest['mbps']} Mbps" if speedtest else ""
        return jsonify({
            "ok": True,
            "data": {
                "user_id": user.id,
                "protocol": protocol,
                "ip": host,
                "port": port,
                "ok": ok,
                "tcp": tcp,
                "udp": udp,
                "bandwidth": bandwidth,
                "speedtest": speedtest,
                "speed_error": speed_error,
                "limit": limit_info,
                "summary": (
                    f"{tcp['message']} / {udp['message']} / "
                    f"链路 {bandwidth['speed']} / 当前下行 {bandwidth['rx']} 上行 {bandwidth['tx']}"
                    f"{speed_text}"
                ),
            },
        })
    finally:
        s.close()
