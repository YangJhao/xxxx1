"""Runtime protection against connection exhaustion and sustained node bandwidth."""
import os
import subprocess
import time
from collections import defaultdict, deque

import psutil

from models import ProxyUser, get_session
from services import proxy_manager
from services.audit_logger import add_operation_log
from services.limit_manager import apply_limit, apply_limit_bps, parse_speed_to_bps

SINGBOX_CONNECTION_LIMIT = int(os.environ.get("IPWIN42_SINGBOX_CONNECTION_LIMIT", "6000"))
SYSTEM_CONNECTION_WARN = int(os.environ.get("IPWIN42_SYSTEM_CONNECTION_WARN", "8000"))
SYSTEM_CONNECTION_PROTECT = int(os.environ.get("IPWIN42_SYSTEM_CONNECTION_PROTECT", "12000"))
NODE_BANDWIDTH_LIMIT_BPS = int(os.environ.get("IPWIN42_NODE_BANDWIDTH_LIMIT_BPS", str(20 * 1000 * 1000)))
NODE_SUSTAIN_SECONDS = int(os.environ.get("IPWIN42_NODE_SUSTAIN_SECONDS", "180"))
NODE_THROTTLE_SECONDS = int(os.environ.get("IPWIN42_NODE_THROTTLE_SECONDS", "600"))
NODE_THROTTLE_BPS = int(os.environ.get("IPWIN42_NODE_THROTTLE_BPS", str(5 * 1000 * 1000)))
NODE_SAMPLE_SECONDS = int(os.environ.get("IPWIN42_NODE_SAMPLE_SECONDS", "5"))

_history: dict[int, deque[tuple[float, int]]] = defaultdict(deque)
_throttled_until: dict[int, float] = {}
_last_conn_totals: dict[str, tuple[int, int, int, float]] = {}
_last_restart_at = 0.0
_last_warn_at = 0.0
_last_system_count: tuple[int, float] = (0, 0.0)


def _connection_tag(conn: dict) -> str:
    return proxy_manager._connection_tag(conn)


def _user_id_from_tag(tag: str) -> int | None:
    marker = "-user-"
    if marker not in tag:
        return None
    try:
        return int(tag.rsplit(marker, 1)[1])
    except ValueError:
        return None


def _system_connection_count() -> int:
    global _last_system_count
    now = time.time()
    last_count, last_ts = _last_system_count
    if now - last_ts < 15:
        return last_count

    try:
        if os.name == "nt":
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
        _last_system_count = (count, now)
        return count
    except Exception:
        pass

    try:
        count = len(psutil.net_connections(kind="inet"))
        _last_system_count = (count, now)
        return count
    except Exception:
        return last_count


def _load_users(session, ids: set[int]) -> dict[int, ProxyUser]:
    if not ids:
        return {}
    return {u.id: u for u in session.query(ProxyUser).filter(ProxyUser.id.in_(ids)).all()}


def _user_port(user: ProxyUser) -> int:
    return int(user.listen_port or user.line.get_port_by_protocol(user.protocol))


def _node_label(user: ProxyUser) -> str:
    return (
        f"user={user.id} {user.line.public_ip if user.line else '-'}:{_user_port(user)} "
        f"{user.protocol or '-'} {user.owner_name or '-'} / {user.project_name or '-'}"
    )


def _apply_node_limit(user: ProxyUser, bps: int | None) -> bool:
    if not user.line:
        return False
    port = _user_port(user)
    if bps:
        result = apply_limit_bps(user, port, user.protocol, bps)
    else:
        result = apply_limit(user, port, user.protocol)
    return bool(result.get("ok"))


def _sum_node_bandwidth_delta(connections: list[dict], users: dict[int, ProxyUser]) -> dict[int, int]:
    global _last_conn_totals
    now = time.time()
    totals: dict[int, int] = defaultdict(int)
    seen: set[str] = set()
    for conn in connections:
        uid = _user_id_from_tag(_connection_tag(conn))
        user = users.get(uid) if uid else None
        if not user:
            continue
        key = int(user.id)
        conn_id = str(conn.get("id") or f"{uid}:{conn.get('start') or ''}:{conn.get('metadata') or ''}")
        seen.add(conn_id)
        upload = int(conn.get("upload") or 0)
        download = int(conn.get("download") or 0)
        old_key, old_upload, old_download, _ = _last_conn_totals.get(conn_id, (key, upload, download, now))
        if old_key == key:
            totals[key] += max(0, upload - old_upload) + max(0, download - old_download)
        _last_conn_totals[conn_id] = (key, upload, download, now)

    for conn_id, (_, _, _, ts) in list(_last_conn_totals.items()):
        if conn_id not in seen and now - ts > NODE_SAMPLE_SECONDS * 2:
            _last_conn_totals.pop(conn_id, None)
    return totals


def _track_node_pressure(session, connections: list[dict]) -> list[str]:
    now = time.time()
    ids = {_user_id_from_tag(_connection_tag(conn)) for conn in connections}
    users = _load_users(session, {int(x) for x in ids if x})
    totals = _sum_node_bandwidth_delta(connections, users)
    messages = []

    for uid, total_bytes in totals.items():
        user = users.get(uid)
        if not user:
            continue
        samples = _history[uid]
        samples.append((now, total_bytes))
        while samples and now - samples[0][0] > NODE_SUSTAIN_SECONDS:
            samples.popleft()
        if len(samples) < 2:
            continue
        elapsed = max(samples[-1][0] - samples[0][0], 1.0)
        delta = sum(value for _, value in samples)
        bps = int(delta * 8 / elapsed)
        if bps < NODE_BANDWIDTH_LIMIT_BPS:
            continue
        if now < _throttled_until.get(uid, 0):
            continue
        ok = _apply_node_limit(user, NODE_THROTTLE_BPS)
        _throttled_until[uid] = now + NODE_THROTTLE_SECONDS
        add_operation_log(
            session,
            "system",
            "自动保护",
            "自动限速节点",
            (
                f"自动限速原因=单节点长期占用带宽；{_node_label(user)}；"
                f"当前={bps} bps；阈值={NODE_BANDWIDTH_LIMIT_BPS} bps；"
                f"限速={NODE_THROTTLE_BPS} bps；恢复等待={NODE_THROTTLE_SECONDS}s；执行成功={ok}"
            ),
            user.line.public_ip if user.line else "",
        )
        session.commit()
        messages.append(f"node throttled to 5m for {NODE_THROTTLE_SECONDS}s; bps={bps}; ok={ok}; {_node_label(user)}")

    for uid, until in list(_throttled_until.items()):
        if now < until:
            continue
        user = session.query(ProxyUser).get(uid)
        ok = _apply_node_limit(user, None) if user else False
        if user:
            add_operation_log(
                session,
                "system",
                "自动保护",
                "恢复节点限速",
                f"自动恢复原因=限速时间结束；{_node_label(user)}；执行成功={ok}",
                user.line.public_ip if user.line else "",
            )
            session.commit()
        _throttled_until.pop(uid, None)
        _history.pop(uid, None)
        messages.append(f"node restored original limit; ok={ok}; user={uid}")

    return messages


def enforce_runtime_protection(timeout: float = 2.0) -> dict:
    global _last_restart_at, _last_warn_at
    now = time.time()
    messages = []
    system_connections = _system_connection_count()
    if system_connections >= SYSTEM_CONNECTION_WARN and now - _last_warn_at > 60:
        _last_warn_at = now
        messages.append(f"system connection warning: {system_connections}/{SYSTEM_CONNECTION_WARN}")

    try:
        connections = proxy_manager._fetch_connections(timeout=timeout)
    except Exception as exc:
        connections = []
        messages.append(f"sing-box connections unavailable: {exc}")
    singbox_connections = len(connections)

    if singbox_connections >= SINGBOX_CONNECTION_LIMIT:
        messages.append(f"sing-box active connections high: {singbox_connections}/{SINGBOX_CONNECTION_LIMIT}")
        if now - _last_restart_at > 300:
            _last_restart_at = now
            messages.append(f"sing-box connection protect restart: {singbox_connections}/{SINGBOX_CONNECTION_LIMIT}")
            try:
                proxy_manager.restart_config()
            except Exception as exc:
                messages.append(f"restart failed: {exc}")

    if system_connections >= SYSTEM_CONNECTION_PROTECT and now - _last_restart_at > 300:
        _last_restart_at = now
        messages.append(f"system connection protect restart: {system_connections}/{SYSTEM_CONNECTION_PROTECT}")
        try:
            proxy_manager.restart_config()
        except Exception as exc:
            messages.append(f"restart failed: {exc}")

    session = get_session()
    try:
        messages.extend(_track_node_pressure(session, connections))
    finally:
        session.close()

    return {
        "system_connections": system_connections,
        "singbox_connections": singbox_connections,
        "messages": messages,
    }
