"""Runtime protection for sustained node bandwidth."""
import json
import os
import re
import subprocess
import time
import urllib.parse
import urllib.request
from collections import defaultdict, deque

import psutil

from models import Line, ProxyUser, get_session
from services import proxy_manager
from services.audit_logger import add_operation_log
from services.limit_manager import apply_limit, apply_limit_bps, parse_speed_to_bps

NODE_BANDWIDTH_LIMIT_BPS = int(os.environ.get("IPWIN42_NODE_BANDWIDTH_LIMIT_BPS", str(20 * 1000 * 1000)))
NODE_SUSTAIN_SECONDS = int(os.environ.get("IPWIN42_NODE_SUSTAIN_SECONDS", "300"))
NODE_THROTTLE_SECONDS = int(os.environ.get("IPWIN42_NODE_THROTTLE_SECONDS", "300"))
NODE_THROTTLE_BPS = int(os.environ.get("IPWIN42_NODE_THROTTLE_BPS", str(5 * 1000 * 1000)))
NODE_SAMPLE_SECONDS = int(os.environ.get("IPWIN42_NODE_SAMPLE_SECONDS", "5"))
SYSTEM_SOCKET_ALERT_LIMIT = int(os.environ.get("IPWIN42_SYSTEM_SOCKET_ALERT_LIMIT", "8000"))
SYSTEM_SOCKET_FORCE_LIMIT = int(os.environ.get("IPWIN42_SYSTEM_SOCKET_FORCE_LIMIT", "12000"))
LINE_UDP_ENDPOINT_LIMIT = int(os.environ.get("IPWIN42_LINE_UDP_ENDPOINT_LIMIT", "1000"))
LINE_TCP_ENDPOINT_LIMIT = int(os.environ.get("IPWIN42_LINE_TCP_ENDPOINT_LIMIT", "1000"))
LINE_SOCKET_RESTART_COOLDOWN = int(os.environ.get("IPWIN42_LINE_SOCKET_RESTART_COOLDOWN", "180"))
INBOUND_CONNECTION_LIMIT = int(os.environ.get("IPWIN42_INBOUND_CONNECTION_LIMIT", "500"))
INBOUND_CONNECTION_FORCE_LIMIT = int(os.environ.get("IPWIN42_INBOUND_CONNECTION_FORCE_LIMIT", "500"))
INBOUND_KILL_BATCH_SIZE = int(os.environ.get("IPWIN42_INBOUND_KILL_BATCH_SIZE", "100"))

_history: dict[int, deque[tuple[float, int]]] = defaultdict(deque)
_throttled_until: dict[int, float] = {}
_last_conn_totals: dict[str, tuple[int, int, int, float]] = {}
_last_system_count: tuple[int, float] = (0, 0.0)
_last_socket_alert_at = 0.0
_inbound_kill_seen: dict[str, float] = {}
_line_socket_notice_at: dict[int, float] = {}


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


def _safe_proc_name(pid: int) -> str:
    try:
        proc = psutil.Process(pid)
        return proc.name()
    except Exception:
        return ""


def _line_id_from_cmdline(cmdline: list[str] | str) -> int | None:
    text = " ".join(cmdline) if isinstance(cmdline, list) else str(cmdline or "")
    match = re.search(r"instances[\\/]+line-(\d+)[\\/]+config\.json", text, flags=re.I)
    if not match:
        return None
    try:
        return int(match.group(1))
    except ValueError:
        return None


def _singbox_line_pid_map() -> dict[int, int]:
    result: dict[int, int] = {}
    for proc in psutil.process_iter(["pid", "name", "cmdline"]):
        try:
            name = (proc.info.get("name") or "").lower()
            if name not in {"sing-box", "sing-box.exe"}:
                continue
            line_id = _line_id_from_cmdline(proc.info.get("cmdline") or [])
            if line_id:
                result[int(line_id)] = int(proc.info["pid"])
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
        except Exception:
            continue
    return result


def _socket_endpoint_snapshot() -> dict:
    tcp_by_pid: dict[int, int] = defaultdict(int)
    tcp_est_by_pid: dict[int, int] = defaultdict(int)
    udp_by_pid: dict[int, int] = defaultdict(int)
    tcp_total = 0
    udp_total = 0
    tcp_established = 0

    try:
        for conn in psutil.net_connections(kind="tcp"):
            tcp_total += 1
            pid = int(conn.pid or 0)
            if pid:
                tcp_by_pid[pid] += 1
                if str(conn.status).upper() == "ESTABLISHED":
                    tcp_est_by_pid[pid] += 1
                    tcp_established += 1
    except Exception:
        pass

    try:
        for conn in psutil.net_connections(kind="udp"):
            udp_total += 1
            pid = int(conn.pid or 0)
            if pid:
                udp_by_pid[pid] += 1
    except Exception:
        pass

    return {
        "tcp_total": tcp_total,
        "udp_total": udp_total,
        "tcp_established": tcp_established,
        "tcp_by_pid": tcp_by_pid,
        "tcp_est_by_pid": tcp_est_by_pid,
        "udp_by_pid": udp_by_pid,
    }


def _line_labels(session, line_ids: set[int]) -> dict[int, str]:
    labels: dict[int, str] = {}
    if not line_ids:
        return labels
    for line in session.query(Line).filter(Line.id.in_(line_ids)).all():
        labels[int(line.id)] = f"{line.public_ip or '-'} {line.name or ''}".strip()
    return labels


def _controller_port(line_id: int) -> int:
    return int(os.environ.get("IPWIN42_SINGBOX_INSTANCE_CONTROLLER_BASE", "19090")) + int(line_id)


def _fetch_connections_url(url: str, timeout: float) -> list[dict]:
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = json.loads(resp.read().decode("utf-8", errors="ignore"))
    return data.get("connections") or []


def _fetch_runtime_connections(session, timeout: float = 1.0) -> list[dict]:
    line_pid = _singbox_line_pid_map()
    mode = (os.environ.get("IPWIN42_SINGBOX_MODE") or "").strip().lower()
    if not line_pid and mode not in {"per_line", "per-line", "line", "multi"}:
        return proxy_manager._fetch_connections(timeout=timeout)

    line_ids = [
        int(line_id)
        for (line_id,) in session.query(Line.id).filter(Line.status == 1).order_by(Line.id).all()
        if line_id
    ]
    all_connections: list[dict] = []
    errors = []
    per_line_timeout = max(0.2, min(float(timeout), 0.8))
    for line_id in line_ids:
        try:
            rows = _fetch_connections_url(f"http://127.0.0.1:{_controller_port(line_id)}/connections", per_line_timeout)
        except Exception as exc:
            errors.append(f"line {line_id}: {exc}")
            continue
        for row in rows:
            if isinstance(row, dict):
                row["_ipwin_line_id"] = int(line_id)
                all_connections.append(row)
    if not all_connections and errors and len(errors) == len(line_ids):
        raise RuntimeError("; ".join(errors[:5]))
    return all_connections


def _close_connection(line_id: int, conn_id: str, timeout: float = 1.0) -> bool:
    if not conn_id:
        return False
    encoded = urllib.parse.quote(str(conn_id), safe="")
    url = f"http://127.0.0.1:{_controller_port(line_id)}/connections/{encoded}"
    req = urllib.request.Request(url, method="DELETE")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return 200 <= resp.status < 300
    except Exception:
        return False


def _line_id_from_connection(conn: dict) -> int | None:
    value = conn.get("_ipwin_line_id")
    try:
        if value:
            return int(value)
    except Exception:
        pass
    for item in conn.get("chains") or []:
        match = re.search(r"out-line-(\d+)", str(item))
        if match:
            return int(match.group(1))
    rule = str(conn.get("rule") or "")
    match = re.search(r"out-line-(\d+)", rule)
    if match:
        return int(match.group(1))
    return None


def _conn_start_value(conn: dict) -> str:
    return str(conn.get("start") or "")


def _inbound_label(user: ProxyUser | None, tag: str) -> str:
    if not user or not user.line:
        return tag
    port = user.listen_port or user.line.get_port_by_protocol(user.protocol)
    return f"{user.line.public_ip}:{port} {user.protocol or '-'} 用户ID={user.id}"


def _enforce_inbound_connection_caps(session, connections: list[dict]) -> list[str]:
    if INBOUND_CONNECTION_LIMIT <= 0 and INBOUND_CONNECTION_FORCE_LIMIT <= 0:
        return []

    grouped: dict[str, list[dict]] = defaultdict(list)
    for conn in connections:
        tag = _connection_tag(conn)
        if tag.startswith("in-"):
            grouped[tag].append(conn)

    messages = []
    for tag, items in grouped.items():
        limit = INBOUND_CONNECTION_LIMIT
        reason = "入站连接数超过上限"
        if INBOUND_CONNECTION_FORCE_LIMIT > 0 and len(items) >= INBOUND_CONNECTION_FORCE_LIMIT:
            limit = min(limit, INBOUND_CONNECTION_LIMIT) if INBOUND_CONNECTION_LIMIT > 0 else INBOUND_CONNECTION_FORCE_LIMIT
            reason = "入站连接数达到强制保护线"
        if limit <= 0 or len(items) <= limit:
            continue

        uid = _user_id_from_tag(tag)
        user = session.query(ProxyUser).get(uid) if uid else None
        ordered = sorted(items, key=_conn_start_value)
        overflow = max(0, len(items) - limit)
        to_close = ordered[: min(overflow, INBOUND_KILL_BATCH_SIZE)]
        closed = 0
        failed = 0
        for conn in to_close:
            line_id = _line_id_from_connection(conn) or (int(user.line_id) if user else None)
            if not line_id:
                failed += 1
                continue
            if _close_connection(line_id, str(conn.get("id") or "")):
                closed += 1
            else:
                failed += 1

        label = _inbound_label(user, tag)
        detail = (
            f"原因={reason}; 处理=只关闭该入站超出的旧连接，不停用入站，不重启线路; "
            f"入站={tag}; 节点={label}; 当前连接数={len(items)}; 保留上限={limit}; "
            f"本次尝试关闭={len(to_close)}; 成功关闭={closed}; 失败={failed}; "
            f"批次上限={INBOUND_KILL_BATCH_SIZE}"
        )
        add_operation_log(session, "system", "运行防护", "入站连接数锁定", detail, user.line.public_ip if user and user.line else "127.0.0.1")
        session.commit()
        _inbound_kill_seen[tag] = time.time()
        messages.append(f"inbound capped {tag}: total={len(items)} limit={limit} closed={closed} failed={failed}")

    return messages


def _track_socket_pressure(session) -> list[str]:
    global _last_socket_alert_at
    if LINE_UDP_ENDPOINT_LIMIT <= 0 and LINE_TCP_ENDPOINT_LIMIT <= 0 and SYSTEM_SOCKET_FORCE_LIMIT <= 0:
        return []

    snapshot = _socket_endpoint_snapshot()
    line_pid = _singbox_line_pid_map()
    if not line_pid:
        return []

    labels = _line_labels(session, set(line_pid))
    rows = []
    for line_id, pid in line_pid.items():
        udp_count = int(snapshot["udp_by_pid"].get(pid, 0))
        tcp_count = int(snapshot["tcp_by_pid"].get(pid, 0))
        rows.append(
            {
                "line_id": int(line_id),
                "pid": int(pid),
                "udp": udp_count,
                "tcp": tcp_count,
                "tcp_established": int(snapshot["tcp_est_by_pid"].get(pid, 0)),
                "total_udp": int(snapshot["udp_total"]),
                "total_tcp": int(snapshot["tcp_total"]),
                "label": labels.get(int(line_id), "-"),
            }
        )
    rows.sort(key=lambda item: (item["udp"], item["tcp"]), reverse=True)

    total_sockets = int(snapshot["udp_total"]) + int(snapshot["tcp_total"])
    messages = []
    now = time.time()
    if SYSTEM_SOCKET_ALERT_LIMIT > 0 and total_sockets >= SYSTEM_SOCKET_ALERT_LIMIT and now - _last_socket_alert_at > 60:
        top = rows[0] if rows else {}
        detail = (
            f"原因=系统 socket 总数达到告警线; 系统socket总数={total_sockets}; "
            f"系统TCP总数={snapshot['tcp_total']}; 系统UDP总数={snapshot['udp_total']}; "
            f"告警阈值={SYSTEM_SOCKET_ALERT_LIMIT}; 强制保护阈值={SYSTEM_SOCKET_FORCE_LIMIT}; "
            f"占用最高线路ID={top.get('line_id')}; 占用最高线路={top.get('label')}; "
            f"占用最高PID={top.get('pid')}; 占用最高UDP数={top.get('udp')}; 占用最高TCP数={top.get('tcp')}"
        )
        add_operation_log(session, "system", "运行防护", "socket 资源告警", detail, "127.0.0.1")
        session.commit()
        _last_socket_alert_at = now
        messages.append(detail)

    target = None
    for row in rows:
        if LINE_UDP_ENDPOINT_LIMIT > 0 and row["udp"] >= LINE_UDP_ENDPOINT_LIMIT:
            target = row
            break
        if LINE_TCP_ENDPOINT_LIMIT > 0 and row["tcp"] >= LINE_TCP_ENDPOINT_LIMIT:
            target = row
            break

    if not target and SYSTEM_SOCKET_FORCE_LIMIT > 0 and total_sockets >= SYSTEM_SOCKET_FORCE_LIMIT and rows:
        target = rows[0]

    if target:
        last_notice = _line_socket_notice_at.get(int(target["line_id"]), 0)
        if now - last_notice < 60:
            return messages
        _line_socket_notice_at[int(target["line_id"])] = now
        detail = (
            f"原因=线路 socket 压力过高; 处理=不重启线路，等待入站连接锁定按入站逐个关闭连接; "
            f"线路ID={target['line_id']}; 线路={target.get('label')}; 进程PID={target['pid']}; "
            f"UDP socket数={target['udp']}; TCP socket数={target['tcp']}; "
            f"系统UDP总数={target['total_udp']}; 系统TCP总数={target['total_tcp']}; "
            f"单线路UDP阈值={LINE_UDP_ENDPOINT_LIMIT}; 单线路TCP阈值={LINE_TCP_ENDPOINT_LIMIT}"
        )
        add_operation_log(session, "system", "运行防护", "线路 socket 压力提示", detail, "127.0.0.1")
        session.commit()
        messages.append(
            f"line socket pressure detected without restart: line={target['line_id']} "
            f"udp={target['udp']} tcp={target['tcp']}"
        )

    return messages


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
        mbps = max(1, int(NODE_THROTTLE_BPS / 1000 / 1000))
        threshold_mbps = round(NODE_BANDWIDTH_LIMIT_BPS / 1000 / 1000, 2)
        current_mbps = round(bps / 1000 / 1000, 2)
        host = user.line.public_ip if user.line else "-"
        port = _user_port(user)
        detail = (
            f"原因=单入站持续占用带宽超过{NODE_SUSTAIN_SECONDS}s；"
            f"处理=临时降速到{mbps}m，不停止节点；"
            f"节点={host}:{port}；协议={user.protocol or '-'}；"
            f"用户={user.owner_name or user.username or '-'}；项目={user.project_name or '-'}；"
            f"当前带宽={current_mbps}Mbps；阈值={threshold_mbps}Mbps；"
            f"恢复等待={NODE_THROTTLE_SECONDS}s；执行成功={ok}"
        )
        add_operation_log(session, "system", "自动保护", "自动临时降速节点", detail, host)
        session.commit()
        messages.append(
            f"node throttled to {mbps}m for {NODE_THROTTLE_SECONDS}s; "
            f"bps={bps}; ok={ok}; {_node_label(user)}"
        )

    for uid, until in list(_throttled_until.items()):
        if now < until:
            continue
        user = session.query(ProxyUser).get(uid)
        ok = _apply_node_limit(user, None) if user else False
        if user:
            host = user.line.public_ip if user.line else "-"
            port = _user_port(user)
            detail = (
                f"原因=临时降速时间结束；处理=恢复节点原限速；"
                f"节点={host}:{port}；协议={user.protocol or '-'}；"
                f"用户={user.owner_name or user.username or '-'}；项目={user.project_name or '-'}；"
                f"执行成功={ok}"
            )
            add_operation_log(session, "system", "自动保护", "自动恢复节点限速", detail, host)
            session.commit()
        _throttled_until.pop(uid, None)
        _history.pop(uid, None)
        messages.append(f"node restored original limit; ok={ok}; user={uid}")

    return messages

def enforce_runtime_protection(timeout: float = 2.0) -> dict:
    messages = []
    system_connections = _system_connection_count()

    session = get_session()
    try:
        connections = _fetch_runtime_connections(session, timeout=timeout)
    except Exception as exc:
        connections = []
        messages.append(f"sing-box connections unavailable: {exc}")
    singbox_connections = len(connections)

    try:
        messages.extend(_enforce_inbound_connection_caps(session, connections))
        messages.extend(_track_node_pressure(session, connections))
        messages.extend(_track_socket_pressure(session))
    finally:
        session.close()

    return {
        "system_connections": system_connections,
        "singbox_connections": singbox_connections,
        "messages": messages,
    }
