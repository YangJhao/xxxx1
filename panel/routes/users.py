"""Proxy user management APIs."""
import re
import secrets
import socket
import struct
import string
import threading
import time
import uuid
from datetime import datetime, timedelta

import psutil
from flask import Blueprint, jsonify, request
from sqlalchemy.orm import joinedload

from models import Line, PROTOCOL_TYPES, ProxyUser, SS_METHODS, get_session
from routes.auth import login_required
from services import proxy_manager
from services.cfg_generator import parse_size_to_bytes, write_cfg
from services.fast_speed import fast_socks5_speed
from services.limit_manager import apply_limit, clear_limit, parse_speed_to_bps, sync_limits
from services.traffic_collector import collect_once, snapshot_connections

bp = Blueprint("users", __name__, url_prefix="/api/users")
_limit_worker_lock = threading.Lock()

USERNAME_RE = re.compile(r"^[A-Za-z0-9_\-]{3,48}$")
TESTABLE_UDP_PROTOCOLS = {"socks5", "ss", "hysteria2"}
RANDOM_PORT_MIN = 10000
RANDOM_PORT_MAX = 59999
DEFAULT_SPEED_LIMIT = "20m"
DEFAULT_TRAFFIC_LIMIT = "130g"


def _gen_password(n: int = 12) -> str:
    chars = string.ascii_letters + string.digits
    return "".join(secrets.choice(chars) for _ in range(n))


def _selected_lines(session, line_id):
    if str(line_id).lower() == "all":
        return (
            session.query(Line)
            .filter((Line.status == 1) | (Line.name.like("%主网卡%")))
            .order_by(Line.id)
            .all()
        )
    line = session.query(Line).get(int(line_id))
    return [line] if line else []


def _target_lines(session, line_id, count: int):
    lines = _selected_lines(session, line_id)
    if str(line_id).lower() == "all":
        return lines
    return lines[:1]


def _assignment_exists(session, line_id: int, owner_name: str, project_name: str) -> bool:
    owner = (owner_name or "").strip()
    project = (project_name or "").strip()
    q = session.query(ProxyUser).filter(ProxyUser.line_id == line_id)
    if owner:
        q = q.filter(ProxyUser.owner_name == owner)
    else:
        q = q.filter((ProxyUser.owner_name.is_(None)) | (ProxyUser.owner_name == ""))
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


def _random_available_port(session, used_ports: set[int] | None = None) -> int:
    used_ports = used_ports if used_ports is not None else _used_listen_ports(session)
    for _ in range(3000):
        port = secrets.randbelow(RANDOM_PORT_MAX - RANDOM_PORT_MIN + 1) + RANDOM_PORT_MIN
        if port not in used_ports:
            used_ports.add(port)
            return port
    for port in range(RANDOM_PORT_MIN, RANDOM_PORT_MAX + 1):
        if port not in used_ports:
            used_ports.add(port)
            return port
    raise ValueError("没有可用端口")


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
        "vm": "vless",
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


def _reload_proxy(session=None):
    write_cfg(session)
    proxy_manager.reload_config()


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
    try:
        targets = {"tcp"}
        if (protocol or "").lower() in TESTABLE_UDP_PROTOCOLS:
            targets.add("udp")
        if "tcp" in targets:
            for conn in psutil.net_connections(kind="tcp"):
                if conn.status == psutil.CONN_LISTEN and conn.laddr and conn.laddr.port == int(port):
                    return True
        if "udp" in targets:
            for conn in psutil.net_connections(kind="udp"):
                if conn.laddr and conn.laddr.port == int(port):
                    return True
    except Exception:
        pass
    return False


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
        "message": "" if not missing else f"端口 {', '.join(map(str, missing[:8]))} 尚未被 sing-box 监听，需要应用配置",
    }


def _ensure_created_applied(users: list[ProxyUser]) -> dict:
    status = _created_apply_status(users)
    if status["applied"]:
        return status
    try:
        proxy_manager.restart_config()
        time.sleep(2)
        status = _created_apply_status(users)
        status["restarted"] = True
        if status["applied"]:
            status["message"] = "配置已自动应用"
        else:
            status["message"] = f"端口 {', '.join(map(str, status['missing_ports'][:8]))} 仍未监听，请检查 sing-box 日志"
    except Exception as exc:
        status["message"] = f"自动应用配置失败：{exc}"
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
    line_id = data.get("line_id") or data.get("ip") or data.get("ip_select") or "all"
    expire_at_str = data.get("expire_at") or ""
    speed_limit = _normalize_speed_limit(data.get("speed_limit"), DEFAULT_SPEED_LIMIT)
    traffic_limit = _normalize_traffic_limit(data.get("traffic_limit"), DEFAULT_TRAFFIC_LIMIT)
    owner_name = (data.get("owner_name") or data.get("owner") or "").strip()
    project_name = (data.get("project_name") or data.get("project") or "").strip()
    custom_port = data.get("custom_port")
    count = min(max(int(data.get("count") or 1), 1), 500)
    skip_existing = bool(data.get("skip_existing", True))
    note = data.get("note", "")

    if protocol == "ss":
        base_username = "ss_user"
    if protocol not in PROTOCOL_TYPES:
        return jsonify({"ok": False, "error": f"协议必须是 {', '.join(PROTOCOL_TYPES)}"}), 400
    if protocol == "ss" and ss_method not in SS_METHODS:
        return jsonify({"ok": False, "error": f"SS 加密方式必须是 {', '.join(SS_METHODS)}"}), 400
    if not USERNAME_RE.match(base_username):
        return jsonify({"ok": False, "error": "用户名格式错误：3-48 位字母、数字、下划线或横线"}), 400
    if not project_name:
        return jsonify({"ok": False, "error": "请选择项目"}), 400

    if not password:
        password = str(uuid.uuid4()) if protocol == "vless" else _gen_password(12)
    elif protocol == "vless":
        try:
            password = str(uuid.UUID(password))
        except ValueError:
            return jsonify({"ok": False, "error": "VLESS 密码必须是 UUID，留空可自动生成"}), 400
    ss_password = (data.get("ss_password") or "").strip() or password or _gen_password(12)

    expire_at = _parse_expire(expire_at_str)
    if expire_at_str and expire_at is None:
        return jsonify({"ok": False, "error": "到期时间格式错误"}), 400

    s = get_session()
    try:
        lines = _target_lines(s, line_id, count)
        if not lines:
            return jsonify({"ok": False, "error": "线路不存在"}), 400

        forced_port = None
        used_ports = _used_listen_ports(s)
        if custom_port not in (None, "", 0, "0"):
            forced_port = int(custom_port)
            if not (1024 < forced_port < 65536):
                return jsonify({"ok": False, "error": "端口范围错误"}), 400
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
                    return jsonify({"ok": False, "error": "该线路端口已被占用"}), 400

        created = []
        skipped = []
        errors = []
        for line in lines:
            if len(created) >= count:
                break
            assignment_owner = _assignment_label(owner_name, base_username)
            if _assignment_exists(s, line.id, assignment_owner, project_name):
                msg = f"{line.name} / {line.public_ip}: 用户 {assignment_owner or '-'} + 项目 {project_name or '-'} 已创建，已跳过"
                if skip_existing:
                    skipped.append(msg)
                    continue
                return jsonify({"ok": False, "error": msg}), 400
            username = base_username

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
            user_password = str(uuid.uuid4()) if protocol == "vless" and not data.get("password") else password
            user = ProxyUser(
                username=username,
                password=user_password,
                ss_password=ss_password if protocol == "ss" else None,
                line_id=line.id,
                protocol=protocol,
                listen_port=listen_port,
                ss_method=ss_method if protocol == "ss" else None,
                owner_name=assignment_owner or None,
                project_name=project_name or None,
                speed_limit=speed_limit or None,
                traffic_limit=traffic_limit or None,
                expire_at=expire_at,
                note=note,
            )
            s.add(user)
            created.append(user)

        if len(created) < count:
            errors.append(f"节点不足：需要 {count} 个，实际创建 {len(created)} 个，缺少 {count - len(created)} 个")

        if not created:
            details = errors or skipped
            detail = "；".join(details[:3]) if details else "没有可用线路"
            return jsonify({"ok": False, "error": f"未创建任何节点：{detail}"}), 400

        s.commit()
        for user in created:
            s.refresh(user)
        _reload_proxy(s)
        limited_ids = [u.id for u in created if parse_speed_to_bps(u.speed_limit)]
        _apply_user_limits_background(limited_ids)
        result = {
            "created": [u.to_dict() for u in created],
            "created_count": len(created),
            "skipped": skipped,
            "skipped_count": len(skipped),
            "errors": errors,
            "limits": [{"ok": True, "queued": True, "user_id": uid} for uid in limited_ids],
            "limit_queued": len(limited_ids),
            "apply_status": _ensure_created_applied(created),
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
        connection_snapshot = snapshot_connections()
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
            item["traffic_available"] = True
            item["traffic_source"] = "sing-box 实时连接统计"
            rows.append(item)
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
        for user in users:
            s.delete(user)
        s.commit()
        _reload_proxy(s)
        _clear_user_limits_background(limit_ids)
        return jsonify({"ok": True, "data": {"deleted": count, "limit_clear_queued": len(limit_ids)}})
    finally:
        s.close()


@bp.route("/batch-delete", methods=["POST"])
@login_required
def batch_delete():
    ids = (request.get_json(silent=True) or {}).get("ids") or []
    ids = [int(x) for x in ids if str(x).isdigit()]
    if not ids:
        return jsonify({"ok": False, "error": "请选择要删除的用户"}), 400
    s = get_session()
    try:
        users = s.query(ProxyUser).filter(ProxyUser.id.in_(ids)).all()
        count = len(users)
        limit_ids = [user.id for user in users]
        for user in users:
            s.delete(user)
        s.commit()
        _reload_proxy(s)
        _clear_user_limits_background(limit_ids)
        return jsonify({"ok": True, "data": {"deleted": count, "limit_clear_queued": len(limit_ids)}})
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
        for user in users:
            if user.status:
                user.status = 0
                changed.append(user.id)
        s.commit()
        if changed:
            _clear_user_limits_background(changed)
            _reload_proxy(s)
        return jsonify({"ok": True, "data": {"updated": len(changed), "matched": len(users), "limit_clear_queued": len(changed)}})
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
        _reload_proxy(s)
        _clear_user_limits_background(clear_ids)
        _apply_user_limits_background(limit_ids)
        return jsonify({"ok": True, "data": {"updated": len(users), "updated_ids": ids, "limit_queued": len(limit_ids)}})
    finally:
        s.close()


@bp.route("/batch-renew", methods=["POST"])
@login_required
def batch_renew():
    data = request.get_json(silent=True) or {}
    ids = [int(x) for x in (data.get("ids") or []) if str(x).isdigit()]
    try:
        days = max(1, int(data.get("days") or 0))
    except Exception:
        days = 0
    expire_at = _parse_expire(data.get("expire_at") or "")
    if not ids:
        return jsonify({"ok": False, "error": "请选择节点"}), 400
    if not days and not expire_at:
        return jsonify({"ok": False, "error": "请输入有效到期时间"}), 400
    s = get_session()
    try:
        users = s.query(ProxyUser).filter(ProxyUser.id.in_(ids)).all()
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
        _reload_proxy(s)
        _apply_user_limits_background(limit_ids)
        return jsonify({"ok": True, "data": {"updated": len(users), "users": [u.to_dict() for u in users]}})
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
        s.delete(user)
        s.commit()
        _reload_proxy(s)
        _clear_user_limits_background(limit_ids)
        return jsonify({"ok": True})
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
            _reload_proxy(s)
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
            user.ss_method = None
            user.ss_password = None

        old_limit_enabled = bool(parse_speed_to_bps(user.speed_limit))
        user.line_id = line.id
        user.protocol = proto
        user.listen_port = listen_port
        user.username = username
        user.password = password
        user.owner_name = (data.get("owner_name") or "").strip()
        user.project_name = (data.get("project_name") or "").strip()
        user.speed_limit = _normalize_speed_limit(data.get("speed_limit"), DEFAULT_SPEED_LIMIT)
        user.traffic_limit = _normalize_traffic_limit(data.get("traffic_limit"), DEFAULT_TRAFFIC_LIMIT)
        user.note = (data.get("note") or "").strip()
        user.expire_at = _parse_expire(data.get("expire_at")) if data.get("expire_at") else None

        s.commit()
        s.refresh(user)
        _reload_proxy(s)
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
        user.status = 0 if user.status else 1
        s.commit()
        if user.status:
            _apply_user_limits_background([user.id])
        else:
            _clear_user_limits_background([user.id])
        _reload_proxy(s)
        return jsonify({"ok": True, "data": user.to_dict()})
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
            _reload_proxy(s)
            return jsonify({"ok": False, "error": "节点已到期并停用"}), 410
        if not user.status:
            return jsonify({"ok": False, "error": "节点已停用"}), 410
        return jsonify({"ok": True, "data": user.get_connection_info()})
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
            _reload_proxy(s)
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
