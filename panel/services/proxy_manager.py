"""sing-box process management."""
import json
import os
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta
from contextlib import closing
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from config import SING_BOX_CFG, SING_BOX_EXE, SING_BOX_PID
from services.audit_logger import add_operation_log
from services.cfg_generator import write_cfg


HEALTH_URLS = (
    "http://127.0.0.1:9090/connections",
    "http://127.0.0.1:9090/configs",
)
MAX_CONNECTIONS_PER_PORT = int(os.environ.get("IPWIN42_MAX_PORT_CONNECTIONS", "100"))
AUTO_STOP_RESTORE_SECONDS = int(os.environ.get("IPWIN42_AUTO_STOP_RESTORE_SECONDS", "120"))
AUTO_RESTORE_MARKER = "auto_restore_at="


def _append_auto_restore_marker(note: str | None, restore_at: datetime) -> str:
    marker_line = f"{AUTO_RESTORE_MARKER}{restore_at.isoformat(timespec='seconds')}"
    lines = [
        line
        for line in (note or "").splitlines()
        if not line.strip().startswith(AUTO_RESTORE_MARKER)
    ]
    lines.insert(0, marker_line)
    return "\n".join(line for line in lines if line.strip()).strip()


def _pop_auto_restore_marker(note: str | None) -> tuple[datetime | None, str]:
    restore_at = None
    keep = []
    for line in (note or "").splitlines():
        stripped = line.strip()
        if stripped.startswith(AUTO_RESTORE_MARKER):
            raw = stripped.split("=", 1)[1].strip()
            try:
                restore_at = datetime.fromisoformat(raw)
            except ValueError:
                restore_at = None
            continue
        keep.append(line)
    return restore_at, "\n".join(line for line in keep if line.strip()).strip()


def _linux_process_cmdline(pid: int) -> str:
    try:
        raw = Path(f"/proc/{pid}/cmdline").read_bytes()
        return raw.replace(b"\x00", b" ").decode("utf-8", errors="ignore").strip()
    except Exception:
        return ""


def _linux_sing_box_pids() -> list[int]:
    if os.name == "nt":
        return []
    cfg_path = os.path.abspath(SING_BOX_CFG)
    exe_name = os.path.basename(SING_BOX_EXE)
    pids: list[int] = []
    for proc_dir in Path("/proc").iterdir():
        if not proc_dir.name.isdigit():
            continue
        pid = int(proc_dir.name)
        cmdline = _linux_process_cmdline(pid)
        if not cmdline:
            continue
        if exe_name not in cmdline and "sing-box" not in cmdline:
            continue
        if cfg_path in cmdline or SING_BOX_CFG in cmdline or "42IPwin/sing-box/config.json" in cmdline:
            pids.append(pid)
    return sorted(set(pids))


def _read_pid():
    if not os.path.exists(SING_BOX_PID):
        return None
    try:
        with open(SING_BOX_PID, "r", encoding="utf-8") as f:
            return int(f.read().strip() or 0)
    except Exception:
        return None


def _write_pid(pid: int):
    os.makedirs(os.path.dirname(SING_BOX_PID), exist_ok=True)
    with open(SING_BOX_PID, "w", encoding="utf-8") as f:
        f.write(str(pid))


def _is_running(pid: int | None) -> bool:
    if not pid:
        return False
    try:
        if os.name != "nt":
            stat_path = f"/proc/{pid}/stat"
            if os.path.exists(stat_path):
                with open(stat_path, "r", encoding="utf-8") as f:
                    fields = f.read().split()
                if len(fields) > 2 and fields[2] == "Z":
                    return False
            os.kill(pid, 0)
            return True
        out = subprocess.run(["tasklist", "/FI", f"PID eq {pid}"], capture_output=True, text=True)
        return str(pid) in out.stdout
    except Exception:
        return False


def _find_running_process() -> int | None:
    if os.name != "nt":
        pids = [pid for pid in _linux_sing_box_pids() if _is_running(pid)]
        if pids:
            return pids[0]
        return _read_pid() if _is_running(_read_pid()) else None
    try:
        cmd = (
            "Get-CimInstance Win32_Process | "
            "Where-Object {$_.Name -eq 'sing-box.exe' -and $_.CommandLine -like '*42IPwin*config.json*'} | "
            "Select-Object -First 1 -ExpandProperty ProcessId"
        )
        out = subprocess.run(["powershell", "-NoProfile", "-Command", cmd], capture_output=True, text=True, timeout=8)
        text = (out.stdout or "").strip()
        if text.isdigit():
            return int(text)
    except Exception:
        pass
    return None


def get_status() -> dict:
    pid = _find_running_process() or _read_pid()
    running = _is_running(pid)
    if running and pid:
        _write_pid(pid)
    return {"running": running, "pid": pid if running else None, "engine": "sing-box"}


def _read_exact(sock: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise RuntimeError("connection closed")
        data += chunk
    return data


def _probe_socks5_user(timeout: float = 2.0) -> tuple[bool, str]:
    try:
        from models import ProxyUser, get_session
    except Exception as exc:
        return False, f"load probe user failed: {exc}"

    session = get_session()
    try:
        user = (
            session.query(ProxyUser)
            .filter(ProxyUser.status == 1, ProxyUser.protocol == "socks5")
            .order_by(ProxyUser.id.desc())
            .first()
        )
        if not user or not user.line:
            return True, "no active socks5 user to probe"
        port = int(user.listen_port or user.line.get_port_by_protocol("socks5"))
        username = (user.username or "").encode("utf-8")
        password = (user.password or "").encode("utf-8")
        if len(username) > 255 or len(password) > 255:
            return False, f"socks5 probe user {user.id} credential too long"

        with closing(socket.create_connection(("127.0.0.1", port), timeout=timeout)) as sock:
            sock.settimeout(timeout)
            sock.sendall(b"\x05\x01\x02")
            method = _read_exact(sock, 2)
            if method != b"\x05\x02":
                return False, f"socks5 probe user {user.id} port {port} method={method!r}"
            sock.sendall(b"\x01" + bytes([len(username)]) + username + bytes([len(password)]) + password)
            auth = _read_exact(sock, 2)
            if auth != b"\x01\x00":
                return False, f"socks5 probe user {user.id} port {port} auth={auth!r}"
        return True, f"socks5 probe ok: user {user.id} port {port}"
    except Exception as exc:
        try:
            uid = user.id if user else "none"
        except Exception:
            uid = "unknown"
        return False, f"socks5 probe failed: user {uid}: {exc}"
    finally:
        session.close()


def _connection_tag(conn: dict) -> str:
    metadata = conn.get("metadata") or {}
    for key in ("inbound", "inboundName"):
        value = str(metadata.get(key) or "")
        if value.startswith("in-"):
            return value
    conn_type = str(metadata.get("type") or "")
    if "/" in conn_type:
        value = conn_type.rsplit("/", 1)[-1]
        if value.startswith("in-"):
            return value
    rule = str(conn.get("rule") or "")
    marker = "inbound="
    if marker in rule:
        return rule.split(marker, 1)[1].split()[0].strip(",;")
    chains = conn.get("chains") or []
    return str(chains[0] or "") if chains else ""


def _fetch_connections(timeout: float = 2.0) -> list[dict]:
    req = urllib.request.Request("http://127.0.0.1:9090/connections", headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = json.loads(resp.read().decode("utf-8", errors="ignore"))
    return data.get("connections") or []


def _disable_over_limit_users(by_tag: dict[str, list[dict]]) -> tuple[int, str]:
    from datetime import datetime
    from models import ProxyUser, get_session

    disabled = 0
    details = []
    session = get_session()
    try:
        for tag, items in by_tag.items():
            if len(items) <= MAX_CONNECTIONS_PER_PORT:
                continue
            marker = "-user-"
            if marker not in tag:
                continue
            try:
                user_id = int(tag.rsplit(marker, 1)[1])
            except ValueError:
                continue
            user = session.query(ProxyUser).get(user_id)
            if not user or not user.status:
                continue
            restore_at = datetime.now() + timedelta(seconds=AUTO_STOP_RESTORE_SECONDS)
            user.status = 0
            reason = (
                f"自动停用：连接数 {len(items)} 超过单端口上限 {MAX_CONNECTIONS_PER_PORT}，"
                f"时间 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}，请人工确认后手动启用"
            )
            note = (user.note or "").strip()
            user.note = _append_auto_restore_marker(reason if not note else f"{reason}\n{note}", restore_at)
            host = user.line.public_ip if user.line else "-"
            port = user.listen_port or (user.line.get_port_by_protocol(user.protocol) if user.line else "-")
            detail = (
                f"自动停用原因=单节点连接数超限；节点={host}:{port}；协议={user.protocol or '-'}；"
                f"用户={user.owner_name or user.username or '-'}；项目={user.project_name or '-'}；"
                f"连接数={len(items)}；上限={MAX_CONNECTIONS_PER_PORT}；入站={tag}；"
                f"时间={datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            )
            add_operation_log(session, "system", "自动保护", "自动停用节点", detail, str(host))
            disabled += 1
            details.append(f"user {user_id} {tag}={len(items)}")
        if disabled:
            session.commit()
            write_cfg(session)
            _hot_reload_config()
        return disabled, ", ".join(details)
    finally:
        session.close()


def _probe_connection_limits(timeout: float = 2.0) -> tuple[bool, str]:
    if MAX_CONNECTIONS_PER_PORT <= 0:
        return True, "connection limit disabled"

    try:
        connections = _fetch_connections(timeout=timeout)
    except Exception as exc:
        return False, f"connection limit probe failed: {exc}"

    by_tag: dict[str, list[dict]] = {}
    for conn in connections:
        tag = _connection_tag(conn)
        if not tag.startswith("in-"):
            continue
        by_tag.setdefault(tag, []).append(conn)

    over_limit = {tag: items for tag, items in by_tag.items() if len(items) > MAX_CONNECTIONS_PER_PORT}
    if not over_limit:
        return True, f"connection limits ok: max {MAX_CONNECTIONS_PER_PORT}"

    disabled, disabled_details = _disable_over_limit_users(over_limit)
    details = ", ".join(f"{tag}={len(items)}" for tag, items in over_limit.items())
    if disabled:
        return True, f"connection limit exceeded; disabled {disabled}: {disabled_details}"
    return True, f"connection limit exceeded; no users disabled: {details}"


def enforce_connection_limits(timeout: float = 2.0) -> dict:
    ok, message = _probe_connection_limits(timeout=timeout)
    return {"ok": ok, "message": message, "max_per_port": MAX_CONNECTIONS_PER_PORT}


def restore_auto_stopped_users() -> dict:
    from models import ProxyUser, get_session
    from services.cfg_generator import parse_size_to_bytes

    now = datetime.now()
    restored = []
    skipped = []
    session = get_session()
    try:
        users = session.query(ProxyUser).filter(ProxyUser.status == 0).all()
        for user in users:
            restore_at, clean_note = _pop_auto_restore_marker(user.note)
            if not restore_at or now < restore_at:
                continue
            if user.expire_at and user.expire_at <= now:
                user.note = clean_note
                skipped.append(f"user {user.id} expired")
                continue
            limit = parse_size_to_bytes(user.traffic_limit)
            used = int(user.bytes_in or 0) + int(user.bytes_out or 0)
            if limit and used >= limit:
                user.note = clean_note
                skipped.append(f"user {user.id} traffic exhausted")
                continue
            user.status = 1
            user.note = clean_note
            host = user.line.public_ip if user.line else "-"
            port = user.listen_port or (user.line.get_port_by_protocol(user.protocol) if user.line else "-")
            add_operation_log(
                session,
                "system",
                "自动保护",
                "自动恢复节点",
                (
                    f"自动恢复原因=自动停用等待结束；节点={host}:{port}；协议={user.protocol or '-'}；"
                    f"用户={user.owner_name or user.username or '-'}；项目={user.project_name or '-'}；"
                    f"等待={AUTO_STOP_RESTORE_SECONDS}s"
                ),
                str(host),
            )
            restored.append(user.id)
        if restored or skipped:
            session.commit()
        if restored:
            write_cfg(session)
            _hot_reload_config()
        return {"restored": restored, "skipped": skipped}
    finally:
        session.close()


def health_check(timeout: float = 2.0) -> dict:
    status = get_status()
    if not status["running"]:
        return {**status, "healthy": False, "message": "sing-box process is not running"}

    errors = []
    api_ok = False
    for url in HEALTH_URLS:
        try:
            with urllib.request.urlopen(url, timeout=timeout) as resp:
                if 200 <= resp.status < 300:
                    api_ok = True
                    break
                errors.append(f"{url} returned HTTP {resp.status}")
        except Exception as exc:
            errors.append(f"{url}: {exc}")

    if not api_ok:
        return {**status, "healthy": False, "message": "; ".join(errors)}

    limit_ok, limit_message = _probe_connection_limits(timeout=timeout)
    if not limit_ok:
        return {**status, "healthy": False, "message": limit_message}

    socks_ok, socks_message = _probe_socks5_user(timeout=timeout)
    if socks_ok:
        return {**status, "healthy": True, "message": f"health probe ok: {socks_message}; {limit_message}"}
    return {**status, "healthy": False, "message": socks_message}


def start():
    if not os.path.exists(SING_BOX_EXE):
        raise FileNotFoundError(f"sing-box 不存在: {SING_BOX_EXE}")
    running_pid = _find_running_process()
    if running_pid:
        _write_pid(running_pid)
        return running_pid
    write_cfg()
    kwargs = {
        "cwd": os.path.dirname(SING_BOX_EXE),
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.DEVNULL,
    }
    if os.name == "nt":
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
    else:
        kwargs["start_new_session"] = True
    proc = subprocess.Popen([SING_BOX_EXE, "run", "-c", SING_BOX_CFG], **kwargs)
    _write_pid(proc.pid)
    time.sleep(1.5)
    return_code = proc.poll()
    if return_code is not None:
        raise RuntimeError(f"sing-box 启动后立即退出，退出码 {return_code}")
    return proc.pid


def ensure_running():
    running_pid = _find_running_process()
    if running_pid:
        _write_pid(running_pid)
        return running_pid
    return start()


def ensure_healthy() -> int:
    health = health_check()
    if health.get("healthy"):
        pid = health.get("pid")
        if pid:
            return int(pid)
    if health.get("running"):
        print(f"[sing-box watchdog] unhealthy, restarting: {health.get('message')}")
        return restart_config()
    print(f"[sing-box watchdog] missing, starting: {health.get('message')}")
    return start()


def _hot_reload_config() -> bool:
    body = b'{"path": "' + SING_BOX_CFG.replace("\\", "\\\\").encode("utf-8") + b'"}'
    urls = [
        "http://127.0.0.1:9090/configs?force=true",
        "http://127.0.0.1:9090/configs",
    ]
    for url in urls:
        try:
            req = urllib.request.Request(
                url,
                data=body,
                method="PUT",
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=3) as resp:
                if 200 <= resp.status < 300:
                    return True
        except (urllib.error.URLError, TimeoutError, OSError):
            pass
    return False


def stop():
    if os.name != "nt":
        pids = set(_linux_sing_box_pids())
        pid_file_pid = _read_pid()
        if pid_file_pid:
            pids.add(pid_file_pid)
        pids = {pid for pid in pids if _is_running(pid)}
        if not pids:
            return True
        for pid in pids:
            try:
                os.kill(pid, signal.SIGTERM)
            except Exception as e:
                print(f"stop error pid={pid}: {e}")
        deadline = time.time() + 3
        while time.time() < deadline:
            if not any(_is_running(pid) for pid in pids):
                return True
            time.sleep(0.2)
        for pid in pids:
            try:
                if _is_running(pid):
                    os.kill(pid, signal.SIGKILL)
            except Exception as e:
                print(f"kill error pid={pid}: {e}")
        return not any(_is_running(pid) for pid in pids)

    pid = _read_pid()
    if not pid:
        return True
    try:
        subprocess.run(["taskkill", "/F", "/PID", str(pid)], capture_output=True, text=True)
        time.sleep(0.5)
        return True
    except Exception as e:
        print(f"stop error: {e}")
        return False


def reload_config_no_restart(session=None) -> dict:
    write_cfg(session)
    status = get_status()
    if not status["running"]:
        return {"ok": False, "restarted": False, "pid": None, "message": "sing-box is not running; config written only"}
    if _hot_reload_config():
        return {"ok": True, "restarted": False, "pid": status.get("pid"), "message": "config hot-reloaded"}
    return {"ok": False, "restarted": False, "pid": status.get("pid"), "message": "hot reload failed; manual apply required"}


def reload_config():
    write_cfg()
    status = get_status()
    if not status["running"]:
        return start()
    stop()
    return start()


def restart_config():
    write_cfg()
    stop()
    return start()


def test_outbound_ip(public_ip: str) -> dict:
    import psutil

    found = False
    for _, addr_list in psutil.net_if_addrs().items():
        for a in addr_list:
            if a.family == socket.AF_INET and a.address == public_ip:
                found = True
                break
    return {"ok": found, "ip": public_ip, "info": "网卡上找到该 IP" if found else "网卡上未找到该 IP"}
