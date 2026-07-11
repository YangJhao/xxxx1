"""Per-line sing-box instance management.

Default production mode still uses the single global sing-box process. This
module is only used when IPWIN42_SINGBOX_MODE=per_line is explicitly enabled.
"""
import json
import os
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from config import PROJECT_DIR, SING_BOX_EXE
from models import Line, ProxyUser, get_session
from services.audit_logger import add_operation_log
from services.cfg_generator import generate_cfg_for_lines


INSTANCE_ROOT = Path(os.environ.get("IPWIN42_SINGBOX_INSTANCE_DIR") or (PROJECT_DIR / "sing-box" / "instances"))
CONTROLLER_BASE_PORT = int(os.environ.get("IPWIN42_SINGBOX_INSTANCE_CONTROLLER_BASE", "19090"))


def _operation_log(action: str, detail: str, ip: str = "127.0.0.1") -> None:
    try:
        session = get_session()
        try:
            add_operation_log(session, "system", "sing-box 单线路", action, detail[:4000], ip)
            session.commit()
        finally:
            session.close()
    except Exception:
        pass


def _normalize_line_ids(line_ids) -> list[int]:
    ids = []
    for value in line_ids or []:
        try:
            item = int(value)
        except Exception:
            continue
        if item > 0 and item not in ids:
            ids.append(item)
    return ids


def _controller_port(line_id: int) -> int:
    return CONTROLLER_BASE_PORT + int(line_id)


def _instance_dir(line_id: int) -> Path:
    return INSTANCE_ROOT / f"line-{int(line_id)}"


def _paths(line_id: int) -> dict[str, Path]:
    base = _instance_dir(line_id)
    return {
        "dir": base,
        "config": base / "config.json",
        "pid": base / "sing-box.pid",
        "log": base / "sing-box.log",
        "stdout": base / "stdout.log",
        "stderr": base / "stderr.log",
    }


def _read_pid(line_id: int) -> int | None:
    try:
        text = _paths(line_id)["pid"].read_text(encoding="utf-8").strip()
        return int(text or 0) or None
    except Exception:
        return None


def _write_pid(line_id: int, pid: int) -> None:
    paths = _paths(line_id)
    paths["dir"].mkdir(parents=True, exist_ok=True)
    paths["pid"].write_text(str(pid), encoding="utf-8")


def _is_running(pid: int | None) -> bool:
    if not pid:
        return False
    try:
        if os.name != "nt":
            stat_path = Path(f"/proc/{pid}/stat")
            if stat_path.exists():
                fields = stat_path.read_text(encoding="utf-8").split()
                if len(fields) > 2 and fields[2] == "Z":
                    return False
            os.kill(pid, 0)
            return True
        out = subprocess.run(["tasklist", "/FI", f"PID eq {pid}"], capture_output=True, text=True, timeout=8)
        return str(pid) in out.stdout
    except Exception:
        return False


def _process_cmdline(pid: int) -> str:
    if os.name != "nt":
        try:
            return Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\x00", b" ").decode("utf-8", "ignore")
        except Exception:
            return ""
    try:
        cmd = f"(Get-CimInstance Win32_Process -Filter \"ProcessId={int(pid)}\").CommandLine"
        out = subprocess.run(["powershell", "-NoProfile", "-Command", cmd], capture_output=True, text=True, timeout=8)
        return out.stdout or ""
    except Exception:
        return ""


def _find_process(line_id: int) -> int | None:
    pid = _read_pid(line_id)
    if _is_running(pid):
        return pid
    cfg = str(_paths(line_id)["config"])
    try:
        if os.name == "nt":
            escaped = cfg.replace("\\", "\\\\")
            cmd = (
                "Get-CimInstance Win32_Process | "
                f"Where-Object {{$_.Name -eq 'sing-box.exe' -and $_.CommandLine -like '*{escaped}*'}} | "
                "Select-Object -First 1 -ExpandProperty ProcessId"
            )
            out = subprocess.run(["powershell", "-NoProfile", "-Command", cmd], capture_output=True, text=True, timeout=8)
            text = (out.stdout or "").strip()
            if text.isdigit() and _is_running(int(text)):
                _write_pid(line_id, int(text))
                return int(text)
            return None

        for proc_dir in Path("/proc").iterdir():
            if not proc_dir.name.isdigit():
                continue
            item = int(proc_dir.name)
            cmdline = _process_cmdline(item)
            if "sing-box" in cmdline and cfg in cmdline and _is_running(item):
                _write_pid(line_id, item)
                return item
    except Exception:
        return None
    return None


def _line_has_active_users(session, line_id: int) -> bool:
    return (
        session.query(ProxyUser.id)
        .join(Line)
        .filter(ProxyUser.line_id == int(line_id), ProxyUser.status == 1, Line.status == 1)
        .first()
        is not None
    )


def write_line_cfg(session, line_id: int) -> str:
    paths = _paths(line_id)
    paths["dir"].mkdir(parents=True, exist_ok=True)
    cfg_text = generate_cfg_for_lines(
        session,
        [line_id],
        controller_port=_controller_port(line_id),
        log_path=str(paths["log"]),
    )
    paths["config"].write_text(cfg_text, encoding="utf-8")
    return str(paths["config"])


def _config_listener_ports(line_id: int) -> set[int]:
    try:
        payload = json.loads(_paths(line_id)["config"].read_text(encoding="utf-8"))
    except Exception:
        return set()
    ports = set()
    for inbound in payload.get("inbounds") or []:
        try:
            port = int(inbound.get("listen_port") or 0)
        except Exception:
            port = 0
        if port > 0:
            ports.add(port)
    return ports


def _runtime_listener_ports(line_id: int) -> set[int]:
    pid = _find_process(line_id)
    if not pid:
        return set()
    if os.name != "nt":
        proc = subprocess.run(["ss", "-Hltun"], capture_output=True, text=True, timeout=8)
        ports = set()
        for line in (proc.stdout or "").splitlines():
            parts = line.split()
            local = parts[4] if len(parts) >= 5 else ""
            try:
                ports.add(int(local.rsplit(":", 1)[1]))
            except Exception:
                pass
        return ports

    proc = subprocess.run(["netstat", "-ano", "-p", "tcp"], capture_output=True, text=True, timeout=10)
    ports = set()
    for line in (proc.stdout or "").splitlines():
        parts = line.split()
        if len(parts) < 5 or parts[0].upper() != "TCP" or parts[3].upper() != "LISTENING":
            continue
        try:
            listen_pid = int(parts[4])
            port = int(parts[1].rsplit(":", 1)[1])
        except Exception:
            continue
        if listen_pid == int(pid):
            ports.add(port)
    try:
        cmd = (
            f"Get-NetUDPEndpoint -OwningProcess {int(pid)} -ErrorAction SilentlyContinue | "
            "Select-Object -ExpandProperty LocalPort"
        )
        udp_proc = subprocess.run(["powershell", "-NoProfile", "-Command", cmd], capture_output=True, text=True, timeout=10)
        for line in (udp_proc.stdout or "").splitlines():
            line = line.strip()
            if line.isdigit():
                ports.add(int(line))
    except Exception:
        pass
    return ports


def _listener_sync_status(line_id: int) -> dict:
    config_ports = _config_listener_ports(line_id)
    runtime_ports = _runtime_listener_ports(line_id)
    control_ports = {_controller_port(line_id)}
    missing = sorted(config_ports - runtime_ports)
    orphan = sorted((runtime_ports - config_ports) - control_ports)
    return {
        "ok": not missing and not orphan,
        "config_count": len(config_ports),
        "runtime_count": len(runtime_ports),
        "missing": missing,
        "orphan": orphan,
    }


def _hot_reload(line_id: int) -> bool:
    cfg_path = str(_paths(line_id)["config"])
    body = b'{"path": "' + cfg_path.replace("\\", "\\\\").encode("utf-8") + b'"}'
    port = _controller_port(line_id)
    for url in (f"http://127.0.0.1:{port}/configs?force=true", f"http://127.0.0.1:{port}/configs"):
        try:
            req = urllib.request.Request(url, data=body, method="PUT", headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=3) as resp:
                if 200 <= resp.status < 300:
                    return True
        except (urllib.error.URLError, TimeoutError, OSError):
            pass
    return False


def start_line(line_id: int) -> int:
    if not os.path.exists(SING_BOX_EXE):
        raise FileNotFoundError(f"sing-box not found: {SING_BOX_EXE}")
    running_pid = _find_process(line_id)
    if running_pid:
        return running_pid
    paths = _paths(line_id)
    paths["dir"].mkdir(parents=True, exist_ok=True)
    stdout = open(paths["stdout"], "ab")
    stderr = open(paths["stderr"], "ab")
    kwargs = {
        "cwd": os.path.dirname(SING_BOX_EXE),
        "stdout": stdout,
        "stderr": stderr,
    }
    if os.name == "nt":
        kwargs["creationflags"] = (
            getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
            | getattr(subprocess, "DETACHED_PROCESS", 0x00000008)
            | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200)
        )
    else:
        kwargs["start_new_session"] = True
    proc = subprocess.Popen([SING_BOX_EXE, "run", "-c", str(paths["config"])], **kwargs)
    _write_pid(line_id, proc.pid)
    time.sleep(1.5)
    return_code = proc.poll()
    if return_code is not None:
        raise RuntimeError(f"line {line_id} sing-box exited immediately: code={return_code}")
    return proc.pid


def stop_line(line_id: int) -> bool:
    pid = _find_process(line_id)
    if not pid:
        return True
    try:
        if os.name == "nt":
            subprocess.run(["taskkill", "/F", "/PID", str(pid)], capture_output=True, text=True, timeout=10)
        else:
            os.kill(pid, signal.SIGTERM)
            deadline = time.time() + 3
            while time.time() < deadline:
                if not _is_running(pid):
                    return True
                time.sleep(0.2)
            if _is_running(pid):
                os.kill(pid, signal.SIGKILL)
        time.sleep(0.5)
        return not _is_running(pid)
    except Exception as exc:
        _operation_log("stop-line-failed", f"line_id={line_id}; pid={pid}; error={exc}")
        return False


def reload_line(session, line_id: int, reason: str = "line-change") -> dict:
    line_id = int(line_id)
    has_users = _line_has_active_users(session, line_id)
    write_line_cfg(session, line_id)
    if not has_users:
        before_pid = _find_process(line_id)
        stopped = stop_line(line_id)
        _operation_log(
            "空线路停止",
            f"原因={reason}; 线路ID={line_id}; 处理前PID={before_pid}; 是否停止成功={stopped}",
        )
        return {"ok": stopped, "line_id": line_id, "stopped": True, "restarted": False, "pid": None}

    before_pid = _find_process(line_id)
    hot_ok = bool(before_pid and _hot_reload(line_id))
    sync = _listener_sync_status(line_id)
    if hot_ok and sync.get("ok"):
        return {"ok": True, "line_id": line_id, "restarted": False, "pid": before_pid, "listener_sync": sync}

    stop_line(line_id)
    after_pid = start_line(line_id)
    time.sleep(1.2)
    after_sync = _listener_sync_status(line_id)
    line = session.query(Line).get(line_id)
    detail = (
        f"原因={reason}; 线路ID={line_id}; 公网IP={(line.public_ip if line else '-')}; "
        f"处理前PID={before_pid}; 处理后PID={after_pid}; 热加载是否成功={hot_ok}; "
        f"处理前缺少监听端口={sync.get('missing')[:20]}; 处理前多余监听端口={sync.get('orphan')[:20]}; "
        f"处理后仍缺少监听端口={after_sync.get('missing')[:20]}; 处理后多余监听端口={after_sync.get('orphan')[:20]}"
    )
    _operation_log("线路监听修复", detail, (line.public_ip if line else "127.0.0.1"))
    return {
        "ok": bool(after_sync.get("ok")),
        "line_id": line_id,
        "restarted": True,
        "pid": after_pid,
        "listener_sync": after_sync,
    }


def reload_lines(session, line_ids, reason: str = "line-change") -> dict:
    ids = _normalize_line_ids(line_ids)
    if not ids:
        ids = [line.id for line in session.query(Line.id).order_by(Line.id).all()]
    results = [reload_line(session, line_id, reason=reason) for line_id in ids]
    return {
        "ok": all(item.get("ok") for item in results),
        "mode": "per_line",
        "results": results,
        "restarted": any(item.get("restarted") for item in results),
        "line_ids": ids,
    }


def ensure_lines_running(session, line_ids, reason: str = "ensure-lines-running") -> dict:
    ids = _normalize_line_ids(line_ids)
    results = []
    for line_id in ids:
        has_users = _line_has_active_users(session, line_id)
        pid = _find_process(line_id)
        if not has_users:
            if pid:
                stopped = stop_line(line_id)
                _operation_log(
                    "空线路停止",
                    f"原因={reason}; 线路ID={line_id}; 处理前PID={pid}; 是否停止成功={stopped}",
                )
                results.append({"ok": stopped, "line_id": line_id, "stopped": True, "restarted": False, "pid": None})
            else:
                results.append({"ok": True, "line_id": line_id, "stopped": True, "restarted": False, "pid": None})
            continue

        if pid:
            sync = _listener_sync_status(line_id)
            if sync.get("ok"):
                results.append({"ok": True, "line_id": line_id, "restarted": False, "pid": pid, "listener_sync": sync})
                continue

        try:
            result = reload_line(session, line_id, reason=reason)
        except Exception as exc:
            _operation_log("线路检查失败", f"原因={reason}; 线路ID={line_id}; 处理前PID={pid}; 错误={exc}")
            result = {"ok": False, "line_id": line_id, "restarted": False, "pid": pid, "error": str(exc)}
        results.append(result)

    return {
        "ok": all(item.get("ok") for item in results),
        "mode": "per_line",
        "results": results,
        "restarted": any(item.get("restarted") for item in results),
        "line_ids": ids,
    }


def ensure_missing_lines(session=None, reason: str = "ensure-missing-lines") -> dict:
    own_session = session is None
    if own_session:
        session = get_session()
    try:
        ids = [
            int(line_id)
            for (line_id,) in (
                session.query(ProxyUser.line_id)
                .join(Line)
                .filter(ProxyUser.status == 1, Line.status == 1)
                .distinct()
                .all()
            )
        ]
        results = []
        for line_id in ids:
            pid = _find_process(line_id)
            if pid:
                sync = _listener_sync_status(line_id)
                if sync.get("ok"):
                    continue
            try:
                results.append(reload_line(session, line_id, reason=reason))
            except Exception as exc:
                _operation_log("线路检查失败", f"原因={reason}; 线路ID={line_id}; 处理前PID={pid}; 错误={exc}")
                results.append({"ok": False, "line_id": line_id, "pid": pid, "error": str(exc)})
        return {
            "ok": all(item.get("ok") for item in results),
            "mode": "per_line",
            "checked": len(ids),
            "results": results,
            "restarted": any(item.get("restarted") for item in results),
        }
    finally:
        if own_session:
            session.close()


def ensure_active_lines(session=None) -> dict:
    own_session = session is None
    if own_session:
        session = get_session()
    try:
        line_ids = [
            line_id
            for (line_id,) in (
                session.query(ProxyUser.line_id)
                .join(Line)
                .filter(ProxyUser.status == 1, Line.status == 1)
                .distinct()
                .all()
            )
        ]
        return ensure_lines_running(session, line_ids, reason="ensure-active-lines")
    finally:
        if own_session:
            session.close()
