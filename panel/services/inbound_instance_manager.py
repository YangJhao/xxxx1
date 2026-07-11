"""One sing-box process per newly created inbound.

Legacy rows stay in the main sing-box config. Rows marked with
runtime_mode="inbound_instance" are managed here so stop/delete/re-enable only
touches that inbound process.
"""
import json
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

import psutil

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from config import PROJECT_DIR, SING_BOX_CERT, SING_BOX_EXE, SING_BOX_KEY
from models import ProxyUser
from services.cfg_generator import (
    SING_BOX_LOG_LEVEL,
    _line_interface as cfg_line_interface,
    _listen_ip_for_protocol as cfg_listen_ip_for_protocol,
    _outbound_bind_ip as cfg_outbound_bind_ip,
)


INSTANCE_ROOT = Path(os.environ.get("IPWIN42_INBOUND_INSTANCE_DIR") or (PROJECT_DIR / "sing-box" / "inbound-instances"))
CONTROLLER_BASE_PORT = int(os.environ.get("IPWIN42_INBOUND_INSTANCE_CONTROLLER_BASE", "29090"))


def is_instance_user(user: ProxyUser | None) -> bool:
    return bool(user and (user.runtime_mode or "") == "inbound_instance")


def _paths(user_id: int) -> dict[str, Path]:
    base = INSTANCE_ROOT / f"user-{int(user_id)}"
    return {
        "dir": base,
        "config": base / "config.json",
        "pid": base / "sing-box.pid",
        "log": base / "sing-box.log",
        "stdout": base / "stdout.log",
        "stderr": base / "stderr.log",
    }


def _controller_port(user_id: int) -> int:
    return CONTROLLER_BASE_PORT + int(user_id)


def _read_pid(user_id: int) -> int | None:
    try:
        return int(_paths(user_id)["pid"].read_text(encoding="utf-8").strip() or 0) or None
    except Exception:
        return None


def _write_pid(user_id: int, pid: int) -> None:
    paths = _paths(user_id)
    paths["dir"].mkdir(parents=True, exist_ok=True)
    paths["pid"].write_text(str(pid), encoding="utf-8")


def _is_running(pid: int | None) -> bool:
    if not pid:
        return False
    try:
        if os.name != "nt":
            stat = Path(f"/proc/{pid}/stat")
            if stat.exists() and len(stat.read_text(encoding="utf-8").split()) > 2:
                if stat.read_text(encoding="utf-8").split()[2] == "Z":
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


def find_process(user_id: int) -> int | None:
    pid = _read_pid(user_id)
    if _is_running(pid):
        return pid
    cfg = str(_paths(user_id)["config"])
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
                _write_pid(user_id, int(text))
                return int(text)
            return None

        for proc_dir in Path("/proc").iterdir():
            if not proc_dir.name.isdigit():
                continue
            item = int(proc_dir.name)
            if cfg in _process_cmdline(item) and _is_running(item):
                _write_pid(user_id, item)
                return item
    except Exception:
        return None
    return None


def _local_ipv4s() -> set[str]:
    ips = set()
    try:
        for rows in psutil.net_if_addrs().values():
            for addr in rows:
                if addr.family == socket.AF_INET:
                    ips.add(addr.address)
    except Exception:
        pass
    return ips


def _line_interface(user: ProxyUser) -> str:
    line = user.line
    if not line:
        return ""
    return cfg_line_interface(line)


def _outbound(user: ProxyUser, bind_ip: str) -> dict:
    outbound = {"type": "direct", "tag": "out"}
    iface = _line_interface(user)
    if os.name != "nt" and iface in psutil.net_if_addrs():
        outbound["bind_interface"] = iface
        if bind_ip:
            outbound["inet4_bind_address"] = bind_ip
    elif bind_ip:
        outbound["inet4_bind_address"] = bind_ip
    return outbound


def _tls_config() -> dict:
    return {
        "enabled": True,
        "server_name": "42ipwin.local",
        "certificate_path": SING_BOX_CERT,
        "key_path": SING_BOX_KEY,
    }


def _inbound(user: ProxyUser, listen_ip: str) -> dict:
    proto = (user.protocol or "socks5").lower()
    port = int(user.listen_port or user.line.get_port_by_protocol(proto))
    base = {"tag": f"in-user-{user.id}", "listen": listen_ip, "listen_port": port}
    if proto == "socks5":
        return {**base, "type": "socks", "users": [{"username": user.username, "password": user.password}]}
    if proto == "http":
        return {**base, "type": "http", "users": [{"username": user.username, "password": user.password}]}
    if proto == "ss":
        return {
            **base,
            "type": "shadowsocks",
            "method": user.ss_method or "aes-256-gcm",
            "password": user.ss_password or user.password,
        }
    if proto == "vless":
        return {**base, "type": "vless", "users": [{"name": user.username, "uuid": user.password}]}
    if proto == "vmess":
        return {**base, "type": "vmess", "users": [{"name": user.username, "uuid": user.password}]}
    if proto == "trojan":
        return {**base, "type": "trojan", "users": [{"name": user.username, "password": user.password}], "tls": _tls_config()}
    if proto == "hysteria2":
        return {**base, "type": "hysteria2", "users": [{"name": user.username, "password": user.password}], "tls": _tls_config()}
    raise ValueError(f"unsupported protocol for inbound instance: {proto}")


def write_config(user: ProxyUser) -> str:
    if not user.id or not user.line:
        raise ValueError("inbound instance user must be flushed and have a line")
    local_ips = _local_ipv4s()
    bind_ip = cfg_outbound_bind_ip(user.line, local_ips)
    listen_ip = cfg_listen_ip_for_protocol(user.line, user.protocol, local_ips)
    if os.name == "nt" and not listen_ip:
        raise RuntimeError("line IP is not available on this host")
    listen_ip = listen_ip or "0.0.0.0"
    paths = _paths(user.id)
    paths["dir"].mkdir(parents=True, exist_ok=True)
    inbound = _inbound(user, listen_ip)
    cfg = {
        "log": {
            "disabled": False,
            "level": SING_BOX_LOG_LEVEL,
            "output": str(paths["log"]),
            "timestamp": True,
        },
        "experimental": {
            "clash_api": {
                "external_controller": f"127.0.0.1:{_controller_port(user.id)}",
                "secret": "",
            }
        },
        "inbounds": [inbound],
        "outbounds": [_outbound(user, bind_ip), {"type": "block", "tag": "block"}],
        "route": {"rules": [{"inbound": [inbound["tag"]], "outbound": "out"}]},
    }
    paths["config"].write_text(json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")
    return str(paths["config"])


def start_user(user: ProxyUser) -> dict:
    if not is_instance_user(user):
        return {"ok": True, "skipped": True, "runtime_mode": user.runtime_mode or "legacy"}
    if not os.path.exists(SING_BOX_EXE):
        raise FileNotFoundError(f"sing-box not found: {SING_BOX_EXE}")
    write_config(user)
    pid = find_process(user.id)
    if pid:
        return {"ok": True, "pid": pid, "restarted": False}
    paths = _paths(user.id)
    stdout = open(paths["stdout"], "ab")
    stderr = open(paths["stderr"], "ab")
    kwargs = {"cwd": os.path.dirname(SING_BOX_EXE), "stdout": stdout, "stderr": stderr}
    if os.name == "nt":
        kwargs["creationflags"] = (
            getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
            | getattr(subprocess, "DETACHED_PROCESS", 0x00000008)
            | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200)
        )
    else:
        kwargs["start_new_session"] = True
    proc = subprocess.Popen([SING_BOX_EXE, "run", "-c", str(paths["config"])], **kwargs)
    _write_pid(user.id, proc.pid)
    time.sleep(1.2)
    if proc.poll() is not None:
        raise RuntimeError(f"inbound instance exited immediately: user={user.id} code={proc.returncode}")
    return {"ok": True, "pid": proc.pid, "restarted": True}


def stop_user(user_or_id) -> dict:
    user_id = int(user_or_id.id if hasattr(user_or_id, "id") else user_or_id)
    pid = find_process(user_id)
    if not pid:
        return {"ok": True, "pid": None, "stopped": True}
    try:
        if os.name == "nt":
            subprocess.run(["taskkill", "/F", "/PID", str(pid)], capture_output=True, text=True, timeout=10)
        else:
            os.kill(pid, signal.SIGTERM)
            deadline = time.time() + 3
            while time.time() < deadline:
                if not _is_running(pid):
                    break
                time.sleep(0.2)
            if _is_running(pid):
                os.kill(pid, signal.SIGKILL)
        time.sleep(0.4)
        return {"ok": not _is_running(pid), "pid": pid, "stopped": not _is_running(pid)}
    except Exception as exc:
        return {"ok": False, "pid": pid, "error": str(exc)}


def remove_user(user_or_id) -> dict:
    user_id = int(user_or_id.id if hasattr(user_or_id, "id") else user_or_id)
    result = stop_user(user_id)
    paths = _paths(user_id)
    for item in ("config", "pid"):
        try:
            paths[item].unlink(missing_ok=True)
        except Exception:
            pass
    return result


def apply_user(user: ProxyUser) -> dict:
    if not is_instance_user(user):
        return {"ok": True, "skipped": True, "runtime_mode": user.runtime_mode or "legacy"}
    if user.status:
        return start_user(user)
    return stop_user(user)
