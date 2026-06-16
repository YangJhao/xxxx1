"""sing-box process management."""
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from config import SING_BOX_CFG, SING_BOX_EXE, SING_BOX_PID
from services.cfg_generator import write_cfg


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
            os.kill(pid, 0)
            return True
        out = subprocess.run(["tasklist", "/FI", f"PID eq {pid}"], capture_output=True, text=True)
        return str(pid) in out.stdout
    except Exception:
        return False


def _find_running_process() -> int | None:
    if os.name != "nt":
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
    return proc.pid


def ensure_running():
    running_pid = _find_running_process()
    if running_pid:
        _write_pid(running_pid)
        return running_pid
    return start()


def stop():
    pid = _read_pid()
    if not pid:
        return True
    try:
        if os.name == "nt":
            subprocess.run(["taskkill", "/F", "/PID", str(pid)], capture_output=True, text=True)
        else:
            os.kill(pid, signal.SIGTERM)
        time.sleep(0.5)
        return True
    except Exception as e:
        print(f"stop error: {e}")
        return False


def reload_config():
    if get_status()["running"]:
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
