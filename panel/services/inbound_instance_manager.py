"""Per-inbound sing-box instance manager.

Each proxy user marked with runtime_mode="inbound_instance" owns exactly one
sing-box config and one systemd service. Creating, deleting, enabling, disabling
or updating that user only touches its own service.
"""
import json
import os
import shutil
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
    _current_public_ip,
    _line_interface,
    _listen_ip_for_protocol,
    _outbound_bind_ip,
)


INSTANCE_ROOT = Path(os.environ.get("IPWIN42_INBOUND_INSTANCE_DIR") or (PROJECT_DIR / "sing-box" / "inbound-instances"))
SYSTEMD_DIR = Path("/etc/systemd/system")
LOG_LEVEL = (os.environ.get("IPWIN42_SINGBOX_LOG_LEVEL") or "warn").strip().lower() or "warn"
DNS_SERVER = (os.environ.get("IPWIN42_DNS_SERVER") or "tcp://168.126.63.1:53").strip() or "tcp://168.126.63.1:53"


def is_instance_user(user: ProxyUser | None) -> bool:
    return bool(user and (getattr(user, "runtime_mode", "") or "") == "inbound_instance")


def _paths(user_id: int) -> dict[str, Path]:
    base = INSTANCE_ROOT / f"user-{int(user_id)}"
    return {
        "dir": base,
        "config": base / "config.json",
        "log": base / "sing-box.log",
        "stdout": base / "stdout.log",
        "stderr": base / "stderr.log",
    }


def _unit_name(user_id: int) -> str:
    return f"42ipwin-inbound-{int(user_id)}.service"


def _unit_path(user_id: int) -> Path:
    return SYSTEMD_DIR / _unit_name(user_id)


def _run(cmd: list[str], timeout: int = 20) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


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


def _ensure_tls_cert() -> None:
    cert = Path(SING_BOX_CERT)
    key = Path(SING_BOX_KEY)
    if cert.exists() and key.exists():
        return
    cert.parent.mkdir(parents=True, exist_ok=True)
    proc = _run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(key),
            "-out",
            str(cert),
            "-days",
            "3650",
            "-subj",
            "/CN=42ipwin.local",
        ],
        timeout=30,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or proc.stdout.strip() or "failed to create TLS certificate")


def _tls_config() -> dict:
    _ensure_tls_cert()
    return {
        "enabled": True,
        "server_name": "42ipwin.local",
        "certificate_path": SING_BOX_CERT,
        "key_path": SING_BOX_KEY,
    }


def _listen_ip(user: ProxyUser, local_ips: set[str]) -> str:
    line = user.line
    if not line:
        return ""
    public_ip = _current_public_ip(line, local_ips)
    if public_ip:
        return public_ip
    listen_ip = _listen_ip_for_protocol(line, user.protocol, local_ips)
    if listen_ip:
        return listen_ip
    if line.public_ip and line.public_ip in local_ips:
        return line.public_ip
    if line.internal_ip and line.internal_ip != "0.0.0.0" and line.internal_ip in local_ips:
        return line.internal_ip
    return ""


def _outbound(user: ProxyUser, bind_ip: str) -> dict:
    outbound = {"type": "direct", "tag": "out"}
    line = user.line
    iface = _line_interface(line) if line else ""
    if os.name != "nt" and iface in psutil.net_if_addrs():
        outbound["bind_interface"] = iface
        if bind_ip:
            outbound["inet4_bind_address"] = bind_ip
    elif bind_ip:
        outbound["inet4_bind_address"] = bind_ip
    return outbound


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


def write_config(user: ProxyUser) -> tuple[str, bool]:
    if not user.id or not user.line:
        raise ValueError("inbound instance user must have a line")
    local_ips = _local_ipv4s()
    listen_ip = _listen_ip(user, local_ips)
    if not listen_ip:
        raise RuntimeError(f"user {user.id} line IP is not available on this host")
    bind_ip = _outbound_bind_ip(user.line, local_ips)
    paths = _paths(user.id)
    paths["dir"].mkdir(parents=True, exist_ok=True)
    inbound = _inbound(user, listen_ip)
    cfg = {
        "log": {
            "disabled": False,
            "level": LOG_LEVEL,
            "output": str(paths["log"]),
            "timestamp": True,
        },
        "dns": {"servers": [{"tag": "dns-direct", "address": DNS_SERVER}], "strategy": "ipv4_only"},
        "inbounds": [inbound],
        "outbounds": [_outbound(user, bind_ip), {"type": "block", "tag": "block"}],
        "route": {"rules": [{"inbound": [inbound["tag"]], "outbound": "out"}]},
    }
    new_text = json.dumps(cfg, ensure_ascii=False, indent=2)
    changed = True
    if paths["config"].exists():
        try:
            changed = paths["config"].read_text(encoding="utf-8") != new_text
        except Exception:
            changed = True
    if changed:
        paths["config"].write_text(new_text, encoding="utf-8")
        check = _run([SING_BOX_EXE, "check", "-c", str(paths["config"])], timeout=20)
        if check.returncode != 0:
            raise RuntimeError(check.stderr.strip() or check.stdout.strip() or f"sing-box check failed for user {user.id}")
    return str(paths["config"]), changed


def _write_unit(user_id: int, *, reload: bool = True) -> tuple[str, bool]:
    paths = _paths(user_id)
    unit = f"""[Unit]
Description=42IPwin inbound user {int(user_id)}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory={Path(SING_BOX_EXE).parent}
ExecStart={SING_BOX_EXE} run -c {paths["config"]}
Restart=on-failure
RestartSec=2
KillMode=process
LimitNOFILE=1048576
StandardOutput=append:{paths["stdout"]}
StandardError=append:{paths["stderr"]}

[Install]
WantedBy=multi-user.target
"""
    path = _unit_path(user_id)
    changed = True
    if path.exists():
        try:
            changed = path.read_text(encoding="utf-8") != unit
        except Exception:
            changed = True
    if changed:
        path.write_text(unit, encoding="utf-8")
        if reload:
            _run(["systemctl", "daemon-reload"], timeout=20)
    return str(path), changed


def status_user(user_or_id) -> dict:
    user_id = int(user_or_id.id if hasattr(user_or_id, "id") else user_or_id)
    unit = _unit_name(user_id)
    active = _run(["systemctl", "is-active", unit], timeout=8)
    pid = _run(["systemctl", "show", unit, "-p", "MainPID", "--value"], timeout=8)
    pid_text = (pid.stdout or "").strip()
    return {
        "ok": active.returncode == 0,
        "active": (active.stdout or "").strip(),
        "pid": int(pid_text) if pid_text.isdigit() else 0,
        "unit": unit,
    }


def _user_id_list(users_or_ids) -> list[int]:
    ids: list[int] = []
    for item in list(users_or_ids or []):
        user_id = int(item.id if hasattr(item, "id") else item)
        if user_id not in ids:
            ids.append(user_id)
    return ids


def start_users(users) -> list[dict]:
    prepared = []
    results: list[dict] = []
    needs_reload = False
    for user in list(users or []):
        if not is_instance_user(user):
            results.append({
                "ok": True,
                "skipped": True,
                "runtime_mode": getattr(user, "runtime_mode", "") or "legacy",
                "user_id": getattr(user, "id", None),
            })
            continue
        if not os.path.exists(SING_BOX_EXE):
            raise FileNotFoundError(f"sing-box not found: {SING_BOX_EXE}")
        cfg_path, cfg_changed = write_config(user)
        unit_path, unit_changed = _write_unit(user.id, reload=False)
        needs_reload = needs_reload or unit_changed
        before = status_user(user.id)
        if before.get("active") == "active" and before.get("pid") and not cfg_changed and not unit_changed:
            before.update({
                "config": cfg_path,
                "unit_path": unit_path,
                "restarted": False,
                "unchanged": True,
                "user_id": user.id,
            })
            results.append(before)
            continue
        prepared.append((user, _unit_name(user.id), cfg_path, unit_path, cfg_changed, unit_changed, before))

    if prepared and needs_reload:
        proc = _run(["systemctl", "daemon-reload"], timeout=30)
        if proc.returncode != 0:
            err = proc.stderr.strip() or proc.stdout.strip() or "systemctl daemon-reload failed"
            for user, unit, cfg_path, unit_path, cfg_changed, unit_changed, before in prepared:
                results.append({"ok": False, "user_id": user.id, "unit": unit, "error": err})
            return results

    starts = [unit for _user, unit, _cfg, _unit_path_text, _cfg_changed, _unit_changed, before in prepared if before.get("active") != "active"]
    restarts = [unit for _user, unit, _cfg, _unit_path_text, _cfg_changed, _unit_changed, before in prepared if before.get("active") == "active"]
    command_errors: dict[str, str] = {}
    if starts:
        proc = _run(["systemctl", "enable", "--now", *starts], timeout=max(30, len(starts) * 4))
        if proc.returncode != 0:
            err = proc.stderr.strip() or proc.stdout.strip() or "systemctl enable --now failed"
            for unit in starts:
                command_errors[unit] = err
    if restarts:
        proc = _run(["systemctl", "restart", *restarts], timeout=max(30, len(restarts) * 4))
        if proc.returncode != 0:
            err = proc.stderr.strip() or proc.stdout.strip() or "systemctl restart failed"
            for unit in restarts:
                command_errors[unit] = err

    if prepared:
        time.sleep(0.1)
    for user, unit, cfg_path, unit_path, cfg_changed, unit_changed, before in prepared:
        if unit in command_errors:
            results.append({
                "ok": False,
                "user_id": user.id,
                "unit": unit,
                "error": command_errors[unit],
                "config": cfg_path,
                "unit_path": unit_path,
            })
            continue
        status = status_user(user.id)
        status.update({
            "user_id": user.id,
            "config": cfg_path,
            "unit_path": unit_path,
            "restarted": True,
            "config_changed": cfg_changed,
            "unit_changed": unit_changed,
        })
        results.append(status)
    return results


def start_user(user: ProxyUser) -> dict:
    rows = start_users([user])
    return rows[0] if rows else {"ok": False, "error": "no user"}


def stop_users(users_or_ids) -> list[dict]:
    ids = _user_id_list(users_or_ids)
    units = [_unit_name(user_id) for user_id in ids]
    if not units:
        return []
    proc = _run(["systemctl", "disable", "--now", *units], timeout=max(25, len(units) * 3))
    status_proc = _run(["systemctl", "is-active", *units], timeout=max(8, len(units)))
    statuses = (status_proc.stdout or "").splitlines()
    results = []
    for index, user_id in enumerate(ids):
        unit = units[index]
        active = statuses[index].strip() if index < len(statuses) else ""
        ok = active != "active"
        item = {"ok": ok, "user_id": user_id, "unit": unit, "active": active, "stopped": ok}
        if proc.returncode != 0 and not ok:
            item["error"] = proc.stderr.strip() or proc.stdout.strip()
        results.append(item)
    return results


def stop_user(user_or_id) -> dict:
    rows = stop_users([user_or_id])
    return rows[0] if rows else {"ok": True, "pid": None, "stopped": True}


def remove_users(users_or_ids) -> list[dict]:
    ids = _user_id_list(users_or_ids)
    by_id = {item["user_id"]: item for item in stop_users(ids)}
    needs_reload = False
    for user_id in ids:
        result = by_id.setdefault(user_id, {"ok": True, "user_id": user_id, "stopped": True})
        try:
            path = _unit_path(user_id)
            if path.exists():
                path.unlink()
                needs_reload = True
        except Exception as exc:
            result.setdefault("errors", []).append(str(exc))
            result["ok"] = False
        try:
            shutil.rmtree(_paths(user_id)["dir"], ignore_errors=True)
        except Exception as exc:
            result.setdefault("errors", []).append(str(exc))
            result["ok"] = False
    if needs_reload:
        proc = _run(["systemctl", "daemon-reload"], timeout=30)
        if proc.returncode != 0:
            err = proc.stderr.strip() or proc.stdout.strip() or "systemctl daemon-reload failed"
            for result in by_id.values():
                result.setdefault("errors", []).append(err)
                result["ok"] = False
    return [by_id[user_id] for user_id in ids]


def remove_user(user_or_id) -> dict:
    rows = remove_users([user_or_id])
    return rows[0] if rows else {"ok": True, "stopped": True}


def apply_user(user: ProxyUser) -> dict:
    if not is_instance_user(user):
        return {"ok": True, "skipped": True, "runtime_mode": getattr(user, "runtime_mode", "") or "legacy"}
    if user.status:
        return start_user(user)
    return stop_user(user)
