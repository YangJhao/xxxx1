"""sing-box config generator."""
import json
import os
import re
import socket
import sys
from pathlib import Path

import psutil

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from config import SING_BOX_CERT, SING_BOX_CFG, SING_BOX_KEY, SING_BOX_LOG
from models import Line, ProxyUser, get_session


def parse_size_to_bytes(value) -> int | None:
    if not value:
        return None
    text = str(value).strip().lower().replace(" ", "")
    m = re.match(r"^(\d+(?:\.\d+)?)(b|k|kb|m|mb|g|gb|t|tb|kib|mib|gib|tib)?$", text)
    if not m:
        return None
    number = float(m.group(1))
    unit = m.group(2) or "gb"
    mult = {
        "b": 1,
        "k": 1000,
        "kb": 1000,
        "m": 1000**2,
        "mb": 1000**2,
        "g": 1000**3,
        "gb": 1000**3,
        "t": 1000**4,
        "tb": 1000**4,
        "kib": 1024,
        "mib": 1024**2,
        "gib": 1024**3,
        "tib": 1024**4,
    }[unit]
    return int(number * mult)


def _outbound_tag(line: Line) -> str:
    return f"out-line-{line.id}"


def _inbound_tag(line: Line, proto: str) -> str:
    return f"in-{proto}-line-{line.id}"


def _user_inbound_tag(user: ProxyUser) -> str:
    return f"in-{user.protocol}-user-{user.id}"


def _auth_user(user: ProxyUser) -> dict:
    return {"username": user.username, "password": user.password}


def _ss_user(user: ProxyUser) -> dict:
    return {"name": user.username, "password": user.ss_password or user.password}


def _uuid_user(user: ProxyUser) -> dict:
    return {"name": user.username, "uuid": user.password}


def _password_user(user: ProxyUser) -> dict:
    return {"name": user.username, "password": user.password}


def _tls_config() -> dict:
    return {
        "enabled": True,
        "server_name": "42ipwin.local",
        "certificate_path": SING_BOX_CERT,
        "key_path": SING_BOX_KEY,
    }


def _add_route(cfg: dict, tag: str, out_tag: str):
    cfg["route"]["rules"].append({"inbound": [tag], "outbound": out_tag})


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


def _bind_ip(line: Line, local_ips: set[str] | None = None) -> str:
    local_ips = local_ips if local_ips is not None else _local_ipv4s()
    if line.public_ip in local_ips:
        return line.public_ip
    if line.internal_ip and line.internal_ip != "0.0.0.0" and line.internal_ip in local_ips:
        return line.internal_ip
    return ""


def _listen_ip(line: Line, local_ips: set[str] | None = None) -> str:
    local_ips = local_ips if local_ips is not None else _local_ipv4s()
    if line.public_ip in local_ips:
        return line.public_ip
    if line.internal_ip and line.internal_ip != "0.0.0.0" and line.internal_ip in local_ips:
        return line.internal_ip
    return ""


def _user_port(user: ProxyUser) -> int:
    return user.listen_port or user.line.get_port_by_protocol(user.protocol)


def generate_cfg(session=None) -> str:
    own_session = session is None
    if own_session:
        session = get_session()
    try:
        users = session.query(ProxyUser).filter_by(status=1).all()
        lines = [
            line
            for line in session.query(Line).order_by(Line.id).all()
            if line.status == 1 and "\u4e3b\u7f51\u5361" not in (line.name or "")
        ]
        cfg = {
            "log": {
                "disabled": False,
                "level": "info",
                "output": SING_BOX_LOG,
                "timestamp": True,
            },
            "experimental": {
                "clash_api": {
                    "external_controller": "127.0.0.1:9090",
                    "secret": "",
                }
            },
            "inbounds": [],
            "outbounds": [
                {"type": "direct", "tag": "direct"},
                {"type": "block", "tag": "block"},
            ],
            "route": {"rules": []},
        }
        local_ips = _local_ipv4s()

        for line in lines:
            line_users = [u for u in users if u.line_id == line.id]
            if not line_users:
                continue
            bind_ip = _bind_ip(line, local_ips)
            listen_ip = _listen_ip(line, local_ips)
            if not bind_ip or not listen_ip:
                continue

            out_tag = _outbound_tag(line)
            cfg["outbounds"].append({
                "type": "direct",
                "tag": out_tag,
                "inet4_bind_address": bind_ip,
            })

            for user in [u for u in line_users if u.protocol == "socks5"]:
                tag = _user_inbound_tag(user)
                cfg["inbounds"].append({
                    "type": "socks",
                    "tag": tag,
                    "listen": listen_ip,
                    "listen_port": _user_port(user),
                    "users": [_auth_user(user)],
                })
                _add_route(cfg, tag, out_tag)

            for user in [u for u in line_users if u.protocol == "http"]:
                tag = _user_inbound_tag(user)
                cfg["inbounds"].append({
                    "type": "http",
                    "tag": tag,
                    "listen": listen_ip,
                    "listen_port": _user_port(user),
                    "users": [_auth_user(user)],
                })
                _add_route(cfg, tag, out_tag)

            for user in [u for u in line_users if u.protocol == "ss"]:
                tag = _user_inbound_tag(user)
                cfg["inbounds"].append({
                    "type": "shadowsocks",
                    "tag": tag,
                    "listen": listen_ip,
                    "listen_port": _user_port(user),
                    "method": user.ss_method or "aes-256-gcm",
                    "password": user.ss_password or user.password,
                })
                _add_route(cfg, tag, out_tag)

            for user in [u for u in line_users if u.protocol == "vless"]:
                tag = _user_inbound_tag(user)
                cfg["inbounds"].append({
                    "type": "vless",
                    "tag": tag,
                    "listen": listen_ip,
                    "listen_port": _user_port(user),
                    "users": [_uuid_user(user)],
                })
                _add_route(cfg, tag, out_tag)

            for user in [u for u in line_users if u.protocol == "trojan"]:
                tag = _user_inbound_tag(user)
                cfg["inbounds"].append({
                    "type": "trojan",
                    "tag": tag,
                    "listen": listen_ip,
                    "listen_port": _user_port(user),
                    "users": [_password_user(user)],
                    "tls": _tls_config(),
                })
                _add_route(cfg, tag, out_tag)

            for user in [u for u in line_users if u.protocol == "hysteria2"]:
                tag = _user_inbound_tag(user)
                cfg["inbounds"].append({
                    "type": "hysteria2",
                    "tag": tag,
                    "listen": listen_ip,
                    "listen_port": _user_port(user),
                    "users": [_password_user(user)],
                    "tls": _tls_config(),
                })
                _add_route(cfg, tag, out_tag)

        return json.dumps(cfg, ensure_ascii=False, indent=2)
    finally:
        if own_session:
            session.close()


def write_cfg(session=None) -> str:
    cfg_text = generate_cfg(session)
    os.makedirs(os.path.dirname(SING_BOX_CFG), exist_ok=True)
    with open(SING_BOX_CFG, "w", encoding="utf-8") as f:
        f.write(cfg_text)
    return SING_BOX_CFG


if __name__ == "__main__":
    print(write_cfg())
