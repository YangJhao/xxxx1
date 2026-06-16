"""sing-box config generator."""
import json
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from config import SING_BOX_CERT, SING_BOX_CFG, SING_BOX_KEY, SING_BOX_LOG
from models import Line, ProxyUser, get_session


def parse_size_to_bytes(value) -> int | None:
    if not value:
        return None
    text = str(value).strip().lower().replace(" ", "")
    m = re.match(r"^(\d+(?:\.\d+)?)(b|kb|mb|gb|tb|kib|mib|gib|tib)?$", text)
    if not m:
        return None
    number = float(m.group(1))
    unit = m.group(2) or "gb"
    mult = {
        "b": 1,
        "kb": 1000,
        "mb": 1000**2,
        "gb": 1000**3,
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


def _listen_ip(line: Line) -> str:
    # Bind the inbound to the current client-facing IP for this line. This prevents the same
    # port/auth from being accepted through other public IPs. Line sync rewrites this when IPs move.
    return line.public_ip


def _user_port(user: ProxyUser) -> int:
    return user.listen_port or user.line.get_port_by_protocol(user.protocol)


def generate_cfg(session=None) -> str:
    own_session = session is None
    if own_session:
        session = get_session()
    try:
        lines = session.query(Line).filter_by(status=1).order_by(Line.id).all()
        users = session.query(ProxyUser).filter_by(status=1).all()
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

        for line in lines:
            line_users = [u for u in users if u.line_id == line.id]
            if not line_users:
                continue

            out_tag = _outbound_tag(line)
            cfg["outbounds"].append({
                "type": "direct",
                "tag": out_tag,
                "inet4_bind_address": line.public_ip,
            })

            for user in [u for u in line_users if u.protocol == "socks5"]:
                tag = _user_inbound_tag(user)
                cfg["inbounds"].append({
                    "type": "socks",
                    "tag": tag,
                    "listen": _listen_ip(line),
                    "listen_port": _user_port(user),
                    "users": [_auth_user(user)],
                })
                _add_route(cfg, tag, out_tag)

            for user in [u for u in line_users if u.protocol == "http"]:
                tag = _user_inbound_tag(user)
                cfg["inbounds"].append({
                    "type": "http",
                    "tag": tag,
                    "listen": _listen_ip(line),
                    "listen_port": _user_port(user),
                    "users": [_auth_user(user)],
                })
                _add_route(cfg, tag, out_tag)

            for user in [u for u in line_users if u.protocol == "ss"]:
                tag = _user_inbound_tag(user)
                cfg["inbounds"].append({
                    "type": "shadowsocks",
                    "tag": tag,
                    "listen": _listen_ip(line),
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
                    "listen": _listen_ip(line),
                    "listen_port": _user_port(user),
                    "users": [_uuid_user(user)],
                })
                _add_route(cfg, tag, out_tag)

            for user in [u for u in line_users if u.protocol == "trojan"]:
                tag = _user_inbound_tag(user)
                cfg["inbounds"].append({
                    "type": "trojan",
                    "tag": tag,
                    "listen": _listen_ip(line),
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
                    "listen": _listen_ip(line),
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
