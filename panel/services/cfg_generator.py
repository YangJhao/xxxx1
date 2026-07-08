"""sing-box config generator."""
import json
import os
import re
import socket
import subprocess
import sys
from pathlib import Path
import ipaddress

import psutil

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from config import SING_BOX_CERT, SING_BOX_CFG, SING_BOX_KEY, SING_BOX_LOG
from models import Line, ProxyUser, get_session

SING_BOX_LOG_LEVEL = os.environ.get("IPWIN42_SINGBOX_LOG_LEVEL", "warn").strip().lower() or "warn"
DNS_SERVER = (os.environ.get("IPWIN42_DNS_SERVER") or "tcp://168.126.63.1:53").strip() or "tcp://168.126.63.1:53"

LINUX_PARENT_SEGMENTS = {
    "ens2": 2,
    "enp7s0f0": 3,
    "enp7s0f1": 4,
}
STATIC_MASTER_IPS = {
    "211.230.223.67": "ens2",
    "220.82.161.1": "enp7s0f0",
    "121.154.232.7": "enp7s0f1",
}


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
    _ensure_tls_cert()
    return {
        "enabled": True,
        "server_name": "42ipwin.local",
        "certificate_path": SING_BOX_CERT,
        "key_path": SING_BOX_KEY,
    }


def _ensure_tls_cert() -> None:
    cert = Path(SING_BOX_CERT)
    key = Path(SING_BOX_KEY)
    if cert.exists() and key.exists():
        return
    cert.parent.mkdir(parents=True, exist_ok=True)
    try:
        subprocess.run(
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
            check=True,
            capture_output=True,
            text=True,
            timeout=20,
        )
        return
    except Exception:
        pass
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    from datetime import datetime, timedelta

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "42ipwin.local")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow() - timedelta(days=1))
        .not_valid_after(datetime.utcnow() + timedelta(days=3650))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("42ipwin.local")]), critical=False)
        .sign(private_key, hashes.SHA256())
    )
    key.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    cert.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))


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


def _is_public_candidate(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except Exception:
        return False
    return not (
        addr.is_loopback
        or addr.is_link_local
        or addr.is_private
        or addr.is_multicast
        or addr.is_unspecified
    )


def _iface_public_ips(iface: str, dynamic_only: bool = False) -> list[str]:
    if os.name == "nt" or not iface:
        return []
    try:
        proc = subprocess.run(["ip", "-j", "-4", "addr", "show", "dev", iface], capture_output=True, text=True, timeout=5)
        if proc.returncode != 0:
            return []
        rows = json.loads(proc.stdout or "[]")
    except Exception:
        return []
    ips = []
    for row in (rows[0].get("addr_info") if rows else []) or []:
        ip = row.get("local") or ""
        if not _is_public_candidate(ip):
            continue
        if dynamic_only and not row.get("dynamic"):
            continue
        ips.append(ip)
    return ips


def _bind_ip(line: Line, local_ips: set[str] | None = None) -> str:
    local_ips = local_ips if local_ips is not None else _local_ipv4s()
    if line.public_ip in local_ips:
        return line.public_ip
    if line.internal_ip and line.internal_ip != "0.0.0.0" and line.internal_ip in local_ips:
        return line.internal_ip
    return ""


def _current_public_ip(line: Line, local_ips: set[str] | None = None) -> str:
    local_ips = local_ips if local_ips is not None else _local_ipv4s()
    public_ip = (line.public_ip or "").strip()
    if public_ip and public_ip != "0.0.0.0" and _is_public_candidate(public_ip) and public_ip in local_ips:
        return public_ip
    iface = _line_interface(line)
    for ip in _iface_public_ips(iface, dynamic_only=True):
        if ip in local_ips:
            return ip
    return ""


def _outbound_bind_ip(line: Line, local_ips: set[str] | None = None) -> str:
    """Outbound source must be a real public address, never the fixed 10.42 listener."""
    return _current_public_ip(line, local_ips)


def _listen_ip(line: Line, local_ips: set[str] | None = None) -> str:
    if (line.note or "").strip() == "lite-auto":
        return "0.0.0.0"
    if os.name != "nt" and line.internal_ip and line.internal_ip != "0.0.0.0":
        return line.internal_ip
    local_ips = local_ips if local_ips is not None else _local_ipv4s()
    if line.public_ip in local_ips:
        return line.public_ip
    if line.internal_ip and line.internal_ip != "0.0.0.0" and line.internal_ip in local_ips:
        return line.internal_ip
    return ""


def _listen_ip_for_protocol(line: Line, proto: str, local_ips: set[str] | None = None) -> str:
    if (line.note or "").strip() == "lite-auto":
        return "0.0.0.0"
    if os.name != "nt" and (proto or "").lower() == "socks5":
        return _current_public_ip(line, local_ips)
    return _listen_ip(line, local_ips)


def _line_interface(line: Line) -> str:
    note = (line.note or "").strip()
    if not note:
        return ""
    sep = "||" if "||" in note else "|"
    iface = note.split(sep, 1)[0].strip()
    return iface.replace("-主网卡", "")


def _user_port(user: ProxyUser) -> int:
    return user.listen_port or user.line.get_port_by_protocol(user.protocol)


def _legacy_users(users: list[ProxyUser]) -> list[ProxyUser]:
    return [user for user in users if (getattr(user, "runtime_mode", "") or "") != "inbound_instance"]


def _nat_protocols(proto: str) -> list[str]:
    proto = (proto or "socks5").lower()
    if proto in {"socks5", "ss", "hysteria2"}:
        return ["tcp", "udp"]
    return ["tcp"]


def _run_iptables(args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(["iptables", *args], capture_output=True, text=True, timeout=10)


def _run_ip(args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(["ip", *args], capture_output=True, text=True, timeout=10)


def _linux_fixed_child_slot(iface: str) -> tuple[str, int]:
    if os.name == "nt":
        return "", 0
    match = re.match(r"^(.+)-(\d+)$", (iface or "").strip())
    if not match:
        return "", 0
    parent = match.group(1)
    idx = int(match.group(2))
    if parent not in LINUX_PARENT_SEGMENTS or idx < 1:
        return "", 0
    return parent, idx


def _linux_policy_table(parent: str, idx: int) -> tuple[int, int]:
    segment = LINUX_PARENT_SEGMENTS.get(parent, 9)
    return 42100 + segment * 100 + idx, 12100 + segment * 100 + idx


def _delete_source_rules(ip: str) -> None:
    for _ in range(20):
        proc = _run_ip(["rule", "del", "from", f"{ip}/32"])
        if proc.returncode != 0:
            break


def _default_gateway_for_iface(iface: str, ip: str) -> str:
    proc = _run_ip(["route", "show", "default", "dev", iface])
    for line in (proc.stdout or "").splitlines():
        words = line.split()
        if "via" in words:
            return words[words.index("via") + 1]
    proc = _run_ip(["route", "get", "1.1.1.1", "from", ip, "oif", iface])
    words = (proc.stdout or "").split()
    if "via" in words:
        return words[words.index("via") + 1]
    return ""


def _network_for_iface_ip(iface: str, ip: str) -> str:
    if os.name == "nt" or not iface or not ip:
        return ""
    try:
        proc = subprocess.run(["ip", "-j", "-4", "addr", "show", "dev", iface], capture_output=True, text=True, timeout=5)
        if proc.returncode != 0:
            return ""
        rows = json.loads(proc.stdout or "[]")
        for row in (rows[0].get("addr_info") if rows else []) or []:
            if row.get("local") == ip:
                prefix = int(row.get("prefixlen") or 0)
                if prefix:
                    return str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))
    except Exception:
        return ""
    return ""


def _ensure_linux_source_routes(session, local_ips: set[str] | None = None) -> None:
    if os.name == "nt":
        return
    ifaces = psutil.net_if_addrs()
    local_ips = local_ips if local_ips is not None else _local_ipv4s()
    for public_ip, iface in STATIC_MASTER_IPS.items():
        if public_ip not in local_ips or iface not in ifaces:
            continue
        segment = LINUX_PARENT_SEGMENTS.get(iface, 9)
        table, priority = 42100 + segment * 100 + 54, 12100 + segment * 100 + 54
        gateway = _default_gateway_for_iface(iface, public_ip)
        if not gateway:
            continue
        _run_ip(["route", "flush", "table", str(table)])
        network = _network_for_iface_ip(iface, public_ip)
        if network:
            _run_ip(["route", "replace", network, "dev", iface, "src", public_ip, "table", str(table)])
        route = _run_ip(["route", "replace", "default", "via", gateway, "dev", iface, "src", public_ip, "table", str(table)])
        if route.returncode != 0:
            _run_ip(["route", "replace", "default", "via", gateway, "dev", iface, "src", public_ip, "table", str(table), "onlink"])
        _delete_source_rules(public_ip)
        _run_ip(["rule", "add", "from", f"{public_ip}/32", "priority", str(priority), "table", str(table)])

    users = _legacy_users(session.query(ProxyUser).filter_by(status=1).all())
    line_ids = {user.line_id for user in users}
    if not line_ids:
        return
    lines = session.query(Line).filter(Line.id.in_(line_ids), Line.status == 1).all()
    for line in lines:
        iface = _line_interface(line)
        parent, idx = _linux_fixed_child_slot(iface)
        if not parent or iface not in ifaces:
            continue
        public_ip = _current_public_ip(line, local_ips)
        if not public_ip:
            continue
        gateway = _default_gateway_for_iface(iface, public_ip)
        if not gateway:
            continue
        table, priority = _linux_policy_table(parent, idx)
        _run_ip(["route", "flush", "table", str(table)])
        network = _network_for_iface_ip(iface, public_ip)
        if network:
            _run_ip(["route", "replace", network, "dev", iface, "src", public_ip, "table", str(table)])
        route = _run_ip(["route", "replace", "default", "via", gateway, "dev", iface, "src", public_ip, "table", str(table)])
        if route.returncode != 0:
            _run_ip(["route", "replace", "default", "via", gateway, "dev", iface, "src", public_ip, "table", str(table), "onlink"])
        _delete_source_rules(public_ip)
        _run_ip(["rule", "add", "from", f"{public_ip}/32", "priority", str(priority), "table", str(table)])
    _run_ip(["route", "flush", "cache"])


def _ensure_linux_listen_ips(session) -> None:
    if os.name == "nt":
        return
    ifaces = psutil.net_if_addrs()
    users = _legacy_users(session.query(ProxyUser).filter_by(status=1).all())
    line_ids = {user.line_id for user in users}
    if not line_ids:
        return
    for line in session.query(Line).filter(Line.id.in_(line_ids), Line.status == 1).all():
        iface = _line_interface(line)
        internal_ip = (line.internal_ip or "").strip()
        if not iface or iface not in ifaces:
            continue
        if not internal_ip or internal_ip == "0.0.0.0":
            continue
        _run_ip(["addr", "replace", f"{internal_ip}/32", "dev", iface])


def _ensure_nat_jump(hook: str, chain: str):
    check = _run_iptables(["-t", "nat", "-C", hook, "-j", chain])
    if check.returncode != 0:
        _run_iptables(["-t", "nat", "-I", hook, "1", "-j", chain])


def _apply_linux_nat(session) -> None:
    if os.name == "nt":
        return
    chain = "42IPWIN_DNAT"
    if _run_iptables(["-t", "nat", "-N", chain]).returncode != 0:
        _run_iptables(["-t", "nat", "-F", chain])
    _ensure_nat_jump("PREROUTING", chain)
    _ensure_nat_jump("OUTPUT", chain)

    users = _legacy_users(session.query(ProxyUser).filter_by(status=1).all())
    for user in users:
        line = user.line
        if not line or line.status != 1:
            continue
        if (user.protocol or "").lower() == "socks5" and _listen_ip_for_protocol(line, user.protocol):
            continue
        public_ip = (line.public_ip or "").strip()
        internal_ip = (line.internal_ip or "").strip()
        if not public_ip or public_ip == "0.0.0.0" or not internal_ip or internal_ip == "0.0.0.0":
            continue
        if public_ip == internal_ip:
            continue
        port = str(_user_port(user))
        for proto in _nat_protocols(user.protocol):
            _run_iptables([
                "-t", "nat", "-A", chain,
                "-d", public_ip,
                "-p", proto,
                "--dport", port,
                "-j", "DNAT",
                "--to-destination", f"{internal_ip}:{port}",
            ])


def generate_cfg(session=None) -> str:
    own_session = session is None
    if own_session:
        session = get_session()
    try:
        users = _legacy_users(session.query(ProxyUser).filter_by(status=1).all())
        lines = [
            line
            for line in session.query(Line).order_by(Line.id).all()
            if line.status == 1
        ]
        cfg = {
            "log": {
                "disabled": False,
                "level": SING_BOX_LOG_LEVEL,
                "output": SING_BOX_LOG,
                "timestamp": True,
            },
            "experimental": {
                "clash_api": {
                    "external_controller": "127.0.0.1:9090",
                    "secret": "",
                }
            },
            "dns": {"servers": [{"tag": "dns-direct", "address": DNS_SERVER}], "strategy": "ipv4_only"},
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
            if os.name == "nt" and not bind_ip:
                continue
            listen_by_proto = {
                proto: _listen_ip_for_protocol(line, proto, local_ips)
                for proto in {u.protocol for u in line_users}
            }
            if not any(listen_by_proto.values()):
                continue

            out_tag = _outbound_tag(line)
            iface = _line_interface(line)
            outbound = {
                "type": "direct",
                "tag": out_tag,
            }
            outbound_bind_ip = _outbound_bind_ip(line, local_ips)
            if os.name != "nt" and iface in psutil.net_if_addrs():
                outbound["bind_interface"] = iface
                if outbound_bind_ip:
                    outbound["inet4_bind_address"] = outbound_bind_ip
            elif outbound_bind_ip:
                outbound["inet4_bind_address"] = outbound_bind_ip
            elif os.name == "nt":
                outbound["inet4_bind_address"] = bind_ip
            cfg["outbounds"].append(outbound)

            for user in [u for u in line_users if u.protocol == "socks5"]:
                listen_ip = listen_by_proto.get(user.protocol) or ""
                if not listen_ip:
                    continue
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
                listen_ip = listen_by_proto.get(user.protocol) or ""
                if not listen_ip:
                    continue
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
                listen_ip = listen_by_proto.get(user.protocol) or ""
                if not listen_ip:
                    continue
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
                listen_ip = listen_by_proto.get(user.protocol) or ""
                if not listen_ip:
                    continue
                tag = _user_inbound_tag(user)
                cfg["inbounds"].append({
                    "type": "vless",
                    "tag": tag,
                    "listen": listen_ip,
                    "listen_port": _user_port(user),
                    "users": [_uuid_user(user)],
                })
                _add_route(cfg, tag, out_tag)

            for user in [u for u in line_users if u.protocol == "vmess"]:
                listen_ip = listen_by_proto.get(user.protocol) or ""
                if not listen_ip:
                    continue
                tag = _user_inbound_tag(user)
                cfg["inbounds"].append({
                    "type": "vmess",
                    "tag": tag,
                    "listen": listen_ip,
                    "listen_port": _user_port(user),
                    "users": [_uuid_user(user)],
                })
                _add_route(cfg, tag, out_tag)

            for user in [u for u in line_users if u.protocol == "trojan"]:
                listen_ip = listen_by_proto.get(user.protocol) or ""
                if not listen_ip:
                    continue
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
                listen_ip = listen_by_proto.get(user.protocol) or ""
                if not listen_ip:
                    continue
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

            # WireGuard is managed by the system wg-quick service, not sing-box.

        return json.dumps(cfg, ensure_ascii=False, indent=2)
    finally:
        if own_session:
            session.close()


def write_cfg(session=None) -> str:
    own_session = session is None
    if own_session:
        session = get_session()
    _ensure_linux_listen_ips(session)
    _ensure_linux_source_routes(session)
    cfg_text = generate_cfg(session)
    os.makedirs(os.path.dirname(SING_BOX_CFG), exist_ok=True)
    with open(SING_BOX_CFG, "w", encoding="utf-8") as f:
        f.write(cfg_text)
    try:
        _apply_linux_nat(session)
        try:
            from services.traffic_collector import ensure_port_counters

            ensure_port_counters(session)
        except Exception:
            pass
    finally:
        if own_session:
            session.close()
    return SING_BOX_CFG


if __name__ == "__main__":
    print(write_cfg())
