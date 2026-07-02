"""Lightweight WireGuard provisioning helpers."""
import ipaddress
import os
import re
import secrets
import shutil
import subprocess
from pathlib import Path

from config import WIREGUARD_DIR
from models import ProxyUser

WG_DIR = Path(WIREGUARD_DIR)
SYSTEM_WG_DIR = Path("/etc/wireguard")
SYSTEM_SERVER_CONF = SYSTEM_WG_DIR / "wg42.conf"
SERVER_PRIVATE_KEY = WG_DIR / "server_private.key"
SERVER_PUBLIC_KEY = WG_DIR / "server_public.key"
SERVER_CONF = WG_DIR / "wg42.conf"
SERVER_PORT = int(os.environ.get("IPWIN42_WG_PORT", "51820") or 51820)
SERVER_ADDRESS = os.environ.get("IPWIN42_WG_SERVER_ADDRESS", "10.42.42.1/24")
CLIENT_DNS = os.environ.get("IPWIN42_WG_CLIENT_DNS", "1.1.1.1,8.8.8.8")
DEFAULT_ALLOWED_IPS = os.environ.get("IPWIN42_WG_ALLOWED_IPS", "0.0.0.0/0, ::/0")
REDIRECT_CHAIN = "IPWIN42_WG_PORTS"


def available() -> bool:
    return bool(shutil.which("wg") and shutil.which("wg-quick"))


def _run(cmd: list[str], input_text: str | None = None) -> str:
    proc = subprocess.run(cmd, input=input_text, capture_output=True, text=True, timeout=20)
    if proc.returncode != 0:
        raise RuntimeError((proc.stderr or proc.stdout or "command failed").strip())
    return (proc.stdout or "").strip()


def _genkey() -> tuple[str, str]:
    private = _run(["wg", "genkey"])
    public = _run(["wg", "pubkey"], input_text=private + "\n")
    return private, public


def _server_network() -> ipaddress.IPv4Network:
    return ipaddress.ip_network(SERVER_ADDRESS, strict=False)


def ensure_server_keys() -> tuple[str, str]:
    WG_DIR.mkdir(parents=True, exist_ok=True)
    if SERVER_PRIVATE_KEY.exists() and SERVER_PUBLIC_KEY.exists():
        return SERVER_PRIVATE_KEY.read_text(encoding="utf-8").strip(), SERVER_PUBLIC_KEY.read_text(encoding="utf-8").strip()
    private, public = _genkey()
    SERVER_PRIVATE_KEY.write_text(private + "\n", encoding="utf-8")
    SERVER_PUBLIC_KEY.write_text(public + "\n", encoding="utf-8")
    try:
        os.chmod(SERVER_PRIVATE_KEY, 0o600)
    except Exception:
        pass
    return private, public


def next_client_address(session) -> str:
    network = _server_network()
    used = set()
    for user in session.query(ProxyUser).filter(ProxyUser.protocol == "wireguard").all():
        note = user.note or ""
        match = re.search(r"wg_ip=([0-9.]+)", note)
        if match:
            used.add(match.group(1))
    for host in network.hosts():
        text = str(host)
        if text.endswith(".1"):
            continue
        if text not in used:
            return f"{text}/32"
    raise ValueError("WireGuard 地址池已用完")


def client_conf(user: ProxyUser) -> str:
    note = user.note or ""
    private = re.search(r"wg_private=([A-Za-z0-9+/=]+)", note)
    server_public = re.search(r"wg_server_public=([A-Za-z0-9+/=]+)", note)
    client_ip = re.search(r"wg_ip=([0-9./]+)", note)
    endpoint = re.search(r"^wg_endpoint=([^\r\n]+)", note, re.MULTILINE)
    if not (private and server_public and client_ip and endpoint):
        raise ValueError("该节点没有 WireGuard 配置信息")
    return "\n".join([
        "[Interface]",
        f"PrivateKey = {private.group(1)}",
        f"Address = {client_ip.group(1)}",
        f"DNS = {CLIENT_DNS}",
        "",
        "[Peer]",
        f"PublicKey = {server_public.group(1)}",
        f"Endpoint = {endpoint.group(1)}",
        f"AllowedIPs = {DEFAULT_ALLOWED_IPS}",
        "PersistentKeepalive = 25",
        "",
    ])


def _peer_block(user: ProxyUser) -> str:
    note = user.note or ""
    public = re.search(r"wg_public=([A-Za-z0-9+/=]+)", note)
    client_ip = re.search(r"wg_ip=([0-9.]+)/32", note)
    if not public or not client_ip:
        return ""
    return "\n".join([
        "[Peer]",
        f"# {user.username} {user.owner_name or ''} {user.project_name or ''}".strip(),
        f"PublicKey = {public.group(1)}",
        f"AllowedIPs = {client_ip.group(1)}/32",
        "",
    ])


def _note_value(note: str, key: str) -> str:
    match = re.search(rf"^{re.escape(key)}=([^\r\n]+)", note or "", re.MULTILINE)
    return match.group(1).strip() if match else ""


def transfer_snapshot(session) -> dict[int, tuple[int, int]]:
    """Return WireGuard peer cumulative transfer counters by ProxyUser id."""
    if not available():
        return {}
    try:
        raw = _run(["wg", "show", str(SERVER_CONF.with_suffix("").name), "transfer"])
    except Exception:
        return {}
    by_public = {}
    for line in raw.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        try:
            by_public[parts[0]] = (int(parts[1]), int(parts[2]))
        except ValueError:
            continue
    if not by_public:
        return {}
    result = {}
    users = session.query(ProxyUser).filter(ProxyUser.protocol == "wireguard").all()
    for user in users:
        public = _note_value(user.note or "", "wg_public")
        if public in by_public:
            result[user.id] = by_public[public]
    return result


def write_server_conf(session) -> str:
    private, _public = ensure_server_keys()
    network = _server_network()
    nat_iface = os.environ.get("IPWIN42_WG_NAT_IFACE", "").strip()
    if not nat_iface and os.name != "nt":
        try:
            proc = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True, timeout=5)
            words = (proc.stdout or "").split()
            if "dev" in words:
                nat_iface = words[words.index("dev") + 1]
        except Exception:
            nat_iface = ""
    nat_iface = nat_iface or "eth0"
    nat_rule = f"POSTROUTING -s {network.with_prefixlen} -o {nat_iface} -j MASQUERADE"
    peers = []
    users = (
        session.query(ProxyUser)
        .filter(ProxyUser.protocol == "wireguard", ProxyUser.status == 1)
        .order_by(ProxyUser.id)
        .all()
    )
    for user in users:
        block = _peer_block(user)
        if block:
            peers.append(block)
    text = "\n".join([
        "[Interface]",
        f"Address = {SERVER_ADDRESS}",
        f"ListenPort = {SERVER_PORT}",
        f"PrivateKey = {private}",
        "SaveConfig = false",
        f"PostUp = sysctl -w net.ipv4.ip_forward=1; iptables -t nat -C {nat_rule} || iptables -t nat -A {nat_rule}",
        f"PostDown = iptables -t nat -D {nat_rule} || true",
        "",
        *peers,
    ])
    WG_DIR.mkdir(parents=True, exist_ok=True)
    SERVER_CONF.write_text(text, encoding="utf-8")
    if os.name != "nt":
        SYSTEM_WG_DIR.mkdir(parents=True, exist_ok=True)
        SYSTEM_SERVER_CONF.write_text(text, encoding="utf-8")
    try:
        os.chmod(SERVER_CONF, 0o600)
        if os.name != "nt":
            os.chmod(SYSTEM_SERVER_CONF, 0o600)
    except Exception:
        pass
    return str(SYSTEM_SERVER_CONF if os.name != "nt" else SERVER_CONF)


def _wireguard_ports(session) -> list[int]:
    ports = {SERVER_PORT}
    users = (
        session.query(ProxyUser)
        .filter(ProxyUser.protocol == "wireguard", ProxyUser.status == 1)
        .all()
    )
    for user in users:
        try:
            port = int(user.listen_port or SERVER_PORT)
        except Exception:
            continue
        if 1 <= port <= 65535:
            ports.add(port)
    return sorted(ports)


def _ensure_rule(cmd: list[str], add_cmd: list[str]) -> None:
    check = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    if check.returncode != 0:
        subprocess.run(add_cmd, capture_output=True, text=True, timeout=10)


def sync_port_redirects(session) -> dict:
    if os.name == "nt" or not shutil.which("iptables"):
        return {"ok": True, "skipped": True, "message": "iptables not available"}
    ports = _wireguard_ports(session)
    subprocess.run(["iptables", "-t", "nat", "-N", REDIRECT_CHAIN], capture_output=True, text=True, timeout=10)
    subprocess.run(["iptables", "-t", "nat", "-F", REDIRECT_CHAIN], capture_output=True, text=True, timeout=10)
    _ensure_rule(
        ["iptables", "-t", "nat", "-C", "PREROUTING", "-p", "udp", "-j", REDIRECT_CHAIN],
        ["iptables", "-t", "nat", "-A", "PREROUTING", "-p", "udp", "-j", REDIRECT_CHAIN],
    )
    _ensure_rule(
        ["iptables", "-t", "nat", "-C", "OUTPUT", "-p", "udp", "-j", REDIRECT_CHAIN],
        ["iptables", "-t", "nat", "-A", "OUTPUT", "-p", "udp", "-j", REDIRECT_CHAIN],
    )
    for port in ports:
        if port == SERVER_PORT:
            continue
        subprocess.run(
            [
                "iptables",
                "-t",
                "nat",
                "-A",
                REDIRECT_CHAIN,
                "-p",
                "udp",
                "--dport",
                str(port),
                "-j",
                "REDIRECT",
                "--to-ports",
                str(SERVER_PORT),
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
    return {"ok": True, "ports": ports, "server_port": SERVER_PORT}


def reload_service(session) -> dict:
    path = write_server_conf(session)
    if not available():
        return {"ok": False, "config": path, "message": "WireGuard tools not installed: install wireguard-tools first"}
    unit = str(SERVER_CONF.with_suffix("").name)
    subprocess.run(["systemctl", "enable", f"wg-quick@{unit}"], capture_output=True, text=True, timeout=20)
    proc = subprocess.run(["systemctl", "restart", f"wg-quick@{unit}"], capture_output=True, text=True, timeout=30)
    redirect = sync_port_redirects(session) if proc.returncode == 0 else {}
    return {
        "ok": proc.returncode == 0,
        "applied": proc.returncode == 0,
        "restarted": True,
        "config": path,
        "unit": f"wg-quick@{unit}",
        "redirect": redirect,
        "message": (proc.stderr or proc.stdout or "WireGuard 已自动应用").strip(),
    }


def create_client_material(session, user: ProxyUser, endpoint_ip: str) -> dict:
    server_private, server_public = ensure_server_keys()
    private, public = _genkey()
    address = next_client_address(session)
    listen_port = int(user.listen_port or SERVER_PORT)
    endpoint = f"{endpoint_ip}:{listen_port}"
    token = secrets.token_hex(4)
    meta = [
        f"wg_ip={address}",
        f"wg_private={private}",
        f"wg_public={public}",
        f"wg_server_public={server_public}",
        f"wg_endpoint={endpoint}",
        f"wg_token={token}",
    ]
    user.password = public
    user.listen_port = listen_port
    user.note = "\n".join([line for line in (user.note or "").splitlines() if not line.startswith("wg_")] + meta).strip()
    return {"client_ip": address, "public_key": public, "endpoint": endpoint, "server_public_key": server_public}
