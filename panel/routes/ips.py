"""Line/IP management routes."""
from datetime import datetime
import ipaddress
import json
import os
import random
import re
import shutil
import socket
import subprocess
import time
from pathlib import Path

import psutil
from flask import Blueprint, jsonify, request
from sqlalchemy.orm import selectinload

from config import DATA_DIR, is_single_ip_mode
from models import Line, get_session
from routes.auth import login_required
from services import proxy_manager
from services.cfg_generator import write_cfg
from services.system_info import get_public_ip
from services.traffic_collector import snapshot_connections

bp = Blueprint("ips", __name__, url_prefix="/api/lines")

IP_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
LAST_IO = {}
DETECT_CACHE = {"time": 0.0, "data": None}
WINDOWS_SWITCH_CACHE = {"time": 0.0, "data": None}
MASTER_OPTIONS_CACHE = {"time": 0.0, "data": None}
STATIC_MASTER_IPS = {
    "211.230.223.67": "ens2",
    "220.82.161.61": "enp7s0f0",
    "121.154.232.7": "enp7s0f1",
}
STATIC_MASTER_NAMES = set(STATIC_MASTER_IPS.values())
MASTER_LABEL = "\u4e3b\u7f51\u5361"
MAC_CHILDREN_PER_PARENT = 13
LINUX_PARENT_SEGMENTS = {
    "ens2": 2,
    "enp7s0f0": 3,
    "enp7s0f1": 4,
}
MACVLAN_STATE_FILE = Path(DATA_DIR) / "macvlan_current.json"
HOST_MACVLAN_STATE_FILE = Path(DATA_DIR) / "macvlan_current_211.230.223.67.json"
NOTE_SEP = "||"
ETHERNET_4_LABEL = "\u4ee5\u592a\u7f51 4"
ETHERNET_5_LABEL = "\u4ee5\u592a\u7f51 5"


def _single_ip_public_ip() -> str:
    for key in ("IPWIN42_PUBLIC_IP", "PUBLIC_IP", "SERVER_PUBLIC_IP"):
        value = (os.environ.get(key) or "").strip()
        if value:
            return value
    try:
        data = get_public_ip() or {}
        value = (data.get("ip") or "").strip()
        if value:
            return value
    except Exception:
        pass
    return ""


def _ensure_single_ip_line(session) -> Line:
    public_ip = _single_ip_public_ip()
    if not public_ip:
        line = session.query(Line).order_by(Line.id).first()
        if line:
            return line
        raise ValueError("无法自动获取本机公网 IP，请设置 IPWIN42_PUBLIC_IP")
    line = session.query(Line).filter(Line.public_ip == public_ip).first()
    if line:
        line.name = line.name or "本机公网IP"
        line.status = 1
        return line
    used_ports = {int(row[0]) for row in session.query(Line.socks_port).all() if row[0]}
    socks_port = 10801
    while socks_port in used_ports:
        socks_port += 1
    line = Line(
        name="本机公网IP",
        public_ip=public_ip,
        internal_ip="0.0.0.0",
        socks_port=socks_port,
        http_port=socks_port + 10,
        ss_port=socks_port + 20,
        status=1,
        note="single-ip-auto",
    )
    session.add(line)
    session.flush()
    return line


def _line_note(interface: str, **meta) -> str:
    parts = [interface or ""]
    for key, value in meta.items():
        if value not in (None, ""):
            parts.append(f"{key}={value}")
    return NOTE_SEP.join(parts)


def _note_parts(note: str) -> list[str]:
    if not note:
        return [""]
    sep = NOTE_SEP if NOTE_SEP in note else "|"
    return note.split(sep)


def _note_interface(note: str) -> str:
    return _note_parts(note)[0].strip()


def _note_meta(note: str) -> dict:
    meta = {}
    for part in _note_parts(note)[1:]:
        if "=" in part:
            key, value = part.split("=", 1)
            meta[key.strip()] = value.strip()
    return meta


def _windows_short_master_name(interface_name: str) -> str:
    if os.name != "nt":
        return ""
    raw = (interface_name or "").strip()
    match = re.match(r"^vEthernet \((WAN-.+-External)\)$", raw)
    switch_name = match.group(1) if match else raw
    mapping = {
        "WAN-59-External": f"{ETHERNET_4_LABEL}-{MASTER_LABEL}",
        "WAN-Ethernet5-External": f"{ETHERNET_5_LABEL}-{MASTER_LABEL}",
        "WAN-Slot01-x8-External": f"Slot01 x8-{MASTER_LABEL}",
    }
    return mapping.get(switch_name, "")


def _valid_ip(value: str) -> bool:
    if not value or not IP_RE.match(value):
        return False
    return all(0 <= int(part) <= 255 for part in value.split("."))


def _is_public_candidate(ip: str) -> bool:
    if not _valid_ip(ip):
        return False
    if ip.startswith(("127.", "169.254.", "10.", "192.168.")):
        return False
    if ip.startswith("172."):
        second = int(ip.split(".")[1])
        if 16 <= second <= 31:
            return False
    return True


def _format_line_name(interface_name: str) -> str:
    text = interface_name or ""
    m = re.search(r"vEthernet \((.+)-(\d{3})\)", text, re.I)
    if m:
        if m.group(1).lower() == "wan-auto":
            return f"vEthernet-{m.group(2)}"
        return f"{m.group(1)}-{m.group(2)}"
    m = re.search(r"^(.+)-(\d{3})$", text)
    if m and m.group(1).lower() != "wan-auto":
        return f"{m.group(1)}-{m.group(2)}"
    m = re.search(r"以太网\s*([567])-(\d{1,3})", text)
    if m:
        return f"以太网 {m.group(1)}-{int(m.group(2)):03d}"
    m = re.search(r"WAN([567])-MAC(\d{1,2})", text, re.I)
    if m:
        return f"以太网 {m.group(1)}-{int(m.group(2)):03d}"
    m = re.search(r"WAN([567])-SW", text, re.I)
    if m:
        return f"以太网 {m.group(1)}-主网卡"
    m = re.search(r"以太网\s*([567])$", text)
    if m:
        return f"以太网 {m.group(1)}-主网卡"
    return text or "未知网卡"


def _parent_adapter(interface_name: str) -> str:
    raw = interface_name or ""
    if os.name == "nt":
        if "WAN-AUTO-" in raw or re.match(r"^vEthernet-\d{3}$", raw):
            return "以太网 4"
        if "Slot01 x8" in raw:
            return "Slot01 x8"
        if "以太网 5" in raw:
            return "以太网 5"
    display = _format_line_name(interface_name)
    m = re.match(r"^(.+)-(\d{3})$", display)
    if m:
        return m.group(1)
    m = re.search(r"以太网\s*([567])", display)
    if m:
        return f"以太网 {m.group(1)}"
    return ""


def _is_master_interface(interface_name: str) -> bool:
    text = interface_name or ""
    return bool(
        text in STATIC_MASTER_NAMES
        or
        re.search(r"WAN[567]-SW", text, re.I)
        or re.search(r"以太网\s*[567]$", text)
        or text.endswith("-主网卡")
    )


def _adapter_index(interface_name: str) -> int:
    text = _format_line_name(interface_name or "")
    m = re.search(r"-(\d{3})$", text)
    if m:
        return int(m.group(1))
    m = re.search(r"MAC(\d{1,2})", interface_name or "", re.I)
    if m:
        return int(m.group(1))
    return 0


def _generated_internal_ip(interface_name: str) -> str:
    display = _format_line_name(interface_name)
    parent = _parent_key(interface_name)
    if parent:
        segment = _parent_segment(parent)
        idx = _adapter_index(interface_name)
        return f"10.42.{segment}.{idx or 254}"
    if os.name == "nt" and re.match(r"^vEthernet-(\d{3})$", display):
        return f"10.42.4.{int(display.rsplit('-', 1)[1])}"
    if os.name == "nt" and re.match(r"^Slot01 x8-(\d{3})$", display):
        return f"10.42.8.{int(display.rsplit('-', 1)[1])}"
    m = re.search(r"以太网\s*([567])-(\d{3})", display)
    if m:
        return f"10.42.{m.group(1)}.{int(m.group(2))}"
    m = re.search(r"以太网\s*([567])-主网卡", display)
    if m:
        return f"10.42.{m.group(1)}.254"
    return "0.0.0.0"


def _is_generated_child_interface(interface_name: str) -> bool:
    text = interface_name or ""
    return bool(
        re.search(r"-\d{3}$", text)
        or text.startswith(("dummy42-", "v42", "macv42-"))
    )


def _linux_fixed_child_slot(interface_name: str) -> tuple[str, int]:
    if os.name == "nt":
        return "", 0
    match = re.match(r"^(.+)-(\d{3})$", (interface_name or "").strip())
    if not match:
        return "", 0
    parent = match.group(1)
    idx = int(match.group(2))
    if parent not in LINUX_PARENT_SEGMENTS:
        return "", 0
    if idx < 1 or idx > MAC_CHILDREN_PER_PARENT:
        return "", 0
    return parent, idx


def _is_linux_fixed_child_interface(interface_name: str) -> bool:
    parent, idx = _linux_fixed_child_slot(interface_name)
    return bool(parent and idx)


def _is_linux_managed_interface(interface_name: str) -> bool:
    if os.name == "nt":
        return True
    iface = (interface_name or "").replace(f"-{MASTER_LABEL}", "").strip()
    return iface in LINUX_PARENT_SEGMENTS or _is_linux_fixed_child_interface(iface)


def _parent_key(interface_name: str) -> str:
    text = (interface_name or "").strip()
    if not text:
        return ""
    text = text.replace(f"-{MASTER_LABEL}", "")
    match = re.match(r"^(.+)-(\d{3})$", text)
    if match:
        return match.group(1)
    return text


def _parent_segment(parent: str) -> int:
    parent = _parent_key(parent)
    if parent in LINUX_PARENT_SEGMENTS:
        return LINUX_PARENT_SEGMENTS[parent]
    known = sorted(set(LINUX_PARENT_SEGMENTS) | {name for name in psutil.net_if_addrs() if name != "lo" and not _is_generated_child_interface(name)})
    if parent in known:
        return 2 + known.index(parent)
    return 9


def _generated_internal_ip_for_line(line, fallback: str = "") -> str:
    iface = (_note_interface(line.note) or fallback or line.name or "").strip()
    parent = _parent_key(iface)
    if parent:
        segment = _parent_segment(parent)
        idx = _adapter_index(iface)
        return f"10.42.{segment}.{idx or 254}"
    return _generated_internal_ip(fallback or line.name or "")


def _generated_internal_ip_for_interface(interface_name: str, fallback_name: str = "") -> str:
    class LineLike:
        note = interface_name
        name = fallback_name

    return _generated_internal_ip_for_line(LineLike(), fallback_name)


def _has_master_label(text: str) -> bool:
    return MASTER_LABEL in (text or "")


def _is_linux_real_master_line(line, iface: str = "") -> bool:
    if os.name == "nt":
        return False
    note = (_note_interface(line.note) or iface or "").strip()
    name = (line.name or "").strip()
    if _is_generated_child_interface(note):
        return False
    if line.public_ip in STATIC_MASTER_IPS:
        return True
    if _has_master_label(name) or _has_master_label(note):
        return True
    if note and note in psutil.net_if_addrs() and not _is_generated_child_interface(note):
        return True
    return False


def _hyperv_adapter_name(interface_name: str) -> str:
    text = interface_name or ""
    m = re.search(r"以太网\s*([567])-(\d{1,3})", text)
    if m:
        return f"WAN{m.group(1)}-MAC{int(m.group(2)):02d}"
    m = re.search(r"WAN([567])-MAC(\d{1,2})", text, re.I)
    if m:
        return f"WAN{m.group(1)}-MAC{int(m.group(2)):02d}"
    return ""


def _iface_snapshot() -> dict:
    stats = psutil.net_if_stats()
    addrs = psutil.net_if_addrs()
    io = psutil.net_io_counters(pernic=True)
    default_ifaces = set(_linux_default_interfaces()) if os.name != "nt" else set()
    now = time.time()
    snapshot = {}
    for iface, rows in addrs.items():
        is_master = _is_master_interface(iface) or (iface in default_ifaces and not _is_generated_child_interface(iface))
        item = {
            "interface": iface,
            "display_name": _format_line_name(iface),
            "parent_adapter": _parent_adapter(iface),
            "adapter_index": _adapter_index(iface),
            "is_master": is_master,
            "mac": "",
            "ipv4": [],
            "internal_ip": "",
            "is_up": bool(stats.get(iface).isup) if iface in stats else None,
            "speed_mbps": stats.get(iface).speed if iface in stats else None,
            "rx_bps": 0,
            "tx_bps": 0,
            "bytes_in": 0,
            "bytes_out": 0,
        }
        for addr in rows:
            if addr.family == socket.AF_INET:
                item["ipv4"].append(addr.address)
                if not _is_public_candidate(addr.address) and not item["internal_ip"]:
                    item["internal_ip"] = addr.address
            elif getattr(psutil, "AF_LINK", object()) == addr.family:
                item["mac"] = addr.address
        if os.name != "nt" and _is_linux_managed_interface(iface):
            item["internal_ip"] = _generated_internal_ip_for_interface(iface)
        if iface in io:
            counters = io[iface]
            item["bytes_in"] = counters.bytes_recv
            item["bytes_out"] = counters.bytes_sent
            prev = LAST_IO.get(iface)
            if prev:
                dt = max(now - prev["time"], 0.001)
                item["rx_bps"] = max(0, int((counters.bytes_recv - prev["bytes_in"]) / dt))
                item["tx_bps"] = max(0, int((counters.bytes_sent - prev["bytes_out"]) / dt))
            LAST_IO[iface] = {"time": now, "bytes_in": counters.bytes_recv, "bytes_out": counters.bytes_sent}
        snapshot[iface] = item
    return snapshot


def _add_detected(results: list, seen: set, iface_info: dict, ip: str, **extra):
    iface = iface_info.get("interface", "")
    if not ip or ip == "127.0.0.1" or (iface, ip) in seen:
        return
    forced_master_iface = STATIC_MASTER_IPS.get(ip)
    is_forced_master = bool(forced_master_iface)
    if is_forced_master:
        iface = forced_master_iface
    is_master = True if is_forced_master else iface_info.get("is_master", _is_master_interface(iface))
    display_name = f"{forced_master_iface}-主网卡" if is_forced_master else iface_info.get("display_name") or _format_line_name(iface)
    if is_master and "主网卡" not in display_name:
        display_name = f"{display_name}-主网卡"
    seen.add((iface, ip))
    item = {
        "interface": iface,
        "display_name": display_name,
        "parent_adapter": forced_master_iface if is_forced_master else iface_info.get("parent_adapter") or _parent_adapter(iface),
        "adapter_index": 0 if is_forced_master else iface_info.get("adapter_index") or _adapter_index(iface),
        "is_master": is_master,
        "locked": is_master,
        "ip": ip,
        "mac": iface_info.get("mac", ""),
        "internal_ip": iface_info.get("internal_ip", ""),
        "is_up": iface_info.get("is_up"),
        "speed_mbps": iface_info.get("speed_mbps"),
        "rx_bps": iface_info.get("rx_bps", 0),
        "tx_bps": iface_info.get("tx_bps", 0),
        "bytes_in": iface_info.get("bytes_in", 0),
        "bytes_out": iface_info.get("bytes_out", 0),
    }
    item.update({k: v for k, v in extra.items() if v not in (None, "")})
    results.append(item)


def _first_default_iface_info() -> dict:
    ifaces = _iface_snapshot()
    for name in _linux_default_interfaces():
        info = ifaces.get(name)
        if info and info.get("ipv4"):
            return info
    for name, info in ifaces.items():
        if name != "lo" and info.get("ipv4"):
            return info
    return {}


def _fetch_public_ip_for_source(source_ip: str) -> str:
    if not source_ip or os.name == "nt" or not shutil.which("curl"):
        return ""
    for url in ("https://api.ipify.org", "http://ifconfig.me/ip"):
        try:
            proc = subprocess.run(
                ["curl", "-s", "--interface", source_ip, "--max-time", "8", url],
                capture_output=True,
                text=True,
                timeout=10,
            )
            ip = (proc.stdout or "").strip()
            if proc.returncode == 0 and _is_public_candidate(ip):
                return ip
        except Exception:
            pass
    return ""


def _add_source_nat_public_ips(results: list, seen: set):
    if os.name == "nt":
        return
    ifaces = _iface_snapshot()
    existing_public = {item.get("ip") for item in results if _is_public_candidate(item.get("ip", ""))}
    for iface_info in ifaces.values():
        if iface_info.get("interface") == "lo":
            continue
        private_ips = [
            ip for ip in iface_info.get("ipv4", [])
            if not _is_public_candidate(ip) and ip != "127.0.0.1" and not ip.startswith("169.254.")
        ]
        for private_ip in private_ips:
            public_ip = _fetch_public_ip_for_source(private_ip)
            if not public_ip or public_ip in existing_public:
                continue
            label = iface_info.get("display_name") or iface_info.get("interface") or "榛樿缃戝崱"
            nat_iface = dict(iface_info)
            nat_iface["internal_ip"] = private_ip
            _add_detected(
                results,
                seen,
                nat_iface,
                public_ip,
                display_name=f"{label}-{private_ip}-NAT鍏綉",
                parent_adapter=label,
                nat_public=True,
            )
            existing_public.add(public_ip)


def _add_cloud_nat_public_ip(results: list, seen: set):
    # Cloud NAT/EIP public addresses usually do not appear on the NIC itself.
    public_ip = (get_public_ip() or {}).get("ip")
    if any(item.get("ip") == public_ip for item in results):
        return
    if not _is_public_candidate(public_ip):
        return
    iface_info = _first_default_iface_info()
    if not iface_info:
        return
    label = iface_info.get("display_name") or iface_info.get("interface") or "榛樿缃戝崱"
    _add_detected(
        results,
        seen,
        iface_info,
        public_ip,
        display_name=f"{label}-NAT鍏綉",
        parent_adapter=label,
        nat_public=True,
    )


def _detect_local_ips(force: bool = False) -> list:
    now = time.time()
    if not force and DETECT_CACHE["data"] is not None and now - DETECT_CACHE["time"] < 5:
        return DETECT_CACHE["data"]

    results = []
    seen = set()
    ifaces = _iface_snapshot()
    for iface_info in ifaces.values():
        for ip in iface_info["ipv4"]:
            _add_detected(results, seen, iface_info, ip)

    if os.name == "nt":
        try:
            cmd = (
                "Get-NetIPAddress -AddressFamily IPv4 | "
                "Where-Object {$_.IPAddress -ne '127.0.0.1'} | "
                "Select-Object InterfaceAlias,IPAddress,PrefixLength,AddressState | "
                "ConvertTo-Json -Compress"
            )
            out = subprocess.run(["powershell", "-NoProfile", "-Command", cmd], capture_output=True, text=True, timeout=15)
            if out.returncode == 0 and out.stdout.strip():
                rows = json.loads(out.stdout)
                if isinstance(rows, dict):
                    rows = [rows]
                for row in rows:
                    iface = row.get("InterfaceAlias") or ""
                    iface_info = ifaces.get(iface, {"interface": iface})
                    _add_detected(
                        results,
                        seen,
                        iface_info,
                        row.get("IPAddress") or "",
                        prefix=row.get("PrefixLength"),
                        state=row.get("AddressState"),
                    )
        except Exception as exc:
            print(f"[detect_ips powershell] {exc}")
    if os.name != "nt":
        _add_source_nat_public_ips(results, seen)
        _add_cloud_nat_public_ip(results, seen)
    DETECT_CACHE["time"] = now
    DETECT_CACHE["data"] = results
    return results


def _next_available_port(session, base: int, used: set[int]) -> int:
    port = base
    while port in used or session.query(Line).filter(
        (Line.socks_port == port) | (Line.http_port == port) | (Line.ss_port == port)
    ).first():
        port += 1
    used.add(port)
    return port


def _reload_after_change(session=None):
    write_cfg(session)
    if proxy_manager.get_status()["running"]:
        proxy_manager.reload_config()


def _run_cmd(args: list[str], timeout: int = 20) -> tuple[bool, str]:
    proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    out = (proc.stdout or "") + (proc.stderr or "")
    return proc.returncode == 0, out.strip()


def _run_json(args: list[str], timeout: int = 15):
    proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if proc.returncode != 0 or not (proc.stdout or "").strip():
        return None
    return json.loads(proc.stdout)


def _linux_ipv4_rows(iface: str) -> list[dict]:
    if os.name == "nt" or not iface:
        return []
    try:
        data = _run_json(["ip", "-j", "-4", "addr", "show", "dev", iface])
    except Exception:
        return []
    if not data:
        return []
    return data[0].get("addr_info") or []


def _linux_public_addr_info(iface: str) -> dict:
    for row in _linux_ipv4_rows(iface):
        ip = row.get("local") or ""
        if _is_public_candidate(ip):
            return {
                "ip": ip,
                "prefix": int(row.get("prefixlen") or 0) or "",
            }
    return {}


def _linux_route_info(iface: str, ip: str, prefix) -> dict:
    if os.name == "nt" or not iface or not ip or not prefix:
        return {"router": "", "network": ""}
    router = ""
    try:
        proc = subprocess.run(
            ["ip", "route", "get", "1.1.1.1", "from", ip, "oif", iface],
            capture_output=True,
            text=True,
            timeout=5,
        )
        words = (proc.stdout or "").split()
        if "via" in words:
            router = words[words.index("via") + 1]
    except Exception:
        router = ""
    try:
        network = str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))
    except Exception:
        network = ""
    return {"router": router, "network": network}


def _linux_managed_internal_ip(iface: str) -> str:
    if os.name == "nt" or not _is_linux_managed_interface(iface):
        return ""
    return _generated_internal_ip_for_interface(iface)


def _ensure_linux_internal_ips() -> dict:
    if os.name == "nt":
        return {"ok": True, "skipped": True}
    applied = []
    errors = []
    for parent in LINUX_PARENT_SEGMENTS:
        targets = [parent] + [_fixed_child_interface_name(parent, idx) for idx in range(1, MAC_CHILDREN_PER_PARENT + 1)]
        for iface in targets:
            if iface not in psutil.net_if_addrs():
                continue
            internal_ip = _linux_managed_internal_ip(iface)
            if not internal_ip or internal_ip == "0.0.0.0":
                continue
            ok, output = _run_cmd(["ip", "addr", "replace", f"{internal_ip}/32", "dev", iface], timeout=10)
            if ok:
                applied.append({"iface": iface, "internal_ip": internal_ip})
            else:
                errors.append({"iface": iface, "error": output})
    DETECT_CACHE["data"] = None
    return {"ok": not errors, "applied_count": len(applied), "errors": errors}


def _linux_policy_table(parent: str, idx: int) -> tuple[int, int]:
    segment = _parent_segment(parent)
    return 42100 + segment * 100 + idx, 12100 + segment * 100 + idx


def _persist_linux_macvlan_state() -> dict:
    if os.name == "nt":
        return {"ok": True, "skipped": True}
    ifaces = _iface_snapshot()
    rows = []
    for parent in LINUX_PARENT_SEGMENTS:
        for idx in range(1, MAC_CHILDREN_PER_PARENT + 1):
            iface = _fixed_child_interface_name(parent, idx)
            info = ifaces.get(iface, {})
            addr = _linux_public_addr_info(iface)
            ip = addr.get("ip") or ""
            prefix = addr.get("prefix") or ""
            route = _linux_route_info(iface, ip, prefix)
            table, priority = _linux_policy_table(parent, idx)
            internal_ip = _linux_managed_internal_ip(iface)
            rows.append({
                "parent": parent,
                "idx": idx,
                "iface": iface,
                "mac": (info.get("mac") or "").lower(),
                "ip": ip,
                "prefix": prefix,
                "internal_ip": internal_ip,
                "internal_prefix": 32 if internal_ip else "",
                "router": route.get("router") or "",
                "table": table,
                "priority": priority,
                "network": route.get("network") or "",
                "public_ok": bool(ip and prefix),
            })
    payload = {
        "updated_at": datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
        "host": "211.230.223.67",
        "parents": list(LINUX_PARENT_SEGMENTS.keys()),
        "children_per_parent": MAC_CHILDREN_PER_PARENT,
        "rows": rows,
    }
    MACVLAN_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    for path in (MACVLAN_STATE_FILE, HOST_MACVLAN_STATE_FILE):
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        tmp.replace(path)
    return {
        "ok": True,
        "path": str(MACVLAN_STATE_FILE),
        "host_path": str(HOST_MACVLAN_STATE_FILE),
        "rows": len(rows),
        "public_count": len([row for row in rows if row.get("public_ok")]),
    }


def _next_dummy_name() -> str:
    existing = set(psutil.net_if_addrs().keys())
    for idx in range(1, 1000):
        name = f"dummy42-{idx:03d}"
        if name not in existing:
            return name
    raise RuntimeError("虚拟网卡名称已用完")


def _linux_default_interfaces() -> list[str]:
    names = []
    try:
        proc = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True, timeout=5)
        words = (proc.stdout or "").split()
        for idx, word in enumerate(words):
            if word == "dev" and idx + 1 < len(words) and words[idx + 1] not in names:
                names.append(words[idx + 1])
    except Exception:
        pass
    return names


def _master_interfaces() -> list[str]:
    ifaces = _iface_snapshot()
    if os.name != "nt":
        return [name for name in LINUX_PARENT_SEGMENTS if name in ifaces]
    masters = []
    defaults = _linux_default_interfaces() if os.name != "nt" else []
    for name, info in ifaces.items():
        if name == "lo" or _is_generated_child_interface(name):
            continue
        if os.name == "nt" and (name.startswith("vEthernet ") or "WAN-AUTO" in name):
            continue
        has_public = any(_is_public_candidate(ip) for ip in info.get("ipv4", []))
        if os.name == "nt":
            if info.get("is_up") and has_public:
                if name not in masters:
                    masters.append(name)
            continue
        if info.get("is_master") or name in defaults or has_public:
            if name not in masters:
                masters.append(name)
    return masters


def _is_silent_master_item(item: dict) -> bool:
    iface = item.get("interface") or ""
    if _is_generated_child_interface(iface):
        return False
    return bool(item.get("is_master") or iface in _linux_default_interfaces())


def _windows_external_switch_options() -> list[dict]:
    if os.name != "nt":
        return []
    now = time.time()
    if WINDOWS_SWITCH_CACHE["data"] is not None and now - WINDOWS_SWITCH_CACHE["time"] < 30:
        return WINDOWS_SWITCH_CACHE["data"]
    script = r"""
$ErrorActionPreference = 'Stop'
Import-Module Hyper-V
$adapters = @(Get-NetAdapter | Select-Object Name,InterfaceDescription,MacAddress,LinkSpeed)
$ips = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object InterfaceAlias,IPAddress)
Get-VMSwitch | Where-Object {$_.SwitchType -eq 'External'} | ForEach-Object {
  $sw = $_
  $physical = $adapters | Where-Object {$_.InterfaceDescription -eq $sw.NetAdapterInterfaceDescription} | Select-Object -First 1
  $mgmtAlias = 'vEthernet (' + $sw.Name + ')'
  $ipv4 = @($ips | Where-Object {$_.InterfaceAlias -eq $mgmtAlias} | ForEach-Object {$_.IPAddress})
  [pscustomobject]@{
    name = $sw.Name
    label = if ($physical) { $physical.Name + '-主网卡' } else { $sw.Name }
    parent_name = if ($physical) { $physical.Name } else { $sw.Name }
    mac = if ($physical) { $physical.MacAddress } else { '' }
    public_ips = $ipv4
    ipv4 = $ipv4
    is_default = $false
    is_up = $true
    speed_mbps = if ($physical -and $physical.LinkSpeed -match '(\d+)\s*Gbps') { [int]$matches[1] * 1000 } elseif ($physical -and $physical.LinkSpeed -match '(\d+)\s*Mbps') { [int]$matches[1] } else { $null }
    is_hyperv_switch = $true
  }
} | ConvertTo-Json -Depth 4
"""
    try:
        data = _run_powershell_json(script, timeout=8)
    except Exception:
        WINDOWS_SWITCH_CACHE["time"] = now
        WINDOWS_SWITCH_CACHE["data"] = []
        return []
    if not data:
        WINDOWS_SWITCH_CACHE["time"] = now
        WINDOWS_SWITCH_CACHE["data"] = []
        return []
    if isinstance(data, dict):
        data = [data]
    WINDOWS_SWITCH_CACHE["time"] = now
    WINDOWS_SWITCH_CACHE["data"] = data
    return data


def _windows_master_public_ip_map() -> dict:
    if os.name != "nt":
        return {}
    mapping = {}
    for item in _master_interface_options():
        for ip in item.get("public_ips") or []:
            mapping[ip] = item
    return mapping


def _windows_parent_label_for_switch(switch_name: str, display_name: str = "") -> str:
    switch_name = switch_name or ""
    if switch_name == "WAN-59-External":
        return ETHERNET_4_LABEL
    if switch_name == "WAN-Ethernet5-External":
        return ETHERNET_5_LABEL
    if switch_name == "WAN-Slot01-x8-External":
        return "Slot01 x8"
    return _parent_adapter(display_name)


def _windows_virtual_adapter_slots() -> list[dict]:
    if os.name != "nt":
        return []
    script = r"""
$ErrorActionPreference = 'Stop'
Import-Module Hyper-V
$ips = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object InterfaceAlias,IPAddress,PrefixLength,AddressState)
Get-VMNetworkAdapter -ManagementOS -ErrorAction SilentlyContinue |
  Where-Object { $_.Name -match '^WAN-AUTO-\d{3}$' -or $_.Name -match '^.+-\d{3}$' } |
  Sort-Object SwitchName,Name |
  ForEach-Object {
    $adapter = $_
    $alias = 'vEthernet (' + $adapter.Name + ')'
    $rows = @($ips | Where-Object { $_.InterfaceAlias -eq $alias })
    [pscustomobject]@{
      name = $adapter.Name
      switch = $adapter.SwitchName
      interface = $alias
      mac = $adapter.MacAddress
      ips = @($rows | ForEach-Object { $_.IPAddress })
      states = @($rows | ForEach-Object { $_.AddressState })
      prefixes = @($rows | ForEach-Object { $_.PrefixLength })
    }
  } | ConvertTo-Json -Depth 5
"""
    try:
        data = _run_powershell_json(script, timeout=20)
    except Exception as exc:
        print(f"[windows virtual slots] {exc}")
        return []
    if not data:
        return []
    if isinstance(data, dict):
        data = [data]
    slots = []
    for row in data:
        raw_name = row.get("name") or ""
        if not _adapter_index(raw_name):
            continue
        interface = row.get("interface") or f"vEthernet ({raw_name})"
        display_name = _format_line_name(interface)
        ips = row.get("ips") or []
        if isinstance(ips, str):
            ips = [ips]
        public_ip = next((ip for ip in ips if _is_public_candidate(ip)), "")
        lease_ip = next((ip for ip in ips if ip and ip.startswith("169.254.")), "")
        parent = _windows_parent_label_for_switch(row.get("switch") or "", display_name)
        slots.append({
            "interface": interface,
            "display_name": display_name,
            "parent_adapter": parent,
            "adapter_index": _adapter_index(display_name),
            "ip": public_ip,
            "mac": row.get("mac") or "",
            "internal_ip": _generated_internal_ip_for_interface(interface, display_name),
            "is_master": False,
            "is_slot": True,
            "dhcp_state": "ok" if public_ip else "pending",
            "lease_ip": lease_ip,
        })
    return slots


def _linux_virtual_adapter_slots() -> list[dict]:
    if os.name == "nt":
        return []
    slots = []
    for iface, info in _iface_snapshot().items():
        parent, slot_idx = _linux_fixed_child_slot(iface)
        if not parent:
            continue
        display_name = info.get("display_name") or _format_line_name(iface)
        ipv4 = info.get("ipv4") or []
        public_ip = next((ip for ip in ipv4 if _is_public_candidate(ip)), "")
        lease_ip = next((ip for ip in ipv4 if ip and ip.startswith("169.254.")), "")
        slots.append({
            "interface": iface,
            "display_name": display_name,
            "parent_adapter": parent,
            "adapter_index": slot_idx,
            "ip": public_ip,
            "mac": info.get("mac") or "",
            "internal_ip": info.get("internal_ip") or _generated_internal_ip_for_interface(iface, display_name),
            "is_master": False,
            "is_slot": True,
            "dhcp_state": "ok" if public_ip else "pending",
            "lease_ip": lease_ip,
            "is_up": info.get("is_up"),
            "speed_mbps": info.get("speed_mbps"),
            "rx_bps": info.get("rx_bps", 0),
            "tx_bps": info.get("tx_bps", 0),
            "bytes_in": info.get("bytes_in", 0),
            "bytes_out": info.get("bytes_out", 0),
        })
    slots.sort(key=lambda item: (item.get("parent_adapter") or "ZZZ", item.get("adapter_index") or 0, item.get("interface") or ""))
    return slots


def _master_interface_options() -> list[dict]:
    now = time.time()
    if MASTER_OPTIONS_CACHE["data"] is not None and now - MASTER_OPTIONS_CACHE["time"] < 60:
        return MASTER_OPTIONS_CACHE["data"]
    ifaces = _iface_snapshot()
    defaults = set(_linux_default_interfaces()) if os.name != "nt" else set()
    options = []
    for name in _master_interfaces():
        info = ifaces.get(name, {})
        ipv4 = info.get("ipv4") or []
        public_ips = [ip for ip in ipv4 if _is_public_candidate(ip)]
        options.append({
            "name": name,
            "label": info.get("display_name") or _format_line_name(name),
            "mac": info.get("mac") or "",
            "public_ips": public_ips,
            "ipv4": ipv4,
            "is_default": name in defaults,
            "is_up": info.get("is_up"),
            "speed_mbps": info.get("speed_mbps"),
        })
    if os.name == "nt":
        existing = {item["name"] for item in options}
        for item in _windows_external_switch_options():
            if item["name"] not in existing:
                options.append(item)
        if not options:
            s = get_session()
            try:
                for line in s.query(Line).order_by(Line.id).all():
                    if "主网卡" not in (line.name or ""):
                        continue
                    parent_name = (line.name or "").replace("-主网卡", "")
                    options.append({
                        "name": line.name,
                        "label": line.name,
                        "parent_name": parent_name,
                        "mac": "",
                        "public_ips": [line.public_ip],
                        "ipv4": [line.public_ip],
                        "is_default": line.public_ip == "59.2.110.210",
                        "is_up": True,
                        "speed_mbps": None,
                        "is_hyperv_switch": True,
                    })
            finally:
                s.close()
    MASTER_OPTIONS_CACHE["time"] = now
    MASTER_OPTIONS_CACHE["data"] = options
    return options


def _windows_switch_name_for_parent(parent: str) -> str:
    parent = (parent or "").replace("-主网卡", "").strip()
    aliases = {
        "以太网 4": "WAN-59-External",
        "vEthernet": "WAN-59-External",
        "Slot01 x8": "WAN-Slot01-x8-External",
        "以太网 5": "WAN-Ethernet5-External",
    }
    if parent in aliases:
        return aliases[parent]
    for item in _windows_external_switch_options():
        if parent in {item.get("name"), item.get("parent_name"), item.get("label")}:
            return item.get("name") or parent
    return parent


def _generated_mac(parent_idx: int, child_idx: int) -> str:
    return f"02:42:{parent_idx & 0xff:02x}:{child_idx >> 8 & 0xff:02x}:{child_idx & 0xff:02x}:{random.randint(0,255):02x}"


def _safe_iface_label(name: str, max_len: int = 11) -> str:
    label = re.sub(r"[^a-zA-Z0-9_.-]+", "", name).strip(".-")
    label = label[:max_len]
    return label or "wan"


def _next_child_interface_name(parent_name: str, existing: set[str]) -> tuple[str, int]:
    base = _safe_iface_label(parent_name, 11)
    for idx in range(1, 1000):
        child_name = f"{base}-{idx:03d}"
        if len(child_name) > 15:
            child_name = f"{base[:11]}-{idx:03d}"
        if child_name not in existing:
            return child_name, idx
    raise RuntimeError(f"{parent_name}: 虚拟网卡名称已用完")


def _fixed_child_interface_name(parent_name: str, idx: int) -> str:
    base = _safe_iface_label(parent_name, 11)
    child_name = f"{base}-{idx:03d}"
    if len(child_name) > 15:
        child_name = f"{base[:11]}-{idx:03d}"
    return child_name


def _request_dhcp_for_interfaces(interface_names: list[str], timeout: int = 12) -> dict:
    client = shutil.which("dhcpcd") or shutil.which("dhclient") or shutil.which("udhcpc")
    if not client or not interface_names:
        return {}
    procs = {}
    for iface in interface_names:
        try:
            if os.path.basename(client) == "dhcpcd":
                args = [client, "-4", "-t", str(timeout), "-q", iface]
            elif os.path.basename(client) == "dhclient":
                args = [client, "-4", "-1", "-v", iface]
            else:
                args = [client, "-i", iface, "-q", "-t", "3", "-T", "3"]
            procs[iface] = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        except Exception as exc:
            procs[iface] = exc
    deadline = time.time() + timeout + 3
    results = {}
    for iface, proc in procs.items():
        if isinstance(proc, Exception):
            results[iface] = {"ok": False, "message": str(proc)}
            continue
        remain = max(1, int(deadline - time.time()))
        try:
            out, err = proc.communicate(timeout=remain)
            results[iface] = {"ok": proc.returncode == 0, "message": ((out or "") + (err or "")).strip()}
        except subprocess.TimeoutExpired:
            proc.kill()
            out, err = proc.communicate()
            results[iface] = {"ok": False, "message": "DHCP 鑾峰彇 IP 瓒呮椂"}
    return results


def _run_powershell_json(script: str, timeout: int = 120):
    proc = subprocess.run(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if proc.returncode != 0:
        raise RuntimeError((proc.stderr or proc.stdout or "").strip() or f"PowerShell exited {proc.returncode}")
    out = (proc.stdout or "").strip()
    if not out:
        return None
    return json.loads(out)


def _hyperv_powershell_available() -> bool:
    if os.name != "nt":
        return False
    try:
        proc = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                "if (Get-Command Get-VMSwitch,Add-VMNetworkAdapter,Set-VMNetworkAdapter -ErrorAction SilentlyContinue) { '1' }",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return proc.returncode == 0 and "1" in (proc.stdout or "")
    except Exception:
        return False


def _create_windows_virtual_adapters(parent: str, count: int) -> dict:
    if not _hyperv_powershell_available():
        raise RuntimeError("Windows 版需要先安装 Hyper-V PowerShell 管理模块。")
    target_name = _windows_switch_name_for_parent(parent) if parent else ""
    script = rf"""
$ErrorActionPreference = 'Stop'
Import-Module Hyper-V
$count = {int(count)}
$targetName = {json.dumps(target_name)}
$requestedParent = {json.dumps(parent or "")}
$switches = @(Get-VMSwitch | Sort-Object Name)
$namePrefix = $targetName
if (-not $targetName) {{
  $targetSwitch = $switches | Select-Object -First 1
  if ($targetSwitch) {{ $namePrefix = ($targetSwitch.Name -replace '^WAN-', '' -replace '-External$', '') }}
}} else {{
  $targetSwitch = $switches | Where-Object {{ $_.Name -eq $targetName }} | Select-Object -First 1
  if ($targetSwitch) {{
    $physical = Get-NetAdapter | Where-Object {{ $_.InterfaceDescription -eq $targetSwitch.NetAdapterInterfaceDescription }} | Select-Object -First 1
    if ($physical) {{ $namePrefix = $physical.Name }}
    if ($targetSwitch.Name -eq 'WAN-59-External') {{ $namePrefix = 'vEthernet' }}
    if ($targetSwitch.Name -eq 'WAN-Ethernet5-External') {{ $namePrefix = '以太网 5' }}
    if ($targetSwitch.Name -eq 'WAN-Slot01-x8-External') {{ $namePrefix = 'Slot01 x8' }}
  }}
  if (-not $targetSwitch) {{
    $netAdapter = Get-NetAdapter -Name $targetName -ErrorAction SilentlyContinue
    if ($netAdapter) {{
      $safe = ($targetName -replace '[^a-zA-Z0-9_-]+', '-').Trim('-')
      if (-not $safe) {{ $safe = 'adapter' }}
      $newSwitchName = "WAN-$safe-External"
      $targetSwitch = Get-VMSwitch -Name $newSwitchName -ErrorAction SilentlyContinue
      if (-not $targetSwitch) {{
        New-VMSwitch -Name $newSwitchName -NetAdapterName $targetName -AllowManagementOS $true | Out-Null
        Start-Sleep -Seconds 12
        $targetSwitch = Get-VMSwitch -Name $newSwitchName -ErrorAction Stop
      }}
    }}
  }}
}}
if (-not $targetSwitch) {{ throw '未找到可用 Hyper-V 虚拟交换机，请先创建外部虚拟交换机。' }}
if (-not $namePrefix) {{ $namePrefix = ($targetSwitch.Name -replace '^WAN-', '' -replace '-External$', '') }}
$existing = @(Get-VMNetworkAdapter -ManagementOS -ErrorAction SilentlyContinue)
$created = @()
$errors = @()
for ($i = 1; $i -le $count; $i++) {{
  $name = $null
  for ($n = 1; $n -le 999; $n++) {{
    $candidate = ('{{0}}-{{1:D3}}' -f $namePrefix, $n)
    if (-not ($existing | Where-Object {{ $_.Name -eq $candidate }}) -and -not ($created | Where-Object {{ $_.name -eq $candidate }})) {{
      $name = $candidate
      break
    }}
  }}
  if (-not $name) {{
    $errors += '虚拟网卡名称已用完'
    continue
  }}
  try {{
    $macBytes = 0..2 | ForEach-Object {{ Get-Random -Minimum 16 -Maximum 255 }}
    $mac = '00155D{{0:X2}}{{1:X2}}{{2:X2}}' -f $macBytes[0],$macBytes[1],$macBytes[2]
    Add-VMNetworkAdapter -ManagementOS -Name $name -SwitchName $targetSwitch.Name -StaticMacAddress $mac | Out-Null
    $created += [pscustomobject]@{{ parent=$targetSwitch.Name; name=$name; mac=$mac }}
  }} catch {{
    $errors += ($name + ': ' + $_.Exception.Message)
  }}
}}
Start-Sleep -Seconds 5
[pscustomobject]@{{
  switch = $targetSwitch.Name
  created = $created
  errors = $errors
}} | ConvertTo-Json -Depth 5
"""
    data = _run_powershell_json(script, timeout=max(120, count * 8))
    created = data.get("created") or []
    if isinstance(created, dict):
        created = [created]
    errors = data.get("errors") or []
    if isinstance(errors, str):
        errors = [errors]
    DETECT_CACHE["data"] = None
    return {
        "created": created,
        "errors": errors,
        "created_count": len(created),
        "acquired_count": 0,
        "switch": data.get("switch") or "",
    }


def _line_to_dict(line, detected_by_ip, iface_map, windows_master_map=None, connection_snapshot=None):
    data = line.to_dict()
    detected = detected_by_ip.get(line.public_ip) or {}
    iface = detected.get("interface") or line.note or ""
    iface_info = iface_map.get(iface, {})
    display_name = detected.get("display_name") or iface_info.get("display_name") or _format_line_name(iface or line.name)
    forced_master_iface = STATIC_MASTER_IPS.get(line.public_ip)
    windows_master = (windows_master_map or {}).get(line.public_ip) if os.name == "nt" else None
    db_master = os.name == "nt" and (
        "主网卡" in (line.name or "")
        or ((line.note or "").startswith("vEthernet (WAN-") and (line.note or "").endswith("-External)"))
    )
    if forced_master_iface:
        iface = forced_master_iface
        iface_info = iface_map.get(iface, iface_info)
    if windows_master:
        display_name = windows_master.get("label") or display_name
    if db_master:
        display_name = line.name
    short_master_name = _windows_short_master_name(saved_iface or iface)
    if short_master_name:
        display_name = short_master_name
    linux_master = _is_linux_real_master_line(line, iface)
    if linux_master and not _has_master_label(display_name):
        display_name = f"{display_name}-{MASTER_LABEL}"
    is_master = bool(linux_master or db_master or forced_master_iface or windows_master or detected.get("is_master", iface_info.get("is_master", _is_master_interface(iface))))
    node_count = len(line.users or [])
    connection_snapshot = connection_snapshot or {}
    connection_count = sum(
        int((connection_snapshot.get(user.id) or {}).get("connections") or 0)
        for user in (line.users or [])
    )
    data.update({
        "name": f"{forced_master_iface}-主网卡" if forced_master_iface else display_name,
        "interface": f"{forced_master_iface}-主网卡" if forced_master_iface else display_name,
        "raw_interface": iface,
        "parent_adapter": (line.note or iface) if linux_master else (line.name or "").replace("-主网卡", "") if db_master else forced_master_iface or (windows_master or {}).get("parent_name") or detected.get("parent_adapter") or iface_info.get("parent_adapter") or _parent_adapter(display_name),
        "adapter_index": detected.get("adapter_index") or iface_info.get("adapter_index") or _adapter_index(display_name),
        "is_master": is_master,
        "locked": is_master,
        "mac": detected.get("mac") or iface_info.get("mac") or "",
        "internal_ip": line.internal_ip if line.internal_ip != "0.0.0.0" else detected.get("internal_ip", "") or _generated_internal_ip_for_line(line, display_name),
        "rx_bps": detected.get("rx_bps", iface_info.get("rx_bps", 0)),
        "tx_bps": detected.get("tx_bps", iface_info.get("tx_bps", 0)),
        "bytes_in": detected.get("bytes_in", iface_info.get("bytes_in", 0)),
        "bytes_out": detected.get("bytes_out", iface_info.get("bytes_out", 0)),
        "is_up": detected.get("is_up", iface_info.get("is_up")),
        "speed_mbps": detected.get("speed_mbps", iface_info.get("speed_mbps")),
        "node_count": node_count,
        "connection_count": connection_count,
    })
    return data


def _line_to_dict(line, detected_by_ip, iface_map, windows_master_map=None, connection_snapshot=None):
    data = line.to_dict()
    note_meta = _note_meta(line.note)
    saved_iface = _note_interface(line.note)
    detected = detected_by_ip.get(line.public_ip) or {}
    iface = detected.get("interface") or saved_iface or ""
    iface_info = iface_map.get(iface, {})
    display_name = detected.get("display_name") or iface_info.get("display_name") or _format_line_name(iface or line.name)
    forced_master_iface = STATIC_MASTER_IPS.get(line.public_ip)
    windows_master = (windows_master_map or {}).get(line.public_ip) if os.name == "nt" else None
    db_master = os.name == "nt" and (
        _has_master_label(line.name or "")
        or (saved_iface.startswith("vEthernet (WAN-") and saved_iface.endswith("-External)"))
    )
    if forced_master_iface:
        iface = forced_master_iface
        iface_info = iface_map.get(iface, iface_info)
    if windows_master:
        display_name = windows_master.get("label") or display_name
    if db_master:
        display_name = line.name
    linux_master = _is_linux_real_master_line(line, iface)
    if linux_master and not _has_master_label(display_name):
        display_name = f"{display_name}-{MASTER_LABEL}"
    is_master = bool(
        linux_master
        or db_master
        or forced_master_iface
        or windows_master
        or detected.get("is_master", iface_info.get("is_master", _is_master_interface(iface)))
    )
    node_count = len(line.users or [])
    connection_snapshot = connection_snapshot or {}
    connection_count = sum(
        int((connection_snapshot.get(user.id) or {}).get("connections") or 0)
        for user in (line.users or [])
    )
    public_ok = _is_public_candidate(line.public_ip)
    data.update({
        "name": f"{forced_master_iface}-{MASTER_LABEL}" if forced_master_iface else display_name,
        "interface": f"{forced_master_iface}-{MASTER_LABEL}" if forced_master_iface else display_name,
        "raw_interface": iface,
        "parent_adapter": (
            (saved_iface or iface)
            if linux_master
            else (display_name or line.name or "").replace(f"-{MASTER_LABEL}", "")
            if db_master
            else forced_master_iface
            or (windows_master or {}).get("parent_name")
            or note_meta.get("parent")
            or detected.get("parent_adapter")
            or iface_info.get("parent_adapter")
            or _parent_adapter(display_name)
        ),
        "adapter_index": detected.get("adapter_index") or iface_info.get("adapter_index") or _adapter_index(display_name),
        "is_master": is_master,
        "locked": is_master,
        "mac": detected.get("mac") or iface_info.get("mac") or note_meta.get("mac") or "",
        "internal_ip": line.internal_ip if line.internal_ip != "0.0.0.0" else detected.get("internal_ip", "") or _generated_internal_ip_for_line(line, display_name),
        "dhcp_state": note_meta.get("dhcp") or ("ok" if public_ok else "pending"),
        "lease_ip": note_meta.get("lease_ip") or "",
        "rx_bps": detected.get("rx_bps", iface_info.get("rx_bps", 0)),
        "tx_bps": detected.get("tx_bps", iface_info.get("tx_bps", 0)),
        "bytes_in": detected.get("bytes_in", iface_info.get("bytes_in", 0)),
        "bytes_out": detected.get("bytes_out", iface_info.get("bytes_out", 0)),
        "is_up": detected.get("is_up", iface_info.get("is_up")),
        "speed_mbps": detected.get("speed_mbps", iface_info.get("speed_mbps")),
        "node_count": node_count,
        "connection_count": connection_count,
        "creatable": bool(public_ok and (line.status == 1 or is_master)),
    })
    return data


@bp.route("/detect-ips", methods=["GET"])
@login_required
def detect_ips():
    return jsonify({"ok": True, "data": _detect_local_ips()})


@bp.route("/master-interfaces", methods=["GET"])
@login_required
def master_interfaces():
    return jsonify({"ok": True, "data": _master_interface_options()})


@bp.route("/capabilities", methods=["GET"])
@login_required
def capabilities():
    can_create = os.name != "nt" or _hyperv_powershell_available()
    return jsonify({
        "ok": True,
        "data": {
            "platform": "windows" if os.name == "nt" else "linux",
            "can_create_virtual_adapters": can_create,
            "virtual_adapter_message": (
                "Windows 版需要安装 Hyper-V PowerShell 管理模块后才能创建虚拟网卡。"
                if os.name == "nt" and not can_create
                else ""
            ),
        },
    })


def _sync_local_lines_impl():
    detected_all = _detect_local_ips(force=True)
    if os.name == "nt":
        detected = [item for item in detected_all if _is_public_candidate(item.get("ip", ""))]
    else:
        detected = [
            item
            for item in detected_all
            if _is_public_candidate(item.get("ip", ""))
            and _is_linux_managed_interface(item.get("interface") or "")
        ]
    detected.sort(key=lambda item: (item.get("parent_adapter") or "ZZZ", item.get("adapter_index") or 0, item.get("ip") or ""))
    virtual_slots = _windows_virtual_adapter_slots() if os.name == "nt" else _linux_virtual_adapter_slots()
    slot_by_interface = {item.get("interface"): item for item in virtual_slots if item.get("interface")}
    s = get_session()
    try:
        lines = s.query(Line).all()
        lines_by_iface = {_note_interface(line.note): line for line in lines if _note_interface(line.note)}
        lines_by_name = {line.name: line for line in lines if line.name}
        existing_ips = {line.public_ip for line in lines if _is_public_candidate(line.public_ip)}
        used_ports = set()
        for line in lines:
            for port in (line.socks_port, line.http_port, line.ss_port):
                if port:
                    used_ports.add(int(port))

        created = []
        skipped = []
        base = 10801

        def assign_ports():
            nonlocal base
            socks_port = _next_available_port(s, base, used_ports)
            http_port = _next_available_port(s, socks_port + 1000, used_ports)
            ss_port = _next_available_port(s, socks_port + 2000, used_ports)
            base = socks_port + 1
            return socks_port, http_port, ss_port

        def update_note(line, iface, item=None, slot=None, dhcp="ok"):
            item = item or {}
            slot = slot or {}
            line.note = _line_note(
                iface,
                mac=slot.get("mac") or item.get("mac") or _note_meta(line.note).get("mac") or "",
                parent=slot.get("parent_adapter") or item.get("parent_adapter") or _note_meta(line.note).get("parent") or "",
                dhcp=dhcp,
                lease_ip=slot.get("lease_ip") or "",
            )

        for item in detected:
            ip = item.get("ip") or ""
            iface = item.get("interface") or ""
            display_name = item.get("display_name") or _format_line_name(iface)
            slot = slot_by_interface.get(iface, {})
            line = lines_by_iface.get(iface) or lines_by_name.get(display_name)
            if line:
                line.name = display_name
                line.public_ip = ip
                line.internal_ip = item.get("internal_ip") or line.internal_ip or _generated_internal_ip_for_interface(iface, display_name)
                line.status = 1
                update_note(line, iface, item=item, slot=slot, dhcp="ok")
                skipped.append({"ip": ip, "reason": "updated"})
                lines_by_iface[iface] = line
                lines_by_name[display_name] = line
                existing_ips.add(ip)
                continue
            if ip in existing_ips:
                skipped.append({"ip": ip, "reason": "exists"})
                continue
            socks_port, http_port, ss_port = assign_ports()
            line = Line(
                name=display_name,
                public_ip=ip,
                internal_ip=item.get("internal_ip") or _generated_internal_ip_for_interface(iface, display_name),
                socks_port=socks_port,
                http_port=http_port,
                ss_port=ss_port,
                status=1,
                note=_line_note(
                    iface,
                    mac=slot.get("mac") or item.get("mac") or "",
                    parent=slot.get("parent_adapter") or item.get("parent_adapter") or "",
                    dhcp="ok",
                    lease_ip=slot.get("lease_ip") or "",
                ),
            )
            s.add(line)
            s.flush()
            created.append(line.to_dict())
            lines_by_iface[iface] = line
            lines_by_name[display_name] = line
            existing_ips.add(ip)

        for slot in virtual_slots:
            iface = slot.get("interface") or ""
            display_name = slot.get("display_name") or _format_line_name(iface)
            if not iface or not display_name or _adapter_index(display_name) < 1:
                continue
            ip = slot.get("ip") or ""
            public_ok = _is_public_candidate(ip)
            line = lines_by_iface.get(iface) or lines_by_name.get(display_name)
            note = _line_note(
                iface,
                mac=slot.get("mac") or "",
                parent=slot.get("parent_adapter") or "",
                dhcp="ok" if public_ok else "pending",
                lease_ip=slot.get("lease_ip") or "",
            )
            if line:
                line.name = display_name
                line.note = note
                line.internal_ip = slot.get("internal_ip") or line.internal_ip or _generated_internal_ip_for_interface(iface, display_name)
                if public_ok:
                    line.public_ip = ip
                    line.status = 1
                else:
                    line.public_ip = "0.0.0.0"
                    line.status = 0
                continue
            socks_port, http_port, ss_port = assign_ports()
            line = Line(
                name=display_name,
                public_ip=ip if public_ok else "0.0.0.0",
                internal_ip=slot.get("internal_ip") or _generated_internal_ip_for_interface(iface, display_name),
                socks_port=socks_port,
                http_port=http_port,
                ss_port=ss_port,
                status=1 if public_ok else 0,
                note=note,
            )
            s.add(line)
            s.flush()
            created.append(line.to_dict())
            lines_by_iface[iface] = line
            lines_by_name[display_name] = line

        if os.name != "nt":
            for line in list(lines):
                iface = (_note_interface(line.note) or line.name or "").replace(f"-{MASTER_LABEL}", "")
                if _is_generated_child_interface(iface) and not _is_linux_fixed_child_interface(iface):
                    s.delete(line)

        internal_result = _ensure_linux_internal_ips()
        for line in s.query(Line).all():
            iface = (_note_interface(line.note) or line.name or "").replace(f"-{MASTER_LABEL}", "")
            internal_ip = _linux_managed_internal_ip(iface)
            if internal_ip:
                line.internal_ip = internal_ip
        s.commit()
        persisted = _persist_linux_macvlan_state()
        try:
            _reload_after_change(s)
        except Exception as exc:
            print(f"[lines sync reload] {exc}")
        return jsonify({
            "ok": True,
            "data": {
                "detected_count": len(detected),
                "interface_count": len(detected_all),
                "public_count": len(detected),
                "slot_count": len(virtual_slots),
                "created_count": len(created),
                "skipped_count": len(skipped),
                "internal_ips": internal_result,
                "persisted": persisted,
                "created": created,
                "skipped": skipped,
            },
        })
    finally:
        s.close()


@bp.route("/sync-local", methods=["POST"])
@login_required
def sync_local_lines():
    return _sync_local_lines_impl()
    detected = [item for item in _detect_local_ips(force=True) if _is_public_candidate(item["ip"])]
    detected.sort(key=lambda item: (item.get("parent_adapter") or "ZZZ", item.get("adapter_index") or 0, item.get("ip") or ""))
    s = get_session()
    try:
        existing_ips = {line.public_ip for line in s.query(Line).all()}
        used_ports = set()
        for line in s.query(Line).all():
            used_ports.add(line.socks_port)
            if line.http_port:
                used_ports.add(line.http_port)
            if line.ss_port:
                used_ports.add(line.ss_port)

        created = []
        skipped = []
        base = 10801
        for item in detected:
            ip = item["ip"]
            display_name = item.get("display_name") or _format_line_name(item.get("interface", ""))
            if ip in existing_ips:
                skipped.append({"ip": ip, "reason": "exists"})
                continue
            socks_port = _next_available_port(s, base, used_ports)
            http_port = _next_available_port(s, socks_port + 1000, used_ports)
            ss_port = _next_available_port(s, socks_port + 2000, used_ports)
            base = socks_port + 1
            line = Line(
                name=display_name,
                public_ip=ip,
                internal_ip=item.get("internal_ip") or _generated_internal_ip_for_interface(item.get("interface", ""), display_name),
                socks_port=socks_port,
                http_port=http_port,
                ss_port=ss_port,
                status=1,
                note=item.get("interface", ""),
            )
            s.add(line)
            s.flush()
            created.append(line.to_dict())
            existing_ips.add(ip)

        for line in s.query(Line).all():
            matched = next((item for item in detected if item["ip"] == line.public_ip), None)
            if matched:
                display_name = matched.get("display_name") or _format_line_name(matched.get("interface", ""))
                line.name = display_name
                line.note = matched.get("interface", line.note)
                if line.public_ip in STATIC_MASTER_IPS:
                    line.name = f"{STATIC_MASTER_IPS[line.public_ip]}-主网卡"
                    line.note = STATIC_MASTER_IPS[line.public_ip]
                if not line.internal_ip or line.internal_ip == "0.0.0.0":
                    line.internal_ip = matched.get("internal_ip") or _generated_internal_ip_for_line(line, display_name)

        s.commit()
        try:
            _reload_after_change(s)
        except Exception as exc:
            print(f"[lines sync reload] {exc}")
        return jsonify({
            "ok": True,
            "data": {
                "detected_count": len(detected),
                "created_count": len(created),
                "skipped_count": len(skipped),
                "created": created,
                "skipped": skipped,
            },
        })
    finally:
        s.close()

@bp.route("/add-virtual-adapter", methods=["POST"])
@login_required
def add_virtual_adapter():
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    internal_ip = (data.get("internal_ip") or "").strip()
    prefix = int(data.get("prefix") or 24)
    count = max(1, min(int(data.get("count") or 1), 200))
    parent = (data.get("parent") or "").strip()
    if os.name != "nt":
        if name:
            return jsonify({"ok": False, "error": "Linux 线路已锁定为每个主网卡 13 个固定虚拟网卡，不支持自定义网卡名"}), 400
        count = MAC_CHILDREN_PER_PARENT
    if os.name == "nt":
        try:
            targets = [parent] if parent else [item["name"] for item in _master_interface_options()]
            if not targets:
                s = get_session()
                try:
                    targets = [
                        (line.name or "").strip()
                        for line in s.query(Line).all()
                        if "主网卡" in (line.name or "")
                    ]
                finally:
                    s.close()
            batches = [_create_windows_virtual_adapters(target, count) for target in targets]
            created = []
            errors = []
            switches = []
            for batch in batches:
                created.extend(batch.get("created") or [])
                errors.extend(batch.get("errors") or [])
                if batch.get("switch"):
                    switches.append(batch.get("switch"))
            result = {
                "created": created,
                "errors": errors,
                "created_count": len(created),
                "acquired_count": 0,
                "switches": switches,
            }
            detected = [item for item in _detect_local_ips(force=True) if _is_public_candidate(item["ip"])]
            result["detected_count"] = len(detected)
            return jsonify({"ok": True, "data": result})
        except Exception as exc:
            return jsonify({"ok": False, "error": str(exc)}), 500
    if name and count > 1:
        return jsonify({"ok": False, "error": "鎵归噺鍒涘缓鏃惰鐣欑┖鍚嶇О锛岀郴缁熶細鑷姩鍛藉悕"}), 400
    if name and not re.match(r"^[a-zA-Z0-9_.:-]{1,15}$", name):
        return jsonify({"ok": False, "error": "虚拟网卡名称只能包含字母数字和 . _ : -，最长 15 位"}), 400
    if internal_ip and not _valid_ip(internal_ip):
        return jsonify({"ok": False, "error": "鍐呯綉 IP 鏍煎紡閿欒"}), 400
    if prefix < 1 or prefix > 32:
        return jsonify({"ok": False, "error": "鎺╃爜鑼冨洿蹇呴』鏄?1-32"}), 400
    available_masters = [name for name in _master_interfaces() if _is_linux_managed_interface(name)]
    if parent and parent not in available_masters:
        return jsonify({"ok": False, "error": "璇烽€夋嫨绯荤粺妫€娴嬪埌鐨勭湡瀹炰富缃戝崱"}), 400
    parents = [parent] if parent else available_masters
    if not parents:
        return jsonify({"ok": False, "error": "未找到主网卡，请确认服务器有可用公网网卡或默认路由"}), 400
    created = []
    errors = []
    existing_children = []
    existing = set(psutil.net_if_addrs().keys())
    created_names = []
    for parent_idx, parent_name in enumerate(parents, start=1):
        if parent_name not in psutil.net_if_addrs():
            errors.append(f"{parent_name}: 主网卡不存在")
            continue
        for child_idx in range(1, count + 1):
            if name:
                child_name = name
                seq = child_idx
            elif count == MAC_CHILDREN_PER_PARENT:
                child_name = _fixed_child_interface_name(parent_name, child_idx)
                seq = child_idx
                if child_name in existing:
                    existing_children.append({"parent": parent_name, "name": child_name})
                    continue
            else:
                try:
                    child_name, seq = _next_child_interface_name(parent_name, existing)
                except RuntimeError as exc:
                    errors.append(str(exc))
                    continue
            mac = _generated_mac(parent_idx, seq)
            ok, output = _run_cmd(["ip", "link", "add", "link", parent_name, child_name, "address", mac, "type", "macvlan", "mode", "bridge"])
            if not ok and "File exists" not in output:
                errors.append(f"{parent_name}/{child_name}: {output or '鍒涘缓澶辫触'}")
                continue
            existing.add(child_name)
            if internal_ip and len(parents) == 1 and count == 1:
                ok, output = _run_cmd(["ip", "addr", "replace", f"{internal_ip}/{prefix}", "dev", child_name])
                if not ok:
                    errors.append(f"{child_name}: {output or '缁戝畾鍐呯綉 IP 澶辫触'}")
            ok, output = _run_cmd(["ip", "link", "set", child_name, "up"])
            if not ok:
                errors.append(f"{child_name}: {output or '鍚敤澶辫触'}")
                continue
            created.append({"parent": parent_name, "name": child_name, "mac": mac})
            created_names.append(child_name)
    dhcp_results = _request_dhcp_for_interfaces(created_names)
    if dhcp_results:
        time.sleep(1)
        snapshot = _iface_snapshot()
        for item in created:
            info = snapshot.get(item["name"], {})
            public_ips = [ip for ip in info.get("ipv4", []) if _is_public_candidate(ip)]
            item["ip"] = public_ips[0] if public_ips else ""
            dhcp = dhcp_results.get(item["name"]) or {}
            item["dhcp_ok"] = bool(dhcp.get("ok"))
            if not item["ip"] and dhcp.get("message"):
                item["dhcp_message"] = dhcp.get("message")[-300:]
    DETECT_CACHE["data"] = None
    internal_result = _ensure_linux_internal_ips()
    persisted = _persist_linux_macvlan_state()
    acquired_count = len([item for item in created if item.get("ip")])
    return jsonify({"ok": True, "data": {"created": created, "created_count": len(created), "existing": existing_children, "existing_count": len(existing_children), "acquired_count": acquired_count, "errors": errors, "prefix": prefix, "internal_ips": internal_result, "persisted": persisted}})


@bp.route("/<int:lid>/internal-ip", methods=["POST"])
@login_required
def update_internal_ip(lid):
    data = request.get_json(silent=True) or {}
    internal_ip = (data.get("internal_ip") or "").strip()
    if not _valid_ip(internal_ip):
        return jsonify({"ok": False, "error": "鍐呯綉 IP 鏍煎紡閿欒"}), 400
    s = get_session()
    try:
        line = s.query(Line).get(lid)
        if not line:
            return jsonify({"ok": False, "error": "线路不存在"}), 404
        line.internal_ip = internal_ip
        s.commit()
        try:
            _reload_after_change(s)
        except Exception as exc:
            print(f"[lines internal ip reload] {exc}")
        return jsonify({"ok": True, "data": line.to_dict()})
    finally:
        s.close()


@bp.route("/auto-internal-ips", methods=["POST"])
@login_required
def auto_internal_ips():
    data = request.get_json(silent=True) or {}
    base = (data.get("base") or "10.42").strip().rstrip(".")
    if not re.match(r"^\d{1,3}\.\d{1,3}$", base) or any(int(x) > 255 for x in base.split(".")):
        return jsonify({"ok": False, "error": "缃戞鏍煎紡閿欒锛屼緥濡?10.42"}), 400
    s = get_session()
    try:
        lines = s.query(Line).order_by(Line.name, Line.id).all()
        updated = []
        for line in lines:
            generated = _generated_internal_ip_for_line(line)
            if generated.startswith("10.42."):
                parts = generated.split(".")
                ip = f"{base}.{parts[2]}.{parts[3]}"
            else:
                ip = generated
            line.internal_ip = ip
            updated.append({"id": line.id, "name": line.name, "internal_ip": ip})
        s.commit()
        try:
            _reload_after_change(s)
        except Exception as exc:
            print(f"[lines auto internal reload] {exc}")
        return jsonify({"ok": True, "data": {"updated": updated, "updated_count": len(updated)}})
    finally:
        s.close()


@bp.route("", methods=["GET"])
@login_required
def list_lines():
    s = get_session()
    try:
        if is_single_ip_mode():
            line = _ensure_single_ip_line(s)
            s.commit()
            s.refresh(line)
            return jsonify({"ok": True, "data": [line.to_dict()]})
        live = request.args.get("live") == "1"
        if live:
            detected = _detect_local_ips()
            detected_by_ip = {item["ip"]: item for item in detected}
            iface_map = {item["interface"]: item for item in detected}
            windows_master_map = _windows_master_public_ip_map() if os.name == "nt" else {}
            connection_snapshot = snapshot_connections()
        else:
            detected_by_ip = {}
            iface_map = {}
            windows_master_map = {}
            connection_snapshot = {}
        lines = s.query(Line).options(selectinload(Line.users)).order_by(Line.name, Line.id).all()
        return jsonify({"ok": True, "data": [
            _line_to_dict(line, detected_by_ip, iface_map, windows_master_map, connection_snapshot)
            for line in lines
        ]})
    finally:
        s.close()


@bp.route("/<int:lid>/change-mac", methods=["POST"])
@login_required
def change_mac(lid):
    s = get_session()
    try:
        line = s.query(Line).get(lid)
        if not line:
            return jsonify({"ok": False, "error": "线路不存在"}), 404
        info = _line_to_dict(line, {item["ip"]: item for item in _detect_local_ips()}, _iface_snapshot())
        if info["is_master"]:
            return jsonify({"ok": False, "error": "主网卡为静默线路，不能更换 MAC"}), 400
        if os.name != "nt":
            iface = (_note_interface(line.note) or info.get("raw_interface") or line.name or "").replace(f"-{MASTER_LABEL}", "")
            if not _is_linux_fixed_child_interface(iface):
                return jsonify({"ok": False, "error": "只有固定 001-013 虚拟 MAC 网卡可以更换 MAC"}), 400
            if iface not in psutil.net_if_addrs():
                return jsonify({"ok": False, "error": f"系统里找不到虚拟网卡 {iface}"}), 404
            idx = _adapter_index(iface) or random.randint(1, 999)
            new_mac = _generated_mac(_parent_segment(_parent_key(iface)), idx)
            for args in (
                ["ip", "link", "set", "dev", iface, "down"],
                ["ip", "addr", "flush", "dev", iface],
                ["ip", "link", "set", "dev", iface, "address", new_mac],
                ["ip", "link", "set", "dev", iface, "up"],
            ):
                ok, output = _run_cmd(args, timeout=15)
                if not ok:
                    return jsonify({"ok": False, "error": output or "更换 MAC 失败"}), 500
            dhcp_results = _request_dhcp_for_interfaces([iface], timeout=18)
            time.sleep(1)
            snapshot = _iface_snapshot()
            iface_info = snapshot.get(iface, {})
            public_ips = [ip for ip in iface_info.get("ipv4", []) if _is_public_candidate(ip)]
            if public_ips:
                line.public_ip = public_ips[0]
                line.status = 1
            else:
                line.public_ip = "0.0.0.0"
                line.status = 0
            line.name = _format_line_name(iface)
            line.internal_ip = _linux_managed_internal_ip(iface) or iface_info.get("internal_ip") or _generated_internal_ip_for_line(line, line.name)
            lease_ip = next((ip for ip in (iface_info.get("ipv4") or []) if ip.startswith("169.254.")), "")
            line.note = _line_note(
                iface,
                mac=iface_info.get("mac") or new_mac,
                parent=iface_info.get("parent_adapter") or _parent_key(iface),
                dhcp="ok" if public_ips else "pending",
                lease_ip=lease_ip,
            )
            internal_result = _ensure_linux_internal_ips()
            s.commit()
            persisted = _persist_linux_macvlan_state()
            try:
                _reload_after_change(s)
            except Exception as exc:
                print(f"[lines linux change mac reload] {exc}")
            detected = _detect_local_ips(force=True)
            return jsonify({"ok": True, "data": {
                "mac": new_mac,
                "dhcp": dhcp_results.get(iface) or {},
                "internal_ips": internal_result,
                "persisted": persisted,
                "line": _line_to_dict(line, {item["ip"]: item for item in detected}, _iface_snapshot()),
            }})
        adapter_name = _hyperv_adapter_name(info["raw_interface"] or info["interface"])
        if not adapter_name:
            return jsonify({"ok": False, "error": "未找到对应虚拟网卡"}), 400
        parent = info.get("parent_adapter") or ""
        m = re.search(r"(\d+)", parent)
        parent_no = int(m.group(1)) if m else 9
        idx = int(info.get("adapter_index") or random.randint(1, 99))
        suffix = random.randint(0x10, 0xFF)
        new_mac = f"00155D{parent_no:02X}{idx:02X}{suffix:02X}"
        cmd = (
            f"Set-VMNetworkAdapter -ManagementOS -Name '{adapter_name}' -StaticMacAddress '{new_mac}'; "
            "Start-Sleep -Seconds 12; "
            "Get-NetIPAddress -AddressFamily IPv4 | "
            "Where-Object {$_.IPAddress -ne '127.0.0.1'} | "
            "Select-Object InterfaceAlias,IPAddress | ConvertTo-Json -Compress"
        )
        out = subprocess.run(["powershell", "-NoProfile", "-Command", cmd], capture_output=True, text=True, timeout=45)
        if out.returncode != 0:
            return jsonify({"ok": False, "error": out.stderr.strip() or "更换 MAC 失败"}), 500
        detected = _detect_local_ips(force=True)
        display = info["interface"]
        matched = next((item for item in detected if item.get("display_name") == display), None)
        if matched and _is_public_candidate(matched["ip"]):
            line.public_ip = matched["ip"]
            line.note = matched["interface"]
            line.name = matched["display_name"]
            s.commit()
            try:
                _reload_after_change(s)
            except Exception as exc:
                print(f"[lines change mac reload] {exc}")
        return jsonify({"ok": True, "data": {"mac": new_mac, "line": _line_to_dict(line, {item["ip"]: item for item in detected}, _iface_snapshot())}})
    finally:
        s.close()


def _change_linux_line_mac(session, line) -> dict:
    info = _line_to_dict(line, {item["ip"]: item for item in _detect_local_ips()}, _iface_snapshot())
    if info["is_master"]:
        raise ValueError("主网卡不能更换 MAC")
    iface = (_note_interface(line.note) or info.get("raw_interface") or line.name or "").replace(f"-{MASTER_LABEL}", "")
    if not _is_linux_fixed_child_interface(iface):
        raise ValueError("只有固定 001-013 虚拟 MAC 网卡可以更换 MAC")
    if iface not in psutil.net_if_addrs():
        raise FileNotFoundError(f"系统里找不到虚拟网卡 {iface}")
    idx = _adapter_index(iface) or random.randint(1, 999)
    new_mac = _generated_mac(_parent_segment(_parent_key(iface)), idx)
    for args in (
        ["ip", "link", "set", "dev", iface, "down"],
        ["ip", "addr", "flush", "dev", iface],
        ["ip", "link", "set", "dev", iface, "address", new_mac],
        ["ip", "link", "set", "dev", iface, "up"],
    ):
        ok, output = _run_cmd(args, timeout=15)
        if not ok:
            raise RuntimeError(output or f"{iface}: 更换 MAC 失败")
    dhcp_results = _request_dhcp_for_interfaces([iface], timeout=18)
    time.sleep(1)
    snapshot = _iface_snapshot()
    iface_info = snapshot.get(iface, {})
    public_ips = [ip for ip in iface_info.get("ipv4", []) if _is_public_candidate(ip)]
    lease_ip = next((ip for ip in (iface_info.get("ipv4") or []) if ip.startswith("169.254.")), "")
    line.public_ip = public_ips[0] if public_ips else "0.0.0.0"
    line.status = 1 if public_ips else 0
    line.name = _format_line_name(iface)
    line.internal_ip = _linux_managed_internal_ip(iface) or iface_info.get("internal_ip") or _generated_internal_ip_for_line(line, line.name)
    line.note = _line_note(
        iface,
        mac=iface_info.get("mac") or new_mac,
        parent=iface_info.get("parent_adapter") or _parent_key(iface),
        dhcp="ok" if public_ips else "pending",
        lease_ip=lease_ip,
    )
    return {
        "id": line.id,
        "name": line.name,
        "interface": iface,
        "mac": iface_info.get("mac") or new_mac,
        "public_ip": line.public_ip,
        "dhcp": dhcp_results.get(iface) or {},
        "lease_ip": lease_ip,
    }


def _refresh_line_after_dhcp(line, iface: str, dhcp_result: dict | None = None) -> dict:
    snapshot = _iface_snapshot()
    iface_info = snapshot.get(iface, {})
    ipv4 = iface_info.get("ipv4") or []
    public_ips = [ip for ip in ipv4 if _is_public_candidate(ip)]
    lease_ip = next((ip for ip in ipv4 if ip.startswith("169.254.")), "")
    line.public_ip = public_ips[0] if public_ips else "0.0.0.0"
    line.status = 1 if public_ips else 0
    line.name = _format_line_name(iface)
    line.internal_ip = _linux_managed_internal_ip(iface) or iface_info.get("internal_ip") or _generated_internal_ip_for_line(line, line.name)
    line.note = _line_note(
        iface,
        mac=iface_info.get("mac") or _note_meta(line.note).get("mac") or "",
        parent=iface_info.get("parent_adapter") or _parent_key(iface),
        dhcp="ok" if public_ips else "pending",
        lease_ip=lease_ip,
    )
    return {
        "id": line.id,
        "name": line.name,
        "interface": iface,
        "mac": iface_info.get("mac") or _note_meta(line.note).get("mac") or "",
        "public_ip": line.public_ip,
        "lease_ip": lease_ip,
        "dhcp": dhcp_result or {},
    }


@bp.route("/batch-change-mac", methods=["POST"])
@login_required
def batch_change_mac():
    data = request.get_json(silent=True) or {}
    raw_ids = data.get("ids") or []
    if not isinstance(raw_ids, list):
        return jsonify({"ok": False, "error": "ids must be a list"}), 400
    ids = [int(x) for x in raw_ids if str(x).isdigit()]
    if not ids:
        return jsonify({"ok": False, "error": "请选择要更换的线路"}), 400
    if os.name == "nt":
        return jsonify({"ok": False, "error": "Windows 批量更换请逐条操作"}), 400
    s = get_session()
    try:
        lines = s.query(Line).filter(Line.id.in_(ids)).all()
        found_ids = {line.id for line in lines}
        changed = []
        errors = [{"id": missing_id, "error": "线路不存在"} for missing_id in ids if missing_id not in found_ids]
        for line in lines:
            try:
                changed.append(_change_linux_line_mac(s, line))
            except Exception as exc:
                errors.append({"id": line.id, "name": line.name, "error": str(exc)})
        if changed:
            s.commit()
            DETECT_CACHE["data"] = None
            internal_result = _ensure_linux_internal_ips()
            persisted = _persist_linux_macvlan_state()
            try:
                _reload_after_change(s)
            except Exception as exc:
                print(f"[lines batch change mac reload] {exc}")
        else:
            s.rollback()
            internal_result = {"ok": True, "skipped": True}
            persisted = {"ok": True, "skipped": True}
        return jsonify({"ok": True, "data": {"changed": changed, "changed_count": len(changed), "errors": errors, "internal_ips": internal_result, "persisted": persisted}})
    finally:
        s.close()


@bp.route("/batch-request-dhcp", methods=["POST"])
@login_required
def batch_request_dhcp():
    data = request.get_json(silent=True) or {}
    raw_ids = data.get("ids") or []
    if not isinstance(raw_ids, list):
        return jsonify({"ok": False, "error": "ids must be a list"}), 400
    ids = [int(x) for x in raw_ids if str(x).isdigit()]
    if not ids:
        return jsonify({"ok": False, "error": "请选择要请求 DHCP 的线路"}), 400
    if os.name == "nt":
        return jsonify({"ok": False, "error": "Windows 请使用系统网络面板续租 DHCP"}), 400
    s = get_session()
    try:
        lines = s.query(Line).filter(Line.id.in_(ids)).all()
        found_ids = {line.id for line in lines}
        targets = []
        errors = [{"id": missing_id, "error": "线路不存在"} for missing_id in ids if missing_id not in found_ids]
        for line in lines:
            try:
                info = _line_to_dict(line, {item["ip"]: item for item in _detect_local_ips()}, _iface_snapshot())
                if info["is_master"]:
                    raise ValueError("主网卡不能请求 DHCP")
                iface = (_note_interface(line.note) or info.get("raw_interface") or line.name or "").replace(f"-{MASTER_LABEL}", "")
                if not _is_linux_fixed_child_interface(iface):
                    raise ValueError("只有固定 001-013 虚拟 MAC 网卡可以请求 DHCP")
                if iface not in psutil.net_if_addrs():
                    raise FileNotFoundError(f"系统里找不到虚拟网卡 {iface}")
                targets.append((line, iface))
            except Exception as exc:
                errors.append({"id": line.id, "name": line.name, "error": str(exc)})
        dhcp_results = _request_dhcp_for_interfaces([iface for _, iface in targets], timeout=18)
        time.sleep(1)
        refreshed = []
        for line, iface in targets:
            refreshed.append(_refresh_line_after_dhcp(line, iface, dhcp_results.get(iface) or {}))
        if refreshed:
            s.commit()
            DETECT_CACHE["data"] = None
            internal_result = _ensure_linux_internal_ips()
            persisted = _persist_linux_macvlan_state()
            try:
                _reload_after_change(s)
            except Exception as exc:
                print(f"[lines batch dhcp reload] {exc}")
        else:
            s.rollback()
            internal_result = {"ok": True, "skipped": True}
            persisted = {"ok": True, "skipped": True}
        acquired_count = len([item for item in refreshed if item.get("public_ip") and item.get("public_ip") != "0.0.0.0"])
        return jsonify({"ok": True, "data": {"requested_count": len(targets), "acquired_count": acquired_count, "refreshed": refreshed, "errors": errors, "internal_ips": internal_result, "persisted": persisted}})
    finally:
        s.close()


@bp.route("/<int:lid>/toggle", methods=["POST"])
@login_required
def toggle_line(lid):
    s = get_session()
    try:
        line = s.query(Line).get(lid)
        if not line:
            return jsonify({"ok": False, "error": "线路不存在"}), 404
        info = _line_to_dict(line, {item["ip"]: item for item in _detect_local_ips()}, _iface_snapshot())
        if info["is_master"]:
            return jsonify({"ok": False, "error": "主网卡为静默线路，不能修改状态"}), 400
        line.status = 0 if line.status else 1
        s.commit()
        try:
            _reload_after_change(s)
        except Exception as exc:
            print(f"[lines toggle reload] {exc}")
        return jsonify({"ok": True, "data": line.to_dict()})
    finally:
        s.close()


def _delete_line_record(session, line) -> dict:
    info = _line_to_dict(line, {item["ip"]: item for item in _detect_local_ips()}, _iface_snapshot())
    if info["is_master"]:
        raise ValueError("主网卡不能删除")
    deleted_iface = ""
    if os.name != "nt":
        iface = (_note_interface(line.note) or info.get("raw_interface") or line.name or "").replace(f"-{MASTER_LABEL}", "")
        if _is_generated_child_interface(iface):
            deleted_iface = iface
            if iface in psutil.net_if_addrs():
                ok, output = _run_cmd(["ip", "link", "delete", iface], timeout=15)
                if not ok and "Cannot find device" not in output:
                    raise RuntimeError(output or f"删除虚拟网卡 {iface} 失败")
    result = {"id": line.id, "name": line.name, "public_ip": line.public_ip, "deleted_interface": deleted_iface}
    session.delete(line)
    return result


@bp.route("/<int:lid>", methods=["DELETE"])
@login_required
def delete_line(lid):
    s = get_session()
    try:
        line = s.query(Line).get(lid)
        if not line:
            return jsonify({"ok": False, "error": "线路不存在"}), 404
        info = _line_to_dict(line, {item["ip"]: item for item in _detect_local_ips()}, _iface_snapshot())
        if info["is_master"]:
            return jsonify({"ok": False, "error": "主网卡为静默线路，不能删除"}), 400
        deleted_iface = ""
        if os.name != "nt":
            iface = (_note_interface(line.note) or info.get("raw_interface") or line.name or "").replace(f"-{MASTER_LABEL}", "")
            if _is_generated_child_interface(iface):
                deleted_iface = iface
                if iface in psutil.net_if_addrs():
                    ok, output = _run_cmd(["ip", "link", "delete", iface], timeout=15)
                    if not ok and "Cannot find device" not in output:
                        return jsonify({"ok": False, "error": output or f"删除虚拟网卡 {iface} 失败"}), 500
        s.delete(line)
        s.commit()
        persisted = _persist_linux_macvlan_state()
        try:
            _reload_after_change()
        except Exception as exc:
            print(f"[lines delete reload] {exc}")
        return jsonify({"ok": True, "data": {"deleted_interface": deleted_iface, "persisted": persisted}})
    finally:
        s.close()


@bp.route("/batch-delete", methods=["POST"])
@login_required
def batch_delete_lines():
    data = request.get_json(silent=True) or {}
    raw_ids = data.get("ids") or []
    if not isinstance(raw_ids, list):
        return jsonify({"ok": False, "error": "ids must be a list"}), 400
    ids = [int(x) for x in raw_ids if str(x).isdigit()]
    if not ids:
        return jsonify({"ok": False, "error": "请选择要删除的线路"}), 400
    s = get_session()
    try:
        lines = s.query(Line).filter(Line.id.in_(ids)).all()
        found_ids = {line.id for line in lines}
        deleted = []
        errors = [{"id": missing_id, "error": "线路不存在"} for missing_id in ids if missing_id not in found_ids]
        for line in lines:
            try:
                deleted.append(_delete_line_record(s, line))
            except Exception as exc:
                errors.append({"id": line.id, "name": line.name, "error": str(exc)})
        if deleted:
            s.commit()
            persisted = _persist_linux_macvlan_state()
            try:
                _reload_after_change()
            except Exception as exc:
                print(f"[lines batch delete reload] {exc}")
        else:
            s.rollback()
            persisted = {"ok": True, "skipped": True}
        return jsonify({"ok": True, "data": {"deleted": deleted, "deleted_count": len(deleted), "errors": errors, "persisted": persisted}})
    finally:
        s.close()


@bp.route("/<int:lid>/test", methods=["GET"])
@login_required
def test_line(lid):
    s = get_session()
    try:
        line = s.query(Line).get(lid)
        if not line:
            return jsonify({"ok": False, "error": "线路不存在"}), 404
        result = proxy_manager.test_outbound_ip(line.public_ip)
        return jsonify({"ok": True, "data": result})
    finally:
        s.close()
