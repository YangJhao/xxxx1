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
import threading
import time
from collections import Counter, defaultdict
from pathlib import Path

import psutil
from flask import Blueprint, jsonify, request
from sqlalchemy.orm import selectinload

from config import DATA_DIR
from models import Line, get_session
from routes.auth import login_required
from services import hyperv_manager
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
DHCP_REQUEST_CACHE = {}
DHCP_RETRY_COOLDOWN_SECONDS = 30
DHCP_BATCH_SIZE = 30
DHCP_BATCH_PAUSE_SECONDS = 3
PROTECTED_MANAGEMENT_IPS = {"169.214.190.43"}
PROTECTED_MANAGEMENT_INTERFACES = {"vEthernet (WAN7-SW)", "WAN7-SW"}
STATIC_MASTER_IPS = {
    "211.230.223.67": "ens2",
    "220.82.161.1": "enp7s0f0",
    "121.154.232.7": "enp7s0f1",
}
STATIC_MASTER_NAMES = set(STATIC_MASTER_IPS.values())
MASTER_LABEL = "\u4e3b\u7f51\u5361"
MAC_CHILDREN_PER_PARENT = 14
MAC_CHILDREN_DEFAULT_CREATE = 14
MAC_CHILDREN_MAX_CREATE = 500
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


def _mac_hex(value: str) -> str:
    text = re.sub(r"[^0-9A-Fa-f]", "", value or "")
    return text.upper() if len(text) == 12 else ""


def _apply_sing_box_config(session) -> dict:
    try:
        status = proxy_manager.reload_config_no_restart(session)
        return {
            "applied": bool(status.get("ok")),
            "restarted": bool(status.get("restarted")),
            "pid": status.get("pid"),
            "message": status.get("message") or "",
        }
    except Exception as exc:
        return {
            "applied": False,
            "restarted": False,
            "pid": None,
            "message": f"sing-box config apply failed: {exc}",
        }


def _format_mac(value: str) -> str:
    text = _mac_hex(value)
    if not text:
        return value or ""
    return "-".join(text[i:i + 2] for i in range(0, 12, 2))


def _mac_for_hyperv(value: str) -> str:
    return _mac_hex(value) or (value or "").replace("-", "").replace(":", "")


def _display_mac(value: str) -> str:
    return _format_mac(value) if os.name == "nt" else (value or "")


def _line_note(interface: str, **meta) -> str:
    parts = [interface or ""]
    for key, value in meta.items():
        if value not in (None, ""):
            if os.name == "nt" and key.lower() == "mac":
                value = _format_mac(str(value))
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
            key = key.strip()
            value = value.strip()
            if os.name == "nt" and key.lower() == "mac":
                value = _format_mac(value)
            meta[key] = value
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
    if ip == "0.0.0.0" or ip.startswith("0."):
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
    m = re.search(r"vEthernet \((.+)-(\d+)\)", text, re.I)
    if m:
        if m.group(1).lower() == "wan-auto":
            return f"vEthernet-{m.group(2)}"
        return f"{m.group(1)}-{m.group(2)}"
    m = re.search(r"^(.+)-(\d+)$", text)
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
        if "WAN-AUTO-" in raw or re.match(r"^vEthernet-\d+$", raw):
            return "以太网 4"
        if "Slot01 x8" in raw:
            return "Slot01 x8"
        if "以太网 5" in raw:
            return "以太网 5"
    display = _format_line_name(interface_name)
    m = re.match(r"^(.+)-(\d+)$", display)
    if m:
        return m.group(1)
    m = re.search(r"以太网\s*([567])", display)
    if m:
        return f"以太网 {m.group(1)}"
    return ""


def _is_master_interface(interface_name: str) -> bool:
    text = interface_name or ""
    if os.name == "nt":
        raw = text.strip()
        display = _format_line_name(raw)
        if raw in {ETHERNET_4_LABEL, ETHERNET_5_LABEL, "Slot01 x8"}:
            return True
        if display in {ETHERNET_4_LABEL, ETHERNET_5_LABEL, "Slot01 x8"}:
            return True
        if raw.startswith("vEthernet (WAN-") and raw.endswith("-External)"):
            return True
    return bool(
        text in STATIC_MASTER_NAMES
        or
        re.search(r"WAN[567]-SW", text, re.I)
        or re.search(r"以太网\s*[567]$", text)
        or text.endswith("-主网卡")
    )


def _adapter_index(interface_name: str) -> int:
    text = _format_line_name(interface_name or "")
    m = re.search(r"-(\d+)$", text)
    if m:
        return int(m.group(1))
    m = re.search(r"WAN-AUTO-(\d{1,3})", interface_name or "", re.I)
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
    if os.name == "nt" and re.match(r"^vEthernet-(\d+)$", display):
        return f"10.42.4.{int(display.rsplit('-', 1)[1])}"
    if os.name == "nt" and re.match(r"^Slot01 x8-(\d+)$", display):
        return f"10.42.8.{int(display.rsplit('-', 1)[1])}"
    m = re.search(r"以太网\s*([567])-(\d+)", display)
    if m:
        return f"10.42.{m.group(1)}.{int(m.group(2))}"
    m = re.search(r"以太网\s*([567])-主网卡", display)
    if m:
        return f"10.42.{m.group(1)}.254"
    return "0.0.0.0"


def _is_generated_child_interface(interface_name: str) -> bool:
    text = interface_name or ""
    master_suffix = f"-{MASTER_LABEL}"
    if text.endswith(master_suffix):
        text = text[:-len(master_suffix)]
    return bool(
        re.search(r"-\d+$", text)
        or text.startswith(("dummy42-", "v42", "macv42-"))
    )


def _linux_fixed_child_slot(interface_name: str) -> tuple[str, int]:
    if os.name == "nt":
        return "", 0
    match = re.match(r"^(.+)-(\d+)$", (interface_name or "").strip())
    if not match:
        return "", 0
    parent = match.group(1)
    idx = int(match.group(2))
    if parent not in LINUX_PARENT_SEGMENTS:
        return "", 0
    if idx < 1:
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
    match = re.match(r"^(.+)-(\d+)$", text)
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


def _windows_line_display_name(interface_name: str, adapter_name: str = "") -> str:
    if os.name != "nt":
        return _format_line_name(interface_name or adapter_name)
    raw = (interface_name or "").strip()
    name = (adapter_name or "").strip()
    if not name:
        match = re.match(r"^vEthernet \((.+)\)$", raw)
        name = match.group(1) if match else raw
    if re.match(r"^WAN-AUTO-\d{1,3}$", name, re.I):
        return f"vEthernet-{int(name.rsplit('-', 1)[1]):03d}"
    match = re.match(r"^(.+)-(\d{1,3})$", name)
    if match:
        return f"{match.group(1)}-{int(match.group(2)):03d}"
    return _format_line_name(raw or name)


def _windows_parent_for_display(display_name: str, switch_name: str = "") -> str:
    if switch_name:
        return _windows_parent_label_for_switch(switch_name, display_name)
    if re.match(r"^vEthernet-\d{1,3}$", display_name or "", re.I):
        return ETHERNET_4_LABEL
    if (display_name or "").startswith(f"{ETHERNET_5_LABEL}-"):
        return ETHERNET_5_LABEL
    if (display_name or "").startswith("Slot01 x8-"):
        return "Slot01 x8"
    return _parent_adapter(display_name)


def _windows_internal_ip_for_display(display_name: str, interface_name: str = "") -> str:
    idx = _adapter_index(display_name) or _adapter_index(interface_name)
    parent = _windows_parent_for_display(display_name)
    if parent == ETHERNET_4_LABEL:
        segment = 4
    elif parent == ETHERNET_5_LABEL:
        segment = 5
    elif parent == "Slot01 x8":
        segment = 8
    else:
        segment = _parent_segment(parent or display_name)
    return f"10.42.{segment}.{idx or 254}"


def _windows_normalized_slot_name(parent: str, idx: int) -> str:
    if idx < 1:
        return ""
    if parent == ETHERNET_4_LABEL:
        return f"vEthernet-{idx:03d}"
    if parent == ETHERNET_5_LABEL:
        return f"{ETHERNET_5_LABEL}-{idx:03d}"
    if parent == "Slot01 x8":
        return f"Slot01 x8-{idx:03d}"
    return ""


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
    m = re.match(r"^vEthernet \((.+)\)$", text)
    if m:
        return m.group(1)
    m = re.match(r"^vEthernet-(\d{1,3})$", text, re.I)
    if m:
        return f"WAN-AUTO-{int(m.group(1)):03d}"
    m = re.match(r"^(Slot01 x8|.+? 5)-(\d{1,3})$", text, re.I)
    if m:
        return f"{m.group(1)}-{int(m.group(2)):03d}"
    m = re.match(r"^WAN-AUTO-(\d{1,3})$", text, re.I)
    if m:
        return f"WAN-AUTO-{int(m.group(1)):03d}"
    m = re.search(r"以太网\s*([567])-(\d{1,3})", text)
    if m:
        return f"WAN{m.group(1)}-MAC{int(m.group(2)):02d}"
    m = re.search(r"WAN([567])-MAC(\d{1,2})", text, re.I)
    if m:
        return f"WAN{m.group(1)}-MAC{int(m.group(2)):02d}"
    return ""


def _windows_adapter_alias_for_line(line) -> str:
    saved = (_note_interface(line.note) or "").strip()
    candidates = [
        saved,
        line.name or "",
        _hyperv_adapter_name(saved),
        _hyperv_adapter_name(line.name or ""),
    ]
    seen = set()
    aliases = []
    for value in candidates:
        value = (value or "").strip()
        if not value or value in seen:
            continue
        seen.add(value)
        aliases.append(value)
        if not value.lower().startswith("vethernet ("):
            aliases.append(f"vEthernet ({value})")
    script = rf"""
$ErrorActionPreference = 'Stop'
$aliases = ConvertFrom-Json @'
{json.dumps(aliases, ensure_ascii=False)}
'@
foreach ($alias in $aliases) {{
  if (-not $alias) {{ continue }}
  $adapter = Get-NetAdapter -Name $alias -ErrorAction SilentlyContinue
  if ($adapter) {{
    [pscustomobject]@{{ name=$adapter.Name; status=$adapter.Status.ToString(); mac=$adapter.MacAddress }} | ConvertTo-Json -Depth 3
    exit 0
  }}
}}
throw ('未找到线路对应的 Windows 网卡：' + ($aliases -join ', '))
"""
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],
        capture_output=True,
        text=True,
        timeout=20,
        encoding="utf-8",
        errors="replace",
    )
    if result.returncode != 0:
        raise RuntimeError((result.stderr or result.stdout or "").strip() or "读取网卡失败")
    data = json.loads(result.stdout or "{}")
    return data.get("name") or ""


def _windows_set_line_adapter_state(line, enabled: bool) -> dict:
    if os.name != "nt":
        raise RuntimeError("当前功能只支持 Windows 网卡。")
    iface = _windows_adapter_alias_for_line(line)
    if _line_is_master_fast(line, iface):
        raise ValueError("主网卡不能禁用。")
    if (line.public_ip or "") in PROTECTED_MANAGEMENT_IPS:
        raise ValueError("主 IP 线路不能禁用。")
    if iface in PROTECTED_MANAGEMENT_INTERFACES:
        raise ValueError("主网卡线路不能禁用。")
    action = "Enable-NetAdapter" if enabled else "Disable-NetAdapter"
    script = rf"""
$ErrorActionPreference = 'Stop'
$alias = {json.dumps(iface, ensure_ascii=False)}
$protectedIps = ConvertFrom-Json @'
{json.dumps(sorted(PROTECTED_MANAGEMENT_IPS), ensure_ascii=False)}
'@
$adapter = Get-NetAdapter -Name $alias -ErrorAction Stop
$ips = @(Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty IPAddress)
foreach ($ip in $ips) {{
  if ($protectedIps -contains $ip) {{ throw "禁止禁用主 IP 网卡：$ip / $alias" }}
}}
{action} -Name $alias -Confirm:$false
Start-Sleep -Seconds 1
$fresh = Get-NetAdapter -Name $alias -ErrorAction Stop
$freshIps = @(Get-NetIPAddress -InterfaceIndex $fresh.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty IPAddress)
[pscustomobject]@{{
  interface = $fresh.Name
  status = $fresh.Status.ToString()
  mac = $fresh.MacAddress
  ips = $freshIps
}} | ConvertTo-Json -Depth 4
"""
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],
        capture_output=True,
        text=True,
        timeout=45,
        encoding="utf-8",
        errors="replace",
    )
    if result.returncode != 0:
        raise RuntimeError((result.stderr or result.stdout or "").strip() or "网卡状态切换失败")
    data = json.loads(result.stdout or "{}")
    meta = _note_meta(line.note)
    if data.get("mac"):
        meta["mac"] = _display_mac(data.get("mac") or "")
    if data.get("interface"):
        meta["adapter_status"] = data.get("status") or ""
        line.note = _line_note(data.get("interface") or iface, **meta)
    line.status = 1 if enabled else 0
    return data


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
                item["mac"] = _display_mac(addr.address)
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
        "mac": _display_mac(iface_info.get("mac", "")),
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
        return proxy_manager.reload_config_no_restart(session)
    return {"ok": False, "restarted": False, "pid": None, "message": "sing-box is not running; config written only"}


def _reload_after_change_background():
    def worker():
        try:
            _reload_after_change()
        except Exception as exc:
            print(f"[proxy reload background] {exc}")

    threading.Thread(target=worker, daemon=True).start()


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


def _linux_public_addr_rows(iface: str, dhcp_only_for_child: bool = True) -> list[dict]:
    rows = []
    for row in _linux_ipv4_rows(iface):
        ip = row.get("local") or ""
        if not _is_public_candidate(ip):
            continue
        if dhcp_only_for_child and _is_linux_fixed_child_interface(iface) and not row.get("dynamic"):
            continue
        rows.append(row)
    rows.sort(key=lambda row: (0 if row.get("dynamic") else 1, -(int(row.get("preferred_life_time") or 0))))
    return rows


def _linux_public_ips(iface: str, dhcp_only_for_child: bool = True) -> list[str]:
    return [row.get("local") or "" for row in _linux_public_addr_rows(iface, dhcp_only_for_child) if row.get("local")]


def _linux_public_addr_info(iface: str) -> dict:
    for row in _linux_public_addr_rows(iface):
        ip = row.get("local") or ""
        if _is_public_candidate(ip):
            return {
                "ip": ip,
                "prefix": int(row.get("prefixlen") or 0) or "",
                "dynamic": bool(row.get("dynamic")),
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
            timeout=1,
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


def _saved_macvlan_row(iface: str) -> dict:
    if os.name == "nt" or not iface:
        return {}
    for path in (MACVLAN_STATE_FILE, HOST_MACVLAN_STATE_FILE):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        for row in payload.get("rows") or []:
            if row.get("iface") == iface:
                return row
    return {}


def _ensure_linux_child_interface(iface: str, mac: str = "") -> tuple[bool, str, str]:
    if os.name == "nt":
        return True, mac, ""
    parent, idx = _linux_fixed_child_slot(iface)
    if not parent or not idx:
        return False, mac, "只有受管虚拟 MAC 网卡可以操作"
    addrs = psutil.net_if_addrs()
    if iface in addrs:
        current_mac = ""
        for addr in addrs.get(iface, []):
            if getattr(psutil, "AF_LINK", object()) == addr.family:
                current_mac = addr.address
                break
        return True, current_mac or mac, ""
    if parent not in addrs:
        return False, mac, f"主网卡 {parent} 不存在"
    saved = _saved_macvlan_row(iface)
    target_mac = (mac or saved.get("mac") or _generated_mac(_parent_segment(parent), idx)).lower()
    ok, output = _run_cmd(["ip", "link", "add", "link", parent, "name", iface, "address", target_mac, "type", "macvlan", "mode", "bridge"], timeout=15)
    if not ok and "File exists" not in output:
        return False, target_mac, output or f"创建虚拟网卡 {iface} 失败"
    ok, output = _run_cmd(["ip", "link", "set", "dev", iface, "up"], timeout=10)
    if not ok:
        return False, target_mac, output or f"启动虚拟网卡 {iface} 失败"
    return True, target_mac, ""


def _persist_linux_macvlan_state_safe() -> dict:
    try:
        return _persist_linux_macvlan_state()
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def _persist_linux_macvlan_state_quick() -> dict:
    if os.name == "nt":
        return {"ok": True, "skipped": True}
    try:
        ifaces = _iface_snapshot()
        old_rows = {}
        for path in (MACVLAN_STATE_FILE, HOST_MACVLAN_STATE_FILE):
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                continue
            old_rows = {row.get("iface"): row for row in payload.get("rows") or [] if row.get("iface")}
            if old_rows:
                break
        rows = []
        managed_ifaces = {
            iface: _linux_fixed_child_slot(iface)
            for iface in ifaces
            if _linux_fixed_child_slot(iface)[0]
        }
        for parent in LINUX_PARENT_SEGMENTS:
            child_slots = {
                idx: iface
                for iface, (slot_parent, idx) in managed_ifaces.items()
                if slot_parent == parent
            }
            for idx in sorted(child_slots):
                iface = child_slots[idx]
                info = ifaces.get(iface, {})
                prefix_by_ip = {
                    row.get("local") or "": int(row.get("prefixlen") or 0) or ""
                    for row in _linux_public_addr_rows(iface)
                }
                public_ips = _linux_public_ips(iface)
                ip = public_ips[0] if public_ips else ""
                prefix = prefix_by_ip.get(ip) or ""
                old = old_rows.get(iface, {})
                table, priority = _linux_policy_table(parent, idx)
                internal_ip = _linux_managed_internal_ip(iface)
                try:
                    network = str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False)) if ip and prefix else ""
                except Exception:
                    network = ""
                rows.append({
                    "parent": parent,
                    "idx": idx,
                    "iface": iface,
                    "mac": (info.get("mac") or old.get("mac") or "").lower(),
                    "ip": ip,
                    "ips": public_ips,
                    "prefix": prefix,
                    "internal_ip": internal_ip,
                    "internal_prefix": 32 if internal_ip else "",
                    "router": old.get("router") if old.get("ip") == ip else "",
                    "table": old.get("table") or table,
                    "priority": old.get("priority") or priority,
                    "network": network,
                    "public_ok": bool(public_ips),
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
        return {"ok": True, "rows": len(rows), "public_count": sum(len(row.get("ips") or []) for row in rows)}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def _line_iface_fast(line) -> str:
    return (_note_interface(line.note) or line.name or "").replace(f"-{MASTER_LABEL}", "").strip()


def _line_pair(line) -> tuple[str, str]:
    return (_line_iface_fast(line), line.public_ip or "0.0.0.0")


def _line_is_master_fast(line, iface: str = "") -> bool:
    iface = iface or _line_iface_fast(line)
    if os.name == "nt":
        display = _windows_line_display_name(iface)
        if display in {ETHERNET_4_LABEL, ETHERNET_5_LABEL, "Slot01 x8"}:
            return True
        if (line.name or "") in {ETHERNET_4_LABEL, ETHERNET_5_LABEL, "Slot01 x8"}:
            return True
    if os.name != "nt" and iface:
        if iface in STATIC_MASTER_NAMES:
            return True
        if not _is_generated_child_interface(iface) and iface in psutil.net_if_addrs():
            return True
    return bool(_has_master_label(line.name or "") or _has_master_label(line.note or "") or line.public_ip in STATIC_MASTER_IPS)


def _line_live_info(iface: str) -> dict:
    info = _iface_snapshot().get(iface, {})
    ipv4 = info.get("ipv4") or []
    public_ips = _linux_public_ips(iface) if os.name != "nt" else [ip for ip in ipv4 if _is_public_candidate(ip)]
    lease_ip = next((ip for ip in ipv4 if ip.startswith("169.254.")), "")
    return {
        "iface_info": info,
        "public_ip": public_ips[0] if public_ips else "0.0.0.0",
        "public_ips": public_ips,
        "lease_ip": lease_ip,
        "mac": _display_mac(info.get("mac") or ""),
        "parent": info.get("parent_adapter") or _parent_key(iface),
    }


def _update_line_from_iface(line, iface: str, dhcp_result: dict | None = None) -> dict:
    live = _line_live_info(iface)
    current_ip = line.public_ip or ""
    result_ip = (dhcp_result or {}).get("public_ip") or ""
    public_ip = result_ip if _is_public_candidate(result_ip) else current_ip if current_ip in live["public_ips"] else live["public_ip"]
    line.public_ip = public_ip
    line.status = 1 if public_ip and public_ip != "0.0.0.0" else 0
    line.name = _windows_line_display_name(iface) if os.name == "nt" else _format_line_name(iface)
    line.internal_ip = (
        _windows_internal_ip_for_display(line.name, iface)
        if os.name == "nt"
        else _linux_managed_internal_ip(iface) or live["iface_info"].get("internal_ip") or _generated_internal_ip_for_line(line, line.name)
    )
    lease_ip = (dhcp_result or {}).get("lease_ip") or live["lease_ip"]
    line.note = _line_note(
        iface,
        mac=_display_mac(live["mac"] or _note_meta(line.note).get("mac") or ""),
        parent=_windows_parent_for_display(line.name) if os.name == "nt" else live["parent"],
        dhcp="ok" if line.status else "pending",
        lease_ip=lease_ip,
        ip=public_ip if public_ip and public_ip != "0.0.0.0" else "",
    )
    return {
        "id": line.id,
        "name": line.name,
        "interface": iface,
        "mac": _display_mac(live["mac"] or _note_meta(line.note).get("mac") or ""),
        "public_ip": line.public_ip,
        "lease_ip": lease_ip,
        "dhcp": dhcp_result or {},
    }


def _linux_managed_internal_ip(iface: str) -> str:
    if os.name == "nt" or not _is_linux_managed_interface(iface):
        return ""
    return _generated_internal_ip_for_interface(iface)


def _ensure_linux_internal_ips() -> dict:
    if os.name == "nt":
        return {"ok": True, "skipped": True}
    applied = []
    errors = []
    managed_children = [
        iface
        for iface in psutil.net_if_addrs()
        if _linux_fixed_child_slot(iface)[0]
    ]
    for parent in LINUX_PARENT_SEGMENTS:
        targets = [parent] + [
            iface for iface in managed_children if _linux_fixed_child_slot(iface)[0] == parent
        ]
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
    managed_ifaces = {
        iface: _linux_fixed_child_slot(iface)
        for iface in ifaces
        if _linux_fixed_child_slot(iface)[0]
    }
    for parent in LINUX_PARENT_SEGMENTS:
        child_slots = {
            idx: iface
            for iface, (slot_parent, idx) in managed_ifaces.items()
            if slot_parent == parent
        }
        for idx in sorted(child_slots):
            iface = child_slots[idx]
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
            label = _windows_short_master_name(item.get("name") or "") or item.get("label") or item.get("name") or ""
            parent_name = label.replace(f"-{MASTER_LABEL}", "") if label else item.get("parent_name") or ""
            mapping[ip] = {**item, "label": label, "parent_name": parent_name}
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
$netAdapters = @(Get-NetAdapter -ErrorAction SilentlyContinue | Select-Object Name,MacAddress)
function Normalize-Mac([string]$value) {
  if (-not $value) { return '' }
  return (($value -replace '[^0-9A-Fa-f]', '').ToUpperInvariant())
}
Get-VMNetworkAdapter -ManagementOS -ErrorAction SilentlyContinue |
  Where-Object { $_.Name -match '^WAN-AUTO-\d{3}$' -or $_.Name -match '^.+-\d{3}$' } |
  Sort-Object SwitchName,Name |
  ForEach-Object {
    $adapter = $_
    $mac = Normalize-Mac $adapter.MacAddress
    $net = $netAdapters | Where-Object { (Normalize-Mac $_.MacAddress) -eq $mac } | Select-Object -First 1
    $alias = if ($net) { $net.Name } else { 'vEthernet (' + $adapter.Name + ')' }
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
        display_name = _windows_line_display_name(interface, raw_name)
        ips = row.get("ips") or []
        if isinstance(ips, str):
            ips = [ips]
        public_ip = next((ip for ip in ips if _is_public_candidate(ip)), "")
        lease_ip = next((ip for ip in ips if ip and ip.startswith("169.254.")), "")
        parent = _windows_parent_for_display(display_name, row.get("switch") or "")
        slots.append({
            "interface": interface,
            "hyperv_name": raw_name,
            "switch_name": row.get("switch") or "",
            "display_name": display_name,
            "raw_display_name": display_name,
            "parent_adapter": parent,
            "adapter_index": _adapter_index(display_name),
            "ip": public_ip,
            "mac": _display_mac(row.get("mac") or ""),
            "internal_ip": _windows_internal_ip_for_display(display_name, interface),
            "is_master": False,
            "is_slot": True,
            "dhcp_state": "ok" if public_ip else "pending",
            "lease_ip": lease_ip,
        })
    grouped = defaultdict(list)
    for slot in slots:
        grouped[slot.get("parent_adapter") or ""].append(slot)
    for parent, group in grouped.items():
        used = set()
        pending = []

        def raw_index(slot: dict) -> int:
            return (
                _adapter_index(slot.get("raw_display_name") or "")
                or _adapter_index(slot.get("hyperv_name") or "")
                or _adapter_index(slot.get("interface") or "")
            )

        def apply_index(slot: dict, idx: int):
            normalized = _windows_normalized_slot_name(parent, idx)
            if normalized:
                slot["display_name"] = normalized
                slot["adapter_index"] = idx
                slot["internal_ip"] = _windows_internal_ip_for_display(normalized, slot.get("interface") or "")

        for slot in sorted(group, key=lambda item: (raw_index(item) or 9999, item.get("interface") or "", item.get("mac") or "")):
            idx = raw_index(slot)
            if 1 <= idx <= len(group) and idx not in used:
                used.add(idx)
                apply_index(slot, idx)
            else:
                pending.append(slot)
        next_idx = 1
        for slot in pending:
            while next_idx in used:
                next_idx += 1
            used.add(next_idx)
            apply_index(slot, next_idx)
    return slots


def _windows_slot_maps(slots: list[dict]) -> dict:
    maps = {"interface": {}, "mac": {}, "name": {}, "ip": {}}
    if os.name != "nt":
        return maps
    for slot in slots or []:
        names = {
            slot.get("interface") or "",
            slot.get("display_name") or "",
            slot.get("raw_display_name") or "",
            slot.get("hyperv_name") or "",
        }
        if slot.get("hyperv_name"):
            names.add(f"vEthernet ({slot.get('hyperv_name')})")
        for name in names:
            if name:
                maps["interface"][name] = slot
                maps["name"][name] = slot
        mac = _mac_hex(slot.get("mac") or "")
        if mac:
            maps["mac"][mac] = slot
        ip = slot.get("ip") or ""
        if ip:
            maps["ip"][ip] = slot
    return maps


def _windows_slot_for_item(item: dict | None, slot_maps: dict) -> dict:
    if os.name != "nt" or not item:
        return {}
    for key in ("interface", "display_name", "raw_interface", "name"):
        value = item.get(key) or ""
        slot = (slot_maps.get("interface") or {}).get(value) or (slot_maps.get("name") or {}).get(value)
        if slot:
            return slot
    mac = _mac_hex(item.get("mac") or "")
    if mac:
        slot = (slot_maps.get("mac") or {}).get(mac)
        if slot:
            return slot
    ip = item.get("ip") or item.get("public_ip") or ""
    if ip:
        slot = (slot_maps.get("ip") or {}).get(ip)
        if slot:
            return slot
    return {}


def _windows_slot_for_line(line, slot_maps: dict, detected: dict | None = None, iface_info: dict | None = None) -> dict:
    if os.name != "nt":
        return {}
    slot = _windows_slot_for_item(detected, slot_maps) or _windows_slot_for_item(iface_info, slot_maps)
    if slot:
        return slot
    note_meta = _note_meta(line.note)
    candidates = {
        _note_interface(line.note),
        line.name or "",
        (line.name or "").replace(f"-{MASTER_LABEL}", ""),
    }
    for value in candidates:
        if value:
            slot = (slot_maps.get("interface") or {}).get(value) or (slot_maps.get("name") or {}).get(value)
            if slot:
                return slot
    mac = _mac_hex(note_meta.get("mac") or "")
    if mac:
        slot = (slot_maps.get("mac") or {}).get(mac)
        if slot:
            return slot
    return (slot_maps.get("ip") or {}).get(line.public_ip or "") or {}


def _apply_windows_slot(item: dict, slot: dict) -> dict:
    if os.name != "nt" or not slot:
        return item
    item.update({
        "interface": slot.get("interface") or item.get("interface") or "",
        "display_name": slot.get("display_name") or item.get("display_name") or "",
        "parent_adapter": slot.get("parent_adapter") or item.get("parent_adapter") or "",
        "adapter_index": slot.get("adapter_index") or item.get("adapter_index") or 0,
        "mac": _display_mac(slot.get("mac") or item.get("mac") or ""),
        "internal_ip": slot.get("internal_ip") or item.get("internal_ip") or "",
        "dhcp_state": slot.get("dhcp_state") or item.get("dhcp_state") or "",
        "lease_ip": slot.get("lease_ip") or item.get("lease_ip") or "",
        "is_slot": True,
    })
    return item


def _normalize_windows_detected_items(items: list[dict], slots: list[dict]) -> list[dict]:
    if os.name != "nt":
        return items
    slot_maps = _windows_slot_maps(slots)
    normalized = []
    for item in items or []:
        item = dict(item)
        slot = _windows_slot_for_item(item, slot_maps)
        if slot:
            _apply_windows_slot(item, slot)
        normalized.append(item)
    return normalized


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
        public_ip = next(iter(_linux_public_ips(iface)), "")
        lease_ip = next((ip for ip in ipv4 if ip and ip.startswith("169.254.")), "")
        slots.append({
            "interface": iface,
            "display_name": display_name,
            "parent_adapter": parent,
            "adapter_index": slot_idx,
            "ip": public_ip,
            "mac": _display_mac(info.get("mac") or ""),
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
    used = []
    pattern = re.compile(rf"^{re.escape(base)}-(\d+)$")
    for iface in existing:
        match = pattern.match(iface)
        if match:
            used.append(int(match.group(1)))
    for idx in range(max(used or [0]) + 1, 10000):
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


def _dhcp_client_processes(iface: str) -> list[psutil.Process]:
    if os.name == "nt" or not iface:
        return []
    matches = []
    try:
        current_pid = os.getpid()
        for proc in psutil.process_iter(["pid", "name", "cmdline"]):
            if proc.info.get("pid") == current_pid:
                continue
            name = proc.info.get("name") or ""
            cmdline = [str(part) for part in (proc.info.get("cmdline") or [])]
            if not any(client in name for client in ("dhcpcd", "dhclient", "udhcpc")):
                continue
            if iface not in cmdline:
                continue
            matches.append(proc)
    except Exception:
        return matches
    return matches


def _dhcp_client_running(iface: str) -> bool:
    return bool(_dhcp_client_processes(iface))


def _dhcp_unit_name(iface: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "-", iface or "unknown")
    return f"42ipwin-dhcp-{safe}.service"


def _dhcp_unit_names(iface: str) -> list[str]:
    service = _dhcp_unit_name(iface)
    return [service, service.removesuffix(".service") + ".scope"]


def _systemd_unit_active(unit: str) -> bool:
    if os.name == "nt" or not shutil.which("systemctl"):
        return False
    try:
        proc = subprocess.run(["systemctl", "is-active", "--quiet", unit], timeout=3)
        return proc.returncode == 0
    except Exception:
        return False


def _stop_dhcp_client(iface: str) -> dict:
    result = {"units": [], "terminated": [], "killed": []}
    if os.name == "nt" or not iface:
        return result
    if shutil.which("systemctl"):
        for unit in _dhcp_unit_names(iface):
            try:
                if _systemd_unit_active(unit):
                    subprocess.run(["systemctl", "stop", unit], capture_output=True, text=True, timeout=8)
                    result["units"].append(unit)
                subprocess.run(["systemctl", "reset-failed", unit], capture_output=True, text=True, timeout=5)
            except Exception:
                pass
    procs = _dhcp_client_processes(iface)
    for proc in procs:
        try:
            proc.terminate()
            result["terminated"].append(proc.pid)
        except Exception:
            pass
    _, alive = psutil.wait_procs(procs, timeout=2)
    for proc in alive:
        try:
            proc.kill()
            result["killed"].append(proc.pid)
        except Exception:
            pass
    return result


def _public_ip_on_interface(iface: str) -> str:
    if os.name != "nt":
        public_ips = _linux_public_ips(iface)
        if public_ips:
            return public_ips[0]
    info = _iface_snapshot().get(iface, {})
    return next((ip for ip in info.get("ipv4") or [] if _is_public_candidate(ip)), "")


def _wait_for_interface_public_ip(iface: str, timeout: int) -> str:
    deadline = time.time() + max(1, timeout)
    while time.time() < deadline:
        public_ip = _public_ip_on_interface(iface)
        if public_ip:
            return public_ip
        time.sleep(1)
    return _public_ip_on_interface(iface)


def _start_dhcp_systemd_service(iface: str, client: str, timeout: int, wait_timeout: int | None = None) -> dict:
    unit = _dhcp_unit_name(iface)
    active_unit = next((name for name in _dhcp_unit_names(iface) if _systemd_unit_active(name)), "")
    if active_unit:
        public_ip = _wait_for_interface_public_ip(iface, min(timeout, 5))
        if public_ip:
            return {
                "ok": True,
                "message": f"DHCP renewal already running: {active_unit}",
                "unit": active_unit,
                "public_ip": public_ip,
                "skipped": True,
            }
        _stop_dhcp_client(iface)
    if _dhcp_client_running(iface):
        public_ip = _wait_for_interface_public_ip(iface, min(timeout, 5))
        if public_ip:
            return {
                "ok": True,
                "message": f"Existing DHCP renewal process is running for {iface}",
                "unit": unit,
                "public_ip": public_ip,
                "skipped": True,
            }
        _stop_dhcp_client(iface)
    name = os.path.basename(client)
    if name == "dhcpcd":
        client_args = [client, "-4", "-B", "-t", "0", "-q", iface]
    elif name == "dhclient":
        client_args = [client, "-4", "-d", "-v", iface]
    else:
        client_args = [client, "-f", "-i", iface, "-t", "0", "-T", "3"]
    subprocess.run(["systemctl", "reset-failed", unit], capture_output=True, text=True, timeout=5)
    args = [
        "systemd-run",
        "--quiet",
        "--unit",
        unit.removesuffix(".service"),
        "--collect",
        "--property",
        "Restart=always",
        "--property",
        "RestartSec=10",
        "--property",
        "KillMode=process",
        "--property",
        "Description=42IPwin DHCP renewal for " + iface,
        *client_args,
    ]
    proc = subprocess.run(args, capture_output=True, text=True, timeout=10)
    message = ((proc.stdout or "") + (proc.stderr or "")).strip()
    wait_timeout = timeout if wait_timeout is None else wait_timeout
    public_ip = _wait_for_interface_public_ip(iface, wait_timeout) if wait_timeout > 0 else _public_ip_on_interface(iface)
    ok = proc.returncode == 0 or _systemd_unit_active(unit) or bool(public_ip)
    return {"ok": ok, "message": message, "unit": unit, "public_ip": public_ip, "started": proc.returncode == 0}


def _request_dhcp_for_interfaces(interface_names: list[str], timeout: int = 12) -> dict:
    if os.name == "nt":
        return _windows_request_dhcp_for_interfaces(interface_names, timeout=timeout)
    client = shutil.which("dhcpcd") or shutil.which("dhclient") or shutil.which("udhcpc")
    if not client or not interface_names:
        return {}
    interface_names = list(dict.fromkeys([iface for iface in interface_names if iface]))
    use_systemd_service = os.name != "nt" and bool(shutil.which("systemd-run"))
    results = {}
    batch_size = max(1, DHCP_BATCH_SIZE)
    for batch_no, start in enumerate(range(0, len(interface_names), batch_size), start=1):
        batch = interface_names[start:start + batch_size]
        procs = {}
        pending = set()
        for iface in batch:
            try:
                public_ip = _public_ip_on_interface(iface)
                unit = _dhcp_unit_name(iface)
                active_unit = next((name for name in _dhcp_unit_names(iface) if _systemd_unit_active(name)), "")
                dhcp_active = bool(active_unit) or _dhcp_client_running(iface)
                if public_ip and dhcp_active:
                    results[iface] = {
                        "ok": True,
                        "message": "DHCP renewal already running; refreshed current public IP",
                        "public_ip": public_ip,
                        "unit": active_unit or unit,
                        "batch": batch_no,
                        "skipped": True,
                    }
                    continue
                now = time.time()
                last_request = DHCP_REQUEST_CACHE.get(iface, 0)
                if public_ip and now - last_request < DHCP_RETRY_COOLDOWN_SECONDS:
                    results[iface] = {
                        "ok": True,
                        "message": "DHCP request cooldown; refreshed current public IP",
                        "public_ip": public_ip,
                        "batch": batch_no,
                        "skipped": True,
                    }
                    continue
                stale = {}
                if dhcp_active and not public_ip:
                    stale = _stop_dhcp_client(iface)
                DHCP_REQUEST_CACHE[iface] = now
                if use_systemd_service:
                    result = _start_dhcp_systemd_service(iface, client, timeout, wait_timeout=0)
                    result["batch"] = batch_no
                    if stale:
                        result["stale_stopped"] = stale
                    results[iface] = result
                    if not result.get("public_ip"):
                        pending.add(iface)
                    continue
                if _dhcp_client_running(iface):
                    stale = _stop_dhcp_client(iface)
                if os.path.basename(client) == "dhcpcd":
                    args = [client, "-4", "-t", str(timeout), "-q", iface]
                elif os.path.basename(client) == "dhclient":
                    args = [client, "-4", "-1", "-v", iface]
                else:
                    args = [client, "-i", iface, "-q", "-t", "3", "-T", "3"]
                procs[iface] = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                if stale:
                    results[iface] = {"ok": True, "message": "restarted stale DHCP client", "stale_stopped": stale, "batch": batch_no}
            except Exception as exc:
                procs[iface] = exc
        deadline = time.time() + timeout + 3
        while pending and time.time() < deadline:
            for iface in list(pending):
                public_ip = _public_ip_on_interface(iface)
                if public_ip:
                    results.setdefault(iface, {})["public_ip"] = public_ip
                    results[iface]["ok"] = True
                    pending.discard(iface)
            if pending:
                time.sleep(1)
        for iface in list(pending):
            results.setdefault(iface, {})["public_ip"] = _public_ip_on_interface(iface)
            if not results[iface].get("public_ip"):
                stopped = _stop_dhcp_client(iface)
                results[iface]["ok"] = False
                results[iface]["message"] = (results[iface].get("message") or "DHCP request timed out; stopped stale client").strip()
                results[iface]["stale_stopped_after_timeout"] = stopped
        for iface, proc in procs.items():
            if isinstance(proc, Exception):
                results[iface] = {"ok": False, "message": str(proc), "batch": batch_no}
                continue
            remain = max(1, int(deadline - time.time()))
            try:
                out, err = proc.communicate(timeout=remain)
                result = results.get(iface) or {}
                result.update({
                    "ok": proc.returncode == 0 or bool(_public_ip_on_interface(iface)),
                    "message": ((out or "") + (err or "")).strip(),
                    "public_ip": _public_ip_on_interface(iface),
                    "batch": batch_no,
                })
                results[iface] = result
            except subprocess.TimeoutExpired:
                proc.kill()
                out, err = proc.communicate()
                result = results.get(iface) or {}
                result.update({"ok": False, "message": "DHCP 鑾峰彇 IP 瓒呮椂", "public_ip": _public_ip_on_interface(iface), "batch": batch_no})
                results[iface] = result
        if start + batch_size < len(interface_names):
            time.sleep(DHCP_BATCH_PAUSE_SECONDS)
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


def _windows_request_dhcp_for_interfaces(interface_names: list[str], timeout: int = 20) -> dict:
    if os.name != "nt":
        return {}
    aliases = list(dict.fromkeys([iface for iface in interface_names if iface]))
    if not aliases:
        return {}
    script = rf"""
$ErrorActionPreference = 'Continue'
$aliases = @({",".join(json.dumps(alias) for alias in aliases)})
$started = @{{}}
foreach ($alias in $aliases) {{
  $net = Get-NetAdapter -Name $alias -ErrorAction SilentlyContinue
  if (-not $net) {{
    $started[$alias] = [pscustomobject]@{{ Missing=$true; Message='adapter not found' }}
    continue
  }}
  try {{ Enable-NetAdapter -Name $alias -Confirm:$false -ErrorAction SilentlyContinue | Out-Null }} catch {{}}
  try {{ Set-NetIPInterface -InterfaceAlias $alias -AddressFamily IPv4 -Dhcp Enabled -ErrorAction SilentlyContinue | Out-Null }} catch {{}}
  try {{ Set-DnsClientServerAddress -InterfaceAlias $alias -ResetServerAddresses -ErrorAction SilentlyContinue | Out-Null }} catch {{}}
  try {{ & netsh.exe interface ipv4 set address name="$alias" source=dhcp | Out-Null }} catch {{}}
  try {{ & netsh.exe interface ipv4 set dnsservers name="$alias" source=dhcp | Out-Null }} catch {{}}
  try {{
    Start-Process -FilePath 'ipconfig.exe' -ArgumentList @('/renew', $alias) -WindowStyle Hidden | Out-Null
    $started[$alias] = [pscustomobject]@{{ Missing=$false; Message='dhcp requested' }}
  }} catch {{
    $started[$alias] = [pscustomobject]@{{ Missing=$false; Message=$_.Exception.Message }}
  }}
}}
$results = foreach ($alias in $aliases) {{
  $entry = $started[$alias]
  $rows = @(Get-NetIPAddress -InterfaceAlias $alias -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object IPAddress,PrefixLength,AddressState,PrefixOrigin,SuffixOrigin)
  $public = @($rows | Where-Object {{
    $_.IPAddress -and
    $_.IPAddress -ne '0.0.0.0' -and
    $_.IPAddress -notlike '127.*' -and
    $_.IPAddress -notlike '169.254.*' -and
    $_.IPAddress -notlike '10.*' -and
    $_.IPAddress -notlike '192.168.*' -and
    -not ($_.IPAddress -match '^172\.(1[6-9]|2[0-9]|3[01])\.')
  }} | Select-Object -ExpandProperty IPAddress -First 1)
  $lease = @($rows | Where-Object {{ $_.IPAddress -like '169.254.*' }} | Select-Object -ExpandProperty IPAddress -First 1)
  [pscustomobject]@{{
    alias=$alias
    ok=[bool](-not $entry.Missing -or $public.Count -gt 0)
    public_ip=if ($public.Count) {{ $public[0] }} else {{ '' }}
    lease_ip=if ($lease.Count) {{ $lease[0] }} else {{ '' }}
    message=$entry.Message
    missing=[bool]$entry.Missing
  }}
}}
$results | ConvertTo-Json -Depth 5
"""
    try:
        data = _run_powershell_json(script, timeout=max(10, min(30, timeout + 5)))
    except Exception as exc:
        return {alias: {"ok": False, "message": str(exc), "public_ip": _public_ip_on_interface(alias)} for alias in aliases}
    if not data:
        return {}
    if isinstance(data, dict):
        data = [data]
    return {
        (row.get("alias") or ""): {
            "ok": bool(row.get("ok")),
            "message": row.get("message") or "",
            "public_ip": row.get("public_ip") or "",
            "lease_ip": row.get("lease_ip") or "",
            "missing": bool(row.get("missing")),
        }
        for row in data
        if row.get("alias")
    }


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
function Get-42IpPhysicalAdapter([string]$switchName, [string]$requested) {{
  $adapters = @(Get-NetAdapter -Physical -ErrorAction SilentlyContinue)
  if ($switchName -eq 'WAN-59-External') {{
    return $adapters | Where-Object {{ $_.Name -eq '以太网 4' -or $_.Name -eq '浠ゅお缃?4' -or $_.InterfaceDescription -eq 'Broadcom NetXtreme Gigabit Ethernet #3' }} | Select-Object -First 1
  }}
  if ($switchName -eq 'WAN-Ethernet5-External') {{
    return $adapters | Where-Object {{ $_.Name -eq '以太网 5' -or $_.Name -eq '浠ゅお缃?5' -or $_.InterfaceDescription -eq 'Broadcom NetXtreme Gigabit Ethernet #4' }} | Select-Object -First 1
  }}
  if ($switchName -eq 'WAN-Slot01-x8-External') {{
    return $adapters | Where-Object {{ $_.Name -eq 'Slot01 x8' -or $_.InterfaceDescription -eq 'Intel(R) Gigabit CT Desktop Adapter #2' }} | Select-Object -First 1
  }}
  if ($requested) {{
    return $adapters | Where-Object {{ $_.Name -eq $requested -or $_.InterfaceDescription -eq $requested }} | Select-Object -First 1
  }}
  return $null
}}
$switches = @(Get-VMSwitch | Sort-Object Name)
$namePrefix = $targetName
if (-not $targetName) {{
  $targetSwitch = $switches | Select-Object -First 1
  if ($targetSwitch) {{ $namePrefix = ($targetSwitch.Name -replace '^WAN-', '' -replace '-External$', '') }}
}} else {{
  $targetSwitch = $switches | Where-Object {{ $_.Name -eq $targetName }} | Select-Object -First 1
  if ($targetSwitch) {{
    $physical = Get-NetAdapter | Where-Object {{ $_.InterfaceDescription -eq $targetSwitch.NetAdapterInterfaceDescription }} | Select-Object -First 1
    if ($targetSwitch.SwitchType.ToString() -ne 'External') {{
      $physical = Get-42IpPhysicalAdapter $targetSwitch.Name $requestedParent
      if (-not $physical) {{ throw "未找到交换机 $($targetSwitch.Name) 对应的物理网卡" }}
      Remove-VMSwitch -Name $targetSwitch.Name -Force -ErrorAction Stop
      Start-Sleep -Seconds 3
      New-VMSwitch -Name $targetName -NetAdapterName $physical.Name -AllowManagementOS $true | Out-Null
      Start-Sleep -Seconds 12
      $targetSwitch = Get-VMSwitch -Name $targetName -ErrorAction Stop
    }}
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
$aliases = @()
for ($n = 1; $n -le $count; $n++) {{
  $name = ('{{0}}-{{1:D3}}' -f $namePrefix, $n)
  $existingAdapter = $existing | Where-Object {{ $_.Name -eq $name }} | Select-Object -First 1
  if ($existingAdapter) {{
    try {{ Set-VMNetworkAdapter -ManagementOS -Name $name -StaticMacAddress $existingAdapter.MacAddress -MacAddressSpoofing On -DhcpGuard Off -RouterGuard Off -ErrorAction SilentlyContinue | Out-Null }} catch {{}}
    $aliases += ('vEthernet (' + $name + ')')
    continue
  }}
  try {{
    $macBytes = 0..2 | ForEach-Object {{ Get-Random -Minimum 16 -Maximum 255 }}
    $mac = '00155D{{0:X2}}{{1:X2}}{{2:X2}}' -f $macBytes[0],$macBytes[1],$macBytes[2]
    Add-VMNetworkAdapter -ManagementOS -Name $name -SwitchName $targetSwitch.Name -StaticMacAddress $mac | Out-Null
    Set-VMNetworkAdapter -ManagementOS -Name $name -StaticMacAddress $mac -MacAddressSpoofing On -DhcpGuard Off -RouterGuard Off -ErrorAction SilentlyContinue | Out-Null
    try {{ Set-VMNetworkAdapter -ManagementOS -Name $name -DeviceNaming On -ErrorAction SilentlyContinue | Out-Null }} catch {{}}
    $created += [pscustomobject]@{{ parent=$targetSwitch.Name; name=$name; mac=$mac }}
    $existing += Get-VMNetworkAdapter -ManagementOS -Name $name -ErrorAction SilentlyContinue
  }} catch {{
    $errors += ($name + ': ' + $_.Exception.Message)
  }}
}}
Start-Sleep -Seconds 3
foreach ($item in $created) {{
  $aliases += ('vEthernet (' + $item.name + ')')
}}
$aliases = @($aliases | Select-Object -Unique)
foreach ($alias in $aliases) {{
  try {{ Enable-NetAdapter -Name $alias -Confirm:$false -ErrorAction SilentlyContinue | Out-Null }} catch {{}}
  try {{ Set-NetIPInterface -InterfaceAlias $alias -AddressFamily IPv4 -Dhcp Enabled -ErrorAction SilentlyContinue | Out-Null }} catch {{}}
  try {{ Set-DnsClientServerAddress -InterfaceAlias $alias -ResetServerAddresses -ErrorAction SilentlyContinue | Out-Null }} catch {{}}
  try {{ & netsh.exe interface ipv4 set address name="$alias" source=dhcp | Out-Null }} catch {{}}
  try {{ & netsh.exe interface ipv4 set dnsservers name="$alias" source=dhcp | Out-Null }} catch {{}}
  try {{ Start-Process -FilePath 'ipconfig.exe' -ArgumentList @('/renew', $alias) -WindowStyle Hidden | Out-Null }} catch {{}}
}}
Start-Sleep -Seconds 8
$backupRoot = Join-Path (Get-Location) 'data'
if (-not (Test-Path $backupRoot)) {{ New-Item -ItemType Directory -Path $backupRoot -Force | Out-Null }}
$backupFile = Join-Path $backupRoot 'windows_mac_backup.json'
@(Get-VMNetworkAdapter -ManagementOS -ErrorAction SilentlyContinue |
  Where-Object {{ $_.Name -match '^.+-\d{{3}}$' }} |
  Sort-Object SwitchName,Name |
  ForEach-Object {{ [pscustomobject]@{{ name=$_.Name; switch=$_.SwitchName; mac=$_.MacAddress }} }}) |
  ConvertTo-Json -Depth 4 | Set-Content -Path $backupFile -Encoding UTF8
$ipRows = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object InterfaceAlias,IPAddress)
$acquired = @()
foreach ($alias in $aliases) {{
  $public = @($ipRows | Where-Object {{
    $_.InterfaceAlias -eq $alias -and
    $_.IPAddress -and
    $_.IPAddress -ne '0.0.0.0' -and
    $_.IPAddress -notlike '127.*' -and
    $_.IPAddress -notlike '169.254.*' -and
    $_.IPAddress -notlike '10.*' -and
    $_.IPAddress -notlike '192.168.*' -and
    -not ($_.IPAddress -match '^172\.(1[6-9]|2[0-9]|3[01])\.')
  }} | Select-Object -ExpandProperty IPAddress -First 1)
  if ($public.Count) {{ $acquired += [pscustomobject]@{{ alias=$alias; ip=$public[0] }} }}
}}
[pscustomobject]@{{
  switch = $targetSwitch.Name
  created = $created
  acquired = $acquired
  errors = $errors
}} | ConvertTo-Json -Depth 5
"""
    data = _run_powershell_json(script, timeout=max(120, count * 8))
    created = data.get("created") or []
    if isinstance(created, dict):
        created = [created]
    acquired = data.get("acquired") or []
    if isinstance(acquired, dict):
        acquired = [acquired]
    errors = data.get("errors") or []
    if isinstance(errors, str):
        errors = [errors]
    DETECT_CACHE["data"] = None
    WINDOWS_SWITCH_CACHE["data"] = None
    MASTER_OPTIONS_CACHE["data"] = None
    return {
        "created": [
            {**item, "mac": _display_mac(item.get("mac") or "")}
            for item in created
        ],
        "acquired": acquired,
        "errors": errors,
        "created_count": len(created),
        "acquired_count": len(acquired),
        "switch": data.get("switch") or "",
    }


def _line_to_dict(line, detected_by_ip, iface_map, windows_master_map=None, connection_snapshot=None, slot_maps=None, vm_map=None):
    data = line.to_dict()
    note_meta = _note_meta(line.note)
    saved_iface = _note_interface(line.note)
    detected = detected_by_ip.get(line.public_ip) or {}
    iface = detected.get("interface") or saved_iface or ""
    iface_info = iface_map.get(iface, {})
    display_name = detected.get("display_name") or iface_info.get("display_name") or line.name or _format_line_name(iface)
    slot = _windows_slot_for_line(line, slot_maps or {}, detected, iface_info)
    if slot:
        iface = slot.get("interface") or iface
        iface_info = {**iface_info, **slot}
        detected = {**detected, **slot}
        display_name = slot.get("display_name") or display_name
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
    short_master_name = _windows_short_master_name(saved_iface or iface) or _windows_short_master_name(display_name)
    if short_master_name:
        display_name = short_master_name
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
            or slot.get("parent_adapter")
            or note_meta.get("parent")
            or detected.get("parent_adapter")
            or iface_info.get("parent_adapter")
            or _parent_adapter(display_name)
        ),
        "adapter_index": slot.get("adapter_index") or detected.get("adapter_index") or iface_info.get("adapter_index") or _adapter_index(iface) or _adapter_index(display_name),
        "is_master": is_master,
        "locked": is_master,
        "mac": _display_mac(slot.get("mac") or detected.get("mac") or iface_info.get("mac") or note_meta.get("mac") or ""),
        "internal_ip": line.internal_ip if line.internal_ip != "0.0.0.0" else slot.get("internal_ip") or detected.get("internal_ip", "") or _generated_internal_ip_for_line(line, display_name),
        "dhcp_state": note_meta.get("dhcp") or slot.get("dhcp_state") or ("ok" if public_ok else "pending"),
        "lease_ip": note_meta.get("lease_ip") or slot.get("lease_ip") or "",
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
    if not data.get("mac") and note_meta.get("mac"):
        data["mac"] = _display_mac(note_meta.get("mac") or "")
    if line.status == 0 and saved_iface:
        data["raw_interface"] = saved_iface
        data["interface"] = display_name or _format_line_name(saved_iface)
        data["is_up"] = False
    vm_info = (vm_map or {}).get(line.public_ip or "") or {}
    data.update({
        "vm_name": vm_info.get("vm_name") or "",
        "vm_internal_ip": vm_info.get("vm_internal_ip") or "",
        "vm_ssh_listen": vm_info.get("ssh_listen") or "",
        "vm_ssh_port": vm_info.get("ssh_port") or "",
        "vm_state": vm_info.get("state") or "",
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
    if os.name == "nt":
        virtual_slots = _windows_virtual_adapter_slots()
        slot_maps = _windows_slot_maps(virtual_slots)
        detected_all = _normalize_windows_detected_items(_detect_local_ips(force=True), virtual_slots)
        detected = [item for item in detected_all if _is_public_candidate(item.get("ip", ""))]
    else:
        virtual_slots = _linux_virtual_adapter_slots()
        slot_maps = {}
        ifaces = _iface_snapshot()
        detected_all = list(ifaces.values())
        detected = [
            {
                **info,
                "ip": ip,
                "display_name": info.get("display_name") or _format_line_name(info.get("interface") or ""),
            }
            for info in ifaces.values()
            for ip in (_linux_public_ips(info.get("interface") or "") if os.name != "nt" else (info.get("ipv4") or []))
            if _is_public_candidate(ip) and _is_linux_managed_interface(info.get("interface") or "")
        ]
    detected.sort(key=lambda item: (item.get("parent_adapter") or "ZZZ", item.get("adapter_index") or 0, item.get("ip") or ""))
    slot_by_interface = {item.get("interface"): item for item in virtual_slots if item.get("interface")}
    slot_by_mac = {_mac_hex(item.get("mac") or ""): item for item in virtual_slots if _mac_hex(item.get("mac") or "")}
    detected_pairs = {(item.get("interface") or "", item.get("ip") or "") for item in detected}
    s = get_session()
    try:
        lines = s.query(Line).all()
        lines_by_ip = defaultdict(list)
        lines_by_pair = defaultdict(list)
        lines_by_iface = {}
        lines_by_mac = defaultdict(list)
        for line in lines:
            iface = _line_iface_fast(line)
            note_mac = _mac_hex(_note_meta(line.note).get("mac") or "")
            if _is_public_candidate(line.public_ip):
                lines_by_ip[line.public_ip].append(line)
            if iface:
                lines_by_pair[(iface, line.public_ip or "0.0.0.0")].append(line)
            if iface and iface not in lines_by_iface:
                lines_by_iface[iface] = line
            if note_mac:
                lines_by_mac[note_mac].append(line)
        lines_by_name = {line.name: line for line in lines if line.name}
        detected_ip_counts = Counter(item.get("ip") or "" for item in detected)
        claimed_line_ids = set()
        live_slot_keys = set()
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
            ip = item.get("ip") or line.public_ip or slot.get("ip") or ""
            line.note = _line_note(
                iface,
                mac=_display_mac(slot.get("mac") or item.get("mac") or _note_meta(line.note).get("mac") or ""),
                parent=slot.get("parent_adapter") or item.get("parent_adapter") or _note_meta(line.note).get("parent") or "",
                dhcp=dhcp,
                lease_ip=slot.get("lease_ip") or "",
                ip=ip if _is_public_candidate(ip) else "",
            )

        def display_name_for_ip(iface: str, ip: str, item=None) -> str:
            item = item or {}
            base_name = item.get("display_name") or _format_line_name(iface)
            if ip in STATIC_MASTER_IPS:
                return f"{STATIC_MASTER_IPS[ip]}-{MASTER_LABEL}"
            public_count = len([
                value
                for value in (item.get("ipv4") or [])
                if _is_public_candidate(value)
            ])
            if public_count > 1:
                suffix = ip.rsplit(".", 1)[-1]
                return f"{base_name}-{suffix}"
            return base_name

        def claim_line(candidates):
            for candidate in candidates or []:
                if candidate and candidate.id not in claimed_line_ids:
                    claimed_line_ids.add(candidate.id)
                    return candidate
            return None

        def choose_existing_line(iface: str, ip: str, display_name: str, item=None, slot=None):
            item = item or {}
            slot = slot or {}
            mac = _mac_hex(slot.get("mac") or item.get("mac") or "")
            if mac:
                line = claim_line(lines_by_mac.get(mac))
                if line:
                    return line
            line = claim_line(lines_by_pair.get((iface, ip)))
            if line:
                return line
            by_name = lines_by_name.get(display_name)
            if by_name and by_name.id not in claimed_line_ids:
                by_name_ip = by_name.public_ip or ""
                if by_name_ip == ip or not _is_public_candidate(by_name_ip):
                    claimed_line_ids.add(by_name.id)
                    return by_name
            same_ip_lines = lines_by_ip.get(ip) or []
            if detected_ip_counts.get(ip, 0) > 1:
                line = claim_line(same_ip_lines)
                if line:
                    return line
            else:
                same_iface = [line for line in same_ip_lines if _line_iface_fast(line) in {"", iface}]
                line = claim_line(same_iface or same_ip_lines)
                if line:
                    return line
            legacy = lines_by_iface.get(iface)
            legacy_is_single_ip = len([
                value
                for value in (item.get("ipv4") or [])
                if _is_public_candidate(value)
            ]) <= 1
            if legacy and legacy.id not in claimed_line_ids and not _is_public_candidate(legacy.public_ip) and legacy_is_single_ip:
                claimed_line_ids.add(legacy.id)
                return legacy
            return None

        for item in detected:
            ip = item.get("ip") or ""
            iface = item.get("interface") or ""
            slot = _windows_slot_for_item(item, slot_maps) if os.name == "nt" else slot_by_interface.get(iface, {})
            if slot:
                if slot.get("ip") and ip != slot.get("ip"):
                    skipped.append({"ip": ip, "interface": iface, "reason": "duplicate_slot_ip"})
                    continue
                _apply_windows_slot(item, slot)
                iface = item.get("interface") or iface
                slot_key = _mac_hex(slot.get("mac") or item.get("mac") or "") or iface
                if slot_key in live_slot_keys:
                    skipped.append({"ip": ip, "interface": iface, "reason": "duplicate_slot_ip"})
                    continue
                live_slot_keys.add(slot_key)
            display_name = slot.get("display_name") or display_name_for_ip(iface, ip, item)
            line = choose_existing_line(iface, ip, display_name, item, slot)
            if line:
                line.name = display_name
                line.public_ip = ip
                line.internal_ip = slot.get("internal_ip") or item.get("internal_ip") or line.internal_ip or _generated_internal_ip_for_interface(iface, display_name)
                line.status = 1
                update_note(line, iface, item=item, slot=slot, dhcp="ok")
                skipped.append({"ip": ip, "reason": "updated"})
                lines_by_ip[ip].append(line)
                lines_by_pair[(iface, ip)].append(line)
                if iface not in lines_by_iface:
                    lines_by_iface[iface] = line
                mac = _mac_hex(slot.get("mac") or item.get("mac") or "")
                if mac:
                    lines_by_mac[mac].append(line)
                lines_by_name[display_name] = line
                continue
            if os.name != "nt" and lines:
                skipped.append({"ip": ip, "interface": iface, "reason": "new_untracked_preserved"})
                continue
            socks_port, http_port, ss_port = assign_ports()
            line = Line(
                name=display_name,
                public_ip=ip,
                internal_ip=slot.get("internal_ip") or item.get("internal_ip") or _generated_internal_ip_for_interface(iface, display_name),
                socks_port=socks_port,
                http_port=http_port,
                ss_port=ss_port,
                status=1,
                note=_line_note(
                    iface,
                    mac=_display_mac(slot.get("mac") or item.get("mac") or ""),
                    parent=slot.get("parent_adapter") or item.get("parent_adapter") or "",
                    dhcp="ok",
                    lease_ip=slot.get("lease_ip") or "",
                ),
            )
            s.add(line)
            s.flush()
            claimed_line_ids.add(line.id)
            created.append(line.to_dict())
            lines_by_ip[ip].append(line)
            lines_by_pair[(iface, ip)].append(line)
            if iface not in lines_by_iface:
                lines_by_iface[iface] = line
            mac = _mac_hex(slot.get("mac") or item.get("mac") or "")
            if mac:
                lines_by_mac[mac].append(line)
            lines_by_name[display_name] = line

        for slot in virtual_slots:
            iface = slot.get("interface") or ""
            display_name = slot.get("display_name") or _format_line_name(iface)
            if not iface or not display_name or _adapter_index(display_name) < 1:
                continue
            ip = slot.get("ip") or ""
            public_ok = _is_public_candidate(ip)
            if public_ok:
                continue
            mac = _mac_hex(slot.get("mac") or "")
            line = claim_line(lines_by_mac.get(mac)) if mac else None
            if not line:
                line = claim_line(lines_by_pair.get((iface, "0.0.0.0")))
            if not line:
                by_name = lines_by_name.get(display_name)
                line = by_name if by_name and by_name.id not in claimed_line_ids else None
                if line:
                    claimed_line_ids.add(line.id)
            note = _line_note(
                iface,
                mac=_display_mac(slot.get("mac") or ""),
                parent=slot.get("parent_adapter") or "",
                dhcp="ok" if public_ok else "pending",
                lease_ip=slot.get("lease_ip") or "",
                ip=ip if public_ok else "",
            )
            if line:
                line.name = display_name
                line.note = note
                line.internal_ip = slot.get("internal_ip") or line.internal_ip or _generated_internal_ip_for_interface(iface, display_name)
                lines_by_pair[(iface, "0.0.0.0")].append(line)
                if mac:
                    lines_by_mac[mac].append(line)
                continue
            if os.name != "nt":
                skipped.append({"interface": iface, "reason": "empty_slot_not_created"})
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
            claimed_line_ids.add(line.id)
            created.append(line.to_dict())
            lines_by_pair[(iface, "0.0.0.0")].append(line)
            if mac:
                lines_by_mac[mac].append(line)
            lines_by_name[display_name] = line

        if os.name != "nt":
            for line in s.query(Line).options(selectinload(Line.users)).all():
                iface = _line_iface_fast(line)
                ip = line.public_ip or ""
                if not _is_public_candidate(ip) or _line_is_master_fast(line, iface):
                    continue
                if (iface, ip) in detected_pairs:
                    continue
                skipped.append({"ip": ip, "interface": iface, "reason": "not_detected_preserved"})
        else:
            # Windows adapters can keep temporary aliases and duplicate Hyper-V names.
            # Never clear saved public IPs just because a sync pass cannot match a slot.
            pass

        for line in s.query(Line).all():
            iface = (_note_interface(line.note) or line.name or "").replace(f"-{MASTER_LABEL}", "")
            internal_ip = _linux_managed_internal_ip(iface)
            if internal_ip:
                line.internal_ip = internal_ip
        s.commit()
        DETECT_CACHE["data"] = None
        persisted = _persist_linux_macvlan_state_quick()
        _reload_after_change_background()
        return jsonify({
            "ok": True,
            "data": {
                "detected_count": len(detected),
                "interface_count": len(detected_all),
                "public_count": len(detected),
                "slot_count": len(virtual_slots),
                "created_count": len(created),
                "skipped_count": len(skipped),
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
    count = max(1, min(int(data.get("count") or MAC_CHILDREN_DEFAULT_CREATE), MAC_CHILDREN_MAX_CREATE))
    parent = (data.get("parent") or "").strip()
    if os.name != "nt":
        if name:
            return jsonify({"ok": False, "error": "Linux 线路使用自动命名追加虚拟 MAC 网卡，不支持自定义网卡名"}), 400
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
            elif False and count == MAC_CHILDREN_PER_PARENT:
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
            child_internal_ip = internal_ip if internal_ip and len(parents) == 1 and count == 1 else _generated_internal_ip_for_interface(child_name)
            if child_internal_ip and child_internal_ip != "0.0.0.0":
                ok, output = _run_cmd(["ip", "addr", "replace", f"{child_internal_ip}/32", "dev", child_name])
                if not ok:
                    errors.append(f"{child_name}: internal IP {child_internal_ip} failed: {output}")
            if internal_ip and len(parents) == 1 and count == 1:
                ok, output = _run_cmd(["ip", "addr", "replace", f"{internal_ip}/{prefix}", "dev", child_name])
                if not ok:
                    errors.append(f"{child_name}: {output or '缁戝畾鍐呯綉 IP 澶辫触'}")
            ok, output = _run_cmd(["ip", "link", "set", child_name, "up"])
            if not ok:
                errors.append(f"{child_name}: {output or '鍚敤澶辫触'}")
                continue
            created.append({"parent": parent_name, "name": child_name, "mac": mac, "internal_ip": child_internal_ip})
            created_names.append(child_name)
    DETECT_CACHE["data"] = None
    internal_result = _ensure_linux_internal_ips()
    persisted = _persist_linux_macvlan_state()
    acquired_count = 0
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
        live = request.args.get("live") == "1"
        slot_maps = {}
        if live:
            virtual_slots = _windows_virtual_adapter_slots() if os.name == "nt" else []
            slot_maps = _windows_slot_maps(virtual_slots)
            detected = _normalize_windows_detected_items(_detect_local_ips(), virtual_slots) if os.name == "nt" else _detect_local_ips()
            detected_by_ip = {item["ip"]: item for item in detected}
            iface_map = {item["interface"]: item for item in detected}
            windows_master_map = _windows_master_public_ip_map() if os.name == "nt" else {}
            connection_snapshot = snapshot_connections()
        else:
            detected_by_ip = {}
            iface_map = {}
            windows_master_map = {}
            connection_snapshot = {}
        vm_map = hyperv_manager.line_vm_internal_ip_map() if os.name == "nt" else {}
        lines = s.query(Line).options(selectinload(Line.users)).order_by(Line.name, Line.id).all()
        return jsonify({"ok": True, "data": [
            _line_to_dict(line, detected_by_ip, iface_map, windows_master_map, connection_snapshot, slot_maps, vm_map)
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
        iface = _line_iface_fast(line)
        if _line_is_master_fast(line, iface):
            return jsonify({"ok": False, "error": "主网卡为静默线路，不能更换 MAC"}), 400
        if os.name != "nt":
            if not _is_linux_fixed_child_interface(iface):
                return jsonify({"ok": False, "error": "只有固定 001-014 虚拟 MAC 网卡可以更换 MAC"}), 400
            ok, _, output = _ensure_linux_child_interface(iface, _note_meta(line.note).get("mac") or "")
            if not ok:
                return jsonify({"ok": False, "error": output or f"系统里找不到虚拟网卡 {iface}"}), 404
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
            dhcp_results = _request_dhcp_for_interfaces([iface], timeout=10)
            time.sleep(1)
            line_info = _update_line_from_iface(line, iface, dhcp_results.get(iface) or {})
            s.commit()
            DETECT_CACHE["data"] = None
            persisted = _persist_linux_macvlan_state_quick()
            return jsonify({"ok": True, "data": {
                "mac": new_mac,
                "dhcp": dhcp_results.get(iface) or {},
                "persisted": persisted,
                "line": line_info,
            }})
        try:
            line_info = _windows_change_line_mac(line)
            s.commit()
            DETECT_CACHE["data"] = None
            _reload_after_change_background()
            return jsonify({"ok": True, "data": {"mac": line_info.get("mac"), "line": line_info}})
        except Exception as exc:
            s.rollback()
            return jsonify({"ok": False, "error": str(exc)}), 500
        info = _line_to_dict(line, {}, _iface_snapshot())
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
    iface = _line_iface_fast(line)
    if _line_is_master_fast(line, iface):
        raise ValueError("主网卡不能更换 MAC")
    if not _is_linux_fixed_child_interface(iface):
        raise ValueError("只有固定 001-014 虚拟 MAC 网卡可以更换 MAC")
    ok, _, output = _ensure_linux_child_interface(iface, _note_meta(line.note).get("mac") or "")
    if not ok:
        raise FileNotFoundError(output or f"系统里找不到虚拟网卡 {iface}")
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
    dhcp_results = _request_dhcp_for_interfaces([iface], timeout=10)
    time.sleep(1)
    return _update_line_from_iface(line, iface, dhcp_results.get(iface) or {})


def _refresh_line_after_dhcp(line, iface: str, dhcp_result: dict | None = None) -> dict:
    return _update_line_from_iface(line, iface, dhcp_result or {})


def _random_hyperv_mac() -> str:
    return "00155D{0:02X}{1:02X}{2:02X}".format(
        random.randint(0x10, 0xFE),
        random.randint(0x10, 0xFE),
        random.randint(0x10, 0xFE),
    )


def _windows_change_line_mac(line) -> dict:
    iface = _line_iface_fast(line)
    if _line_is_master_fast(line, iface):
        raise ValueError("主网卡不能更换 MAC")
    adapter_name = _hyperv_adapter_name(iface)
    if not adapter_name:
        raise ValueError("未找到对应虚拟网卡")
    new_mac = _random_hyperv_mac()
    hyperv_mac = _mac_for_hyperv(new_mac)
    display_mac = _display_mac(new_mac)
    script = rf"""
$ErrorActionPreference = 'Stop'
Import-Module Hyper-V
$name = {json.dumps(adapter_name)}
$alias = 'vEthernet (' + $name + ')'
$mac = {json.dumps(hyperv_mac)}
$vm = Get-VMNetworkAdapter -ManagementOS -Name $name -ErrorAction Stop
Set-VMNetworkAdapter -ManagementOS -Name $name -StaticMacAddress $mac | Out-Null
$net = Get-NetAdapter -Name $alias -ErrorAction SilentlyContinue
if ($net) {{
  Disable-NetAdapter -Name $alias -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
  Start-Sleep -Milliseconds 800
  Enable-NetAdapter -Name $alias -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
  Set-NetIPInterface -InterfaceAlias $alias -AddressFamily IPv4 -Dhcp Enabled -ErrorAction SilentlyContinue | Out-Null
  Set-DnsClientServerAddress -InterfaceAlias $alias -ResetServerAddresses -ErrorAction SilentlyContinue | Out-Null
  netsh interface ipv4 set address name="$alias" source=dhcp | Out-Null
  netsh interface ipv4 set dnsservers name="$alias" source=dhcp | Out-Null
  Start-Job -ScriptBlock {{ param($n) ipconfig /renew $n | Out-Null }} -ArgumentList $alias | Out-Null
}}
[pscustomobject]@{{ name=$name; alias=$alias; mac=$mac }} | ConvertTo-Json -Depth 3
"""
    data = _run_powershell_json(script, timeout=30) or {}
    alias = data.get("alias") or iface
    result = _windows_request_dhcp_for_interfaces([alias], timeout=6).get(alias) or {}
    line.public_ip = result.get("public_ip") if _is_public_candidate(result.get("public_ip") or "") else "0.0.0.0"
    line.status = 1 if _is_public_candidate(line.public_ip) else 0
    line.name = _windows_line_display_name(alias, adapter_name)
    line.internal_ip = _windows_internal_ip_for_display(line.name, alias)
    line.note = _line_note(
        alias,
        mac=display_mac,
        parent=_windows_parent_for_display(line.name),
        dhcp="ok" if line.status else "pending",
        lease_ip=result.get("lease_ip") or "",
        ip=line.public_ip if _is_public_candidate(line.public_ip) else "",
    )
    return {
        "id": line.id,
        "name": line.name,
        "interface": alias,
        "mac": display_mac,
        "public_ip": line.public_ip,
        "lease_ip": result.get("lease_ip") or "",
        "dhcp": result,
    }


def _windows_delete_virtual_adapter(iface: str) -> str:
    adapter_name = _hyperv_adapter_name(iface)
    if not adapter_name:
        return ""
    script = rf"""
$ErrorActionPreference = 'Stop'
Import-Module Hyper-V
$name = {json.dumps(adapter_name)}
$vm = Get-VMNetworkAdapter -ManagementOS -Name $name -ErrorAction SilentlyContinue
if ($vm) {{ Remove-VMNetworkAdapter -ManagementOS -Name $name -Confirm:$false | Out-Null }}
[pscustomobject]@{{ deleted=$name }} | ConvertTo-Json -Depth 3
"""
    data = _run_powershell_json(script, timeout=25) or {}
    return data.get("deleted") or adapter_name


def _windows_delete_virtual_adapters(ifaces: list[str]) -> dict:
    adapter_names = []
    for iface in ifaces:
        adapter_name = _hyperv_adapter_name(iface)
        if adapter_name and adapter_name not in adapter_names:
            adapter_names.append(adapter_name)
    if not adapter_names:
        return {"deleted": [], "errors": []}
    script = rf"""
$ErrorActionPreference = 'Continue'
Import-Module Hyper-V
$names = @({",".join(json.dumps(name) for name in adapter_names)})
$deleted = @()
$errors = @()
foreach ($name in $names) {{
  try {{
    $vm = Get-VMNetworkAdapter -ManagementOS -Name $name -ErrorAction SilentlyContinue
    if ($vm) {{
      Remove-VMNetworkAdapter -ManagementOS -Name $name -Confirm:$false -ErrorAction Stop | Out-Null
      $deleted += $name
    }} else {{
      $deleted += $name
    }}
  }} catch {{
    $errors += [pscustomobject]@{{ name=$name; error=$_.Exception.Message }}
  }}
}}
[pscustomobject]@{{ deleted=$deleted; errors=$errors }} | ConvertTo-Json -Depth 5
"""
    data = _run_powershell_json(script, timeout=max(30, len(adapter_names) * 3)) or {}
    deleted = data.get("deleted") or []
    errors = data.get("errors") or []
    if isinstance(deleted, str):
        deleted = [deleted]
    if isinstance(errors, dict):
        errors = [errors]
    return {"deleted": deleted, "errors": errors}


@bp.route("/batch-change-mac", methods=["POST"])
@login_required
def batch_change_mac():
    data = request.get_json(silent=True) or {}
    raw_ids = data.get("ids") or []
    if not isinstance(raw_ids, list):
        return jsonify({"ok": False, "error": "ids must be a list"}), 400
    ids = [int(x) for x in raw_ids if str(x).isdigit()]
    if os.name == "nt" and ids:
        s = get_session()
        try:
            lines = s.query(Line).filter(Line.id.in_(ids)).all()
            found_ids = {line.id for line in lines}
            changed = []
            errors = [{"id": missing_id, "error": "line not found"} for missing_id in ids if missing_id not in found_ids]
            for line in lines:
                try:
                    changed.append(_windows_change_line_mac(line))
                except Exception as exc:
                    errors.append({"id": line.id, "name": line.name, "error": str(exc)})
            if changed:
                s.commit()
                DETECT_CACHE["data"] = None
                persisted = _persist_linux_macvlan_state_quick()
                _reload_after_change_background()
            else:
                s.rollback()
                persisted = {"ok": True, "skipped": True}
            return jsonify({"ok": True, "data": {"changed": changed, "changed_count": len(changed), "errors": errors, "persisted": persisted}})
        finally:
            s.close()
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
            persisted = _persist_linux_macvlan_state_quick()
        else:
            s.rollback()
            persisted = {"ok": True, "skipped": True}
        return jsonify({"ok": True, "data": {"changed": changed, "changed_count": len(changed), "errors": errors, "persisted": persisted}})
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
    if os.name == "nt" and ids:
        total_requested_ids = len(ids)
        ids = ids[:DHCP_BATCH_SIZE]
        s = get_session()
        try:
            lines = s.query(Line).filter(Line.id.in_(ids)).all()
            found_ids = {line.id for line in lines}
            targets = []
            errors = [{"id": missing_id, "error": "line not found"} for missing_id in ids if missing_id not in found_ids]
            for line in lines:
                try:
                    iface = _line_iface_fast(line)
                    if _line_is_master_fast(line, iface):
                        raise ValueError("master adapter cannot request DHCP")
                    adapter_name = _hyperv_adapter_name(iface)
                    if not adapter_name:
                        raise ValueError("virtual adapter not found")
                    alias = f"vEthernet ({adapter_name})"
                    targets.append((line, alias))
                except Exception as exc:
                    errors.append({"id": line.id, "name": line.name, "error": str(exc)})
            previous_public_ips = {line.id: line.public_ip for line, _ in targets}
            dhcp_results = _request_dhcp_for_interfaces([iface for _, iface in targets], timeout=8)
            refreshed = []
            for line, iface in targets:
                refreshed.append(_refresh_line_after_dhcp(line, iface, dhcp_results.get(iface) or {}))
            if refreshed:
                s.commit()
                DETECT_CACHE["data"] = None
                acquired_new_ip = any(
                    item.get("public_ip")
                    and item.get("public_ip") != "0.0.0.0"
                    and item.get("public_ip") != previous_public_ips.get(item.get("id"))
                    for item in refreshed
                )
                if acquired_new_ip:
                    _reload_after_change_background()
                persisted = _persist_linux_macvlan_state_quick()
            else:
                s.rollback()
                persisted = {"ok": True, "skipped": True}
            acquired_count = len([item for item in refreshed if item.get("public_ip") and item.get("public_ip") != "0.0.0.0"])
            return jsonify({"ok": True, "data": {"requested_count": len(targets), "received_count": total_requested_ids, "remaining_count": max(0, total_requested_ids - len(ids)), "batch_size": DHCP_BATCH_SIZE, "acquired_count": acquired_count, "refreshed": refreshed, "errors": errors, "persisted": persisted}})
        finally:
            s.close()
    if not ids:
        return jsonify({"ok": False, "error": "请选择要请求 DHCP 的线路"}), 400
    total_requested_ids = len(ids)
    ids = ids[:DHCP_BATCH_SIZE]
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
                iface = _line_iface_fast(line)
                if _line_is_master_fast(line, iface):
                    raise ValueError("主网卡不能请求 DHCP")
                if not _is_linux_fixed_child_interface(iface):
                    raise ValueError("只有固定 001-014 虚拟 MAC 网卡可以请求 DHCP")
                ok, _, output = _ensure_linux_child_interface(iface, _note_meta(line.note).get("mac") or "")
                if not ok:
                    raise FileNotFoundError(output or f"系统里找不到虚拟网卡 {iface}")
                targets.append((line, iface))
            except Exception as exc:
                errors.append({"id": line.id, "name": line.name, "error": str(exc)})
        previous_public_ips = {line.id: line.public_ip for line, _ in targets}
        dhcp_results = _request_dhcp_for_interfaces([iface for _, iface in targets], timeout=5)
        time.sleep(1)
        refreshed = []
        for line, iface in targets:
            refreshed.append(_refresh_line_after_dhcp(line, iface, dhcp_results.get(iface) or {}))
        if refreshed:
            s.commit()
            DETECT_CACHE["data"] = None
            persisted = _persist_linux_macvlan_state_quick()
            acquired_new_ip = any(
                item.get("public_ip")
                and item.get("public_ip") != "0.0.0.0"
                and item.get("public_ip") != previous_public_ips.get(item.get("id"))
                for item in refreshed
            )
            if acquired_new_ip:
                try:
                    status = proxy_manager.reload_config_no_restart(s)
                    if not status.get("ok"):
                        errors.append({"error": f"sing-box hot reload failed; not restarted: {status.get('message')}"})
                except Exception as exc:
                    errors.append({"error": f"sing-box hot reload failed; not restarted: {exc}"})
        else:
            s.rollback()
            persisted = {"ok": True, "skipped": True}
        acquired_count = len([item for item in refreshed if item.get("public_ip") and item.get("public_ip") != "0.0.0.0"])
        return jsonify({"ok": True, "data": {"requested_count": len(targets), "received_count": total_requested_ids, "remaining_count": max(0, total_requested_ids - len(ids)), "batch_size": DHCP_BATCH_SIZE, "acquired_count": acquired_count, "refreshed": refreshed, "errors": errors, "persisted": persisted}})
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
        if _line_is_master_fast(line):
            return jsonify({"ok": False, "error": "主网卡为静默线路，不能修改状态"}), 400
        line.status = 0 if line.status else 1
        s.commit()
        return jsonify({"ok": True, "data": line.to_dict()})
    finally:
        s.close()


@bp.route("/<int:lid>/adapter-state", methods=["POST"])
@login_required
def set_line_adapter_state(lid):
    data = request.get_json(silent=True) or {}
    enabled = bool(data.get("enabled"))
    s = get_session()
    try:
        line = s.query(Line).get(lid)
        if not line:
            return jsonify({"ok": False, "error": "线路不存在"}), 404
        try:
            result = _windows_set_line_adapter_state(line, enabled)
        except ValueError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400
        except Exception as exc:
            return jsonify({"ok": False, "error": str(exc)}), 500
        s.commit()
        return jsonify({"ok": True, "data": {"line": line.to_dict(), "adapter": result}})
    finally:
        s.close()


def _delete_line_record(session, line) -> dict:
    iface = _line_iface_fast(line)
    if _line_is_master_fast(line, iface):
        raise ValueError("主网卡不能删除")
    deleted_iface = ""
    if os.name != "nt":
        if _is_generated_child_interface(iface):
            deleted_iface = iface
            if iface in psutil.net_if_addrs():
                ok, output = _run_cmd(["ip", "link", "delete", iface], timeout=15)
                if not ok and "Cannot find device" not in output:
                    raise RuntimeError(output or f"删除虚拟网卡 {iface} 失败")
    if os.name == "nt":
        deleted_iface = _windows_delete_virtual_adapter(iface)
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
        iface = _line_iface_fast(line)
        if _line_is_master_fast(line, iface):
            return jsonify({"ok": False, "error": "主网卡为静默线路，不能删除"}), 400
        deleted_iface = ""
        if os.name != "nt":
            if _is_generated_child_interface(iface):
                deleted_iface = iface
                if iface in psutil.net_if_addrs():
                    ok, output = _run_cmd(["ip", "link", "delete", iface], timeout=15)
                    if not ok and "Cannot find device" not in output:
                        return jsonify({"ok": False, "error": output or f"删除虚拟网卡 {iface} 失败"}), 500
        if os.name == "nt":
            deleted_iface = _windows_delete_virtual_adapter(iface)
        s.delete(line)
        s.commit()
        persisted = _persist_linux_macvlan_state_quick()
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
        if os.name == "nt":
            delete_targets = []
            line_by_adapter = {}
            for line in lines:
                try:
                    iface = _line_iface_fast(line)
                    if _line_is_master_fast(line, iface):
                        raise ValueError("主网卡不能删除")
                    adapter_name = _hyperv_adapter_name(iface)
                    if not adapter_name:
                        raise ValueError("未找到对应虚拟网卡")
                    delete_targets.append(iface)
                    line_by_adapter[adapter_name] = line
                except Exception as exc:
                    errors.append({"id": line.id, "name": line.name, "error": str(exc)})
            result = _windows_delete_virtual_adapters(delete_targets)
            for err in result.get("errors") or []:
                name = err.get("name") or ""
                line = line_by_adapter.get(name)
                errors.append({"id": getattr(line, "id", None), "name": getattr(line, "name", name), "error": err.get("error") or "删除失败"})
            failed_names = {err.get("name") for err in result.get("errors") or []}
            for adapter_name, line in line_by_adapter.items():
                if adapter_name in failed_names:
                    continue
                deleted.append({"id": line.id, "name": line.name, "public_ip": line.public_ip, "deleted_interface": adapter_name})
                s.delete(line)
            if deleted:
                s.commit()
                DETECT_CACHE["data"] = None
                MASTER_OPTIONS_CACHE["data"] = None
                persisted = _persist_linux_macvlan_state_quick()
            else:
                s.rollback()
                persisted = {"ok": True, "skipped": True}
            return jsonify({"ok": True, "data": {"deleted": deleted, "deleted_count": len(deleted), "errors": errors, "persisted": persisted}})
        for line in lines:
            try:
                deleted.append(_delete_line_record(s, line))
            except Exception as exc:
                errors.append({"id": line.id, "name": line.name, "error": str(exc)})
        if deleted:
            s.commit()
            persisted = _persist_linux_macvlan_state_quick()
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
