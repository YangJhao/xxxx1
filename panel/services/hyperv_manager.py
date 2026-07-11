"""Small Hyper-V management wrapper for the web panel."""
import json
import locale
import os
import platform
import subprocess
import re
import tempfile
import threading
import time
import urllib.request
import uuid
import ipaddress
from pathlib import Path
import socket

try:
    import paramiko
except ImportError:
    paramiko = None

from models import Line, get_session


POWERSHELL = "powershell.exe"
PROJECT_DIR = Path(__file__).resolve().parents[2]
DEFAULT_IP_MAP = r"C:\42IPwin\data\hyperv_42ip_vm_map.csv"
DEFAULT_CREATE_SCRIPT = r"C:\42IPwin\tools\create_ikuai_42_vms.ps1"
DEBIAN_IMAGE_URL = "https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-genericcloud-amd64.qcow2"
QEMU_SETUP_URL = "https://qemu.weilnetz.de/w64/qemu-w64-setup-20260501.exe"
LINUX_IMAGE_DIR = Path("/var/lib/libvirt/images/42ipwin")
LINUX_DEBIAN_IMAGE = LINUX_IMAGE_DIR / "debian-12-genericcloud-amd64.qcow2"
LINUX_VM_NETWORK = "VM-LAN"
LINUX_VM_BRIDGE = "br42vm"
LINUX_VM_GATEWAY = "192.168.9.1"
LINUX_VM_PREFIX = "192.168.9"
LINUX_VM_NET_PREFIX = 24
LINUX_VM_MAP_CHAIN_PRE = "42IPWIN_VM_PRE"
LINUX_VM_MAP_CHAIN_POST = "42IPWIN_VM_POST"
LINUX_VM_RESERVED_PUBLIC_IPS = {"211.230.223.67", "220.82.161.1", "121.154.232.7"}
LINUX_VM_RESERVED_PORTS = {8080}
LINUX_VM_NOTE_KEYS = {
    "line_id",
    "line_name",
    "public_ip",
    "wan_ip",
    "wan_mac",
    "internal_ip",
    "internal_gateway",
    "vm_network",
    "ssh_port",
    "root_user",
}
IMAGE_JOBS: dict[str, dict] = {}
IMAGE_JOBS_LOCK = threading.Lock()
CREATE_VM_JOBS: dict[str, dict] = {}
CREATE_VM_JOBS_LOCK = threading.Lock()
START_VM_JOBS: dict[str, dict] = {}
START_VM_JOBS_LOCK = threading.Lock()
VM_LIST_CACHE: dict[str, object] = {"rows": [], "updated_at": 0.0, "refreshing": False, "error": ""}
VM_LIST_CACHE_LOCK = threading.Lock()
ACTION_COMMANDS = {
    "start": "Start-VM -Name $name",
    "shutdown": "Stop-VM -Name $name -Force",
    "turnoff": "Stop-VM -Name $name -TurnOff -Force",
    "restart": "Restart-VM -Name $name -Force",
    "reset": "Reset-VM -Name $name -Force",
    "save": "Save-VM -Name $name",
}


def _is_windows() -> bool:
    return platform.system().lower() == "windows"


def _is_linux() -> bool:
    return platform.system().lower() == "linux"


def _run_cmd(args: list[str], timeout: int = 30, check: bool = True) -> str:
    completed = subprocess.run(
        args,
        capture_output=True,
        text=True,
        timeout=timeout,
        encoding="utf-8",
        errors="replace",
    )
    if check and completed.returncode != 0:
        err = (completed.stderr or completed.stdout or "").strip()
        raise RuntimeError(err or f"{args[0]} exited with {completed.returncode}")
    return completed.stdout.strip()


def _linux_libvirt_available() -> bool:
    if not _is_linux():
        return False
    try:
        subprocess.run(["virsh", "--version"], capture_output=True, text=True, timeout=5)
    except Exception:
        return False
    return subprocess.run(["virsh", "list", "--all"], capture_output=True, text=True, timeout=8).returncode == 0


def _parse_key_value_lines(text: str) -> dict:
    data = {}
    for line in (text or "").splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        data[key.strip().lower()] = value.strip()
    return data


def _memory_kib(value: str) -> int:
    match = re.search(r"(\d+)", value or "")
    return int(match.group(1)) if match else 0


def _linux_state(value: str) -> str:
    low = (value or "").strip().lower()
    if low == "running":
        return "Running"
    if low in {"shut off", "shutoff", "off"}:
        return "Off"
    if low == "paused":
        return "Paused"
    return value or "-"


def _linux_vm_names() -> list[str]:
    raw = _run_cmd(["virsh", "list", "--all", "--name"], timeout=15)
    return [line.strip() for line in raw.splitlines() if line.strip()]


def _linux_domif_rows(name: str) -> list[dict]:
    raw = _run_cmd(["virsh", "domiflist", name], timeout=15, check=False)
    rows = []
    for line in raw.splitlines():
        parts = line.split()
        if len(parts) >= 5 and parts[0] not in {"Interface", "-------------------------------------------------------------"}:
            rows.append({
                "interface": parts[0],
                "type": parts[1],
                "source": parts[2],
                "model": parts[3],
                "mac": parts[4],
            })
    return rows


def _linux_ip_rows(name: str) -> list[str]:
    ips = []
    for source in ("lease", "agent"):
        raw = _run_cmd(["virsh", "domifaddr", name, "--source", source], timeout=15, check=False)
        for line in raw.splitlines():
            match = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})(?:/\d+)?\b", line)
            if match and match.group(1) not in ips:
                ips.append(match.group(1))
    if ips:
        return ips

    macs = [row.get("mac", "").lower() for row in _linux_domif_rows(name)]
    raw = _run_cmd(["virsh", "net-dhcp-leases", "default"], timeout=15, check=False)
    for line in raw.splitlines():
        if not any(mac and mac in line.lower() for mac in macs):
            continue
        match = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})(?:/\d+)?\b", line)
        if match and match.group(1) not in ips:
            ips.append(match.group(1))
    return ips


def _private_ips(ips: list[str]) -> list[str]:
    return [
        ip for ip in ips
        if re.match(r"^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|169\.254\.)", ip)
    ]


def _public_ips(ips: list[str]) -> list[str]:
    return [
        ip for ip in ips
        if not re.match(r"^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|169\.254\.|127\.)", ip)
    ]


def _strip_ip_mask(value: str) -> str:
    value = (value or "").strip()
    return value.split("/", 1)[0].strip()


def _kv_parse_notes(text: str) -> dict[str, str]:
    data: dict[str, str] = {}
    for line in (text or "").splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if key:
            data[key] = value.strip()
    return data


def _kv_notes(mapping: dict[str, object], existing: str = "") -> str:
    body = []
    for line in (existing or "").splitlines():
        key = line.split("=", 1)[0].strip() if "=" in line else ""
        if key and key in LINUX_VM_NOTE_KEYS:
            continue
        if line.strip():
            body.append(line.rstrip())
    for key, value in mapping.items():
        if value not in (None, ""):
            body.append(f"{key}={value}")
    return "\n".join(body).strip()


def _linux_vm_description(name: str) -> str:
    text = _run_cmd(["virsh", "desc", name, "--config"], timeout=15, check=False)
    if text:
        return text
    return _run_cmd(["virsh", "desc", name], timeout=15, check=False)


def _linux_set_vm_mapping_notes(name: str, mapping: dict[str, object]) -> None:
    current_text = _linux_vm_description(name)
    current = _kv_parse_notes(current_text)
    current.update({key: str(value) for key, value in mapping.items() if value not in (None, "")})
    new_text = _kv_notes(current, current_text)
    _run_cmd(["virsh", "desc", name, "--new-desc", new_text, "--config"], timeout=30)
    if _linux_state(_parse_key_value_lines(_run_cmd(["virsh", "dominfo", name], timeout=15, check=False)).get("state", "")).lower() == "running":
        _run_cmd(["virsh", "desc", name, "--new-desc", new_text, "--live"], timeout=30, check=False)


def _line_mac_from_note(note: str) -> str:
    for pattern in (
        r"(?:^|\|\|)mac=([0-9A-Fa-f:.-]+)",
        r"(?:^|\|\|)wan_mac=([0-9A-Fa-f:.-]+)",
        r"\bmac[:=]\s*([0-9A-Fa-f:.-]+)",
    ):
        match = re.search(pattern, note or "")
        if match:
            return match.group(1)
    return ""


def _note_interface(note: str) -> str:
    if not note:
        return ""
    sep = "||" if "||" in note else "|"
    return note.split(sep, 1)[0].strip()


def _line_note_meta(note: str) -> dict[str, str]:
    if not note:
        return {}
    sep = "||" if "||" in note else "|"
    meta: dict[str, str] = {}
    for part in note.split(sep)[1:]:
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        meta[key.strip().lower()] = value.strip()
    return meta


def _looks_like_generated_line_interface(value: str) -> bool:
    text = (value or "").strip()
    if not text:
        return False
    return bool(
        re.search(r"-(\d{1,3})$", text)
        or re.match(r"^(wan-auto|vEthernet|dummy42|macv42|v42)-\d{1,3}$", text, re.I)
        or re.match(r"^WAN\d+-\d{1,3}$", text, re.I)
        or re.match(r"^WAN\d+_[0-9]+$", text, re.I)
    )


def _line_is_reserved_for_vm(line: Line) -> bool:
    name = line.name or ""
    note = line.note or ""
    iface = _note_interface(note)
    meta = _line_note_meta(note)
    marker_text = f"{name} {note}".lower()
    if _strip_ip_mask(line.public_ip or "") in LINUX_VM_RESERVED_PUBLIC_IPS:
        return True
    if any(word in marker_text for word in ("主网卡", "静默", "master", "primary", "silent", "reserved", "management", "manager")):
        return True
    if meta.get("is_master", "").lower() in {"1", "true", "yes"}:
        return True
    if meta.get("locked", "").lower() in {"1", "true", "yes"}:
        return True
    if iface and not _looks_like_generated_line_interface(iface):
        return True
    return False


def _active_lines() -> list[dict]:
    session = get_session()
    try:
        rows = (
            session.query(Line)
            .filter(Line.status == 1, Line.public_ip != "")
            .order_by(Line.id.asc())
            .all()
        )
        result = []
        for line in rows:
            public_ip = _strip_ip_mask(line.public_ip)
            if not public_ip or public_ip == "0.0.0.0":
                continue
            if _line_is_reserved_for_vm(line):
                continue
            result.append({
                "id": int(line.id),
                "name": line.name or f"line-{line.id}",
                "public_ip": public_ip,
                "internal_ip": line.internal_ip or "",
                "note": line.note or "",
                "mac": _line_mac_from_note(line.note or ""),
            })
        return result
    finally:
        session.close()


def _line_by_index_or_id(index: int | None = None, line_id: int | None = None, line_name: str | None = None) -> dict | None:
    rows = _active_lines()
    if not rows:
        return None
    if line_id:
        for row in rows:
            if row["id"] == int(line_id):
                return row
    if line_name:
        for row in rows:
            if row["name"] == line_name:
                return row
    position = max(1, int(index or 1))
    return rows[(position - 1) % len(rows)]


def _index_from_vm_name(name: str) -> int:
    match = re.search(r"(\d+)$", name or "")
    return int(match.group(1)) if match else 1


def _linux_vm_mapping(name: str) -> dict[str, str]:
    mapping = _kv_parse_notes(_linux_vm_description(name))
    if mapping.get("wan_ip") and not mapping.get("public_ip"):
        mapping["public_ip"] = _strip_ip_mask(mapping.get("wan_ip") or "")
    if mapping.get("public_ip"):
        mapping["public_ip"] = _strip_ip_mask(mapping.get("public_ip") or "")
        mapping["wan_ip"] = mapping["public_ip"]
    if not mapping.get("internal_ip"):
        ips = _private_ips(_linux_ip_rows(name))
        if ips:
            mapping["internal_ip"] = ips[0]
    return mapping


def _linux_ensure_chain(table: str, chain: str) -> None:
    _run_cmd(["iptables", "-t", table, "-N", chain], timeout=10, check=False)


def _linux_ensure_chain_jump(table: str, base_chain: str, target_chain: str) -> None:
    exists = subprocess.run(
        ["iptables", "-t", table, "-C", base_chain, "-j", target_chain],
        capture_output=True,
        text=True,
        timeout=10,
    ).returncode == 0
    if not exists:
        _run_cmd(["iptables", "-t", table, "-A", base_chain, "-j", target_chain], timeout=10)


def _linux_delete_rules_by_comment(table: str, chain: str, comment: str) -> None:
    for _ in range(100):
        raw = _run_cmd(["iptables", "-t", table, "-L", chain, "--line-numbers", "-n", "-v"], timeout=10, check=False)
        numbers = []
        for line in raw.splitlines():
            if comment not in line:
                continue
            first = line.split(None, 1)[0]
            if first.isdigit():
                numbers.append(int(first))
        if not numbers:
            break
        for number in sorted(numbers, reverse=True):
            _run_cmd(["iptables", "-t", table, "-D", chain, str(number)], timeout=10, check=False)


def _linux_ensure_vm_network(
    name: str = LINUX_VM_NETWORK,
    gateway: str = LINUX_VM_GATEWAY,
    prefix: int = LINUX_VM_NET_PREFIX,
) -> dict:
    name = (name or LINUX_VM_NETWORK).strip()
    gateway = (gateway or LINUX_VM_GATEWAY).strip()
    prefix = int(prefix or LINUX_VM_NET_PREFIX)
    network = ipaddress.ip_network(f"{gateway}/{prefix}", strict=False)
    netmask = str(network.netmask)
    existing = _run_cmd(["virsh", "net-info", name], timeout=15, check=False)
    created = False
    if "Name:" not in existing:
        xml = f"""<network>
  <name>{name}</name>
  <bridge name='{LINUX_VM_BRIDGE}' stp='on' delay='0'/>
  <ip address='{gateway}' netmask='{netmask}'/>
</network>
"""
        with tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False, encoding="utf-8") as tmp:
            tmp.write(xml)
            tmp_path = tmp.name
        try:
            _run_cmd(["virsh", "net-define", tmp_path], timeout=30)
            created = True
        finally:
            try:
                Path(tmp_path).unlink()
            except OSError:
                pass
    _run_cmd(["virsh", "net-start", name], timeout=30, check=False)
    _run_cmd(["virsh", "net-autostart", name], timeout=30, check=False)
    _run_cmd(["sysctl", "-w", "net.ipv4.ip_forward=1"], timeout=10, check=False)
    return {
        "ok": True,
        "switch_name": name,
        "network": name,
        "bridge": LINUX_VM_BRIDGE,
        "ip": gateway,
        "prefix": prefix,
        "network_cidr": str(network),
        "switch_created": created,
        "restart_required": False,
        "message": "VM internal KVM network is ready.",
    }


def _linux_apply_vm_mapping(name: str) -> dict:
    mapping = _linux_vm_mapping(name)
    internal_ip = _strip_ip_mask(mapping.get("internal_ip") or "")
    if not internal_ip:
        raise RuntimeError("VM mapping missing internal_ip.")
    line_id = int(mapping.get("line_id") or 0)
    line = _line_by_index_or_id(
        index=_index_from_vm_name(name),
        line_id=line_id or None,
        line_name=mapping.get("line_name") or None,
    )
    if not line:
        raise RuntimeError("No active line with public IP is available for VM mapping.")
    public_ip = _strip_ip_mask(line["public_ip"])
    if not public_ip:
        raise RuntimeError("Selected line has no public IP.")
    ssh_port = int(mapping.get("ssh_port") or 22)
    if ssh_port in LINUX_VM_RESERVED_PORTS:
        raise RuntimeError(
            f"VM SSH port {ssh_port} conflicts with the panel port. "
            "Use a dedicated high port such as 22001."
        )

    _run_cmd(["sysctl", "-w", "net.ipv4.ip_forward=1"], timeout=10, check=False)
    _linux_ensure_chain("nat", LINUX_VM_MAP_CHAIN_PRE)
    _linux_ensure_chain("nat", LINUX_VM_MAP_CHAIN_POST)
    _linux_ensure_chain("filter", "42IPWIN_VM_FWD")
    _linux_ensure_chain_jump("nat", "PREROUTING", LINUX_VM_MAP_CHAIN_PRE)
    _linux_ensure_chain_jump("nat", "POSTROUTING", LINUX_VM_MAP_CHAIN_POST)
    _linux_ensure_chain_jump("filter", "FORWARD", "42IPWIN_VM_FWD")

    comment = f"42ipwin-vm-{re.sub(r'[^A-Za-z0-9_.-]', '_', name)}"
    _linux_delete_rules_by_comment("nat", LINUX_VM_MAP_CHAIN_PRE, comment)
    _linux_delete_rules_by_comment("nat", LINUX_VM_MAP_CHAIN_POST, comment)
    _linux_delete_rules_by_comment("filter", "42IPWIN_VM_FWD", comment)
    _run_cmd([
        "iptables", "-t", "nat", "-A", LINUX_VM_MAP_CHAIN_PRE,
        "-d", public_ip, "-p", "tcp", "--dport", str(ssh_port),
        "-m", "comment", "--comment", comment,
        "-j", "DNAT", "--to-destination", f"{internal_ip}:22",
    ], timeout=10)
    _run_cmd([
        "iptables", "-t", "nat", "-A", LINUX_VM_MAP_CHAIN_POST,
        "-s", internal_ip, "-m", "comment", "--comment", comment,
        "-j", "SNAT", "--to-source", public_ip,
    ], timeout=10)
    _run_cmd([
        "iptables", "-t", "filter", "-A", "42IPWIN_VM_FWD",
        "-d", internal_ip, "-m", "comment", "--comment", comment, "-j", "ACCEPT",
    ], timeout=10, check=False)
    _run_cmd([
        "iptables", "-t", "filter", "-A", "42IPWIN_VM_FWD",
        "-s", internal_ip, "-m", "comment", "--comment", comment, "-j", "ACCEPT",
    ], timeout=10, check=False)

    old_public = _strip_ip_mask(mapping.get("public_ip") or mapping.get("wan_ip") or "")
    mapping.update({
        "line_id": str(line["id"]),
        "line_name": line["name"],
        "public_ip": public_ip,
        "wan_ip": public_ip,
        "wan_mac": line.get("mac") or "",
        "internal_ip": internal_ip,
        "internal_gateway": mapping.get("internal_gateway") or LINUX_VM_GATEWAY,
        "vm_network": mapping.get("vm_network") or LINUX_VM_NETWORK,
        "ssh_port": str(ssh_port),
    })
    _linux_set_vm_mapping_notes(name, mapping)
    return {
        "name": name,
        "line_id": line["id"],
        "line_name": line["name"],
        "old_public_ip": old_public,
        "public_ip": public_ip,
        "wan_ip": public_ip,
        "wan_mac": line.get("mac") or "",
        "internal_ip": internal_ip,
        "ssh_host": public_ip,
        "ssh_port": ssh_port,
        "bridge": LINUX_VM_BRIDGE,
        "network": mapping.get("vm_network") or LINUX_VM_NETWORK,
        "changed": old_public != public_ip,
        "safe": True,
        "message": f"{old_public or '-'} -> {public_ip}:{ssh_port}; VM internal IP stays {internal_ip}.",
    }


def _linux_list_vms():
    if not _linux_libvirt_available():
        return []
    rows = []
    for name in _linux_vm_names():
        info = _parse_key_value_lines(_run_cmd(["virsh", "dominfo", name], timeout=15, check=False))
        if_rows = _linux_domif_rows(name)
        ips = _linux_ip_rows(name)
        private_ips = _private_ips(ips)
        public_ips = _public_ips(ips)
        mapping = _linux_vm_mapping(name)
        max_memory = _memory_kib(info.get("max memory", "")) * 1024
        used_memory = _memory_kib(info.get("used memory", "")) * 1024
        rows.append({
            "name": name,
            "state": _linux_state(info.get("state", "")),
            "status": info.get("state", ""),
            "public_ip": mapping.get("public_ip") or mapping.get("wan_ip") or ", ".join(public_ips),
            "internal_ip": mapping.get("internal_ip") or ", ".join(private_ips),
            "line_id": mapping.get("line_id", ""),
            "line_name": mapping.get("line_name", ""),
            "mapping_message": f"{mapping.get('public_ip') or mapping.get('wan_ip') or '-'} -> {mapping.get('internal_ip') or '-'}",
            "mac": ", ".join([row.get("mac", "") for row in if_rows if row.get("mac")]),
            "switch_name": ", ".join([row.get("source", "") for row in if_rows if row.get("source")]),
            "uptime": "",
            "cpu_usage": 0,
            "memory_assigned": used_memory,
            "memory_startup": max_memory,
            "memory_demand": None,
            "processor_count": int(info.get("cpu(s)", "0") or 0),
            "automatic_start_action": "Start" if _linux_autostart(name) else "Nothing",
            "automatic_stop_action": "ShutDown",
            "generation": 0,
            "version": "libvirt",
        })
    return rows


def _linux_autostart(name: str) -> bool:
    raw = _run_cmd(["virsh", "dominfo", name], timeout=15, check=False)
    return "Autostart:      enable" in raw


def _linux_host_summary():
    available = _linux_libvirt_available()
    if not available:
        return {
            "available": False,
            "computer_name": socket.gethostname(),
            "total": 0,
            "running": 0,
            "message": "当前 Ubuntu 主机未检测到可用 KVM/libvirt，无法读取虚拟机。",
        }
    rows = _linux_list_vms()
    return {
        "available": True,
        "platform": "KVM/libvirt",
        "computer_name": socket.gethostname(),
        "total": len(rows),
        "running": len([row for row in rows if str(row.get("state", "")).lower() == "running"]),
        "off": len([row for row in rows if str(row.get("state", "")).lower() == "off"]),
        "paused": len([row for row in rows if str(row.get("state", "")).lower() == "paused"]),
        "saved": 0,
        "virtual_hard_disk_path": "/var/lib/libvirt/images",
        "virtual_machine_path": "/etc/libvirt/qemu",
    }


def _linux_list_switches():
    if not _linux_libvirt_available():
        return []
    rows = []
    raw = _run_cmd(["virsh", "net-list", "--all"], timeout=15, check=False)
    for line in raw.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[0] not in {"Name", "----------------"}:
            rows.append({"name": parts[0], "switch_type": "libvirt network", "net_adapter": ""})
    try:
        raw_links = _run_cmd(["sh", "-c", "ip -j link show type bridge"], timeout=8, check=False)
        for item in json.loads(raw_links or "[]"):
            name = item.get("ifname")
            if name and not any(row["name"] == name for row in rows):
                rows.append({"name": name, "switch_type": "Linux bridge", "net_adapter": ""})
    except Exception:
        pass
    return rows


def _linux_list_images():
    roots = [Path("/var/lib/libvirt/images"), Path("/var/lib/libvirt/images/42ipwin")]
    rows = []
    seen = set()
    for root in roots:
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if not path.is_file() or path.suffix.lower() not in {".qcow2", ".img", ".iso"}:
                continue
            resolved = str(path.resolve())
            if resolved in seen:
                continue
            seen.add(resolved)
            stat = path.stat()
            rows.append({
                "name": path.name,
                "path": str(path),
                "size": stat.st_size,
                "extension": path.suffix.lower(),
                "updated_at": time_string(stat.st_mtime),
            })
    rows.sort(key=lambda row: row.get("updated_at", ""), reverse=True)
    return rows


def time_string(timestamp: float) -> str:
    import datetime

    return datetime.datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")


def _linux_vm_action(name: str, action: str):
    mapping = {
        "start": ["virsh", "start", name],
        "shutdown": ["virsh", "shutdown", name],
        "turnoff": ["virsh", "destroy", name],
        "restart": ["virsh", "reboot", name],
        "reset": ["virsh", "reset", name],
        "save": ["virsh", "managedsave", name],
    }
    if action not in mapping:
        raise ValueError("Unsupported VM action.")
    _run_cmd(mapping[action], timeout=60)
    info = _parse_key_value_lines(_run_cmd(["virsh", "dominfo", name], timeout=15, check=False))
    return {"name": name, "state": _linux_state(info.get("state", "")), "status": info.get("state", ""), "uptime": ""}


def _linux_get_vm_config(name: str):
    info = _parse_key_value_lines(_run_cmd(["virsh", "dominfo", name], timeout=15))
    xml = _run_cmd(["virsh", "dumpxml", name], timeout=15, check=False)
    memory_mb = int((_memory_kib(info.get("max memory", "")) * 1024) / 1024 / 1024)
    description = ""
    match = re.search(r"<description>(.*?)</description>", xml, flags=re.S)
    if match:
        description = re.sub(r"\s+", " ", match.group(1)).strip()
    mapping = _linux_vm_mapping(name)
    ips = _linux_ip_rows(name)
    private_ips = _private_ips(ips)
    public_ips = _public_ips(ips)
    return {
        "name": name,
        "state": _linux_state(info.get("state", "")),
        "processor_count": int(info.get("cpu(s)", "1") or 1),
        "memory_startup_mb": memory_mb,
        "dynamic_memory_enabled": False,
        "memory_minimum_mb": memory_mb,
        "memory_maximum_mb": memory_mb,
        "automatic_start_action": "Start" if _linux_autostart(name) else "Nothing",
        "automatic_stop_action": "ShutDown",
        "notes": description,
        "public_ip_mapping": mapping.get("public_ip") or mapping.get("wan_ip") or ", ".join(public_ips),
        "public_ip_source": mapping.get("line_name") or "KVM/libvirt",
        "public_ip_gateway": "",
        "public_ip_dns": "",
        "public_ip_mac": mapping.get("wan_mac") or ", ".join([row.get("mac", "") for row in _linux_domif_rows(name) if row.get("mac")]),
        "internal_ip_mapping": mapping.get("internal_ip") or ", ".join(private_ips),
        "lan_mac": "",
        "ssh_listen": "",
        "ssh_port": mapping.get("ssh_port") or "",
    }


def _linux_update_vm_config(name: str, data: dict):
    start_action = (data.get("automatic_start_action") or "Nothing").strip()
    notes = data.get("notes") or ""
    if start_action == "Start":
        _run_cmd(["virsh", "autostart", name], timeout=30)
    else:
        _run_cmd(["virsh", "autostart", "--disable", name], timeout=30, check=False)
    if notes:
        _run_cmd(["virsh", "desc", name, "--new-desc", notes, "--config"], timeout=30)
    return _linux_get_vm_config(name)


def _linux_delete_vm(name: str):
    _run_cmd(["virsh", "destroy", name], timeout=60, check=False)
    _run_cmd(["virsh", "undefine", name, "--nvram", "--remove-all-storage"], timeout=120, check=False)
    if name in _linux_vm_names():
        _run_cmd(["virsh", "undefine", name, "--nvram"], timeout=60, check=False)
    return {"name": name, "deleted": True, "disk_deleted": True, "message": "KVM VM was removed."}


def _run_ps(script: str, timeout: int = 30):
    if platform.system().lower() != "windows":
        raise RuntimeError("Hyper-V management is only available on Windows hosts.")

    completed = subprocess.run(
        [
            POWERSHELL,
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ],
        capture_output=True,
        text=True,
        timeout=timeout,
        encoding=locale.getpreferredencoding(False),
        errors="replace",
    )
    if completed.returncode != 0:
        err = (completed.stderr or completed.stdout or "").strip()
        raise RuntimeError(_friendly_error(err) or f"PowerShell exited with {completed.returncode}")
    return completed.stdout.strip()


def _friendly_error(text: str):
    text = text or ""
    if "InvalidState" in text or "InvalidStateException" in text:
        return "虚拟机正在运行，CPU/内存等硬件配置需要先关机后才能修改。"
    if "NamedParameterNotFound" in text and "Stop-VM" in text:
        return "关机命令参数不兼容，已修正为当前 Hyper-V 支持的关机方式，请刷新后重试。"
    if "The operation cannot be performed while the object is in its current state" in text:
        return "当前虚拟机状态不允许执行这个操作，请刷新状态后再试。"
    if "Failed to stop" in text or "Stop-VM" in text:
        return "虚拟机关机失败。可以先尝试正常关机；如果系统无响应，再使用强制断电。"
    if "Set-VMProcessor" in text:
        return "CPU 配置修改失败，请确认虚拟机已关机。"
    if "Set-VMMemory" in text:
        return "内存配置修改失败，请确认虚拟机已关机，且内存范围填写正确。"
    if "Hyper-V" in text and ("not recognized" in text or "无法将" in text):
        return "当前主机没有可用的 Hyper-V PowerShell 管理模块。"
    return text


def _json_ps(script: str, timeout: int = 30):
    output = _run_ps(script, timeout=timeout)
    if not output:
        return []
    return json.loads(output)


def _set_image_job(job_id: str, **updates):
    with IMAGE_JOBS_LOCK:
        job = IMAGE_JOBS.setdefault(job_id, {})
        job.update(updates)
        job["updated_at"] = time.time()
        return dict(job)


def _set_create_vm_job(job_id: str, **updates):
    with CREATE_VM_JOBS_LOCK:
        job = CREATE_VM_JOBS.setdefault(job_id, {})
        job.update(updates)
        job["updated_at"] = time.time()
        return dict(job)


def _append_create_vm_message(job_id: str, message: str):
    if not message:
        return
    with CREATE_VM_JOBS_LOCK:
        job = CREATE_VM_JOBS.setdefault(job_id, {})
        messages = list(job.get("messages") or [])
        messages.append(message)
        job["messages"] = messages[-300:]
        job["updated_at"] = time.time()


def _set_start_vm_job(job_id: str, **updates):
    with START_VM_JOBS_LOCK:
        job = START_VM_JOBS.setdefault(job_id, {})
        job.update(updates)
        job["updated_at"] = time.time()
        return dict(job)


def _append_start_vm_message(job_id: str, message: str):
    if not message:
        return
    with START_VM_JOBS_LOCK:
        job = START_VM_JOBS.setdefault(job_id, {})
        messages = list(job.get("messages") or [])
        messages.append(message)
        job["messages"] = messages[-300:]
        job["updated_at"] = time.time()


def _download_with_progress(url: str, dest: Path, job_id: str, stage: str, start_percent: int, end_percent: int):
    dest.parent.mkdir(parents=True, exist_ok=True)
    req = urllib.request.Request(url, headers={"User-Agent": "42IPwin/1.0"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        total = int(resp.headers.get("Content-Length") or 0)
        done = 0
        tmp = dest.with_suffix(dest.suffix + ".tmp")
        with tmp.open("wb") as fh:
            while True:
                chunk = resp.read(1024 * 1024)
                if not chunk:
                    break
                fh.write(chunk)
                done += len(chunk)
                if total:
                    percent = start_percent + int((end_percent - start_percent) * done / total)
                    _set_image_job(
                        job_id,
                        stage=stage,
                        percent=min(end_percent, percent),
                        downloaded=done,
                        total=total,
                        message=f"{stage}: {done / 1024 / 1024:.1f}/{total / 1024 / 1024:.1f} MB",
                    )
        tmp.replace(dest)


def _prepare_debian_cloud_image_worker(job_id: str, force: bool = False):
    started = time.time()
    if _is_linux():
        try:
            _set_image_job(job_id, status="running", stage="prepare", percent=1, message="Preparing KVM image directory")
            LINUX_IMAGE_DIR.mkdir(parents=True, exist_ok=True)
            if force:
                try:
                    LINUX_DEBIAN_IMAGE.unlink()
                except FileNotFoundError:
                    pass
            if not LINUX_DEBIAN_IMAGE.exists():
                _download_with_progress(DEBIAN_IMAGE_URL, LINUX_DEBIAN_IMAGE, job_id, "Downloading Debian cloud image", 3, 96)
            else:
                size = LINUX_DEBIAN_IMAGE.stat().st_size
                _set_image_job(
                    job_id,
                    status="running",
                    stage="download",
                    percent=96,
                    downloaded=size,
                    total=size,
                    message="Debian cloud image already exists",
                )
            result = {
                "image": str(LINUX_DEBIAN_IMAGE),
                "qcow": str(LINUX_DEBIAN_IMAGE),
                "seconds": int(time.time() - started),
                "qcow_size": LINUX_DEBIAN_IMAGE.stat().st_size if LINUX_DEBIAN_IMAGE.exists() else 0,
                "vhdx_size": 0,
                "virtual_size": 0,
                "platform": "KVM/libvirt",
            }
            _set_image_job(job_id, status="done", stage="done", percent=100, message="KVM image is ready", result=result)
        except Exception as exc:
            _set_image_job(job_id, status="error", stage="error", percent=100, message=str(exc), error=str(exc))
        return

    qcow = Path(r"C:\42IPwin\images\debian-12-genericcloud-amd64.qcow2")
    vhdx = Path(r"C:\42IPwin\images\debian-12-genericcloud-amd64.vhdx")
    qemu_setup = Path(r"C:\42IPwin\tools\qemu-w64-setup-20260501.exe")
    qemu_img = Path(r"C:\Program Files\qemu\qemu-img.exe")
    try:
        _set_image_job(job_id, status="running", stage="prepare", percent=1, message="Preparing image directories")
        qcow.parent.mkdir(parents=True, exist_ok=True)
        qemu_setup.parent.mkdir(parents=True, exist_ok=True)
        if force:
            for path in (qcow, vhdx):
                try:
                    path.unlink()
                except FileNotFoundError:
                    pass

        if not qcow.exists():
            _download_with_progress(DEBIAN_IMAGE_URL, qcow, job_id, "Downloading Debian cloud image", 5, 55)
        else:
            _set_image_job(job_id, stage="download", percent=55, message="Debian cloud image already exists")

        if not qemu_img.exists():
            if not qemu_setup.exists():
                _download_with_progress(QEMU_SETUP_URL, qemu_setup, job_id, "Downloading qemu installer", 56, 70)
            _set_image_job(job_id, stage="install", percent=72, message="Installing qemu")
            subprocess.run([str(qemu_setup), "/S"], check=True, timeout=900)
        if not qemu_img.exists():
            raise RuntimeError("qemu-img install failed.")

        if not vhdx.exists():
            _set_image_job(job_id, stage="convert", percent=75, message="Converting qcow2 to vhdx")
            proc = subprocess.Popen(
                [str(qemu_img), "convert", "-p", "-f", "qcow2", "-O", "vhdx", "-o", "subformat=dynamic", str(qcow), str(vhdx)],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding=locale.getpreferredencoding(False),
                errors="replace",
            )
            last_output = ""
            while True:
                line = proc.stdout.readline() if proc.stdout else ""
                if not line and proc.poll() is not None:
                    break
                if line:
                    last_output = line.strip()
                    match = re.search(r"(\d+(?:\.\d+)?)\s*%", last_output)
                    if match:
                        percent = 75 + int(float(match.group(1)) * 0.23)
                        _set_image_job(job_id, stage="convert", percent=min(98, percent), message=f"Converting qcow2 to vhdx: {match.group(1)}%")
                    else:
                        _set_image_job(job_id, stage="convert", percent=80, message=last_output or "Converting qcow2 to vhdx")
            if proc.returncode:
                raise RuntimeError(last_output or f"qemu-img exited with {proc.returncode}")
        else:
            _set_image_job(job_id, stage="convert", percent=98, message="VHDX image already exists")

        result = {
            "image": str(vhdx),
            "qcow": str(qcow),
            "seconds": int(time.time() - started),
            "qcow_size": qcow.stat().st_size if qcow.exists() else 0,
            "vhdx_size": vhdx.stat().st_size if vhdx.exists() else 0,
            "virtual_size": 0,
            "qemu": "",
        }
        try:
            result["qemu"] = subprocess.check_output([str(qemu_img), "--version"], text=True, timeout=10, errors="replace").splitlines()[0]
        except Exception:
            pass
        _set_image_job(job_id, status="done", stage="done", percent=100, message="Image is ready", result=result)
    except Exception as exc:
        _set_image_job(job_id, status="error", stage="error", percent=100, message=str(exc), error=str(exc))


def _list_vms_uncached():
    if _is_linux():
        return _linux_list_vms()

    script = r"""
$ErrorActionPreference = 'Stop'
Import-Module Hyper-V
$vms = Get-VM | Sort-Object Name | ForEach-Object {
  $cpu = $null
  $plannedPublicIp = ''
  $internalIp = ''
  $mac = ''
  $switchName = ''
  if ($_.Notes -match '(?m)^wan_ip=([0-9.]+)(?:/\d+)?') {
    $plannedPublicIp = $Matches[1]
  } elseif ($_.Notes -match 'wan_ip=([0-9.]+)(?:/\d+)?') {
    $plannedPublicIp = $Matches[1]
  }
  if ($_.Notes -match '(?m)^internal_ip=([0-9.]+)') { $internalIp = $Matches[1] }
  if ($_.Notes -match '(?m)^lan_mac=([0-9A-Fa-f:-]+)') { $mac = $Matches[1] }
  if ($_.Notes -match '(?m)^source=(.+)$') { $switchName = $Matches[1].Trim() }
  try { $cpu = Get-VMMemory -VMName $_.Name } catch {}
  [pscustomobject]@{
    name = $_.Name
    state = $_.State.ToString()
    status = $_.Status
    public_ip = $plannedPublicIp
    internal_ip = $internalIp
    mac = $mac
    switch_name = $switchName
    uptime = $_.Uptime.ToString()
    cpu_usage = $_.CPUUsage
    memory_assigned = $_.MemoryAssigned
    memory_startup = $_.MemoryStartup
    memory_demand = if ($cpu) { $cpu.Demand } else { $null }
    processor_count = $_.ProcessorCount
    automatic_start_action = $_.AutomaticStartAction.ToString()
    automatic_stop_action = $_.AutomaticStopAction.ToString()
    generation = $_.Generation
    version = $_.Version.ToString()
  }
}
$vms | ConvertTo-Json -Depth 4
"""
    data = _json_ps(script)
    if isinstance(data, dict):
        return [data]
    return data or []




def _refresh_vm_list_cache():
    with VM_LIST_CACHE_LOCK:
        if VM_LIST_CACHE.get("refreshing"):
            return
        VM_LIST_CACHE["refreshing"] = True
    try:
        rows = _list_vms_uncached()
        with VM_LIST_CACHE_LOCK:
            VM_LIST_CACHE.update({"rows": rows, "updated_at": time.time(), "refreshing": False, "error": ""})
    except Exception as exc:
        with VM_LIST_CACHE_LOCK:
            VM_LIST_CACHE.update({"refreshing": False, "error": str(exc), "updated_at": time.time()})


def _start_vm_list_refresh():
    with VM_LIST_CACHE_LOCK:
        if VM_LIST_CACHE.get("refreshing"):
            return
        VM_LIST_CACHE["refreshing"] = True
    def worker():
        try:
            rows = _list_vms_uncached()
            with VM_LIST_CACHE_LOCK:
                VM_LIST_CACHE.update({"rows": rows, "updated_at": time.time(), "refreshing": False, "error": ""})
        except Exception as exc:
            with VM_LIST_CACHE_LOCK:
                VM_LIST_CACHE.update({"refreshing": False, "error": str(exc), "updated_at": time.time()})
    threading.Thread(target=worker, daemon=True).start()


def list_vms(force: bool = False):
    if _is_linux():
        return _linux_list_vms()
    if force:
        _refresh_vm_list_cache()
    with VM_LIST_CACHE_LOCK:
        rows = list(VM_LIST_CACHE.get("rows") or [])
        updated_at = float(VM_LIST_CACHE.get("updated_at") or 0)
        refreshing = bool(VM_LIST_CACHE.get("refreshing"))
        error = str(VM_LIST_CACHE.get("error") or "")
    if not rows:
        _refresh_vm_list_cache()
        with VM_LIST_CACHE_LOCK:
            rows = list(VM_LIST_CACHE.get("rows") or [])
            error = str(VM_LIST_CACHE.get("error") or "")
        if error and not rows:
            raise RuntimeError(error)
        return rows
    if not refreshing and (time.time() - updated_at) > 5:
        _start_vm_list_refresh()
    return rows

def get_vm_config(name: str):
    name = (name or "").strip()
    if not name:
        raise ValueError("VM name is required.")
    if _is_linux():
        return _linux_get_vm_config(name)

    script = rf"""
$ErrorActionPreference = 'Stop'
Import-Module Hyper-V
$name = {json.dumps(name)}
$vm = Get-VM -Name $name
$mem = Get-VMMemory -VMName $name
$notes = [string]$vm.Notes
$mapping = @{{}}
foreach ($key in @('source','wan_ip','gateway','dns','wan_mac','image','internal_ip','internal_gateway','lan_mac','ssh_listen','ssh_port')) {{
  if ($notes -match "(?m)^$key=(.+)$") {{
    $mapping[$key] = $Matches[1].Trim()
  }} elseif ($notes -match "$key=(.+?)(?=source=|wan_ip=|gateway=|dns=|wan_mac=|image=|internal_ip=|internal_gateway=|lan_mac=|ssh_listen=|ssh_port=|$)") {{
    $mapping[$key] = $Matches[1].Trim()
  }} else {{
    $mapping[$key] = ''
  }}
}}
[pscustomobject]@{{
  name = $vm.Name
  state = $vm.State.ToString()
  processor_count = $vm.ProcessorCount
  memory_startup_mb = [int]($mem.Startup / 1MB)
  dynamic_memory_enabled = [bool]$mem.DynamicMemoryEnabled
  memory_minimum_mb = [int]($mem.Minimum / 1MB)
  memory_maximum_mb = [int]($mem.Maximum / 1MB)
  automatic_start_action = $vm.AutomaticStartAction.ToString()
  automatic_stop_action = $vm.AutomaticStopAction.ToString()
  notes = $vm.Notes
  public_ip_mapping = $mapping['wan_ip']
  public_ip_source = $mapping['source']
  public_ip_gateway = $mapping['gateway']
  public_ip_dns = $mapping['dns']
  public_ip_mac = $mapping['wan_mac']
  internal_ip_mapping = $mapping['internal_ip']
  lan_mac = $mapping['lan_mac']
  ssh_listen = $mapping['ssh_listen']
  ssh_port = $mapping['ssh_port']
}} | ConvertTo-Json -Depth 4
"""
    return _json_ps(script)


def host_summary():
    if _is_linux():
        return _linux_host_summary()
    with VM_LIST_CACHE_LOCK:
        cached_rows = list(VM_LIST_CACHE.get("rows") or [])
    if cached_rows:
        return {
            "available": True,
            "computer_name": socket.gethostname(),
            "total": len(cached_rows),
            "running": len([row for row in cached_rows if str(row.get("state", "")).lower() == "running"]),
            "off": len([row for row in cached_rows if str(row.get("state", "")).lower() == "off"]),
            "paused": len([row for row in cached_rows if str(row.get("state", "")).lower() == "paused"]),
            "saved": len([row for row in cached_rows if str(row.get("state", "")).lower() == "saved"]),
            "cached": True,
        }

    script = r"""
$ErrorActionPreference = 'Stop'
Import-Module Hyper-V
$vms = @(Get-VM)
$hostInfo = Get-VMHost
$summary = [pscustomobject]@{
  computer_name = $env:COMPUTERNAME
  total = $vms.Count
  running = @($vms | Where-Object {$_.State -eq 'Running'}).Count
  off = @($vms | Where-Object {$_.State -eq 'Off'}).Count
  paused = @($vms | Where-Object {$_.State -eq 'Paused'}).Count
  saved = @($vms | Where-Object {$_.State -eq 'Saved'}).Count
  virtual_hard_disk_path = $hostInfo.VirtualHardDiskPath
  virtual_machine_path = $hostInfo.VirtualMachinePath
}
$summary | ConvertTo-Json -Depth 4
"""
    return _json_ps(script)


def list_switches():
    if _is_linux():
        return _linux_list_switches()

    script = r"""
$ErrorActionPreference = 'Stop'
Import-Module Hyper-V
Get-VMSwitch | Sort-Object Name | ForEach-Object {
  [pscustomobject]@{
    name = $_.Name
    switch_type = $_.SwitchType.ToString()
    net_adapter = $_.NetAdapterInterfaceDescription
  }
} | ConvertTo-Json -Depth 4
"""
    data = _json_ps(script)
    if isinstance(data, dict):
        return [data]
    return data or []


def ensure_vm_lan_switch(name: str = "VM-LAN", ip: str = "192.168.9.1", prefix: int = 24):
    if _is_linux():
        return _linux_ensure_vm_network(name or LINUX_VM_NETWORK, ip or LINUX_VM_GATEWAY, int(prefix or LINUX_VM_NET_PREFIX))
    name = (name or "VM-LAN").strip()
    ip = (ip or "192.168.9.1").strip()
    prefix = int(prefix or 24)
    script = rf"""
$ErrorActionPreference = 'Stop'
$restartRequired = $false
$featureChanged = $false
try {{
  Import-Module Hyper-V -ErrorAction Stop
}} catch {{
  $enabled = $false
  try {{
    $serverFeature = Get-WindowsFeature -Name Hyper-V -ErrorAction Stop
    if ($serverFeature -and -not $serverFeature.Installed) {{
      $result = Install-WindowsFeature -Name Hyper-V -IncludeManagementTools -ErrorAction Stop
      $featureChanged = $true
      $restartRequired = [bool]$result.RestartNeeded
    }}
    $enabled = $true
  }} catch {{
    try {{
      $clientFeature = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -ErrorAction Stop
      if ($clientFeature.State -ne 'Enabled') {{
        $result = Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -All -NoRestart -ErrorAction Stop
        $featureChanged = $true
        $restartRequired = [bool]$result.RestartNeeded
      }}
      $enabled = $true
    }} catch {{
      [pscustomobject]@{{
        ok = $false
        switch_name = {json.dumps(name)}
        switch_created = $false
        ip = {json.dumps(ip)}
        prefix = {prefix}
        feature_state = 'Unavailable'
        feature_changed = $featureChanged
        restart_required = $true
        message = 'Hyper-V is not available yet. Enable Hyper-V and restart Windows before creating VMs.'
      }} | ConvertTo-Json -Depth 4
      exit 0
    }}
  }}
  try {{ Import-Module Hyper-V -ErrorAction Stop }} catch {{
    [pscustomobject]@{{
      ok = $false
      switch_name = {json.dumps(name)}
      switch_created = $false
      ip = {json.dumps(ip)}
      prefix = {prefix}
      feature_state = if ($enabled) {{ 'Enabled' }} else {{ 'Unavailable' }}
      feature_changed = $featureChanged
      restart_required = $true
      message = 'Hyper-V was enabled or changed; restart Windows before creating VMs.'
    }} | ConvertTo-Json -Depth 4
    exit 0
  }}
}}
$switchName = {json.dumps(name)}
$switchCreated = $false
$existing = Get-VMSwitch -Name $switchName -ErrorAction SilentlyContinue
if (-not $existing) {{
  New-VMSwitch -Name $switchName -SwitchType Internal | Out-Null
  $switchCreated = $true
}} elseif ($existing.SwitchType.ToString() -ne 'Internal') {{
  throw "Switch $switchName exists but is not Internal."
}}
$alias = "vEthernet ($switchName)"
for ($i = 0; $i -lt 20; $i++) {{
  if (Get-NetAdapter -Name $alias -ErrorAction SilentlyContinue) {{ break }}
  Start-Sleep -Seconds 1
}}
if (-not (Get-NetAdapter -Name $alias -ErrorAction SilentlyContinue)) {{
  throw "Internal adapter $alias was not created."
}}
$targetIp = {json.dumps(ip)}
$targetPrefix = {prefix}
$current = Get-NetIPAddress -InterfaceAlias $alias -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object {{ $_.IPAddress -eq $targetIp }}
if (-not $current) {{
  Get-NetIPAddress -InterfaceAlias $alias -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object {{ $_.PrefixOrigin -ne 'WellKnown' }} | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
  New-NetIPAddress -InterfaceAlias $alias -IPAddress $targetIp -PrefixLength $targetPrefix | Out-Null
}}
[pscustomobject]@{{
  ok = $true
  switch_name = $switchName
  switch_created = $switchCreated
  adapter = $alias
  ip = $targetIp
  prefix = $targetPrefix
  feature_state = 'Enabled'
  feature_changed = $featureChanged
  restart_required = $restartRequired
  message = if ($restartRequired) {{ 'Hyper-V was enabled; restart Windows before creating VMs.' }} else {{ 'VM internal switch is ready.' }}
}} | ConvertTo-Json -Depth 4
"""
    return _json_ps(script, timeout=300)


def list_images():
    if _is_linux():
        return _linux_list_images()

    script = r"""
$ErrorActionPreference = 'Stop'
Import-Module Hyper-V
$paths = @()
$paths += 'C:\42IPwin\images'
$paths = $paths | Select-Object -Unique
$rows = @()
foreach ($p in $paths) {
  if (-not (Test-Path $p)) { continue }
  $rows += Get-ChildItem -Path $p -File -ErrorAction SilentlyContinue | Where-Object {
    $_.Extension.ToLower() -in @('.vhd','.vhdx','.iso') -and $_.Name -notmatch '-seed\.vhdx$' -and $_.Name -notmatch '^Debian-WAN\d+-\d+\.vhdx$'
  } | ForEach-Object {
    [pscustomobject]@{
      name = $_.Name
      path = $_.FullName
      size = $_.Length
      extension = $_.Extension.ToLower()
      updated_at = $_.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
    }
  }
}
$rows | Sort-Object updated_at -Descending | ConvertTo-Json -Depth 4
"""
    data = _json_ps(script, timeout=60)
    if isinstance(data, dict):
        return [data]
    return data or []


def import_image(source_path: str):
    if _is_linux():
        raise RuntimeError("Linux/KVM 镜像请放到 /var/lib/libvirt/images 或 /var/lib/libvirt/images/42ipwin。")

    source_path = (source_path or "").strip().strip('"')
    if not source_path:
        raise ValueError("Image path is required.")
    if not source_path.lower().endswith((".vhd", ".vhdx", ".iso")):
        raise ValueError("Only .vhd, .vhdx, and .iso images are supported.")

    script = rf"""
$ErrorActionPreference = 'Stop'
$source = {json.dumps(source_path)}
if (-not (Test-Path $source)) {{ throw '镜像文件不存在。' }}
$destDir = 'C:\42IPwin\images'
New-Item -ItemType Directory -Force -Path $destDir | Out-Null
$dest = Join-Path $destDir (Split-Path $source -Leaf)
if ((Resolve-Path $source).Path -ne $dest) {{
  Copy-Item -Force -Path $source -Destination $dest
}}
$item = Get-Item $dest
[pscustomobject]@{{
  name = $item.Name
  path = $item.FullName
  size = $item.Length
  extension = $item.Extension.ToLower()
  updated_at = $item.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
}} | ConvertTo-Json -Depth 4
"""
    return _json_ps(script, timeout=600)


def install_ikuai_vm(data: dict):
    if _is_linux():
        raise RuntimeError("iKuai install is only implemented on the Windows Hyper-V host.")

    name = (data.get("name") or "iKuai").strip()
    image_path = (data.get("image_path") or "").strip()
    processor_count = 4
    memory_startup_mb = 4096
    disk_size_gb = 8
    generation = 1
    lan_switch = (data.get("lan_switch") or "VM-LAN").strip()
    wan_switches = data.get("wan_switches") or []
    if isinstance(wan_switches, str):
        wan_switches = [x.strip() for x in wan_switches.splitlines() if x.strip()]
    wan_switches = [str(x).strip() for x in wan_switches if str(x).strip()]
    internal_ip = (data.get("internal_ip") or "192.168.9.253").strip()
    auto_start = bool(data.get("auto_start"))

    if not name:
        raise ValueError("VM name is required.")
    if not image_path:
        raise ValueError("iKuai image path is required.")
    if processor_count < 1 or processor_count > 64:
        raise ValueError("CPU count must be between 1 and 64.")
    if memory_startup_mb < 128:
        raise ValueError("Startup memory must be at least 128 MB.")
    if disk_size_gb < 1 or disk_size_gb > 2048:
        raise ValueError("Disk size must be between 1 and 2048 GB.")
    if generation not in {1, 2}:
        raise ValueError("VM generation must be 1 or 2.")

    name_json = json.dumps(name, ensure_ascii=False)
    image_json = json.dumps(image_path, ensure_ascii=False)
    lan_json = json.dumps(lan_switch, ensure_ascii=False)
    wan_json = json.dumps(wan_switches, ensure_ascii=False)
    auto_start_ps = "$true" if auto_start else "$false"

    script = rf"""
$ErrorActionPreference = 'Stop'
Import-Module Hyper-V
$name = {name_json}
$imagePath = {image_json}
$lanSwitch = {lan_json}
$wanSwitches = ConvertFrom-Json @'
{wan_json}
'@
$autoStart = {auto_start_ps}
if (Get-VM -Name $name -ErrorAction SilentlyContinue) {{ throw "VM already exists: $name" }}
if (-not (Test-Path $imagePath)) {{ throw "iKuai image not found: $imagePath" }}
if ($lanSwitch -and -not (Get-VMSwitch -Name $lanSwitch -ErrorAction SilentlyContinue)) {{ throw "LAN switch not found: $lanSwitch" }}
foreach ($sw in @($wanSwitches)) {{
  if ($sw -and -not (Get-VMSwitch -Name $sw -ErrorAction SilentlyContinue)) {{ throw "WAN switch not found: $sw" }}
}}
$hostInfo = Get-VMHost
$vmRoot = $hostInfo.VirtualMachinePath
$vhdRoot = $hostInfo.VirtualHardDiskPath
if (-not $vmRoot) {{ $vmRoot = 'C:\HyperV\VMs' }}
if (-not $vhdRoot) {{ $vhdRoot = 'C:\HyperV\VHDs' }}
$vmPath = Join-Path $vmRoot $name
New-Item -ItemType Directory -Force -Path $vmPath,$vhdRoot | Out-Null
$vhdPath = Join-Path $vhdRoot ($name + '.vhdx')
if (Test-Path $vhdPath) {{ throw "VM disk already exists: $vhdPath" }}
$imageLower = $imagePath.ToLower()
$args = @{{ Name = $name; Generation = {generation}; MemoryStartupBytes = ({memory_startup_mb}MB); Path = $vmRoot }}
if ($imageLower.EndsWith('.vhd') -or $imageLower.EndsWith('.vhdx')) {{
  Copy-Item -Force -Path $imagePath -Destination $vhdPath
  $args.VHDPath = $vhdPath
}} else {{
  $args.NewVHDPath = $vhdPath
  $args.NewVHDSizeBytes = ({disk_size_gb}GB)
}}
if ($lanSwitch) {{ $args.SwitchName = $lanSwitch }}
New-VM @args | Out-Null
Set-VMProcessor -VMName $name -Count {processor_count}
Set-VM -Name $name -AutomaticStopAction ShutDown -Notes "role=ikuai`ncreated_by=42IPwin`nlan_switch=$lanSwitch`ninternal_ip={internal_ip}"
if ($imageLower.EndsWith('.iso')) {{
  Add-VMDvdDrive -VMName $name -Path $imagePath
  Set-VMFirmware -VMName $name -FirstBootDevice (Get-VMDvdDrive -VMName $name | Select-Object -First 1)
}}
$index = 1
foreach ($sw in @($wanSwitches)) {{
  if (-not $sw) {{ continue }}
  Add-VMNetworkAdapter -VMName $name -Name ("WAN" + $index) -SwitchName $sw | Out-Null
  $index += 1
}}
if ($autoStart) {{ Start-VM -Name $name }}
$vm = Get-VM -Name $name
$adapters = @(Get-VMNetworkAdapter -VMName $name | ForEach-Object {{
  [pscustomobject]@{{ name=$_.Name; switch_name=$_.SwitchName; mac=$_.MacAddress }}
}})
[pscustomobject]@{{
  name = $vm.Name
  state = $vm.State.ToString()
  generation = $vm.Generation
  cpu = {processor_count}
  memory_mb = {memory_startup_mb}
  vhd = $vhdPath
  image = $imagePath
  lan_switch = $lanSwitch
  internal_ip = {json.dumps(internal_ip, ensure_ascii=False)}
  wan_switches = @($wanSwitches)
  adapters = $adapters
}} | ConvertTo-Json -Depth 6
"""
    return _json_ps(script, timeout=900)


def prepare_debian_cloud_image(force: bool = False):
    if _is_linux():
        started = time.time()
        LINUX_IMAGE_DIR.mkdir(parents=True, exist_ok=True)
        if force:
            try:
                LINUX_DEBIAN_IMAGE.unlink()
            except FileNotFoundError:
                pass
        if not LINUX_DEBIAN_IMAGE.exists():
            _download_with_progress(DEBIAN_IMAGE_URL, LINUX_DEBIAN_IMAGE, uuid.uuid4().hex, "Downloading Debian cloud image", 3, 96)
        return {
            "image": str(LINUX_DEBIAN_IMAGE),
            "qcow": str(LINUX_DEBIAN_IMAGE),
            "seconds": int(time.time() - started),
            "qcow_size": LINUX_DEBIAN_IMAGE.stat().st_size if LINUX_DEBIAN_IMAGE.exists() else 0,
            "vhdx_size": 0,
            "virtual_size": 0,
            "platform": "KVM/libvirt",
        }
    force_flag = "$true" if force else "$false"
    script = rf"""
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$started = Get-Date
$qcow = 'C:\42IPwin\images\debian-12-genericcloud-amd64.qcow2'
$vhdx = 'C:\42IPwin\images\debian-12-genericcloud-amd64.vhdx'
$qemuSetup = 'C:\42IPwin\tools\qemu-w64-setup-20260501.exe'
$qemuImg = 'C:\Program Files\qemu\qemu-img.exe'
New-Item -ItemType Directory -Force -Path 'C:\42IPwin\images','C:\42IPwin\tools' | Out-Null
if ({force_flag}) {{
  Remove-Item -LiteralPath $qcow,$vhdx -Force -ErrorAction SilentlyContinue
}}
if (-not (Test-Path $qcow)) {{
  Invoke-WebRequest -UseBasicParsing -Uri 'https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-genericcloud-amd64.qcow2' -OutFile $qcow -TimeoutSec 1800
}}
if (-not (Test-Path $qemuImg)) {{
  if (-not (Test-Path $qemuSetup)) {{
    Invoke-WebRequest -UseBasicParsing -Uri 'https://qemu.weilnetz.de/w64/qemu-w64-setup-20260501.exe' -OutFile $qemuSetup -TimeoutSec 1800
  }}
  Start-Process -FilePath $qemuSetup -ArgumentList '/S' -Wait -WindowStyle Hidden
}}
if (-not (Test-Path $qemuImg)) {{ throw 'qemu-img install failed.' }}
if (-not (Test-Path $vhdx)) {{
  & $qemuImg convert -f qcow2 -O vhdx -o subformat=dynamic $qcow $vhdx
}}
$elapsed = [int]((Get-Date) - $started).TotalSeconds
$qcowItem = Get-Item $qcow
$vhdxItem = Get-Item $vhdx
$vhd = Get-VHD -Path $vhdx
[pscustomobject]@{{
  image = $vhdx
  qcow = $qcow
  seconds = $elapsed
  qcow_size = $qcowItem.Length
  vhdx_size = $vhdxItem.Length
  virtual_size = $vhd.Size
  qemu = (& $qemuImg --version | Select-Object -First 1)
}} | ConvertTo-Json -Depth 4
"""
    return _json_ps(script, timeout=2400)


def start_prepare_debian_cloud_image(force: bool = False):
    job_id = uuid.uuid4().hex
    _set_image_job(
        job_id,
        id=job_id,
        status="running",
        stage="queued",
        percent=0,
        message="Queued",
        created_at=time.time(),
        force=bool(force),
    )
    thread = threading.Thread(target=_prepare_debian_cloud_image_worker, args=(job_id, bool(force)), daemon=True)
    thread.start()
    return {"job_id": job_id}


def image_job_status(job_id: str):
    job_id = (job_id or "").strip()
    if not job_id:
        raise ValueError("job_id is required.")
    with IMAGE_JOBS_LOCK:
        job = dict(IMAGE_JOBS.get(job_id) or {})
    if not job:
        raise ValueError("Image job not found.")
    return job


def line_vm_internal_ip_map() -> dict[str, dict]:
    if _is_linux():
        return {}
    script = r"""
$ErrorActionPreference = 'Stop'
Import-Module Hyper-V
$rows = @()
foreach ($vm in @(Get-VM)) {
  $notes = [string]$vm.Notes
  $wan = ''
  $internal = ''
  $sshListen = ''
  $sshPort = ''
  if ($notes -match '(?m)^wan_ip=([0-9.]+)(?:/\d+)?') { $wan = $Matches[1] }
  if ($notes -match '(?m)^internal_ip=([0-9.]+)') { $internal = $Matches[1] }
  if ($notes -match '(?m)^ssh_listen=([0-9.]+)') { $sshListen = $Matches[1] }
  if ($notes -match '(?m)^ssh_port=([0-9]+)') { $sshPort = $Matches[1] }
  if ($wan -and $internal) {
    $rows += [pscustomobject]@{
      public_ip = $wan
      vm_name = $vm.Name
      vm_internal_ip = $internal
      ssh_listen = $sshListen
      ssh_port = $sshPort
      state = $vm.State.ToString()
    }
  }
}
$rows | ConvertTo-Json -Depth 4
"""
    try:
        data = _json_ps(script, timeout=30)
    except Exception:
        return {}
    if isinstance(data, dict):
        rows = [data]
    else:
        rows = data or []
    mapping = {}
    for row in rows:
        ip = str(row.get("public_ip") or "").strip()
        if ip:
            mapping[ip] = row
    return mapping


def clear_all_vms():
    if _is_linux():
        raise RuntimeError("Clear all VMs is only implemented on the Windows Hyper-V host.")
    script = r"""
$ErrorActionPreference = 'Stop'
Import-Module Hyper-V
$started = Get-Date
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$backupRoot = "C:\HyperV\deleted-before-42vm-$stamp"
New-Item -ItemType Directory -Force -Path $backupRoot | Out-Null
$deleted = @()
foreach ($vm in @(Get-VM)) {
  Stop-VM -Name $vm.Name -TurnOff -Force -ErrorAction SilentlyContinue
  $paths = @()
  $paths += $vm.Path
  $paths += @(Get-VMHardDiskDrive -VMName $vm.Name -ErrorAction SilentlyContinue | ForEach-Object { Split-Path -Parent $_.Path })
  Remove-VM -Name $vm.Name -Force
  $moved = @()
  foreach ($p in ($paths | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique)) {
    $leaf = Split-Path -Leaf $p
    $dest = Join-Path $backupRoot $leaf
    if (Test-Path $dest) { $dest = Join-Path $backupRoot ($leaf + '-' + ([guid]::NewGuid().ToString('N').Substring(0,6))) }
    Move-Item -LiteralPath $p -Destination $dest -Force
    $moved += $dest
  }
  $deleted += [pscustomobject]@{ name=$vm.Name; moved=($moved -join ', ') }
}
netsh interface portproxy reset | Out-Null
[pscustomobject]@{
  deleted_count = $deleted.Count
  backup_root = $backupRoot
  seconds = [int]((Get-Date) - $started).TotalSeconds
  deleted = $deleted
} | ConvertTo-Json -Depth 5
"""
    return _json_ps(script, timeout=900)


def vm_action(name: str, action: str):
    name = (name or "").strip()
    action = (action or "").strip().lower()
    if not name:
        raise ValueError("VM name is required.")
    if _is_linux():
        return _linux_vm_action(name, action)
    if action not in ACTION_COMMANDS:
        raise ValueError("Unsupported VM action.")

    script = rf"""
$ErrorActionPreference = 'Stop'
Import-Module Hyper-V
$name = {json.dumps(name)}
$vm = Get-VM -Name $name
{ACTION_COMMANDS[action]}
Start-Sleep -Milliseconds 600
$fresh = Get-VM -Name $name
[pscustomobject]@{{
  name = $fresh.Name
  state = $fresh.State.ToString()
  status = $fresh.Status
  uptime = $fresh.Uptime.ToString()
}} | ConvertTo-Json -Depth 4
"""
    return _json_ps(script, timeout=60)


def configure_public_ip_mapping(name: str):
    name = (name or "").strip()
    if not name:
        raise ValueError("VM name is required.")
    if _is_linux():
        return _linux_apply_vm_mapping(name)

    script = rf"""
$ErrorActionPreference = 'Stop'
Import-Module Hyper-V
$name = {json.dumps(name)}
$vm = Get-VM -Name $name
$notes = [string]$vm.Notes
$keys = @('source','wan_ip','gateway','dns','wan_mac','image','internal_ip','internal_gateway','lan_mac','ssh_listen','ssh_port')
$mapping = @{{}}
foreach ($key in $keys) {{
  if ($notes -match "(?m)^$key=(.+)$") {{
    $mapping[$key] = $Matches[1].Trim()
  }} elseif ($notes -match "$key=(.+?)(?=source=|wan_ip=|gateway=|dns=|wan_mac=|image=|internal_ip=|internal_gateway=|lan_mac=|ssh_listen=|ssh_port=|$)") {{
    $mapping[$key] = $Matches[1].Trim()
  }} else {{
    $mapping[$key] = ''
  }}
}}
if (-not $mapping['wan_ip']) {{ throw 'VM notes missing wan_ip= mapping.' }}

$bodyLines = @()
foreach ($line in ($notes -split "`r?`n")) {{
  if ($line -notmatch '^(source|wan_ip|gateway|dns|wan_mac|image|internal_ip|internal_gateway|lan_mac|ssh_listen|ssh_port)=') {{
    if ($line.Trim()) {{ $bodyLines += $line }}
  }}
}}
$mappingLines = @()
foreach ($key in $keys) {{
  if ($mapping[$key]) {{ $mappingLines += "$key=$($mapping[$key])" }}
}}
$newNotes = (($bodyLines + $mappingLines) -join "`n").Trim()
if ($newNotes -and $newNotes -ne $notes) {{
  Set-VM -Name $name -Notes $newNotes
}}
$fresh = Get-VM -Name $name
[pscustomobject]@{{
  name = $fresh.Name
  state = $fresh.State.ToString()
  public_ip = $mapping['wan_ip']
  source = $mapping['source']
  gateway = $mapping['gateway']
  dns = $mapping['dns']
  wan_mac = $mapping['wan_mac']
  internal_ip = $mapping['internal_ip']
  ssh_listen = $mapping['ssh_listen']
  ssh_port = $mapping['ssh_port']
  changed_notes = [bool]($newNotes -and $newNotes -ne $notes)
  safe = $true
  message = 'Only VM Notes public IP mapping was configured; host adapters and IP bindings were not changed.'
}} | ConvertTo-Json -Depth 4
"""
    return _json_ps(script, timeout=60)


def refresh_public_ip_mapping(name: str):
    name = (name or "").strip()
    if not name:
        raise ValueError("VM name is required.")
    if _is_linux():
        return _linux_apply_vm_mapping(name)

    script = rf"""
$ErrorActionPreference = 'Stop'
Import-Module Hyper-V
$name = {json.dumps(name)}
$vm = Get-VM -Name $name
$notes = [string]$vm.Notes
$keys = @('source','wan_ip','gateway','dns','wan_mac','image','internal_ip','internal_gateway','lan_mac','ssh_listen','ssh_port')
$mapping = @{{}}
foreach ($key in $keys) {{
  if ($notes -match "(?m)^$key=(.+)$") {{
    $mapping[$key] = $Matches[1].Trim()
  }} elseif ($notes -match "$key=(.+?)(?=source=|wan_ip=|gateway=|dns=|wan_mac=|image=|internal_ip=|internal_gateway=|lan_mac=|ssh_listen|ssh_port=|$)") {{
    $mapping[$key] = $Matches[1].Trim()
  }} else {{
    $mapping[$key] = ''
  }}
}}
$source = $mapping['source']
if (-not $source) {{ throw 'VM notes missing source= adapter alias.' }}
if (-not $mapping['internal_ip']) {{ throw 'VM notes missing internal_ip= mapping.' }}
if (-not $mapping['ssh_port']) {{ throw 'VM notes missing ssh_port= mapping.' }}

$adapter = Get-NetAdapter -Name $source -ErrorAction Stop
$ipRows = @(Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
  Where-Object {{ $_.IPAddress -and $_.IPAddress -notmatch '^(169\.254\.|127\.)' }} |
  Sort-Object PrefixLength)
if (-not $ipRows.Count) {{ throw "No IPv4 address found on adapter $source." }}
$ipRow = $ipRows[0]
$oldIp = $mapping['wan_ip']
$oldListen = $mapping['ssh_listen']
$newIp = $ipRow.IPAddress
$mapping['wan_ip'] = "$newIp/$($ipRow.PrefixLength)"
$mapping['ssh_listen'] = $newIp
$mapping['wan_mac'] = $adapter.MacAddress

$route = Get-NetRoute -InterfaceIndex $adapter.ifIndex -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
  Sort-Object RouteMetric | Select-Object -First 1
if ($route -and $route.NextHop -and $route.NextHop -ne '0.0.0.0') {{ $mapping['gateway'] = $route.NextHop }}
$dns = @(Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
  ForEach-Object {{ $_.ServerAddresses }} | Where-Object {{ $_ }})
if ($dns.Count) {{ $mapping['dns'] = ($dns -join ',') }}

$bodyLines = @()
foreach ($line in ($notes -split "`r?`n")) {{
  if ($line -notmatch '^(source|wan_ip|gateway|dns|wan_mac|image|internal_ip|internal_gateway|lan_mac|ssh_listen|ssh_port)=') {{
    if ($line.Trim()) {{ $bodyLines += $line }}
  }}
}}
$mappingLines = @()
foreach ($key in $keys) {{
  if ($mapping[$key]) {{ $mappingLines += "$key=$($mapping[$key])" }}
}}
$newNotes = (($bodyLines + $mappingLines) -join "`n").Trim()
Set-VM -Name $name -Notes $newNotes

$port = $mapping['ssh_port']
$internal = $mapping['internal_ip']
if ($oldListen) {{ netsh interface portproxy delete v4tov4 listenaddress=$oldListen listenport=$port | Out-Null }}
if ($oldIp -match '^([0-9.]+)') {{ netsh interface portproxy delete v4tov4 listenaddress=$($Matches[1]) listenport=$port | Out-Null }}
netsh interface portproxy delete v4tov4 listenaddress=$newIp listenport=$port | Out-Null
netsh interface portproxy add v4tov4 listenaddress=$newIp listenport=$port connectaddress=$internal connectport=22 | Out-Null
New-NetFirewallRule -DisplayName "42IPwin VM SSH $name" -Direction Inbound -Action Allow -Protocol TCP -LocalPort $port -LocalAddress $newIp -ErrorAction SilentlyContinue | Out-Null

[pscustomobject]@{{
  name = $name
  source = $source
  old_public_ip = $oldIp
  public_ip = $mapping['wan_ip']
  ssh_listen = $newIp
  ssh_port = $port
  internal_ip = $internal
  wan_mac = $mapping['wan_mac']
  gateway = $mapping['gateway']
  dns = $mapping['dns']
  changed = [bool]($oldIp -ne $mapping['wan_ip'])
  message = 'VM public IP mapping was refreshed from current Windows adapter IP.'
}} | ConvertTo-Json -Depth 4
"""
    return _json_ps(script, timeout=90)


def configure_ssh_portproxy(name: str):
    name = (name or "").strip()
    if not name:
        raise ValueError("VM name is required.")
    if _is_linux():
        data = _linux_apply_vm_mapping(name)
        return {
            "name": name,
            "public_ip": data.get("public_ip", ""),
            "internal_ip": data.get("internal_ip", ""),
            "ssh_host": data.get("public_ip", ""),
            "ssh_port": data.get("ssh_port") or 22,
            "mapping": f"{data.get('public_ip', '')}:{data.get('ssh_port') or 22} -> {data.get('internal_ip', '')}:22",
        }

    script = rf"""
$ErrorActionPreference = 'Stop'
Import-Module Hyper-V
$name = {json.dumps(name)}
$vm = Get-VM -Name $name
$notes = [string]$vm.Notes
$internal = ''
$port = ''
$wan = ''
$listen = ''
if ($notes -match '(?m)^internal_ip=([0-9.]+)') {{ $internal = $Matches[1].Trim() }}
if ($notes -match '(?m)^ssh_port=(\d+)') {{ $port = $Matches[1].Trim() }}
if ($notes -match '(?m)^ssh_listen=([0-9.]+)') {{ $listen = $Matches[1].Trim() }}
if ($notes -match '(?m)^wan_ip=([0-9.]+)') {{ $wan = $Matches[1].Trim() }}
if (-not $internal) {{ throw 'VM notes missing internal_ip= mapping.' }}
if (-not $port) {{ throw 'VM notes missing ssh_port= mapping.' }}
if (-not $listen) {{ $listen = $wan }}
if (-not $listen) {{ throw 'VM notes missing ssh_listen= or wan_ip= mapping.' }}
netsh interface portproxy delete v4tov4 listenaddress=$listen listenport=$port | Out-Null
netsh interface portproxy add v4tov4 listenaddress=$listen listenport=$port connectaddress=$internal connectport=22 | Out-Null
New-NetFirewallRule -DisplayName "42IPwin VM SSH $name" -Direction Inbound -Action Allow -Protocol TCP -LocalPort $port -LocalAddress $listen -ErrorAction SilentlyContinue | Out-Null
[pscustomobject]@{{
  name = $name
  public_ip = $wan
  internal_ip = $internal
  ssh_host = $listen
  ssh_port = [int]$port
  mapping = "$listen`:$port -> $internal`:22"
}} | ConvertTo-Json -Depth 4
"""
    return _json_ps(script, timeout=60)


def configure_custom_portproxy(name: str, data: dict):
    name = (name or "").strip()
    if not name:
        raise ValueError("VM name is required.")
    listen_ip = (data.get("listen_ip") or "").strip()
    listen_port = int(data.get("listen_port") or 0)
    target_ip = (data.get("target_ip") or data.get("internal_ip") or "").strip()
    target_port = int(data.get("target_port") or 0)
    port_count = int(data.get("port_count") or data.get("count") or 1)
    protocol = (data.get("protocol") or "tcp").strip().lower()
    if protocol != "tcp":
        raise ValueError("Only TCP portproxy is supported on Windows.")
    if not listen_ip or not target_ip:
        raise ValueError("listen_ip and target_ip are required.")
    if port_count < 1 or port_count > 100:
        raise ValueError("Port count must be between 1 and 100.")
    listen_end = listen_port + port_count - 1
    target_end = target_port + port_count - 1
    if listen_port < 1 or listen_end > 65535 or target_port < 1 or target_end > 65535:
        raise ValueError("Port must be between 1 and 65535.")
    if listen_port <= 8080 <= listen_end:
        raise ValueError("Port 8080 is reserved for the 42IPwin panel.")

    script = rf"""
$ErrorActionPreference = 'Stop'
$name = {json.dumps(name)}
$listenIp = {json.dumps(listen_ip)}
$listenPort = {listen_port}
$portCount = {port_count}
$targetIp = {json.dumps(target_ip)}
$targetPort = {target_port}

$ip = Get-NetIPAddress -IPAddress $listenIp -AddressFamily IPv4 -ErrorAction SilentlyContinue
if (-not $ip) {{ throw "Listen IP is not present on Windows: $listenIp" }}
$mappings = @()
for ($i = 0; $i -lt $portCount; $i++) {{
  $lp = $listenPort + $i
  $tp = $targetPort + $i
  netsh interface portproxy delete v4tov4 listenaddress=$listenIp listenport=$lp | Out-Null
  netsh interface portproxy add v4tov4 listenaddress=$listenIp listenport=$lp connectaddress=$targetIp connectport=$tp | Out-Null
  $mappings += "$listenIp`:$lp -> $targetIp`:$tp"
}}
$localPort = if ($portCount -eq 1) {{ "$listenPort" }} else {{ "$listenPort-$($listenPort + $portCount - 1)" }}
New-NetFirewallRule -DisplayName "42IPwin VM Port $name $listenIp`:$localPort" -Direction Inbound -Action Allow -Protocol TCP -LocalAddress $listenIp -LocalPort $localPort -ErrorAction SilentlyContinue | Out-Null

[pscustomobject]@{{
  name = $name
  listen_ip = $listenIp
  listen_port = $listenPort
  listen_end_port = ($listenPort + $portCount - 1)
  port_count = $portCount
  target_ip = $targetIp
  target_port = $targetPort
  target_end_port = ($targetPort + $portCount - 1)
  url = "http://$listenIp`:$listenPort/"
  mapping = if ($portCount -eq 1) {{ $mappings[0] }} else {{ "$listenIp`:$listenPort-$($listenPort + $portCount - 1) -> $targetIp`:$targetPort-$($targetPort + $portCount - 1)" }}
  mappings = $mappings
}} | ConvertTo-Json -Depth 4
"""
    return _json_ps(script, timeout=60)


def batch_configure_custom_portproxy(names, data: dict):
    names = [str(x).strip() for x in (names or []) if str(x).strip()]
    if not names:
        raise ValueError("No VMs selected.")
    listen_port = int(data.get("listen_port") or 0)
    target_port = int(data.get("target_port") or 0)
    port_count = int(data.get("port_count") or data.get("count") or 1)
    if listen_port < 1 or target_port < 1:
        raise ValueError("listen_port and target_port are required.")
    if port_count < 1 or port_count > 100:
        raise ValueError("Port count must be between 1 and 100.")
    listen_end = listen_port + port_count - 1
    target_end = target_port + port_count - 1
    if listen_end > 65535 or target_end > 65535:
        raise ValueError("Port range exceeds 65535.")
    if listen_port <= 8080 <= listen_end:
        raise ValueError("Port 8080 is reserved for the 42IPwin panel.")

    names_json = json.dumps(names, ensure_ascii=False)
    script = rf"""
$ErrorActionPreference = 'Stop'
Import-Module Hyper-V
$names = ConvertFrom-Json @'
{names_json}
'@
$listenPort = {listen_port}
$targetPort = {target_port}
$portCount = {port_count}
$results = @()
foreach ($name in $names) {{
  try {{
    $vm = Get-VM -Name $name -ErrorAction Stop
    $notes = [string]$vm.Notes
    $listenIp = ''
    $targetIp = ''
    if ($notes -match '(?m)^wan_ip=([0-9.]+)(?:/\d+)?') {{ $listenIp = $Matches[1].Trim() }}
    if ($notes -match '(?m)^internal_ip=([0-9.]+)') {{ $targetIp = $Matches[1].Trim() }}
    if (-not $listenIp) {{ throw 'VM has no public IP.' }}
    if (-not $targetIp) {{ throw 'VM has no internal IP.' }}
    $ip = Get-NetIPAddress -IPAddress $listenIp -AddressFamily IPv4 -ErrorAction SilentlyContinue
    if (-not $ip) {{ throw "Listen IP is not present on Windows: $listenIp" }}

    for ($i = 0; $i -lt $portCount; $i++) {{
      $lp = $listenPort + $i
      $tp = $targetPort + $i
      netsh interface portproxy delete v4tov4 listenaddress=$listenIp listenport=$lp | Out-Null
      netsh interface portproxy add v4tov4 listenaddress=$listenIp listenport=$lp connectaddress=$targetIp connectport=$tp | Out-Null
    }}
    $localPort = if ($portCount -eq 1) {{ "$listenPort" }} else {{ "$listenPort-$($listenPort + $portCount - 1)" }}
    New-NetFirewallRule -DisplayName "42IPwin VM Open $name $listenIp`:$localPort" -Direction Inbound -Action Allow -Protocol TCP -LocalAddress $listenIp -LocalPort $localPort -ErrorAction SilentlyContinue | Out-Null
    $mapping = if ($portCount -eq 1) {{ "$listenIp`:$listenPort -> $targetIp`:$targetPort" }} else {{ "$listenIp`:$listenPort-$($listenPort + $portCount - 1) -> $targetIp`:$targetPort-$($targetPort + $portCount - 1)" }}
    $results += [pscustomobject]@{{
      name = $name
      ok = $true
      data = [pscustomobject]@{{
        name = $name
        listen_ip = $listenIp
        listen_port = $listenPort
        listen_end_port = ($listenPort + $portCount - 1)
        port_count = $portCount
        target_ip = $targetIp
        target_port = $targetPort
        target_end_port = ($targetPort + $portCount - 1)
        url = "http://$listenIp`:$listenPort/"
        mapping = $mapping
      }}
    }}
  }} catch {{
    $results += [pscustomobject]@{{
      name = $name
      ok = $false
      error = $_.Exception.Message
    }}
  }}
}}
$results | ConvertTo-Json -Depth 6
"""
    return _json_ps(script, timeout=max(180, min(900, len(names) * port_count)))


def delete_vm(name: str):
    name = (name or "").strip()
    if not name:
        raise ValueError("VM name is required.")
    if _is_linux():
        return _linux_delete_vm(name)

    script = rf"""
$ErrorActionPreference = 'Stop'
Import-Module Hyper-V
$name = {json.dumps(name)}
$vm = Get-VM -Name $name
if ($vm.State -ne 'Off') {{
  Stop-VM -Name $name -TurnOff -Force
  Start-Sleep -Seconds 1
}}
Remove-VM -Name $name -Force
[pscustomobject]@{{
  name = $name
  deleted = $true
  disk_deleted = $false
  message = 'VM registration was removed; virtual disk files were not deleted.'
}} | ConvertTo-Json -Depth 4
"""
    return _json_ps(script, timeout=90)


def ssh_exec(host: str, username: str, password: str, command: str, port: int = 22, timeout: int = 30):
    host = (host or "").strip()
    username = (username or "root").strip()
    password = str(password or "")
    command = (command or "").strip()
    port = int(port or 22)
    timeout = max(5, min(int(timeout or 30), 120))

    if not re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host):
        raise ValueError("Invalid SSH host.")
    if not username:
        raise ValueError("SSH username is required.")
    if not password:
        raise ValueError("SSH password is required.")
    if not command:
        raise ValueError("SSH command is required.")
    if len(command) > 2000:
        raise ValueError("SSH command is too long.")
    if port < 1 or port > 65535:
        raise ValueError("Invalid SSH port.")

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            host,
            port=port,
            username=username,
            password=password,
            timeout=timeout,
            banner_timeout=timeout,
            auth_timeout=timeout,
            look_for_keys=False,
            allow_agent=False,
        )
        stdin, stdout, stderr = client.exec_command(command, timeout=timeout, get_pty=True)
        out = stdout.read().decode("utf-8", "replace")
        err = stderr.read().decode("utf-8", "replace")
        code = stdout.channel.recv_exit_status()
        return {"host": host, "port": port, "username": username, "command": command, "exit_code": code, "stdout": out, "stderr": err}
    except (socket.timeout, TimeoutError) as exc:
        raise RuntimeError(f"SSH timeout: {exc}") from exc
    except paramiko.AuthenticationException as exc:
        raise RuntimeError("SSH authentication failed.") from exc
    except Exception as exc:
        raise RuntimeError(f"SSH failed: {exc}") from exc
    finally:
        client.close()


def update_vm_config(name: str, data: dict):
    name = (name or "").strip()
    if not name:
        raise ValueError("VM name is required.")
    if _is_linux():
        return _linux_update_vm_config(name, data)

    processor_count = int(data.get("processor_count") or 0)
    memory_startup_mb = int(data.get("memory_startup_mb") or 0)
    dynamic_memory_enabled = bool(data.get("dynamic_memory_enabled"))
    memory_minimum_mb = int(data.get("memory_minimum_mb") or memory_startup_mb)
    memory_maximum_mb = int(data.get("memory_maximum_mb") or memory_startup_mb)
    start_action = (data.get("automatic_start_action") or "Nothing").strip()
    stop_action = (data.get("automatic_stop_action") or "Save").strip()
    notes = data.get("notes") or ""

    if processor_count < 1 or processor_count > 64:
        raise ValueError("CPU count must be between 1 and 64.")
    if memory_startup_mb < 128:
        raise ValueError("Startup memory must be at least 128 MB.")
    if memory_minimum_mb < 32 or memory_maximum_mb < memory_minimum_mb:
        raise ValueError("Invalid dynamic memory range.")
    if start_action not in {"Nothing", "StartIfRunning", "Start"}:
        raise ValueError("Invalid automatic start action.")
    if stop_action not in {"Save", "TurnOff", "ShutDown"}:
        raise ValueError("Invalid automatic stop action.")

    script = rf"""
$ErrorActionPreference = 'Stop'
Import-Module Hyper-V
$name = {json.dumps(name)}
$vm = Get-VM -Name $name
$mem = Get-VMMemory -VMName $name
$oldNotes = [string]$vm.Notes
$newNotes = {json.dumps(notes)}
$mappingKeys = @('source','wan_ip','gateway','dns','wan_mac','image','internal_ip','internal_gateway','lan_mac','ssh_listen','ssh_port')
$mappingLines = @()
foreach ($key in $mappingKeys) {{
  if ($oldNotes -match "(?m)^$key=(.+)$") {{
    $mappingLines += "$key=$($Matches[1].Trim())"
  }} elseif ($oldNotes -match "$key=(.+?)(?=source=|wan_ip=|gateway=|dns=|wan_mac=|image=|internal_ip=|internal_gateway=|lan_mac=|ssh_listen=|ssh_port=|$)") {{
    $mappingLines += "$key=$($Matches[1].Trim())"
  }}
}}
foreach ($line in $mappingLines) {{
  $key = $line.Split('=', 2)[0]
  if ($newNotes -notmatch "(?m)^$key=") {{
    if ($newNotes.Trim()) {{ $newNotes = $newNotes.TrimEnd() + "`n" + $line }} else {{ $newNotes = $line }}
  }}
}}
$hardwareChanged = $false
if ($vm.ProcessorCount -ne {processor_count}) {{ $hardwareChanged = $true }}
if ([int]($mem.Startup / 1MB) -ne {memory_startup_mb}) {{ $hardwareChanged = $true }}
if ([bool]$mem.DynamicMemoryEnabled -ne ${str(dynamic_memory_enabled).lower()}) {{ $hardwareChanged = $true }}
if ([int]($mem.Minimum / 1MB) -ne {memory_minimum_mb}) {{ $hardwareChanged = $true }}
if ([int]($mem.Maximum / 1MB) -ne {memory_maximum_mb}) {{ $hardwareChanged = $true }}
$hardwareSkipped = $false
if ($hardwareChanged -and $vm.State -eq 'Off') {{
  Set-VMProcessor -VMName $name -Count {processor_count}
  Set-VMMemory -VMName $name -StartupBytes ({memory_startup_mb}MB) -DynamicMemoryEnabled ${str(dynamic_memory_enabled).lower()} -MinimumBytes ({memory_minimum_mb}MB) -MaximumBytes ({memory_maximum_mb}MB)
}} elseif ($hardwareChanged) {{
  $hardwareSkipped = $true
}}
Set-VM -Name $name -AutomaticStartAction {start_action} -AutomaticStopAction {stop_action} -Notes $newNotes
$fresh = Get-VM -Name $name
$freshMem = Get-VMMemory -VMName $name
[pscustomobject]@{{
  name = $fresh.Name
  state = $fresh.State.ToString()
  processor_count = $fresh.ProcessorCount
  memory_startup = $fresh.MemoryStartup
  memory_startup_mb = [int]($freshMem.Startup / 1MB)
  hardware_skipped = $hardwareSkipped
  message = if ($hardwareSkipped) {{ 'CPU/内存硬件配置未修改：请先关闭虚拟机后再保存硬件配置。' }} else {{ '' }}
  automatic_start_action = $fresh.AutomaticStartAction.ToString()
  automatic_stop_action = $fresh.AutomaticStopAction.ToString()
}} | ConvertTo-Json -Depth 4
"""
    return _json_ps(script, timeout=60)


def batch_action(names, action: str):
    names = [str(x).strip() for x in (names or []) if str(x).strip()]
    if not names:
        raise ValueError("No VMs selected.")
    action = (action or "").strip().lower()
    if action == "reset_password":
        raise RuntimeError("Hyper-V cannot reset guest OS passwords directly. Configure a guest script/agent or provide guest credentials first.")
    if action == "configure_public_ip":
        results = []
        for name in names:
            try:
                results.append({"name": name, "ok": True, "data": configure_public_ip_mapping(name)})
            except Exception as exc:
                results.append({"name": name, "ok": False, "error": str(exc)})
        return results
    if action == "refresh_public_ip":
        results = []
        for name in names:
            try:
                results.append({"name": name, "ok": True, "data": refresh_public_ip_mapping(name)})
            except Exception as exc:
                results.append({"name": name, "ok": False, "error": str(exc)})
        return results
    if action == "configure_ssh_portproxy":
        results = []
        for name in names:
            try:
                results.append({"name": name, "ok": True, "data": configure_ssh_portproxy(name)})
            except Exception as exc:
                results.append({"name": name, "ok": False, "error": str(exc)})
        return results
    if action == "delete":
        results = []
        for name in names:
            try:
                results.append({"name": name, "ok": True, "data": delete_vm(name)})
            except Exception as exc:
                results.append({"name": name, "ok": False, "error": str(exc)})
        return results
    if action not in ACTION_COMMANDS:
        raise ValueError("Unsupported VM action.")

    results = []
    for name in names:
        try:
            results.append({"name": name, "ok": True, "data": vm_action(name, action)})
        except Exception as exc:
            results.append({"name": name, "ok": False, "error": str(exc)})
    return results


def _start_vms_staged_worker(job_id: str, names: list[str], batch_size: int = 5, wait_seconds: int = 15):
    started_at = time.time()
    names = [str(x).strip() for x in names if str(x).strip()]
    total = len(names)
    try:
        _set_start_vm_job(
            job_id,
            status="running",
            stage="start",
            percent=0,
            total=total,
            started_count=0,
            failed_count=0,
            messages=["Start VM batch job submitted."],
            results=[],
            message="Starting VMs...",
        )
        results = []
        started_count = 0
        failed_count = 0
        batches = [names[i:i + batch_size] for i in range(0, total, batch_size)]
        for idx, batch in enumerate(batches, start=1):
            _append_start_vm_message(job_id, f"Batch {idx}/{len(batches)}: {', '.join(batch)}")
            _set_start_vm_job(job_id, current_batch=idx, total_batches=len(batches), message=f"Starting batch {idx}/{len(batches)}")
            for name in batch:
                try:
                    result = vm_action(name, "start")
                    results.append({"name": name, "ok": True, "data": result})
                    started_count += 1
                    _append_start_vm_message(job_id, f"Started {name}")
                except Exception as exc:
                    results.append({"name": name, "ok": False, "error": str(exc)})
                    failed_count += 1
                    _append_start_vm_message(job_id, f"Failed {name}: {exc}")
                _set_start_vm_job(
                    job_id,
                    started_count=started_count,
                    failed_count=failed_count,
                    percent=min(99, int(((started_count + failed_count) / max(total, 1)) * 100)),
                    results=results,
                )
            if idx < len(batches):
                for left in range(wait_seconds, 0, -1):
                    _set_start_vm_job(job_id, message=f"Waiting {left}s before next batch", wait_seconds_left=left)
                    time.sleep(1)
        message = f"Start job finished: started {started_count}, failed {failed_count}"
        _append_start_vm_message(job_id, message)
        _set_start_vm_job(
            job_id,
            status="done" if failed_count == 0 else "error",
            stage="done" if failed_count == 0 else "error",
            percent=100,
            seconds=int(time.time() - started_at),
            started_count=started_count,
            failed_count=failed_count,
            wait_seconds_left=0,
            results=results,
            message=message,
        )
    except Exception as exc:
        _append_start_vm_message(job_id, f"Start job failed: {exc}")
        _set_start_vm_job(
            job_id,
            status="error",
            stage="error",
            percent=100,
            seconds=int(time.time() - started_at),
            message=str(exc),
            error=str(exc),
        )


def start_vms_staged(names, batch_size: int = 5, wait_seconds: int = 15):
    names = [str(x).strip() for x in (names or []) if str(x).strip()]
    if not names:
        raise ValueError("No VMs selected.")
    batch_size = max(1, min(20, int(batch_size or 5)))
    wait_seconds = max(0, min(300, int(wait_seconds or 15)))
    job_id = uuid.uuid4().hex
    _set_start_vm_job(
        job_id,
        id=job_id,
        status="queued",
        stage="queued",
        percent=0,
        total=len(names),
        started_count=0,
        failed_count=0,
        messages=["Start job queued."],
        results=[],
        message="Start job queued.",
    )
    thread = threading.Thread(target=_start_vms_staged_worker, args=(job_id, names, batch_size, wait_seconds), daemon=True)
    thread.start()
    return {"job_id": job_id}


def start_vm_job_status(job_id: str):
    with START_VM_JOBS_LOCK:
        job = dict(START_VM_JOBS.get(job_id) or {})
    if not job:
        raise ValueError("Start job not found.")
    return job


def _validate_linux_create_inputs(data: dict) -> dict:
    prefix = (data.get("prefix") or "Debian").strip()
    count = int(data.get("count") or 1)
    start_index = int(data.get("map_start_index") or data.get("start_index") or 1)
    cpu = int(data.get("processor_count") or 1)
    memory_mb = int(data.get("memory_startup_mb") or 1024)
    disk_gb = int(data.get("disk_size_gb") or 12)
    image_path = Path((data.get("image_path") or str(LINUX_DEBIAN_IMAGE)).strip())
    root_password = str(data.get("root_password") or "")
    configure_guest = bool(data.get("configure_guest", True))
    auto_start = bool(data.get("auto_start"))
    internal_base = (data.get("internal_base") or LINUX_VM_PREFIX).strip().rstrip(".")
    internal_start = int(data.get("internal_start_host") or 101)
    gateway = (data.get("internal_gateway") or LINUX_VM_GATEWAY).strip()
    dns = (data.get("internal_dns") or "1.1.1.1").replace(",", " ")
    ssh_port = int(data.get("ssh_port") or data.get("ssh_port_base") or 22)
    network = (data.get("lan_switch") or data.get("switch_name") or LINUX_VM_NETWORK).strip() or LINUX_VM_NETWORK

    if not prefix:
        raise ValueError("Name prefix is required.")
    if count < 1 or count > 300:
        raise ValueError("Create count must be between 1 and 300.")
    if start_index < 1:
        raise ValueError("Start index must be >= 1.")
    if cpu < 1 or cpu > 64:
        raise ValueError("CPU count must be between 1 and 64.")
    if memory_mb < 128:
        raise ValueError("Startup memory must be at least 128 MB.")
    if disk_gb < 1 or disk_gb > 2048:
        raise ValueError("Disk size must be between 1 and 2048 GB.")
    if configure_guest and not root_password:
        raise ValueError("Root password is required when guest config is enabled.")
    if ssh_port < 1 or ssh_port > 65535:
        raise ValueError("Invalid SSH port.")
    if internal_start < 2 or internal_start > 254 or internal_start + count - 1 > 254:
        raise ValueError("VM internal IP range must stay between .2 and .254.")
    if not image_path.exists():
        raise RuntimeError(f"Image not found: {image_path}")
    for binary in ("qemu-img", "virt-install", "cloud-localds"):
        if subprocess.run(["which", binary], capture_output=True, text=True, timeout=5).returncode != 0:
            raise RuntimeError(f"{binary} is not installed on this host.")

    return {
        "prefix": prefix,
        "count": count,
        "start_index": start_index,
        "cpu": cpu,
        "memory_mb": memory_mb,
        "disk_gb": disk_gb,
        "image_path": image_path,
        "root_password": root_password,
        "configure_guest": configure_guest,
        "auto_start": auto_start,
        "internal_base": internal_base,
        "internal_start": internal_start,
        "gateway": gateway,
        "dns": dns,
        "ssh_port": ssh_port,
        "network": network,
    }


def _linux_cloud_init_files(td_path: Path, name: str, internal_ip: str, cfg: dict) -> tuple[Path, Path, Path]:
    root_password = cfg["root_password"]
    user_data = f"""#cloud-config
hostname: {name}
manage_etc_hosts: true
ssh_pwauth: true
disable_root: false
chpasswd:
  expire: false
  list: |
    root:{root_password}
runcmd:
  - sed -i 's/^#\\?PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
  - sed -i 's/^#\\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
  - systemctl restart ssh || systemctl restart sshd || true
"""
    if not cfg["configure_guest"]:
        user_data = f"""#cloud-config
hostname: {name}
manage_etc_hosts: true
"""
    dns_values = ", ".join(cfg["dns"].split())
    network_config = f"""version: 2
ethernets:
  ens3:
    dhcp4: false
    addresses: [{internal_ip}/24]
    gateway4: {cfg["gateway"]}
    nameservers:
      addresses: [{dns_values}]
"""
    meta_data = f"instance-id: {name}\nlocal-hostname: {name}\n"
    user_path = td_path / "user-data"
    meta_path = td_path / "meta-data"
    net_path = td_path / "network-config"
    user_path.write_text(user_data, encoding="utf-8")
    meta_path.write_text(meta_data, encoding="utf-8")
    net_path.write_text(network_config, encoding="utf-8")
    return user_path, meta_path, net_path


def _linux_create_vms(data: dict, progress=None) -> list[dict]:
    cfg = _validate_linux_create_inputs(data)
    _linux_ensure_vm_network(cfg["network"], cfg["gateway"], LINUX_VM_NET_PREFIX)
    LINUX_IMAGE_DIR.mkdir(parents=True, exist_ok=True)
    results = []
    existing = set(_linux_vm_names())
    for offset in range(cfg["count"]):
        index = cfg["start_index"] + offset
        name = f"{cfg['prefix']}-{index:03d}"
        internal_ip = f"{cfg['internal_base']}.{cfg['internal_start'] + offset}"
        line = _line_by_index_or_id(index=index)
        if not line:
            item = {"name": name, "ok": False, "error": "No active line with public IP is available"}
            results.append(item)
            if progress:
                progress(item, f"Failed {name}: no active public line")
            continue
        try:
            if name in existing:
                item = {"name": name, "ok": False, "skipped": True, "error": "VM already exists"}
                results.append(item)
                if progress:
                    progress(item, f"Skipped {name}: VM already exists")
                continue
            disk = LINUX_IMAGE_DIR / f"{name}.qcow2"
            seed = LINUX_IMAGE_DIR / f"{name}-seed.iso"
            if disk.exists() or seed.exists():
                item = {"name": name, "ok": False, "skipped": True, "error": "VM disk or seed already exists"}
                results.append(item)
                if progress:
                    progress(item, f"Skipped {name}: disk or seed already exists")
                continue

            _run_cmd([
                "qemu-img", "create", "-f", "qcow2", "-F", "qcow2",
                "-b", str(cfg["image_path"]), str(disk), f"{cfg['disk_gb']}G",
            ], timeout=120)
            with tempfile.TemporaryDirectory(prefix=f"{name}-cloudinit-") as td:
                td_path = Path(td)
                user_path, meta_path, net_path = _linux_cloud_init_files(td_path, name, internal_ip, cfg)
                _run_cmd(["cloud-localds", "-N", str(net_path), str(seed), str(user_path), str(meta_path)], timeout=60)

            _run_cmd([
                "virt-install",
                "--name", name,
                "--memory", str(cfg["memory_mb"]),
                "--vcpus", str(cfg["cpu"]),
                "--disk", f"path={disk},format=qcow2,bus=virtio",
                "--disk", f"path={seed},device=cdrom",
                "--os-variant", "debian12",
                "--import",
                "--network", f"network={cfg['network']},model=virtio",
                "--graphics", "none",
                "--noautoconsole",
            ], timeout=180)
            _linux_set_vm_mapping_notes(name, {
                "line_id": line["id"],
                "line_name": line["name"],
                "public_ip": line["public_ip"],
                "wan_ip": line["public_ip"],
                "wan_mac": line.get("mac") or "",
                "internal_ip": internal_ip,
                "internal_gateway": cfg["gateway"],
                "vm_network": cfg["network"],
                "ssh_port": cfg["ssh_port"],
                "root_user": "root",
            })
            mapping = _linux_apply_vm_mapping(name)
            if not cfg["auto_start"]:
                _run_cmd(["virsh", "shutdown", name], timeout=30, check=False)
            item = {"name": name, "ok": True, "data": mapping, "ip": internal_ip, "public_ip": mapping.get("public_ip")}
            results.append(item)
            existing.add(name)
            if progress:
                progress(item, f"Created {name}: {mapping.get('public_ip')} -> {internal_ip}")
        except Exception as exc:
            item = {"name": name, "ok": False, "error": str(exc)}
            results.append(item)
            if progress:
                progress(item, f"Failed {name}: {exc}")
    return results


def batch_create_vms(data: dict):
    if _is_linux():
        return _linux_create_vms(data)

    mode = (data.get("mode") or "normal").strip().lower()
    if mode == "ip_map":
        return batch_create_mapped_vms(data)

    prefix = (data.get("prefix") or "hy").strip()
    count = int(data.get("count") or 0)
    start_index = int(data.get("start_index") or 1)
    processor_count = int(data.get("processor_count") or 1)
    memory_startup_mb = int(data.get("memory_startup_mb") or 1024)
    disk_size_gb = int(data.get("disk_size_gb") or 20)
    generation = int(data.get("generation") or 2)
    switch_name = (data.get("switch_name") or "").strip()
    image_path = (data.get("image_path") or "").strip()
    auto_start = bool(data.get("auto_start"))

    if not prefix:
        raise ValueError("Name prefix is required.")
    if count < 1 or count > 200:
        raise ValueError("Create count must be between 1 and 200.")
    if processor_count < 1 or processor_count > 64:
        raise ValueError("CPU count must be between 1 and 64.")
    if memory_startup_mb < 128:
        raise ValueError("Startup memory must be at least 128 MB.")
    if disk_size_gb < 1 or disk_size_gb > 2048:
        raise ValueError("Disk size must be between 1 and 2048 GB.")
    if generation not in {1, 2}:
        raise ValueError("VM generation must be 1 or 2.")

    names = [f"{prefix}-{i:03d}" for i in range(start_index, start_index + count)]
    names_json = json.dumps(names, ensure_ascii=False)
    switch_json = json.dumps(switch_name, ensure_ascii=False)
    image_json = json.dumps(image_path, ensure_ascii=False)

    script = rf"""
$ErrorActionPreference = 'Stop'
Import-Module Hyper-V
$names = ConvertFrom-Json @'
{names_json}
'@
$switchName = {switch_json}
$imagePath = {image_json}
$hostInfo = Get-VMHost
$vmRoot = $hostInfo.VirtualMachinePath
$vhdRoot = $hostInfo.VirtualHardDiskPath
if (-not $vmRoot) {{ $vmRoot = 'C:\HyperV\VMs' }}
if (-not $vhdRoot) {{ $vhdRoot = 'C:\HyperV\VHDs' }}
New-Item -ItemType Directory -Force -Path $vmRoot,$vhdRoot | Out-Null
if ($imagePath -and -not (Test-Path $imagePath)) {{ throw '选择的镜像文件不存在。' }}
$results = @()
foreach ($name in $names) {{
  try {{
    if (Get-VM -Name $name -ErrorAction SilentlyContinue) {{
      $results += [pscustomobject]@{{ name=$name; ok=$false; error='虚拟机名称已存在' }}
      continue
    }}
    $vhdPath = Join-Path $vhdRoot ($name + '.vhdx')
    if (Test-Path $vhdPath) {{
      $results += [pscustomobject]@{{ name=$name; ok=$false; error='虚拟硬盘文件已存在' }}
      continue
    }}
    $args = @{{ Name = $name; Generation = {generation}; MemoryStartupBytes = ({memory_startup_mb}MB); Path = $vmRoot }}
    if ($imagePath -and ($imagePath.ToLower().EndsWith('.vhd') -or $imagePath.ToLower().EndsWith('.vhdx'))) {{
      Copy-Item -Force -Path $imagePath -Destination $vhdPath
      $args.VHDPath = $vhdPath
    }} else {{
      $args.NewVHDPath = $vhdPath
      $args.NewVHDSizeBytes = ({disk_size_gb}GB)
    }}
    if ($switchName) {{ $args.SwitchName = $switchName }}
    New-VM @args | Out-Null
    if ($imagePath -and $imagePath.ToLower().EndsWith('.iso')) {{
      Add-VMDvdDrive -VMName $name -Path $imagePath
    }}
    Set-VMProcessor -VMName $name -Count {processor_count}
    Set-VM -Name $name -AutomaticStopAction ShutDown
    if (${str(auto_start).lower()}) {{ Start-VM -Name $name }}
    $fresh = Get-VM -Name $name
    $results += [pscustomobject]@{{ name=$name; ok=$true; state=$fresh.State.ToString(); vhd=$vhdPath }}
  }} catch {{
    $results += [pscustomobject]@{{ name=$name; ok=$false; error=$_.Exception.Message }}
  }}
}}
$results | ConvertTo-Json -Depth 4
"""
    result = _json_ps(script, timeout=max(90, count * 8))
    if isinstance(result, dict):
        return [result]
    return result or []


def batch_create_mapped_vms(data: dict):
    image_path = (data.get("image_path") or r"C:\42IPwin\images\debian-12-genericcloud-amd64.vhdx").strip()
    map_path = (data.get("map_path") or DEFAULT_IP_MAP).strip()
    script_path = (data.get("script_path") or DEFAULT_CREATE_SCRIPT).strip()
    vm_root = (data.get("vm_root") or r"C:\HyperV\Debian-42").strip()
    lan_switch = (data.get("lan_switch") or "VM-LAN").strip()
    name_prefix = (data.get("prefix") or "Debian").strip()
    start_index = int(data.get("map_start_index") or data.get("start_index") or 1)
    count = int(data.get("count") or 1)
    processor_count = int(data.get("processor_count") or 1)
    memory_startup_mb = int(data.get("memory_startup_mb") or 1024)
    generation = int(data.get("generation") or 2)
    root_password = str(data.get("root_password") or "")
    configure_guest = bool(data.get("configure_guest", True))
    auto_start = bool(data.get("auto_start"))
    include_host_switch_ips = bool(data.get("include_host_switch_ips"))
    internal_base = (data.get("internal_base") or "192.168.9").strip()
    internal_start_host = int(data.get("internal_start_host") or 101)
    internal_gateway = (data.get("internal_gateway") or "192.168.9.1").strip()
    internal_dns = (data.get("internal_dns") or "1.1.1.1").strip()
    ssh_port = int(data.get("ssh_port") or data.get("ssh_port_base") or 22)

    if not name_prefix:
        raise ValueError("Name prefix is required.")
    if count < 1 or count > 200:
        raise ValueError("Create count must be between 1 and 200.")
    if start_index > 42 and count >= 42:
        start_index = 1
    if start_index < 1:
        raise ValueError("Map start index must be >= 1.")
    if processor_count < 1 or processor_count > 64:
        raise ValueError("CPU count must be between 1 and 64.")
    if memory_startup_mb < 128:
        raise ValueError("Startup memory must be at least 128 MB.")
    if generation not in {1, 2}:
        raise ValueError("VM generation must be 1 or 2.")
    if configure_guest and not root_password:
        raise ValueError("Root password is required when guest config is enabled.")

    args = [
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        script_path,
        "-MapPath",
        map_path,
        "-TemplateVhd",
        image_path,
        "-VmRoot",
        vm_root,
        "-LanSwitch",
        lan_switch,
        "-NamePrefix",
        name_prefix,
        "-MemoryStartupBytes",
        str(memory_startup_mb * 1024 * 1024),
        "-ProcessorCount",
        str(processor_count),
        "-Generation",
        str(generation),
        "-InternalBase",
        internal_base,
        "-InternalStartHost",
        str(internal_start_host),
        "-InternalGateway",
        internal_gateway,
        "-InternalDNS",
        internal_dns,
        "-SshPort",
        str(ssh_port),
        "-StartIndex",
        str(start_index),
        "-Count",
        str(count),
        "-Execute",
    ]
    if configure_guest:
        args.extend(["-ConfigureGuest", "-RootPassword", root_password])
    if auto_start:
        args.append("-AutoStart")
    if include_host_switch_ips:
        args.append("-IncludeHostSwitchIps")

    completed = subprocess.run(
        [POWERSHELL, *args],
        capture_output=True,
        text=True,
        timeout=max(180, count * 45),
        encoding=locale.getpreferredencoding(False),
        errors="replace",
    )
    output = ((completed.stdout or "") + "\n" + (completed.stderr or "")).strip()
    if completed.returncode != 0:
        raise RuntimeError(_friendly_error(output) or output or f"PowerShell exited with {completed.returncode}")

    results = []
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("CREATED "):
            match = re.match(r"CREATED\s+(\S+)\s+->\s+(\S+)\s+(\S+)\s+(\S+)", line)
            if match:
                results.append({
                    "name": match.group(1),
                    "ok": True,
                    "switch": match.group(2),
                    "ip": match.group(3),
                    "mac": match.group(4),
                })
        elif line.startswith("SKIP existing VM:"):
            results.append({"name": line.split(":", 1)[1].strip(), "ok": False, "error": "VM already exists"})

    return results or [{"name": "batch", "ok": True, "output": output}]



def _parse_mapped_create_line(line: str) -> dict | None:
    line = (line or "").strip()
    if line.startswith("CREATED "):
        match = re.match(r"CREATED\s+(\S+)\s+->\s+(\S+)\s+(\S+)\s+(\S+)", line)
        if match:
            return {
                "name": match.group(1),
                "ok": True,
                "switch": match.group(2),
                "ip": match.group(3),
                "mac": match.group(4),
                "message": f"Created {match.group(1)} -> {match.group(3)}",
            }
        return {"name": "batch", "ok": True, "message": line}
    if line.startswith("SKIP existing VM:"):
        name = line.split(":", 1)[1].strip()
        return {"name": name, "ok": False, "skipped": True, "error": "VM already exists", "message": f"Skipped {name}: VM already exists"}
    return None


def _batch_create_mapped_vms_stream(data: dict, job_id: str):
    image_path = (data.get("image_path") or r"C:\42IPwin\images\debian-12-genericcloud-amd64.vhdx").strip()
    map_path = (data.get("map_path") or DEFAULT_IP_MAP).strip()
    script_path = (data.get("script_path") or DEFAULT_CREATE_SCRIPT).strip()
    vm_root = (data.get("vm_root") or r"C:\HyperV\Debian-42").strip()
    lan_switch = (data.get("lan_switch") or data.get("switch_name") or "VM-LAN").strip()
    name_prefix = (data.get("prefix") or "Debian").strip()
    start_index = int(data.get("map_start_index") or data.get("start_index") or 1)
    count = int(data.get("count") or 1)
    processor_count = int(data.get("processor_count") or 1)
    memory_startup_mb = int(data.get("memory_startup_mb") or 1024)
    generation = int(data.get("generation") or 2)
    root_password = str(data.get("root_password") or "")
    configure_guest = bool(data.get("configure_guest", True))
    auto_start = bool(data.get("auto_start"))
    include_host_switch_ips = bool(data.get("include_host_switch_ips"))
    internal_base = (data.get("internal_base") or "192.168.9").strip()
    internal_start_host = int(data.get("internal_start_host") or 101)
    internal_gateway = (data.get("internal_gateway") or "192.168.9.1").strip()
    internal_dns = (data.get("internal_dns") or "1.1.1.1").strip()
    ssh_port = int(data.get("ssh_port") or data.get("ssh_port_base") or 22)

    if not name_prefix:
        raise ValueError("Name prefix is required.")
    if count < 1 or count > 200:
        raise ValueError("Create count must be between 1 and 200.")
    if start_index > 42 and count >= 42:
        start_index = 1
    if start_index < 1:
        raise ValueError("Map start index must be >= 1.")
    if processor_count < 1 or processor_count > 64:
        raise ValueError("CPU count must be between 1 and 64.")
    if memory_startup_mb < 128:
        raise ValueError("Startup memory must be at least 128 MB.")
    if generation not in {1, 2}:
        raise ValueError("VM generation must be 1 or 2.")
    if configure_guest and not root_password:
        raise ValueError("Root password is required when guest config is enabled.")

    args = [
        "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", script_path,
        "-MapPath", map_path,
        "-TemplateVhd", image_path,
        "-VmRoot", vm_root,
        "-LanSwitch", lan_switch,
        "-NamePrefix", name_prefix,
        "-MemoryStartupBytes", str(memory_startup_mb * 1024 * 1024),
        "-ProcessorCount", str(processor_count),
        "-Generation", str(generation),
        "-InternalBase", internal_base,
        "-InternalStartHost", str(internal_start_host),
        "-InternalGateway", internal_gateway,
        "-InternalDNS", internal_dns,
        "-SshPort", str(ssh_port),
        "-StartIndex", str(start_index),
        "-Count", str(count),
        "-Execute",
    ]
    if configure_guest:
        args.extend(["-ConfigureGuest", "-RootPassword", root_password])
    if auto_start:
        args.append("-AutoStart")
    if include_host_switch_ips:
        args.append("-IncludeHostSwitchIps")

    results = []
    output_lines = []
    created = 0
    skipped = 0
    proc = subprocess.Popen(
        [POWERSHELL, *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding=locale.getpreferredencoding(False),
        errors="replace",
        bufsize=1,
    )
    try:
        while True:
            line = proc.stdout.readline() if proc.stdout else ""
            if not line and proc.poll() is not None:
                break
            if not line:
                time.sleep(0.2)
                continue
            line = line.strip()
            if not line:
                continue
            output_lines.append(line)
            parsed = _parse_mapped_create_line(line)
            if parsed:
                results.append({k: v for k, v in parsed.items() if k != "message"})
                if parsed.get("ok") and not parsed.get("skipped"):
                    created += 1
                elif parsed.get("skipped"):
                    skipped += 1
                _append_create_vm_message(job_id, parsed.get("message") or line)
                _set_create_vm_job(
                    job_id,
                    created_count=created,
                    skipped_count=skipped,
                    result_count=len(results),
                    percent=min(99, int(((created + skipped) / max(count, 1)) * 100)),
                    message=parsed.get("message") or line,
                    results=results,
                    output="\n".join(output_lines[-400:]),
                )
            else:
                _append_create_vm_message(job_id, line)
                _set_create_vm_job(job_id, message=line, output="\n".join(output_lines[-400:]))

        code = proc.wait()
    finally:
        if proc.poll() is None:
            proc.kill()

    output = "\n".join(output_lines)
    if code != 0:
        raise RuntimeError(_friendly_error(output) or output or f"PowerShell exited with {code}")
    return results or [{"name": "batch", "ok": True, "output": output}]


def _batch_create_vms_worker(job_id: str, data: dict):
    started = time.time()
    count = int(data.get("count") or 0)
    try:
        _set_create_vm_job(
            job_id,
            status="running",
            stage="create",
            percent=1,
            total=count,
            created_count=0,
            skipped_count=0,
            messages=["Start creating VMs..."],
            results=[],
            message="Start creating VMs...",
        )
        mode = (data.get("mode") or "normal").strip().lower()
        if _is_linux():
            processed = 0
            linux_results_so_far = []

            def linux_progress(item: dict, message: str):
                nonlocal processed
                linux_results_so_far.append(item)
                processed += 1
                _append_create_vm_message(job_id, message)
                _set_create_vm_job(
                    job_id,
                    created_count=len([r for r in linux_results_so_far if r.get("ok")]),
                    skipped_count=len([r for r in linux_results_so_far if r.get("skipped")]),
                    result_count=processed,
                    percent=min(99, int((processed / max(count, 1)) * 100)),
                    message=message,
                    results=list(linux_results_so_far),
                )

            results = _linux_create_vms(data, linux_progress)
        elif mode == "ip_map":
            results = _batch_create_mapped_vms_stream(data, job_id)
        else:
            results = batch_create_vms(data)
            for item in results:
                name = item.get("name") or "VM"
                if item.get("ok"):
                    _append_create_vm_message(job_id, f"Created {name}")
                else:
                    _append_create_vm_message(job_id, f"Failed {name}: {item.get('error') or '-'}")
        failed = [item for item in results if not item.get("ok") and not item.get("skipped")]
        created = len([item for item in results if item.get("ok")])
        skipped = len([item for item in results if item.get("skipped")])
        status = "done" if not failed else "error"
        message = f"Create finished: success {created}, skipped {skipped}, failed {len(failed)}"
        _append_create_vm_message(job_id, message)
        _set_create_vm_job(
            job_id,
            status=status,
            stage="done" if status == "done" else "error",
            percent=100,
            seconds=int(time.time() - started),
            created_count=created,
            skipped_count=skipped,
            failed_count=len(failed),
            result_count=len(results),
            results=results,
            message=message,
        )
    except Exception as exc:
        _append_create_vm_message(job_id, f"Create failed: {exc}")
        _set_create_vm_job(
            job_id,
            status="error",
            stage="error",
            percent=100,
            seconds=int(time.time() - started),
            message=str(exc),
            error=str(exc),
        )

def start_batch_create_vms(data: dict):
    job_id = uuid.uuid4().hex
    _set_create_vm_job(
        job_id,
        id=job_id,
        status="queued",
        stage="queued",
        percent=0,
        total=int(data.get("count") or 0),
        created_count=0,
        skipped_count=0,
        failed_count=0,
        messages=["任务已提交，等待开始..."],
        results=[],
        message="任务已提交，等待开始...",
    )
    thread = threading.Thread(target=_batch_create_vms_worker, args=(job_id, dict(data)), daemon=True)
    thread.start()
    return {"job_id": job_id}


def batch_create_job_status(job_id: str):
    with CREATE_VM_JOBS_LOCK:
        job = dict(CREATE_VM_JOBS.get(job_id) or {})
    if not job:
        raise ValueError("Create job not found.")
    return job
