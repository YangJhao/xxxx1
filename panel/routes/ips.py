"""Line/IP management routes."""
import json
import os
import random
import re
import shutil
import socket
import subprocess
import time

import psutil
from flask import Blueprint, jsonify, request

from models import Line, get_session
from routes.auth import login_required
from services import proxy_manager
from services.cfg_generator import write_cfg
from services.system_info import get_port_connections

bp = Blueprint("ips", __name__, url_prefix="/api/lines")

IP_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
LAST_IO = {}
DETECT_CACHE = {"time": 0.0, "data": None}
STATIC_MASTER_IPS = {
    "220.87.187.66": "enp5s0f0",
    "119.206.98.58": "enp5s0f1",
    "119.206.92.112": "enp7s0",
}
STATIC_MASTER_NAMES = set(STATIC_MASTER_IPS.values())


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
    display = _format_line_name(interface_name)
    m = re.search(r"以太网\s*([567])", display)
    if m:
        return f"以太网 {m.group(1)}"
    m = re.match(r"^(.+)-(\d{3})$", display)
    return m.group(1) if m else ""


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
    now = time.time()
    snapshot = {}
    for iface, rows in addrs.items():
        item = {
            "interface": iface,
            "display_name": _format_line_name(iface),
            "parent_adapter": _parent_adapter(iface),
            "adapter_index": _adapter_index(iface),
            "is_master": _is_master_interface(iface),
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
    seen.add((iface, ip))
    item = {
        "interface": iface,
        "display_name": f"{forced_master_iface}-主网卡" if is_forced_master else iface_info.get("display_name") or _format_line_name(iface),
        "parent_adapter": forced_master_iface if is_forced_master else iface_info.get("parent_adapter") or _parent_adapter(iface),
        "adapter_index": 0 if is_forced_master else iface_info.get("adapter_index") or _adapter_index(iface),
        "is_master": True if is_forced_master else iface_info.get("is_master", _is_master_interface(iface)),
        "locked": True if is_forced_master else False,
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
    masters = []
    defaults = _linux_default_interfaces() if os.name != "nt" else []
    for name, info in ifaces.items():
        if name == "lo" or _is_generated_child_interface(name):
            continue
        has_public = any(_is_public_candidate(ip) for ip in info.get("ipv4", []))
        if info.get("is_master") or name in defaults or has_public:
            if name not in masters:
                masters.append(name)
    return masters


def _master_interface_options() -> list[dict]:
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
    return options


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
            results[iface] = {"ok": False, "message": "DHCP 获取 IP 超时"}
    return results


def _line_to_dict(line, detected_by_ip, iface_map):
    data = line.to_dict()
    detected = detected_by_ip.get(line.public_ip) or {}
    iface = detected.get("interface") or line.note or ""
    iface_info = iface_map.get(iface, {})
    display_name = detected.get("display_name") or iface_info.get("display_name") or _format_line_name(iface or line.name)
    forced_master_iface = STATIC_MASTER_IPS.get(line.public_ip)
    if forced_master_iface:
        iface = forced_master_iface
        iface_info = iface_map.get(iface, iface_info)
    is_master = bool(forced_master_iface or detected.get("is_master", iface_info.get("is_master", _is_master_interface(iface))))
    node_count = len(line.users or [])
    connection_count = 0
    for user in line.users or []:
        port = user.listen_port or line.get_port_by_protocol(user.protocol)
        if port:
            conns = get_port_connections(int(port))
            connection_count += int(conns.get("inbound", 0)) + int(conns.get("outbound", 0))
    data.update({
        "name": f"{forced_master_iface}-主网卡" if forced_master_iface else display_name,
        "interface": f"{forced_master_iface}-主网卡" if forced_master_iface else display_name,
        "raw_interface": iface,
        "parent_adapter": forced_master_iface or detected.get("parent_adapter") or iface_info.get("parent_adapter") or _parent_adapter(display_name),
        "adapter_index": detected.get("adapter_index") or iface_info.get("adapter_index") or _adapter_index(display_name),
        "is_master": is_master,
        "locked": is_master,
        "mac": detected.get("mac") or iface_info.get("mac") or "",
        "internal_ip": line.internal_ip if line.internal_ip != "0.0.0.0" else detected.get("internal_ip", "") or _generated_internal_ip(display_name),
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


@bp.route("/detect-ips", methods=["GET"])
@login_required
def detect_ips():
    return jsonify({"ok": True, "data": _detect_local_ips()})


@bp.route("/master-interfaces", methods=["GET"])
@login_required
def master_interfaces():
    return jsonify({"ok": True, "data": _master_interface_options()})


@bp.route("/sync-local", methods=["POST"])
@login_required
def sync_local_lines():
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
                internal_ip=item.get("internal_ip") or _generated_internal_ip(display_name),
                socks_port=socks_port,
                http_port=http_port,
                ss_port=ss_port,
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
                    line.internal_ip = matched.get("internal_ip") or _generated_internal_ip(display_name)

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
    if os.name == "nt":
        return jsonify({"ok": False, "error": "Windows 版本请在 Hyper-V/PVE 中创建虚拟网卡；当前按钮主要用于 Linux/PVE。"}), 400
    if name and count > 1:
        return jsonify({"ok": False, "error": "批量创建时请留空名称，系统会自动命名"}), 400
    if name and not re.match(r"^[a-zA-Z0-9_.:-]{1,15}$", name):
        return jsonify({"ok": False, "error": "虚拟网卡名称只能包含字母数字和 . _ : -，最长 15 位"}), 400
    if internal_ip and not _valid_ip(internal_ip):
        return jsonify({"ok": False, "error": "内网 IP 格式错误"}), 400
    if prefix < 1 or prefix > 32:
        return jsonify({"ok": False, "error": "掩码范围必须是 1-32"}), 400
    available_masters = _master_interfaces()
    if parent and parent not in available_masters:
        return jsonify({"ok": False, "error": "请选择系统检测到的真实主网卡"}), 400
    parents = [parent] if parent else available_masters
    if not parents:
        return jsonify({"ok": False, "error": "未找到主网卡，请确认服务器有可用公网网卡或默认路由"}), 400
    created = []
    errors = []
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
            else:
                try:
                    child_name, seq = _next_child_interface_name(parent_name, existing)
                except RuntimeError as exc:
                    errors.append(str(exc))
                    continue
            mac = _generated_mac(parent_idx, seq)
            ok, output = _run_cmd(["ip", "link", "add", "link", parent_name, child_name, "address", mac, "type", "macvlan", "mode", "bridge"])
            if not ok and "File exists" not in output:
                errors.append(f"{parent_name}/{child_name}: {output or '创建失败'}")
                continue
            existing.add(child_name)
            if internal_ip and len(parents) == 1 and count == 1:
                ok, output = _run_cmd(["ip", "addr", "replace", f"{internal_ip}/{prefix}", "dev", child_name])
                if not ok:
                    errors.append(f"{child_name}: {output or '绑定内网 IP 失败'}")
            ok, output = _run_cmd(["ip", "link", "set", child_name, "up"])
            if not ok:
                errors.append(f"{child_name}: {output or '启用失败'}")
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
    acquired_count = len([item for item in created if item.get("ip")])
    return jsonify({"ok": True, "data": {"created": created, "created_count": len(created), "acquired_count": acquired_count, "errors": errors, "prefix": prefix}})


@bp.route("/<int:lid>/internal-ip", methods=["POST"])
@login_required
def update_internal_ip(lid):
    data = request.get_json(silent=True) or {}
    internal_ip = (data.get("internal_ip") or "").strip()
    if not _valid_ip(internal_ip):
        return jsonify({"ok": False, "error": "内网 IP 格式错误"}), 400
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
        return jsonify({"ok": False, "error": "网段格式错误，例如 10.42"}), 400
    s = get_session()
    try:
        lines = s.query(Line).order_by(Line.name, Line.id).all()
        updated = []
        fallback_idx = 1
        for line in lines:
            label = line.name or line.note or ""
            m = re.search(r"以太网\s*([567])-(\d{3})", label)
            if m:
                ip = f"{base}.{int(m.group(1))}.{int(m.group(2))}"
            else:
                ip = f"{base}.9.{fallback_idx}"
                fallback_idx += 1
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
        detected = _detect_local_ips()
        detected_by_ip = {item["ip"]: item for item in detected}
        iface_map = {item["interface"]: item for item in detected}
        lines = s.query(Line).order_by(Line.name, Line.id).all()
        return jsonify({"ok": True, "data": [_line_to_dict(line, detected_by_ip, iface_map) for line in lines]})
    finally:
        s.close()


@bp.route("/<int:lid>/change-mac", methods=["POST"])
@login_required
def change_mac(lid):
    s = get_session()
    try:
        if os.name != "nt":
            return jsonify({"ok": False, "error": "Linux/PVE 版本不支持在面板内一键更换 MAC，请在 PVE 网卡配置中修改。"}), 400
        line = s.query(Line).get(lid)
        if not line:
            return jsonify({"ok": False, "error": "线路不存在"}), 404
        info = _line_to_dict(line, {item["ip"]: item for item in _detect_local_ips()}, _iface_snapshot())
        if info["is_master"]:
            return jsonify({"ok": False, "error": "主网卡为静默线路，不能更换 MAC"}), 400
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
        s.delete(line)
        s.commit()
        try:
            _reload_after_change()
        except Exception as exc:
            print(f"[lines delete reload] {exc}")
        return jsonify({"ok": True})
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
