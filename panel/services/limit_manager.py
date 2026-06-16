"""Apply per-node speed and traffic limits."""
import os
import re
import shutil
import subprocess


def parse_speed_to_bps(value) -> int | None:
    if not value:
        return None
    text = str(value).strip().lower().replace(" ", "")
    m = re.search(r"(\d+(?:\.\d+)?)(bps|bit|bits|k|kb|kbit|kbps|m|mb|mbit|mbps|g|gb|gbit|gbps)?", text)
    if not m:
        return None
    number = float(m.group(1))
    unit = m.group(2) or "mbps"
    if unit in {"bps", "bit", "bits"}:
        mult = 1
    elif unit in {"k", "kb", "kbit", "kbps"}:
        mult = 1000
    elif unit in {"m", "mb", "mbit", "mbps"}:
        mult = 1000**2
    elif unit in {"g", "gb", "gbit", "gbps"}:
        mult = 1000**3
    else:
        return None
    return max(1, int(number * mult))


def _policy_names(user_id: int) -> list[str]:
    return [
        f"42IPwin-node-{user_id}-tcp-src",
        f"42IPwin-node-{user_id}-tcp-dst",
        f"42IPwin-node-{user_id}-udp-src",
        f"42IPwin-node-{user_id}-udp-dst",
        f"42IPwin-node-{user_id}-tcp",
        f"42IPwin-node-{user_id}-udp",
    ]


def _run_ps(script: str) -> tuple[bool, str]:
    proc = subprocess.run(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],
        capture_output=True,
        text=True,
        timeout=20,
    )
    out = (proc.stdout or "") + (proc.stderr or "")
    return proc.returncode == 0, out.strip()


def _run_cmd(args: list[str], timeout: int = 20) -> tuple[bool, str]:
    proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    out = (proc.stdout or "") + (proc.stderr or "")
    return proc.returncode == 0, out.strip()


def _linux_default_iface() -> str | None:
    try:
        proc = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True, timeout=5)
        for part in (proc.stdout or "").split():
            if part == "dev":
                items = (proc.stdout or "").split()
                idx = items.index("dev")
                return items[idx + 1] if idx + 1 < len(items) else None
    except Exception:
        return None
    return None


def _tc_available() -> bool:
    return os.name != "nt" and bool(shutil.which("tc")) and bool(shutil.which("ip"))


def _linux_mark(user_id: int) -> str:
    return str(10000 + int(user_id))


def _run_linux_limit_script(script: str) -> tuple[bool, str]:
    return _run_cmd(["sh", "-c", script], timeout=25)


def clear_limit(user_id: int) -> dict:
    if os.name != "nt":
        if not _tc_available():
            return {"ok": False, "output": "Linux tc/ip 命令不可用，无法清理限速"}
        mark = _linux_mark(user_id)
        script = "\n".join([
            f"iptables -t mangle -D OUTPUT -m mark --mark {mark} -j MARK --set-mark 0 2>/dev/null || true",
            f"iptables -t mangle -D OUTPUT -m mark --mark {mark} -j RETURN 2>/dev/null || true",
            f"iptables -t mangle -D OUTPUT -p tcp --sport 1:65535 -m mark --mark {mark} -j MARK --set-mark 0 2>/dev/null || true",
            f"iptables -t mangle -D OUTPUT -p udp --sport 1:65535 -m mark --mark {mark} -j MARK --set-mark 0 2>/dev/null || true",
        ])
        ok, output = _run_linux_limit_script(script)
        return {"ok": ok, "output": output}
    names = _policy_names(user_id)
    script = "\n".join(
        f"Get-NetQosPolicy -Name '{name}' -ErrorAction SilentlyContinue | Remove-NetQosPolicy -Confirm:$false -ErrorAction SilentlyContinue"
        for name in names
    )
    ok, output = _run_ps(script)
    return {"ok": ok, "output": output}


def apply_limit(user, port: int, protocol: str | None = None) -> dict:
    bps = parse_speed_to_bps(getattr(user, "speed_limit", None))
    clear = clear_limit(user.id)
    if not bps:
        return {"ok": clear["ok"], "limited": False, "bps": None, "output": clear.get("output", "")}

    if os.name != "nt":
        if not _tc_available():
            return {"ok": False, "limited": False, "bps": bps, "output": "Linux tc/ip 命令不可用，请安装 iproute2/iptables"}
        iface = _linux_default_iface()
        if not iface:
            return {"ok": False, "limited": False, "bps": bps, "output": "未找到默认出口网卡"}
        proto = (protocol or getattr(user, "protocol", "") or "").lower()
        use_udp = proto in {"socks5", "ss", "hysteria2"}
        port = int(port)
        mark = _linux_mark(user.id)
        rate = f"{max(1, int(bps / 1000))}kbit"
        classid = f"1:{1000 + int(user.id)}"
        udp_rule = f"iptables -t mangle -A OUTPUT -p udp --sport {port} -j MARK --set-mark {mark}" if use_udp else "true"
        script = "\n".join([
            f"tc qdisc add dev {iface} root handle 1: htb default 999 2>/dev/null || true",
            f"tc class add dev {iface} parent 1: classid 1:1 htb rate 1000mbit ceil 1000mbit 2>/dev/null || true",
            f"tc class replace dev {iface} parent 1:1 classid {classid} htb rate {rate} ceil {rate}",
            f"tc filter replace dev {iface} protocol ip parent 1: prio {1000 + int(user.id)} handle {mark} fw flowid {classid}",
            f"iptables -t mangle -A OUTPUT -p tcp --sport {port} -j MARK --set-mark {mark}",
            udp_rule,
        ])
        ok, output = _run_linux_limit_script(script)
        return {"ok": ok, "limited": ok, "bps": bps, "output": output, "interface": iface}

    proto = (protocol or getattr(user, "protocol", "") or "").lower()
    use_udp = proto in {"socks5", "ss", "hysteria2"}
    port = int(port)
    parts = [
        f"New-NetQosPolicy -Name '42IPwin-node-{user.id}-tcp-src' -IPProtocolMatchCondition TCP -IPSrcPortMatchCondition {port} -ThrottleRateActionBitsPerSecond {bps} | Out-Null",
        f"New-NetQosPolicy -Name '42IPwin-node-{user.id}-tcp-dst' -IPProtocolMatchCondition TCP -IPDstPortMatchCondition {port} -ThrottleRateActionBitsPerSecond {bps} | Out-Null",
    ]
    if use_udp:
        parts.append(
            f"New-NetQosPolicy -Name '42IPwin-node-{user.id}-udp-src' -IPProtocolMatchCondition UDP -IPSrcPortMatchCondition {port} -ThrottleRateActionBitsPerSecond {bps} | Out-Null"
        )
        parts.append(
            f"New-NetQosPolicy -Name '42IPwin-node-{user.id}-udp-dst' -IPProtocolMatchCondition UDP -IPDstPortMatchCondition {port} -ThrottleRateActionBitsPerSecond {bps} | Out-Null"
        )
    ok, output = _run_ps("\n".join(parts))
    return {"ok": ok, "limited": ok, "bps": bps, "output": output}


def sync_limits(session) -> list[dict]:
    from models import ProxyUser

    results = []
    for user in session.query(ProxyUser).all():
        if not user.line:
            continue
        if not user.status:
            results.append(clear_limit(user.id))
            continue
        port = user.listen_port or user.line.get_port_by_protocol(user.protocol)
        results.append(apply_limit(user, port, user.protocol))
    return results
