"""Traffic and connection collector for sing-box.

Uses the local sing-box Clash API `/connections` endpoint. The endpoint exposes
active connection upload/download counters, which we aggregate by inbound tag.
"""
import json
import os
import re
import subprocess
import sys
import time
import urllib.request
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from models import ProxyUser, TrafficLog, get_session
try:
    from services import wireguard_manager
except ImportError:
    class _NoWireGuardManager:
        @staticmethod
        def transfer_snapshot(session) -> dict:
            return {}

    wireguard_manager = _NoWireGuardManager()

CLASH_CONNECTIONS_URL = "http://127.0.0.1:9090/connections"
INSTANCE_CONTROLLER_BASE_PORT = int(os.environ.get("IPWIN42_SINGBOX_INSTANCE_CONTROLLER_BASE", "19090"))
TRAFFIC_INPUT_CHAIN = "42IPWIN_TRAFFIC_IN"
TRAFFIC_OUTPUT_CHAIN = "42IPWIN_TRAFFIC_OUT"
_last_conn_totals: dict[str, tuple[int, int, int]] = {}
_last_wg_totals: dict[int, tuple[int, int]] = {}
_last_port_totals: dict[tuple[int, str], int] = {}
_last_snapshot: dict[int, dict] = {}
_last_snapshot_ts = 0.0
_last_snapshot_error = ""


def _user_tag(user: ProxyUser) -> str:
    return f"in-{user.protocol}-user-{user.id}"


def _user_port(user: ProxyUser) -> int:
    return int(user.listen_port or user.line.get_port_by_protocol(user.protocol))


def _traffic_protocols(protocol: str | None) -> list[str]:
    proto = (protocol or "socks5").lower()
    if proto in {"socks5", "ss", "hysteria2", "wireguard"}:
        return ["tcp", "udp"]
    return ["tcp"]


def _sing_box_mode() -> str:
    mode = (os.environ.get("IPWIN42_SINGBOX_MODE") or "single").strip().lower()
    return "per_line" if mode in {"per_line", "per-line", "line", "multi"} else "single"


def _controller_port(line_id: int) -> int:
    return INSTANCE_CONTROLLER_BASE_PORT + int(line_id)


def _fetch_connections_url(url: str, timeout: float = 3) -> list[dict]:
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = json.loads(resp.read().decode("utf-8", errors="ignore"))
    return data.get("connections") or []


def _active_line_ids(session) -> list[int]:
    from models import Line

    return [
        int(row[0])
        for row in session.query(Line.id).filter(Line.status == 1).order_by(Line.id).all()
        if row[0]
    ]


def _fetch_connections(timeout: float = 3, session=None) -> list[dict]:
    if _sing_box_mode() != "per_line":
        return _fetch_connections_url(CLASH_CONNECTIONS_URL, timeout=timeout)

    own_session = session is None
    if own_session:
        session = get_session()
    try:
        connections: list[dict] = []
        errors: list[str] = []
        line_ids = _active_line_ids(session)
        for line_id in line_ids:
            url = f"http://127.0.0.1:{_controller_port(line_id)}/connections"
            try:
                rows = _fetch_connections_url(url, timeout=timeout)
            except Exception as exc:
                errors.append(f"line {line_id}: {exc}")
                continue
            for row in rows:
                if isinstance(row, dict):
                    row["_ipwin_line_id"] = line_id
            connections.extend(rows)
        if not connections and errors and len(errors) == len(line_ids):
            raise RuntimeError("; ".join(errors[:5]))
        return connections
    finally:
        if own_session:
            session.close()


def _run_iptables(args: list[str], timeout: int = 10) -> subprocess.CompletedProcess:
    return subprocess.run(["iptables", *args], capture_output=True, text=True, timeout=timeout)


def _ensure_traffic_jump(hook: str, chain: str) -> None:
    if _run_iptables(["-C", hook, "-j", chain]).returncode != 0:
        _run_iptables(["-I", hook, "1", "-j", chain])


def ensure_port_counters(session=None) -> dict:
    """Install Linux iptables byte counters for every active inbound port."""
    if os.name == "nt":
        return {"ok": False, "skipped": True, "reason": "windows"}
    own_session = session is None
    if own_session:
        session = get_session()
    try:
        _run_iptables(["-N", TRAFFIC_INPUT_CHAIN])
        _run_iptables(["-N", TRAFFIC_OUTPUT_CHAIN])
        _ensure_traffic_jump("INPUT", TRAFFIC_INPUT_CHAIN)
        _ensure_traffic_jump("OUTPUT", TRAFFIC_OUTPUT_CHAIN)
        users = session.query(ProxyUser).filter(ProxyUser.status == 1).all()
        installed = 0
        for user in users:
            if not user.line:
                continue
            if (user.protocol or "").lower() == "wireguard":
                continue
            try:
                port = str(_user_port(user))
            except Exception:
                continue
            comment = f"42ipwin-user-{user.id}"
            for proto in _traffic_protocols(user.protocol):
                in_rule = [
                    "-A",
                    TRAFFIC_INPUT_CHAIN,
                    "-p",
                    proto,
                    "--dport",
                    port,
                    "-m",
                    "comment",
                    "--comment",
                    f"{comment}-in",
                    "-j",
                    "RETURN",
                ]
                check_in = ["-C", *in_rule[1:]]
                if _run_iptables(check_in).returncode != 0:
                    _run_iptables(in_rule)
                out_rule = [
                    "-A",
                    TRAFFIC_OUTPUT_CHAIN,
                    "-p",
                    proto,
                    "--sport",
                    port,
                    "-m",
                    "comment",
                    "--comment",
                    f"{comment}-out",
                    "-j",
                    "RETURN",
                ]
                check_out = ["-C", *out_rule[1:]]
                if _run_iptables(check_out).returncode != 0:
                    _run_iptables(out_rule)
                installed += 2
        return {"ok": True, "installed": installed, "users": len(users)}
    finally:
        if own_session:
            session.close()


def _parse_iptables_counter_line(line: str) -> tuple[int, str, int] | None:
    match = re.search(r"/\* 42ipwin-user-(\d+)-(in|out) \*/", line)
    if not match:
        return None
    parts = line.split()
    if len(parts) < 2:
        return None
    try:
        bytes_value = int(parts[1])
    except Exception:
        return None
    return int(match.group(1)), match.group(2), bytes_value


def _port_counter_snapshot() -> dict[int, dict[str, int]]:
    if os.name == "nt":
        return {}
    result: dict[int, dict[str, int]] = {}
    for chain, direction in ((TRAFFIC_INPUT_CHAIN, "in"), (TRAFFIC_OUTPUT_CHAIN, "out")):
        proc = _run_iptables(["-v", "-x", "-L", chain, "-n"], timeout=8)
        if proc.returncode != 0:
            continue
        for line in (proc.stdout or "").splitlines():
            parsed = _parse_iptables_counter_line(line)
            if not parsed:
                continue
            uid, comment_direction, bytes_value = parsed
            if comment_direction != direction:
                continue
            item = result.setdefault(uid, {"in": 0, "out": 0})
            item[direction] += bytes_value
    return result


def _port_counter_deltas(session) -> dict[int, tuple[int, int]]:
    """Return upload/download deltas from persistent Linux port counters."""
    try:
        ensure_port_counters(session)
    except Exception:
        pass
    snapshot = _port_counter_snapshot()
    deltas: dict[int, tuple[int, int]] = {}
    for uid, item in snapshot.items():
        in_total = int(item.get("in") or 0)
        out_total = int(item.get("out") or 0)
        prev_in = _last_port_totals.get((uid, "in"), in_total)
        prev_out = _last_port_totals.get((uid, "out"), out_total)
        _last_port_totals[(uid, "in")] = in_total
        _last_port_totals[(uid, "out")] = out_total
        delta_download = max(0, in_total - prev_in)
        delta_upload = max(0, out_total - prev_out)
        if delta_upload or delta_download:
            deltas[uid] = (delta_upload, delta_download)
    return deltas


def _connection_tag(conn: dict) -> str:
    metadata = conn.get("metadata") or {}
    for key in ("inbound", "inboundName"):
        value = str(metadata.get(key) or "")
        if value.startswith("in-"):
            return value

    conn_type = str(metadata.get("type") or "")
    if "/" in conn_type:
        value = conn_type.rsplit("/", 1)[-1]
        if value.startswith("in-"):
            return value

    rule = str(conn.get("rule") or "")
    match = re.search(r"inbound=([A-Za-z0-9_-]+)", rule)
    if match:
        return match.group(1)

    chains = conn.get("chains") or []
    return str(chains[0] or "") if chains else ""


def snapshot_connections() -> dict[int, dict]:
    """Return current active connection counts and bytes by ProxyUser id."""
    return snapshot_connections_status()["data"]


def snapshot_connections_status() -> dict:
    """Return current connection snapshot with freshness metadata.

    On fetch failure, do not return stale counts as if they were live. The caller can
    decide how to display the failure without misleading operators.
    """
    global _last_snapshot_ts, _last_snapshot_error
    now = time.time()
    if _last_snapshot and now - _last_snapshot_ts < 1.5:
        port_counters = _port_counter_snapshot()
        return {
            "ok": True,
            "stale": False,
            "error": "",
            "data": _last_snapshot.copy(),
            "port_counter_users": set(port_counters),
        }

    session = get_session()
    try:
        users = { _user_tag(u): u.id for u in session.query(ProxyUser).all() }
        try:
            connections = _fetch_connections(timeout=0.5, session=session)
        except Exception as exc:
            _last_snapshot_error = str(exc)
            return {"ok": False, "stale": False, "error": _last_snapshot_error, "data": {}}
    finally:
        session.close()

    result: dict[int, dict] = {}
    for conn in connections:
        uid = users.get(_connection_tag(conn))
        if not uid:
            continue
        item = result.setdefault(uid, {"connections": 0, "upload": 0, "download": 0})
        item["connections"] += 1
        item["upload"] += int(conn.get("upload") or 0)
        item["download"] += int(conn.get("download") or 0)

    _last_snapshot.clear()
    _last_snapshot.update(result)
    _last_snapshot_ts = now
    _last_snapshot_error = ""
    port_counters = _port_counter_snapshot()
    return {"ok": True, "stale": False, "error": "", "data": result.copy(), "port_counter_users": set(port_counters)}


def collect_once() -> dict:
    """Collect sing-box current counters into proxy_users and traffic_log."""
    session = get_session()
    try:
        users = { _user_tag(u): u.id for u in session.query(ProxyUser).all() }
    finally:
        session.close()

    try:
        connections = _fetch_connections(timeout=0.5)
    except Exception:
        connections = []

    snapshot: dict[int, dict] = {}
    deltas: dict[int, tuple[int, int]] = {}
    seen_conn_ids: set[str] = set()

    for conn in connections:
        uid = users.get(_connection_tag(conn))
        if not uid:
            continue
        item = snapshot.setdefault(uid, {"connections": 0, "upload": 0, "download": 0})
        upload = int(conn.get("upload") or 0)
        download = int(conn.get("download") or 0)
        item["connections"] += 1
        item["upload"] += upload
        item["download"] += download

        conn_id = str(conn.get("id") or f"{uid}:{conn.get('start') or ''}:{upload}:{download}")
        seen_conn_ids.add(conn_id)
        # Clash reports counters from the start of an active connection. When a
        # connection is first observed after a panel restart or a delayed poll,
        # count the visible total instead of using it as the baseline; otherwise
        # long-running HY2/SS/SOCKS sessions can appear to have used almost no
        # traffic until the next delta.
        prev_uid, prev_upload, prev_download = _last_conn_totals.get(conn_id, (uid, 0, 0))
        delta_upload = max(0, upload - prev_upload) if prev_uid == uid else 0
        delta_download = max(0, download - prev_download) if prev_uid == uid else 0
        _last_conn_totals[conn_id] = (uid, upload, download)
        if delta_upload or delta_download:
            old_up, old_down = deltas.get(uid, (0, 0))
            deltas[uid] = (old_up + delta_upload, old_down + delta_download)

    for conn_id in list(_last_conn_totals):
        if conn_id not in seen_conn_ids:
            _last_conn_totals.pop(conn_id, None)

    _last_snapshot.clear()
    _last_snapshot.update(snapshot)
    global _last_snapshot_ts
    _last_snapshot_ts = time.time()

    session = get_session()
    updated = 0
    try:
        hour = datetime.now().strftime("%Y-%m-%d %H")
        port_deltas = _port_counter_deltas(session)
        for uid, (delta_upload, delta_download) in port_deltas.items():
            deltas[uid] = (delta_upload, delta_download)
        wg_totals = wireguard_manager.transfer_snapshot(session)
        for uid, (wg_rx, wg_tx) in wg_totals.items():
            prev_rx, prev_tx = _last_wg_totals.get(uid, (wg_rx, wg_tx))
            delta_rx = max(0, int(wg_rx) - int(prev_rx))
            delta_tx = max(0, int(wg_tx) - int(prev_tx))
            _last_wg_totals[uid] = (int(wg_rx), int(wg_tx))
            if delta_rx or delta_tx:
                old_up, old_down = deltas.get(uid, (0, 0))
                deltas[uid] = (old_up + delta_tx, old_down + delta_rx)
        for user in session.query(ProxyUser).all():
            delta_upload, delta_download = deltas.get(user.id, (0, 0))
            if not delta_upload and not delta_download:
                continue

            user.bytes_in = int(user.bytes_in or 0) + delta_upload
            user.bytes_out = int(user.bytes_out or 0) + delta_download
            log = session.query(TrafficLog).filter_by(user_id=user.id, hour=hour).first()
            if not log:
                log = TrafficLog(user_id=user.id, line_id=user.line_id, hour=hour, bytes_in=0, bytes_out=0)
                session.add(log)
            log.bytes_in = int(log.bytes_in or 0) + delta_upload
            log.bytes_out = int(log.bytes_out or 0) + delta_download
            updated += 1
        session.commit()
        return {"updated_rows": updated, "source": "sing-box clash api"}
    finally:
        session.close()


def collector_status() -> dict:
    try:
        session = get_session()
        try:
            connections = _fetch_connections(session=session)
        finally:
            session.close()
        tags = [_connection_tag(conn) for conn in connections]
        matched = [tag for tag in tags if tag.startswith("in-")]
        port_counters = _port_counter_snapshot()
        return {
            "ok": True,
            "mode": _sing_box_mode(),
            "active_connections": len(connections),
            "matched_inbound_tags": len(matched),
            "sample_tags": tags[:8],
            "port_counter_users": len(port_counters),
            "cached_snapshot_users": len(_last_snapshot),
        }
    except Exception as exc:
        return {"ok": False, "mode": _sing_box_mode(), "error": str(exc), "cached_snapshot_users": len(_last_snapshot)}


def start_daemon(interval_sec: int = 10):
    print(f"[traffic] sing-box collector started, interval={interval_sec}s")
    while True:
        try:
            r = collect_once()
            if r["updated_rows"]:
                print(f"[traffic] collected {r['updated_rows']} updates at {datetime.now().isoformat(timespec='seconds')}")
        except Exception as e:
            print(f"[traffic] collect error: {e}")
        time.sleep(interval_sec)


if __name__ == "__main__":
    print(collect_once())
