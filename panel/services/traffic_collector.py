"""Traffic and connection collector for sing-box.

Uses the local sing-box Clash API `/connections` endpoint. The endpoint exposes
active connection upload/download counters, which we aggregate by inbound tag.
"""
import json
import re
import sys
import time
import urllib.request
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from models import ProxyUser, TrafficLog, get_session

CLASH_CONNECTIONS_URL = "http://127.0.0.1:9090/connections"
_last_conn_totals: dict[str, tuple[int, int, int]] = {}
_last_snapshot: dict[int, dict] = {}
_last_snapshot_ts = 0.0


def _user_tag(user: ProxyUser) -> str:
    return f"in-{user.protocol}-user-{user.id}"


def _fetch_connections(timeout: float = 3) -> list[dict]:
    req = urllib.request.Request(CLASH_CONNECTIONS_URL, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = json.loads(resp.read().decode("utf-8", errors="ignore"))
    return data.get("connections") or []


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
    global _last_snapshot_ts
    now = time.time()
    if _last_snapshot and now - _last_snapshot_ts < 1.5:
        return _last_snapshot.copy()

    session = get_session()
    try:
      users = { _user_tag(u): u.id for u in session.query(ProxyUser).all() }
    finally:
      session.close()

    result: dict[int, dict] = {}
    try:
        connections = _fetch_connections(timeout=0.5)
    except Exception:
        return _last_snapshot.copy()

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
    return result


def collect_once() -> dict:
    """Collect sing-box current counters into proxy_users and traffic_log."""
    session = get_session()
    try:
        users = { _user_tag(u): u.id for u in session.query(ProxyUser).all() }
    finally:
        session.close()

    try:
        connections = _fetch_connections()
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
        prev_uid, prev_upload, prev_download = _last_conn_totals.get(conn_id, (uid, upload, download))
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
        connections = _fetch_connections()
        tags = [_connection_tag(conn) for conn in connections]
        matched = [tag for tag in tags if tag.startswith("in-")]
        return {
            "ok": True,
            "active_connections": len(connections),
            "matched_inbound_tags": len(matched),
            "sample_tags": tags[:8],
            "cached_snapshot_users": len(_last_snapshot),
        }
    except Exception as exc:
        return {"ok": False, "error": str(exc), "cached_snapshot_users": len(_last_snapshot)}


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
