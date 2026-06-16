"""fast.com-style speed test helpers."""
import json
import socket
import ssl
import struct
import threading
import time
import urllib.request
from urllib.parse import urlparse

FAST_API = (
    "https://api.fast.com/netflix/speedtest/v2"
    "?https=true&token=YXNkZmFzZGxmbnNkYWZoYXNkZmhrYWxm&urlCount=5"
)


def _read_exact(sock, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise OSError("connection closed")
        data += chunk
    return data


def _open_socks5(proxy: dict, host: str, port: int):
    sock = socket.create_connection((proxy["host"], int(proxy["port"])), timeout=10)
    sock.settimeout(20)
    username = (proxy.get("username") or "").encode("utf-8")
    password = (proxy.get("password") or "").encode("utf-8")
    if username or password:
        sock.sendall(b"\x05\x01\x02")
        if _read_exact(sock, 2) != b"\x05\x02":
            raise OSError("SOCKS5 auth method rejected")
        if len(username) > 255 or len(password) > 255:
            raise OSError("SOCKS5 auth too long")
        sock.sendall(b"\x01" + bytes([len(username)]) + username + bytes([len(password)]) + password)
        if _read_exact(sock, 2) != b"\x01\x00":
            raise OSError("SOCKS5 auth failed")
    else:
        sock.sendall(b"\x05\x01\x00")
        if _read_exact(sock, 2) != b"\x05\x00":
            raise OSError("SOCKS5 no-auth rejected")

    host_b = host.encode("utf-8")
    sock.sendall(b"\x05\x01\x00\x03" + bytes([len(host_b)]) + host_b + struct.pack("!H", int(port)))
    head = _read_exact(sock, 4)
    if head[1] != 0:
        raise OSError(f"SOCKS5 connect failed: {head[1]}")
    atyp = head[3]
    if atyp == 1:
        _read_exact(sock, 4)
    elif atyp == 3:
        _read_exact(sock, _read_exact(sock, 1)[0])
    elif atyp == 4:
        _read_exact(sock, 16)
    else:
        raise OSError(f"SOCKS5 bad address type: {atyp}")
    _read_exact(sock, 2)
    return sock


def _http_get(url: str, proxy: dict | None = None, timeout: int = 20) -> bytes:
    parsed = urlparse(url)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    if proxy and proxy.get("type") == "socks5":
        raw = _open_socks5(proxy, parsed.hostname, port)
    else:
        raw = socket.create_connection((parsed.hostname, port), timeout=timeout)
    raw.settimeout(timeout)
    if parsed.scheme == "https":
        raw = ssl.create_default_context().wrap_socket(raw, server_hostname=parsed.hostname)
        raw.settimeout(timeout)

    try:
        req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {parsed.hostname}\r\n"
            "User-Agent: Mozilla/5.0\r\n"
            "Referer: https://fast.com/\r\n"
            "Connection: close\r\n\r\n"
        ).encode("utf-8")
        raw.sendall(req)
        data = b""
        while True:
            chunk = raw.recv(65536)
            if not chunk:
                break
            data += chunk
    finally:
        raw.close()

    if b"\r\n\r\n" not in data:
        raise OSError("HTTP response missing headers")
    header, body = data.split(b"\r\n\r\n", 1)
    status = header.split(b"\r\n", 1)[0]
    if b" 200 " not in status:
        raise OSError(status.decode("utf-8", errors="ignore"))
    return body


def _fast_targets(proxy: dict | None = None) -> dict:
    body = _http_get(FAST_API, proxy=proxy, timeout=20)
    return json.loads(body.decode("utf-8"))


def _download_worker(proxy: dict, urls: list[str], deadline: float, totals: dict, idx: int):
    total = 0
    errors = []
    cursor = idx
    while time.time() < deadline:
        url = urls[cursor % len(urls)]
        cursor += 1
        parsed = urlparse(url)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        try:
            raw = _open_socks5(proxy, parsed.hostname, port)
            if parsed.scheme == "https":
                raw = ssl.create_default_context().wrap_socket(raw, server_hostname=parsed.hostname)
            raw.settimeout(20)
            raw.sendall((
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {parsed.hostname}\r\n"
                "User-Agent: Mozilla/5.0\r\n"
                "Connection: close\r\n\r\n"
            ).encode("utf-8"))
            header_done = False
            buf = b""
            while time.time() < deadline:
                chunk = raw.recv(65536)
                if not chunk:
                    break
                if not header_done:
                    buf += chunk
                    pos = buf.find(b"\r\n\r\n")
                    if pos >= 0:
                        header_done = True
                        total += len(buf) - pos - 4
                        buf = b""
                else:
                    total += len(chunk)
            raw.close()
        except Exception as exc:
            errors.append(str(exc))
            time.sleep(0.2)
    totals[idx] = {"bytes": total, "errors": errors[:3]}


def fast_socks5_speed(proxy: dict, duration: int = 15, connections: int = 8) -> dict:
    start_api = time.time()
    meta = _fast_targets(proxy)
    urls = [target["url"] for target in meta.get("targets", []) if target.get("url")]
    if not urls:
        raise OSError("fast.com did not return test targets")

    duration = min(max(int(duration or 15), 5), 30)
    connections = min(max(int(connections or 8), 1), 16)
    deadline = time.time() + duration
    totals = {}
    threads = []
    start = time.time()
    for idx in range(connections):
        thread = threading.Thread(target=_download_worker, args=(proxy, urls, deadline, totals, idx), daemon=True)
        thread.start()
        threads.append(thread)
    for thread in threads:
        thread.join(duration + 5)

    elapsed = max(time.time() - start, 0.001)
    total_bytes = sum(item["bytes"] for item in totals.values())
    errors = [err for item in totals.values() for err in item["errors"]]
    mbps = total_bytes * 8 / elapsed / 1_000_000
    return {
        "ok": total_bytes > 0,
        "mbps": round(mbps, 2),
        "bytes": total_bytes,
        "seconds": round(elapsed, 2),
        "connections": connections,
        "client": meta.get("client") or {},
        "targets": [target.get("location") for target in meta.get("targets", [])],
        "errors": errors[:5],
        "api_ms": round((time.time() - start_api) * 1000, 1),
    }
