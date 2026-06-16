"""
系统信息读取模块
- 公网IP（通过多个 API 自动探测）
- 内网IP（读取本机所有网卡）
- MAC地址
- IP归属地
- 当前连接数（SOCKS5/HTTP/SS 各端口）
"""
import os
import re
import socket
import urllib.request
import urllib.error
import json
import threading
import time
import psutil
from pathlib import Path
from datetime import datetime

sys_path = Path(__file__).resolve().parent.parent
import sys
sys.path.insert(0, str(sys_path))
from config import DEFAULT_SOCKS_PORTS


# ---- 公网IP探测 ----

def _fetch_url(url: str, timeout: int = 5) -> str | None:
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            text = resp.read().decode("utf-8", errors="ignore").strip()
            return text
    except Exception:
        return None


def get_public_ip() -> dict:
    """
    探测公网出口 IP，尝试多个服务
    返回: {"ip": "...", "source": "...", "timestamp": "..."}
    """
    sources = [
        ("https://api.ipify.org?format=json",     r'\{"ip"\s*:\s*"([^"]+)"\}'),
        ("https://ipinfo.io/json",                 r'"ip"\s*:\s*"([^"]+)"'),
        ("https://ifconfig.me/ip",                 None),
        ("https://checkip.amazonaws.com",          None),
    ]
    for url, _ in sources:
        text = _fetch_url(url, timeout=5)
        if text:
            # 有些返回纯IP，有些返回JSON
            # 去掉 JSON 包装
            ip = re.search(r'"ip"\s*:\s*"([^"]+)"', text)
            if ip:
                ip = ip.group(1)
            else:
                ip = text.strip()
            if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
                return {
                    "ip": ip,
                    "source": url.split("/")[2],
                    "timestamp": datetime.now().isoformat(timespec="seconds"),
                }
    return {
        "ip": None,
        "source": None,
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "error": "所有公网IP探测服务均失败",
    }


# ---- IP归属地查询 ----

def get_ip_region(ip: str) -> dict:
    """
    查询 IP 归属地（国家/省份/城市/ISP）
    免费服务: ip-api.com (45次/分钟限制)
    """
    if not ip:
        return {}
    url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,isp,org,as,query"
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="ignore"))
            if data.get("status") == "success":
                return {
                    "country": data.get("country", ""),
                    "country_code": data.get("countryCode", ""),
                    "region": data.get("regionName", ""),
                    "city": data.get("city", ""),
                    "isp": data.get("isp", ""),
                    "org": data.get("org", ""),
                    "as": data.get("as", ""),
                    "query_ip": data.get("query", ip),
                }
    except Exception as e:
        return {"error": str(e)}
    return {"error": "查询失败或IP无效"}


# ---- 内网IP & MAC ----

def get_internal_ips() -> list:
    """
    读取本机所有 IPv4 网卡信息
    返回: [{"interface": "...", "ip": "...", "mac": "...", "netmask": "..."}]
    """
    results = []
    try:
        for iface, addrs in psutil.net_if_addrs().items():
            ip_val = mac_val = netmask = None
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    ip_val = addr.address
                    netmask = addr.netmask
                elif addr.family == psutil.AF_LINK:
                    mac_val = addr.address
            if ip_val and ip_val != "127.0.0.1":
                results.append({
                    "interface": iface,
                    "ip": ip_val,
                    "mac": mac_val or "",
                    "netmask": netmask or "",
                })
    except Exception as e:
        print(f"[system_info] get_internal_ips error: {e}")
    return results


def get_mac_by_ip(target_ip: str) -> str | None:
    """根据 IP 返回对应网卡的 MAC 地址"""
    try:
        for iface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET and addr.address == target_ip:
                    for addr2 in addrs:
                        if addr2.family == psutil.AF_LINK:
                            return addr2.address
    except Exception:
        pass
    return None


# ---- 连接数统计 ----

def get_port_connections(port: int) -> dict:
    """
    返回某个端口的当前连接数
    遍历所有进程的 TCP 连接
    """
    inbound = 0
    outbound = 0
    local_ip = "0.0.0.0"
    try:
        for conn in psutil.net_connections(kind="inet"):
            if conn.laddr.port == port:
                if conn.raddr:
                    outbound += 1
                else:
                    inbound += 1
    except Exception as e:
        print(f"[system_info] get_port_connections error: {e}")
    return {"port": port, "inbound": inbound, "outbound": outbound}


def get_all_proxy_connections() -> list:
    """
    返回 DEFAULT_SOCKS_PORTS 中所有端口的连接数
    """
    results = []
    for port in DEFAULT_SOCKS_PORTS:
        results.append(get_port_connections(port))
    return results


# ---- 综合系统信息 ----

def get_system_info(cached: bool = True, cache_ttl: int = 30) -> dict:
    """
    返回完整系统信息（公网IP + 内网IP + MAC + 归属地 + 连接数）
    缓存 30 秒，避免频繁请求外部 API
    """
    if cached and hasattr(get_system_info, "_cache"):
        cache = get_system_info._cache
        if time.time() - cache["ts"] < cache_ttl:
            return cache["data"]

    # 公网IP
    public_ip_data = get_public_ip()

    # 归属地
    region_data = get_ip_region(public_ip_data.get("ip"))

    # 内网IP
    internal_ips = get_internal_ips()

    # 连接数
    connections = get_all_proxy_connections()

    total_connections = sum(c["inbound"] + c["outbound"] for c in connections)

    result = {
        "public_ip": public_ip_data,
        "region": region_data,
        "internal_ips": internal_ips,
        "connections": {
            "total": total_connections,
            "per_port": connections,
        },
        "server_time": datetime.now().isoformat(timespec="seconds"),
    }

    get_system_info._cache = {"ts": time.time(), "data": result}
    return result


def clear_cache():
    """清除缓存，下次调用重新探测"""
    if hasattr(get_system_info, "_cache"):
        del get_system_info._cache


if __name__ == "__main__":
    import pprint
    pprint.pprint(get_system_info())
