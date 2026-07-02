"""
全局配置
- 所有路径都基于 BASE_DIR
- 修改这里即可调整端口、密码、目录等
"""
import json
import os
import platform
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent                      # .../panel
PROJECT_DIR = BASE_DIR.parent                                      # .../42IPwin
APP_VERSION = "1.0.0.5"
IS_WINDOWS = platform.system().lower() == "windows"

# ===== 目录 =====
PROXY_BIN = str(PROJECT_DIR / "3proxy")
PROXY_EXE = str(PROJECT_DIR / "3proxy" / "3proxy.exe")
PROXY_CFG = str(PROJECT_DIR / "3proxy" / "3proxy.cfg")
PROXY_PID = str(PROJECT_DIR / "3proxy" / "3proxy.pid")
PROXY_LOG_DIR = str(PROJECT_DIR / "3proxy" / "logs")
SING_BOX_BIN = str(PROJECT_DIR / "sing-box")
SING_BOX_EXE = str(PROJECT_DIR / "sing-box" / ("sing-box.exe" if IS_WINDOWS else "sing-box"))
SING_BOX_CFG = str(PROJECT_DIR / "sing-box" / "config.json")
SING_BOX_PID = str(PROJECT_DIR / "sing-box" / "sing-box.pid")
SING_BOX_LOG = str(PROJECT_DIR / "sing-box" / "sing-box.log")
SING_BOX_CERT = str(PROJECT_DIR / "sing-box" / "cert.pem")
SING_BOX_KEY = str(PROJECT_DIR / "sing-box" / "key.pem")
COUNTER_DIR = str(PROJECT_DIR / "data" / "counters")
DATA_DIR = str(PROJECT_DIR / "data")
WIREGUARD_DIR = str(PROJECT_DIR / "data" / "wireguard")

PANEL_CFG_FILE = os.path.join(DATA_DIR, "panel_cfg.json")

# ===== 后台管理 =====
PANEL_HOST = "0.0.0.0"
PANEL_PORT = int(os.environ.get("IPWIN42_PANEL_PORT", "8080"))
PANEL_SECRET_KEY = "CHANGE-ME-PLEASE-IN-PROD-xxxxxxxxxxxxxxxxxx"

# ===== 默认 SOCKS5 端口分配 =====
DEFAULT_SOCKS_PORTS = [10801, 10802, 10803]

# ===== 日志 =====
LOG_LEVEL = "INFO"


def is_lite_mode() -> bool:
    return os.environ.get("IPWIN42_LITE") == "1" or os.environ.get("42IPWIN_LITE") == "1"


# ---- Panel 运行配置（持久化）----

def _load_panel_cfg() -> dict:
    """从 JSON 文件加载面板配置"""
    if not os.path.exists(PANEL_CFG_FILE):
        return {}
    try:
        with open(PANEL_CFG_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _save_panel_cfg(cfg: dict):
    """保存面板配置到 JSON 文件"""
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(PANEL_CFG_FILE, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)


def get_panel_bind_ip() -> str:
    """获取面板绑定的监听 IP"""
    return _load_panel_cfg().get("bind_ip", "0.0.0.0")


def set_panel_bind_ip(ip: str) -> str:
    """设置面板绑定的监听 IP 并写入 config"""
    cfg = _load_panel_cfg()
    cfg["bind_ip"] = ip
    _save_panel_cfg(cfg)
    return ip
