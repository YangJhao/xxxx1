"""Basic Proxmox VE management wrapper."""
import json
import os
import socket
import subprocess


def _run(args: list[str], timeout: int = 20) -> str:
    completed = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if completed.returncode != 0:
        raise RuntimeError((completed.stderr or completed.stdout or "").strip() or f"{args[0]} exited with {completed.returncode}")
    return completed.stdout.strip()


def _qm_available() -> bool:
    return os.name != "nt" and subprocess.run(["sh", "-c", "command -v qm"], capture_output=True, text=True).returncode == 0


def _require_pve():
    if not _qm_available():
        raise RuntimeError("PVE 模块需要运行在 Proxmox VE 主机，并且系统可用 qm 命令。")


def environment_status() -> dict:
    available = _qm_available()
    return {
        "available": available,
        "host": socket.gethostname(),
        "message": "" if available else "当前服务器不是 Proxmox VE 主机，或系统没有 qm 命令。PVE 模块需要安装在 PVE 宿主机上。",
    }


def host_summary() -> dict:
    status = environment_status()
    if not status["available"]:
        return {
            "available": False,
            "computer_name": status["host"],
            "total": 0,
            "running": 0,
            "message": status["message"],
        }
    rows = list_vms()
    return {
        "available": True,
        "computer_name": socket.gethostname(),
        "total": len(rows),
        "running": len([x for x in rows if str(x.get("state", "")).lower() == "running"]),
    }


def list_vms() -> list[dict]:
    if not _qm_available():
        return []
    raw = _run(["qm", "list"])
    rows = []
    for line in raw.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 3:
            continue
        vmid, name, status = parts[0], parts[1], parts[2]
        mem_mb = int(parts[3]) if len(parts) > 3 and parts[3].isdigit() else 0
        disk_gb = parts[4] if len(parts) > 4 else "0"
        rows.append({
            "vmid": vmid,
            "name": name,
            "state": "Running" if status.lower() == "running" else "Off",
            "public_ip": "",
            "internal_ip": "",
            "processor_count": 0,
            "memory_assigned": mem_mb * 1024 * 1024,
            "memory_startup": mem_mb * 1024 * 1024,
            "disk": disk_gb,
        })
    return rows


def _vmid(name_or_id: str) -> str:
    text = str(name_or_id or "").strip()
    if text.isdigit():
        return text
    for vm in list_vms():
        if vm.get("name") == text:
            return str(vm["vmid"])
    raise RuntimeError(f"未找到 PVE 虚拟机: {name_or_id}")


def vm_action(name_or_id: str, action: str) -> dict:
    _require_pve()
    vmid = _vmid(name_or_id)
    mapping = {
        "start": ["qm", "start", vmid],
        "shutdown": ["qm", "shutdown", vmid],
        "turnoff": ["qm", "stop", vmid],
        "restart": ["qm", "reboot", vmid],
        "reset": ["qm", "reset", vmid],
    }
    if action not in mapping:
        raise RuntimeError(f"不支持的 PVE 操作: {action}")
    output = _run(mapping[action], timeout=60)
    return {"name": name_or_id, "vmid": vmid, "action": action, "output": output}


def batch_action(names: list[str], action: str) -> list[dict]:
    result = []
    for name in names:
        try:
            data = vm_action(name, action)
            result.append({"name": name, "ok": True, **data})
        except Exception as exc:
            result.append({"name": name, "ok": False, "error": str(exc)})
    return result


def get_vm_config(name_or_id: str) -> dict:
    _require_pve()
    vmid = _vmid(name_or_id)
    raw = _run(["qm", "config", vmid])
    data = {"name": name_or_id, "vmid": vmid}
    for line in raw.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        data[key.strip()] = value.strip()
    memory_mb = int(data.get("memory") or 0)
    return {
        "name": data.get("name") or name_or_id,
        "vmid": vmid,
        "processor_count": int(data.get("cores") or data.get("sockets") or 1),
        "memory_startup_mb": memory_mb,
        "dynamic_memory_enabled": False,
        "memory_minimum_mb": memory_mb,
        "memory_maximum_mb": memory_mb,
        "automatic_start_action": "Start" if data.get("onboot") == "1" else "Nothing",
        "automatic_stop_action": "Shutdown",
        "notes": data.get("description") or "",
    }


def update_vm_config(name_or_id: str, data: dict) -> dict:
    _require_pve()
    vmid = _vmid(name_or_id)
    args = ["qm", "set", vmid]
    if data.get("processor_count"):
        args += ["--cores", str(int(data["processor_count"]))]
    if data.get("memory_startup_mb"):
        args += ["--memory", str(int(data["memory_startup_mb"]))]
    if data.get("automatic_start_action"):
        args += ["--onboot", "1" if data["automatic_start_action"] == "Start" else "0"]
    if data.get("notes"):
        args += ["--description", str(data["notes"])]
    output = _run(args, timeout=60)
    return {"name": name_or_id, "vmid": vmid, "output": output}


def list_switches() -> list[dict]:
    if os.name == "nt":
        return []
    try:
        raw = _run(["sh", "-c", "ip -j link show type bridge"], timeout=8)
        rows = json.loads(raw or "[]")
        return [{"name": item.get("ifname"), "switch_type": "Linux Bridge"} for item in rows if item.get("ifname")]
    except Exception:
        return []


def list_images() -> list[dict]:
    return []


def import_image(path: str) -> dict:
    raise RuntimeError("PVE 镜像导入请先把 ISO/QCOW2 上传到 PVE storage；后续可接入 pvesh/API 自动导入。")


def batch_create_vms(data: dict) -> list[dict]:
    raise RuntimeError("PVE 批量创建需要指定模板 VMID/storage/bridge，当前版本先支持读取和启停控制。")
