"""Human-readable operation log formatting."""
from __future__ import annotations

import ast
import re


MODULE_LABELS = {
    "sing-box-per-line": "sing-box 单线路",
    "runtime-protection": "运行防护",
    "sing-box-watchdog": "sing-box 看护",
}

ACTION_LABELS = {
    "line-listener-sync-restart": "线路监听修复",
    "line-ensure-failed": "线路检查失败",
    "line-stop-empty": "空线路停止",
    "socket-pressure-alert": "socket 资源告警",
    "socket-pressure-line-restart": "socket 超限重启线路",
    "socket-pressure-restart-failed": "socket 超限处理失败",
}

REASON_LABELS = {
    "safe-per-line-keeper": "后台巡检发现线路监听异常",
    "socket-pressure-protection": "socket 资源保护",
    "line_udp_endpoint_limit": "单线路 UDP socket 超限",
    "line_tcp_endpoint_limit": "单线路 TCP socket 超限",
    "system_socket_force_limit": "系统 socket 总数达到强制保护线",
    "system_socket_alert": "系统 socket 总数达到告警线",
    "user-inbound-change": "用户入站配置变更",
    "per-line-health": "单线路健康检查",
    "ensure-active-lines": "启动活跃线路",
    "ensure-missing-lines": "补拉缺失线路",
}

FIELD_LABELS = {
    "reason": "原因",
    "action": "处理",
    "line_id": "线路ID",
    "ip": "公网IP",
    "label": "线路",
    "pid": "进程PID",
    "before_pid": "处理前PID",
    "after_pid": "处理后PID",
    "hot_ok": "热加载是否成功",
    "missing_before": "处理前缺少监听端口",
    "missing_after": "处理后仍缺少监听端口",
    "orphan_before": "处理前多余监听端口",
    "orphan_after": "处理后多余监听端口",
    "udp": "UDP socket 数",
    "tcp": "TCP socket 数",
    "tcp_established": "TCP已建立连接",
    "total_udp": "系统UDP socket总数",
    "total_tcp": "系统TCP socket总数",
    "total_sockets": "系统socket总数",
    "tcp_total": "系统TCP总数",
    "udp_total": "系统UDP总数",
    "alert_limit": "告警阈值",
    "force_limit": "强制保护阈值",
    "system_force_limit": "系统强制保护阈值",
    "per_line_udp_limit": "单线路UDP阈值",
    "per_line_tcp_limit": "单线路TCP阈值",
    "cooldown": "冷却时间",
    "top_line": "占用最高线路ID",
    "top_label": "占用最高线路",
    "top_pid": "占用最高PID",
    "top_udp": "占用最高UDP数",
    "top_tcp": "占用最高TCP数",
    "error": "错误",
    "result": "执行结果",
}

VALUE_LABELS = {
    "restart_single_line": "只重启这一条线路",
    "True": "是",
    "False": "否",
    "None": "无",
}


def _parse_pairs(detail: str) -> list[tuple[str, str]]:
    pairs = []
    for part in re.split(r";\s*", detail or ""):
        part = part.strip()
        if not part or "=" not in part:
            continue
        key, value = part.split("=", 1)
        pairs.append((key.strip(), value.strip()))
    return pairs


def _format_value(value: str) -> str:
    value = str(value or "").strip()
    if value in VALUE_LABELS:
        return VALUE_LABELS[value]
    if value in REASON_LABELS:
        return REASON_LABELS[value]
    if value.startswith("[") and value.endswith("]"):
        try:
            items = ast.literal_eval(value)
            if isinstance(items, list):
                return "无" if not items else "、".join(str(item) for item in items)
        except Exception:
            pass
    if value.startswith("{") and value.endswith("}"):
        return "已记录执行结果"
    return value or "-"


def format_operation_log(row: dict) -> dict:
    module = str(row.get("module") or "-")
    action = str(row.get("action") or "-")
    detail = str(row.get("detail") or "")
    pairs = _parse_pairs(detail)
    if pairs:
        lines = []
        for key, value in pairs:
            label = FIELD_LABELS.get(key, key)
            lines.append(f"{label}：{_format_value(value)}")
        detail = "\n".join(lines)
    return {
        **row,
        "module": MODULE_LABELS.get(module, module),
        "action": ACTION_LABELS.get(action, action),
        "detail": detail or "-",
    }
