"""Operation log helpers shared by routes and background protection tasks."""
from __future__ import annotations

from models import OperationLog, get_session


def add_operation_log(
    session,
    operator: str,
    module: str,
    action: str,
    detail: str = "",
    ip: str = "",
) -> OperationLog:
    row = OperationLog(
        operator=operator or "system",
        module=module or "",
        action=action or "",
        detail=detail or "",
        ip=ip or "",
    )
    session.add(row)
    return row


def write_operation_log(
    operator: str,
    module: str,
    action: str,
    detail: str = "",
    ip: str = "",
) -> None:
    session = get_session()
    try:
        add_operation_log(session, operator, module, action, detail, ip)
        session.commit()
    finally:
        session.close()
