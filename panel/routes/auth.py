"""Authentication, admin user, project, and operation log APIs."""
from functools import wraps

from flask import Blueprint, jsonify, redirect, render_template, request, session, url_for

from config import is_lite_mode, is_single_ip_mode
from models import AdminUser, NodeCustomer, OperationLog, Plan, Project, ProxyUser, get_session

bp = Blueprint("auth", __name__)

PERMISSION_ITEMS = [
    {"key": "dashboard", "label": "仪表盘", "path": "/dashboard"},
    {"key": "lines", "label": "线路管理", "path": "/lines"},
    {"key": "nodes", "label": "节点列表", "path": "/nodes"},
    {"key": "group_control", "label": "服务器管理", "path": "/group-control"},
    {"key": "customers", "label": "客户管理", "path": "/customers"},
    {"key": "pve", "label": "HV虚拟机", "path": "/hyperv"},
    {"key": "logs", "label": "操作日志", "path": "/operation-logs"},
    {"key": "settings", "label": "系统设置", "path": "/settings"},
    {"key": "admin_users", "label": "用户管理", "path": "/admin-users"},
]
ALL_PERMISSION_KEYS = [item["key"] for item in PERMISSION_ITEMS]


def _split_permissions(value: str) -> list[str]:
    keys = [x.strip() for x in (value or "").split(",") if x.strip()]
    return [x for x in keys if x in ALL_PERMISSION_KEYS]


def _current_admin():
    uid = session.get("admin_id")
    if not uid:
        return None
    s = get_session()
    try:
        return s.query(AdminUser).get(uid)
    finally:
        s.close()


def current_permissions() -> set[str]:
    admin = _current_admin()
    if not admin:
        return set()
    permissions = getattr(admin, "permissions", None)
    if admin.is_super or permissions is None:
        keys = set(ALL_PERMISSION_KEYS)
    else:
        keys = set(_split_permissions(permissions))
    if is_single_ip_mode():
        keys -= {"lines", "customers", "pve"}
    elif is_lite_mode():
        keys -= {"lines", "customers", "pve"}
    return keys


def has_permission(key: str) -> bool:
    return key in current_permissions()


def permission_required(key: str):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if not session.get("admin_id"):
                if request.path.startswith("/api/"):
                    return jsonify({"ok": False, "error": "未登录"}), 401
                return redirect(url_for("auth.login_page"))
            if not has_permission(key):
                if request.path.startswith("/api/"):
                    return jsonify({"ok": False, "error": "没有权限"}), 403
                return render_template("no_permission.html", admin=session.get("admin_name")), 403
            return f(*args, **kwargs)
        return wrapper
    return decorator


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("admin_id"):
            if request.path.startswith("/api/"):
                return jsonify({"ok": False, "error": "未登录"}), 401
            return redirect(url_for("auth.login_page"))
        return f(*args, **kwargs)

    return wrapper


@bp.route("/login", methods=["GET"])
def login_page():
    if session.get("admin_id"):
        return redirect(url_for("main_dashboard"))
    return render_template("login.html")


@bp.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json(silent=True) or request.form
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    if not username or not password:
        return jsonify({"ok": False, "error": "请输入账号密码"}), 400
    s = get_session()
    try:
        admin = s.query(AdminUser).filter_by(username=username).first()
        if not admin or not admin.check_password(password):
            return jsonify({"ok": False, "error": "账号或密码错误"}), 401
        if not admin.status:
            return jsonify({"ok": False, "error": "账号已停用"}), 403
        session["admin_id"] = admin.id
        session["admin_name"] = admin.username
        return jsonify({"ok": True})
    finally:
        s.close()


@bp.route("/api/logout", methods=["POST"])
def api_logout():
    session.clear()
    return jsonify({"ok": True})


@bp.route("/api/me", methods=["GET"])
@login_required
def api_me():
    return jsonify({"ok": True, "data": {"id": session["admin_id"], "username": session.get("admin_name")}})


@bp.route("/api/password", methods=["POST"])
@login_required
def api_change_password():
    data = request.get_json(silent=True) or {}
    old = data.get("old_password", "")
    new = data.get("new_password", "")
    if len(new) < 6:
        return jsonify({"ok": False, "error": "新密码至少 6 位"}), 400
    s = get_session()
    try:
        admin = s.query(AdminUser).get(session["admin_id"])
        if not admin or not admin.check_password(old):
            return jsonify({"ok": False, "error": "原密码错误"}), 400
        admin.set_password(new)
        s.commit()
        write_operation(session.get("admin_name"), "用户管理", "修改密码", admin.username, request.remote_addr or "")
        return jsonify({"ok": True})
    finally:
        s.close()


def write_operation(operator: str, module: str, action: str, detail: str = "", ip: str = ""):
    s = get_session()
    try:
        s.add(OperationLog(operator=operator or "admin", module=module, action=action, detail=detail, ip=ip))
        s.commit()
    finally:
        s.close()


def current_operator_name() -> str:
    name = (session.get("admin_name") or "").strip()
    if name:
        return name
    return "admin"


@bp.route("/api/admin-users", methods=["GET"])
@login_required
def admin_users():
    s = get_session()
    try:
        rows = s.query(AdminUser).order_by(AdminUser.id.desc()).all()
        return jsonify({"ok": True, "data": [u.to_dict() for u in rows], "permissions": PERMISSION_ITEMS})
    finally:
        s.close()


@bp.route("/api/operator-options", methods=["GET"])
@login_required
def operator_options():
    s = get_session()
    try:
        names = []
        seen = set()
        for user in s.query(AdminUser).filter_by(status=1).order_by(AdminUser.id.asc()).all():
            for value in (user.display_name, user.username):
                name = (value or "").strip()
                if name and name not in seen:
                    seen.add(name)
                    names.append(name)
        current = current_operator_name()
        if current and current not in seen:
            names.insert(0, current)
        return jsonify({"ok": True, "data": names, "current": current})
    finally:
        s.close()


@bp.route("/api/admin-users", methods=["POST"])
@login_required
def create_admin_user():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    display_name = (data.get("display_name") or username).strip()
    role = (data.get("role") or "普通用户").strip()
    permissions = ",".join(_split_permissions(data.get("permissions") or ""))
    if not username or len(password) < 6:
        return jsonify({"ok": False, "error": "用户名必填，密码至少 6 位"}), 400
    if role not in ("普通管理员", "普通用户"):
        return jsonify({"ok": False, "error": "角色只能是普通管理员或普通用户"}), 400
    s = get_session()
    try:
        if s.query(AdminUser).filter_by(username=username).first():
            return jsonify({"ok": False, "error": "用户名已存在"}), 400
        user = AdminUser(username=username, display_name=display_name, role=role, permissions=permissions, is_super=0, status=1)
        user.set_password(password)
        s.add(user)
        s.commit()
        write_operation(session.get("admin_name"), "用户管理", "新增用户", username, request.remote_addr or "")
        return jsonify({"ok": True, "data": user.to_dict()})
    finally:
        s.close()


@bp.route("/api/admin-users/<int:uid>", methods=["PUT"])
@login_required
def update_admin_user(uid):
    data = request.get_json(silent=True) or {}
    display_name = (data.get("display_name") or "").strip()
    role = (data.get("role") or "普通用户").strip()
    password = data.get("password") or ""
    permissions = ",".join(_split_permissions(data.get("permissions") or ""))
    if role not in ("普通管理员", "普通用户"):
        return jsonify({"ok": False, "error": "角色只能是普通管理员或普通用户"}), 400
    s = get_session()
    try:
        user = s.query(AdminUser).get(uid)
        if not user:
            return jsonify({"ok": False, "error": "用户不存在"}), 404
        if user.is_super:
            return jsonify({"ok": False, "error": "超级管理员不能修改"}), 400
        user.display_name = display_name or user.username
        user.role = role
        user.permissions = permissions
        if password:
            if len(password) < 6:
                return jsonify({"ok": False, "error": "密码至少 6 位"}), 400
            user.set_password(password)
        s.commit()
        write_operation(session.get("admin_name"), "用户管理", "修改用户", user.username, request.remote_addr or "")
        return jsonify({"ok": True, "data": user.to_dict()})
    finally:
        s.close()


@bp.route("/api/permissions", methods=["GET"])
@login_required
def permissions_info():
    return jsonify({"ok": True, "data": {"items": PERMISSION_ITEMS, "current": list(current_permissions())}})


@bp.route("/api/admin-users/<int:uid>/toggle", methods=["POST"])
@login_required
def toggle_admin_user(uid):
    s = get_session()
    try:
        user = s.query(AdminUser).get(uid)
        if not user:
            return jsonify({"ok": False, "error": "用户不存在"}), 404
        if user.is_super:
            return jsonify({"ok": False, "error": "超级管理员不能停用"}), 400
        user.status = 0 if user.status else 1
        s.commit()
        write_operation(session.get("admin_name"), "用户管理", "切换状态", user.username, request.remote_addr or "")
        return jsonify({"ok": True, "data": user.to_dict()})
    finally:
        s.close()


@bp.route("/api/admin-users/<int:uid>", methods=["DELETE"])
@login_required
def delete_admin_user(uid):
    s = get_session()
    try:
        user = s.query(AdminUser).get(uid)
        if not user:
            return jsonify({"ok": False, "error": "用户不存在"}), 404
        if user.is_super:
            return jsonify({"ok": False, "error": "超级管理员不能删除"}), 400
        name = user.username
        s.delete(user)
        s.commit()
        write_operation(session.get("admin_name"), "用户管理", "删除用户", name, request.remote_addr or "")
        return jsonify({"ok": True})
    finally:
        s.close()


@bp.route("/api/projects", methods=["GET"])
@login_required
def projects():
    s = get_session()
    try:
        rows = s.query(Project).order_by(Project.id.desc()).all()
        return jsonify({"ok": True, "data": [p.to_dict() for p in rows]})
    finally:
        s.close()


@bp.route("/api/projects", methods=["POST"])
@login_required
def create_project():
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    note = (data.get("note") or "").strip()
    if not name:
        return jsonify({"ok": False, "error": "项目名称必填"}), 400
    s = get_session()
    try:
        project = Project(name=name, note=note, status=1)
        s.add(project)
        s.commit()
        write_operation(session.get("admin_name"), "项目管理", "新增项目", name, request.remote_addr or "")
        return jsonify({"ok": True, "data": project.to_dict()})
    finally:
        s.close()


@bp.route("/api/projects/<int:pid>", methods=["PUT"])
@login_required
def update_project(pid):
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    note = (data.get("note") or "").strip()
    if not name:
        return jsonify({"ok": False, "error": "项目名称必填"}), 400
    s = get_session()
    try:
        project = s.query(Project).get(pid)
        if not project:
            return jsonify({"ok": False, "error": "项目不存在"}), 404
        project.name = name
        project.note = note
        s.commit()
        write_operation(session.get("admin_name"), "项目管理", "修改项目", name, request.remote_addr or "")
        return jsonify({"ok": True, "data": project.to_dict()})
    finally:
        s.close()


@bp.route("/api/projects/<int:pid>", methods=["DELETE"])
@login_required
def delete_project(pid):
    s = get_session()
    try:
        project = s.query(Project).get(pid)
        if not project:
            return jsonify({"ok": False, "error": "项目不存在"}), 404
        name = project.name
        s.delete(project)
        s.commit()
        write_operation(session.get("admin_name"), "项目管理", "删除项目", name, request.remote_addr or "")
        return jsonify({"ok": True})
    finally:
        s.close()


@bp.route("/api/projects/<int:pid>/toggle", methods=["POST"])
@login_required
def toggle_project(pid):
    s = get_session()
    try:
        project = s.query(Project).get(pid)
        if not project:
            return jsonify({"ok": False, "error": "项目不存在"}), 404
        project.status = 0 if project.status else 1
        s.commit()
        write_operation(session.get("admin_name"), "项目管理", "切换状态", project.name, request.remote_addr or "")
        return jsonify({"ok": True, "data": project.to_dict()})
    finally:
        s.close()


def _save_named_row(model, module_name, create_action, update_action, row_id=None):
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or data.get("username") or "").strip()
    note = (data.get("note") or "").strip()
    if not name:
        return jsonify({"ok": False, "error": "名称必填"}), 400
    s = get_session()
    try:
        row = s.query(model).get(row_id) if row_id else None
        if row_id and not row:
            return jsonify({"ok": False, "error": "数据不存在"}), 404
        duplicate = s.query(model).filter(model.name == name)
        if row_id:
            duplicate = duplicate.filter(model.id != row_id)
        if duplicate.first():
            return jsonify({"ok": False, "error": "名称已存在"}), 400
        if row is None:
            row = model(name=name, note=note, status=1)
            s.add(row)
            action = create_action
        else:
            row.name = name
            row.note = note
            action = update_action
        s.commit()
        write_operation(session.get("admin_name"), module_name, action, name, request.remote_addr or "")
        return jsonify({"ok": True, "data": row.to_dict()})
    finally:
        s.close()


@bp.route("/api/node-customers", methods=["GET"])
@login_required
def node_customers():
    s = get_session()
    try:
        existing = {name for (name,) in s.query(NodeCustomer.name).all()}
        derived = {}
        for user in s.query(ProxyUser).all():
            name = (user.owner_name or user.username or "").strip()
            if not name or name in existing or name in derived:
                continue
            derived[name] = user.created_at
        for name, created_at in derived.items():
            s.add(NodeCustomer(name=name, note="", status=1, created_at=created_at))
        if derived:
            s.commit()
        rows = s.query(NodeCustomer).order_by(NodeCustomer.id.desc()).all()
        return jsonify({"ok": True, "data": [r.to_dict() for r in rows]})
    finally:
        s.close()


@bp.route("/api/node-customers", methods=["POST"])
@login_required
def create_node_customer():
    return _save_named_row(NodeCustomer, "客户管理", "新增客户", "修改客户")


@bp.route("/api/node-customers/<int:cid>", methods=["PUT"])
@login_required
def update_node_customer(cid):
    return _save_named_row(NodeCustomer, "客户管理", "新增客户", "修改客户", cid)


@bp.route("/api/node-customers/<int:cid>", methods=["DELETE"])
@login_required
def delete_node_customer(cid):
    s = get_session()
    try:
        row = s.query(NodeCustomer).get(cid)
        if not row:
            return jsonify({"ok": False, "error": "客户不存在"}), 404
        name = row.name
        s.delete(row)
        s.commit()
        write_operation(session.get("admin_name"), "客户管理", "删除客户", name, request.remote_addr or "")
        return jsonify({"ok": True})
    finally:
        s.close()


@bp.route("/api/plans", methods=["GET"])
@login_required
def plans():
    s = get_session()
    try:
        rows = s.query(Plan).order_by(Plan.id.desc()).all()
        return jsonify({"ok": True, "data": [r.to_dict() for r in rows]})
    finally:
        s.close()


def _save_plan(plan_id=None):
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    bandwidth = (data.get("bandwidth") or "").strip()
    traffic = (data.get("traffic") or "").strip()
    note = (data.get("note") or "").strip()
    try:
        days = max(1, int(data.get("days") or 30))
    except Exception:
        days = 30
    if not name:
        return jsonify({"ok": False, "error": "套餐名称必填"}), 400
    s = get_session()
    try:
        plan = s.query(Plan).get(plan_id) if plan_id else None
        if plan_id and not plan:
            return jsonify({"ok": False, "error": "套餐不存在"}), 404
        duplicate = s.query(Plan).filter(Plan.name == name)
        if plan_id:
            duplicate = duplicate.filter(Plan.id != plan_id)
        if duplicate.first():
            return jsonify({"ok": False, "error": "套餐名称已存在"}), 400
        if plan is None:
            plan = Plan(name=name, status=1)
            s.add(plan)
            action = "新增套餐"
        else:
            action = "修改套餐"
        plan.name = name
        plan.bandwidth = bandwidth
        plan.traffic = traffic
        plan.days = days
        plan.note = note
        s.commit()
        write_operation(session.get("admin_name"), "套餐管理", action, name, request.remote_addr or "")
        return jsonify({"ok": True, "data": plan.to_dict()})
    finally:
        s.close()


@bp.route("/api/plans", methods=["POST"])
@login_required
def create_plan():
    return _save_plan()


@bp.route("/api/plans/<int:pid>", methods=["PUT"])
@login_required
def update_plan(pid):
    return _save_plan(pid)


@bp.route("/api/plans/<int:pid>", methods=["DELETE"])
@login_required
def delete_plan(pid):
    s = get_session()
    try:
        plan = s.query(Plan).get(pid)
        if not plan:
            return jsonify({"ok": False, "error": "套餐不存在"}), 404
        name = plan.name
        s.delete(plan)
        s.commit()
        write_operation(session.get("admin_name"), "套餐管理", "删除套餐", name, request.remote_addr or "")
        return jsonify({"ok": True})
    finally:
        s.close()


@bp.route("/api/operation-logs", methods=["GET"])
@login_required
def operation_logs():
    s = get_session()
    try:
        rows = s.query(OperationLog).order_by(OperationLog.id.desc()).limit(300).all()
        return jsonify({"ok": True, "data": [row.to_dict() for row in rows]})
    finally:
        s.close()
