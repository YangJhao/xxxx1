"""Hyper-V management APIs."""
from flask import Blueprint, jsonify, request, session

from routes.auth import login_required, write_operation
from services import hyperv_manager

bp = Blueprint("hyperv", __name__, url_prefix="/api/hyperv")


@bp.route("/summary", methods=["GET"])
@login_required
def summary():
    try:
        return jsonify({"ok": True, "data": hyperv_manager.host_summary()})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


@bp.route("/vms", methods=["GET"])
@login_required
def vms():
    try:
        return jsonify({"ok": True, "data": hyperv_manager.list_vms()})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


@bp.route("/switches", methods=["GET"])
@login_required
def switches():
    try:
        return jsonify({"ok": True, "data": hyperv_manager.list_switches()})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


@bp.route("/images", methods=["GET"])
@login_required
def images():
    try:
        return jsonify({"ok": True, "data": hyperv_manager.list_images()})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


@bp.route("/images/import", methods=["POST"])
@login_required
def import_image():
    try:
        data = request.get_json(silent=True) or {}
        result = hyperv_manager.import_image(data.get("path") or "")
        write_operation(
            session.get("admin_name") or "admin",
            "Hyper-V",
            "import_image",
            data.get("path") or "",
            request.remote_addr or "",
        )
        return jsonify({"ok": True, "data": result})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


@bp.route("/vms/<path:name>/<action>", methods=["POST"])
@login_required
def action_vm(name, action):
    try:
        data = hyperv_manager.vm_action(name, action)
        write_operation(
            session.get("admin_name") or "admin",
            "Hyper-V",
            action,
            name,
            request.remote_addr or "",
        )
        return jsonify({"ok": True, "data": data})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


@bp.route("/vms/<path:name>/config", methods=["GET"])
@login_required
def vm_config(name):
    try:
        return jsonify({"ok": True, "data": hyperv_manager.get_vm_config(name)})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


@bp.route("/vms/<path:name>/config", methods=["POST"])
@login_required
def update_vm_config(name):
    try:
        data = request.get_json(silent=True) or {}
        result = hyperv_manager.update_vm_config(name, data)
        write_operation(
            session.get("admin_name") or "admin",
            "Hyper-V",
            "update_config",
            name,
            request.remote_addr or "",
        )
        return jsonify({"ok": True, "data": result})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


@bp.route("/batch/<action>", methods=["POST"])
@login_required
def batch_action(action):
    try:
        data = request.get_json(silent=True) or {}
        names = data.get("names") or []
        result = hyperv_manager.batch_action(names, action)
        write_operation(
            session.get("admin_name") or "admin",
            "Hyper-V",
            f"batch_{action}",
            ",".join(names),
            request.remote_addr or "",
        )
        return jsonify({"ok": True, "data": result})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


@bp.route("/batch-create", methods=["POST"])
@login_required
def batch_create():
    try:
        data = request.get_json(silent=True) or {}
        result = hyperv_manager.batch_create_vms(data)
        write_operation(
            session.get("admin_name") or "admin",
            "Hyper-V",
            "batch_create",
            f"{data.get('prefix') or 'hy'} x {data.get('count') or 0}",
            request.remote_addr or "",
        )
        return jsonify({"ok": True, "data": result})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500
