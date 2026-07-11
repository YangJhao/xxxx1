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


@bp.route("/switches/vm-lan/ensure", methods=["POST"])
@login_required
def ensure_vm_lan_switch():
    try:
        data = request.get_json(silent=True) or {}
        result = hyperv_manager.ensure_vm_lan_switch(
            data.get("name") or "VM-LAN",
            data.get("ip") or "192.168.9.1",
            int(data.get("prefix") or 24),
        )
        write_operation(
            session.get("admin_name") or "admin",
            "Hyper-V",
            "ensure_vm_lan_switch",
            f"{result.get('switch_name')} {result.get('ip')}/{result.get('prefix')}",
            request.remote_addr or "",
        )
        return jsonify({"ok": True, "data": result})
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


@bp.route("/ikuai/install", methods=["POST"])
@login_required
def install_ikuai():
    try:
        data = request.get_json(silent=True) or {}
        result = hyperv_manager.install_ikuai_vm(data)
        write_operation(
            session.get("admin_name") or "admin",
            "Hyper-V",
            "install_ikuai",
            result.get("name") or data.get("name") or "iKuai",
            request.remote_addr or "",
        )
        return jsonify({"ok": True, "data": result})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


@bp.route("/images/debian-cloud/prepare", methods=["POST"])
@login_required
def prepare_debian_cloud_image():
    try:
        data = request.get_json(silent=True) or {}
        result = hyperv_manager.prepare_debian_cloud_image(bool(data.get("force")))
        write_operation(
            session.get("admin_name") or "admin",
            "Hyper-V",
            "prepare_debian_cloud_image",
            result.get("image") or "",
            request.remote_addr or "",
        )
        return jsonify({"ok": True, "data": result})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


@bp.route("/images/debian-cloud/prepare/start", methods=["POST"])
@login_required
def start_prepare_debian_cloud_image():
    try:
        data = request.get_json(silent=True) or {}
        result = hyperv_manager.start_prepare_debian_cloud_image(bool(data.get("force")))
        write_operation(
            session.get("admin_name") or "admin",
            "Hyper-V",
            "start_prepare_debian_cloud_image",
            result.get("job_id") or "",
            request.remote_addr or "",
        )
        return jsonify({"ok": True, "data": result})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


@bp.route("/images/debian-cloud/prepare/status/<job_id>", methods=["GET"])
@login_required
def debian_cloud_image_job_status(job_id):
    try:
        return jsonify({"ok": True, "data": hyperv_manager.image_job_status(job_id)})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


@bp.route("/clear-all", methods=["POST"])
@login_required
def clear_all_vms():
    try:
        result = hyperv_manager.clear_all_vms()
        write_operation(
            session.get("admin_name") or "admin",
            "Hyper-V",
            "clear_all_vms",
            str(result.get("deleted_count") or 0),
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


@bp.route("/vms/<path:name>/configure-public-ip", methods=["POST"])
@login_required
def configure_public_ip(name):
    try:
        result = hyperv_manager.configure_public_ip_mapping(name)
        write_operation(
            session.get("admin_name") or "admin",
            "Hyper-V",
            "configure_public_ip",
            name,
            request.remote_addr or "",
        )
        return jsonify({"ok": True, "data": result})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


@bp.route("/vms/<path:name>/update-mapping", methods=["POST"])
@login_required
def update_vm_mapping(name):
    try:
        result = hyperv_manager.refresh_public_ip_mapping(name)
        write_operation(
            session.get("admin_name") or "admin",
            "Hyper-V",
            "update_mapping",
            name,
            request.remote_addr or "",
        )
        return jsonify({"ok": True, "data": result})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


@bp.route("/batch/configure-public-ip", methods=["POST"])
@login_required
def batch_configure_public_ip():
    try:
        data = request.get_json(silent=True) or {}
        names = data.get("names") or []
        result = hyperv_manager.batch_action(names, "configure_public_ip")
        write_operation(
            session.get("admin_name") or "admin",
            "Hyper-V",
            "batch_configure_public_ip",
            ",".join(names),
            request.remote_addr or "",
        )
        return jsonify({"ok": True, "data": result})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


@bp.route("/vms/<path:name>/configure-ssh", methods=["POST"])
@login_required
def configure_ssh(name):
    try:
        result = hyperv_manager.configure_ssh_portproxy(name)
        write_operation(
            session.get("admin_name") or "admin",
            "Hyper-V",
            "configure_ssh_portproxy",
            name,
            request.remote_addr or "",
        )
        return jsonify({"ok": True, "data": result})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


@bp.route("/vms/<path:name>/portproxy", methods=["POST"])
@login_required
def configure_portproxy(name):
    try:
        data = request.get_json(silent=True) or {}
        result = hyperv_manager.configure_custom_portproxy(name, data)
        write_operation(
            session.get("admin_name") or "admin",
            "Hyper-V",
            "configure_portproxy",
            result.get("mapping") or name,
            request.remote_addr or "",
        )
        return jsonify({"ok": True, "data": result})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


@bp.route("/batch/portproxy", methods=["POST"])
@login_required
def batch_configure_portproxy():
    try:
        data = request.get_json(silent=True) or {}
        names = data.get("names") or []
        result = hyperv_manager.batch_configure_custom_portproxy(names, data)
        write_operation(
            session.get("admin_name") or "admin",
            "Hyper-V",
            "batch_configure_portproxy",
            f"{len(names)} vms port={data.get('listen_port')} count={data.get('port_count') or data.get('count') or 1}",
            request.remote_addr or "",
        )
        return jsonify({"ok": True, "data": result})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


@bp.route("/ssh/exec", methods=["POST"])
@login_required
def ssh_exec():
    try:
        data = request.get_json(silent=True) or {}
        result = hyperv_manager.ssh_exec(
            data.get("host") or "",
            data.get("username") or "root",
            data.get("password") or "",
            data.get("command") or "",
            int(data.get("port") or 22),
            int(data.get("timeout") or 30),
        )
        write_operation(
            session.get("admin_name") or "admin",
            "Hyper-V",
            "ssh_exec",
            f"{result.get('username')}@{result.get('host')}:{result.get('port')} {result.get('command')}",
            request.remote_addr or "",
        )
        return jsonify({"ok": True, "data": result})
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


@bp.route("/batch-create/start", methods=["POST"])
@login_required
def start_batch_create():
    try:
        data = request.get_json(silent=True) or {}
        result = hyperv_manager.start_batch_create_vms(data)
        write_operation(
            session.get("admin_name") or "admin",
            "Hyper-V",
            "start_batch_create",
            f"{data.get('prefix') or 'hy'} x {data.get('count') or 0} job={result.get('job_id')}",
            request.remote_addr or "",
        )
        return jsonify({"ok": True, "data": result})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


@bp.route("/batch-create/status/<job_id>", methods=["GET"])
@login_required
def batch_create_status(job_id):
    try:
        return jsonify({"ok": True, "data": hyperv_manager.batch_create_job_status(job_id)})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


@bp.route("/batch-start/start", methods=["POST"])
@login_required
def start_batch_start():
    try:
        data = request.get_json(silent=True) or {}
        names = data.get("names") or []
        result = hyperv_manager.start_vms_staged(
            names,
            int(data.get("batch_size") or 5),
            int(data.get("wait_seconds") or 15),
        )
        write_operation(
            session.get("admin_name") or "admin",
            "Hyper-V",
            "start_batch_start",
            f"{len(names)} job={result.get('job_id')}",
            request.remote_addr or "",
        )
        return jsonify({"ok": True, "data": result})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


@bp.route("/batch-start/status/<job_id>", methods=["GET"])
@login_required
def batch_start_status(job_id):
    try:
        return jsonify({"ok": True, "data": hyperv_manager.start_vm_job_status(job_id)})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500
