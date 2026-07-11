"""42IPwin web panel entrypoint."""
import argparse
import datetime as _dt
import os
import sys
import threading
import traceback
import webbrowser
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

from flask import Flask, redirect, render_template, request, session, url_for
from werkzeug.exceptions import HTTPException

from config import APP_VERSION, PANEL_PORT, PANEL_SECRET_KEY, get_panel_bind_ip, is_lite_mode
from models import init_db
from routes.auth import bp as auth_bp
from routes.auth import login_required
from routes.auth import permission_required
from routes.auth import PERMISSION_ITEMS, current_permissions
from routes.center import bp as center_bp
from routes.hyperv import bp as hyperv_bp
from routes.ips import bp as ips_bp
from routes.monitor import bp as monitor_bp
from routes.pve import bp as pve_bp
from routes.servers import bp as servers_bp
from routes.users import bp as users_bp
from services import protection_manager, proxy_manager
from services.traffic_collector import start_daemon as start_collector

LITE_NAV_KEYS = {"dashboard", "nodes", "group_control", "pve", "logs", "settings", "admin_users"}


def create_app() -> Flask:
    app = Flask(
        __name__,
        template_folder=str(BASE_DIR / "templates"),
        static_folder=str(BASE_DIR / "static"),
    )
    app.secret_key = PANEL_SECRET_KEY
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["JSON_AS_ASCII"] = False

    @app.errorhandler(Exception)
    def log_unhandled_exception(exc):
        if isinstance(exc, HTTPException):
            return exc
        log_path = BASE_DIR.parent / "data" / "panel_runtime_error.log"
        try:
            log_path.parent.mkdir(parents=True, exist_ok=True)
            with log_path.open("a", encoding="utf-8") as fh:
                fh.write(f"\n[{_dt.datetime.now().isoformat(timespec='seconds')}] {request.method} {request.path}\n")
                fh.write(f"admin_id={session.get('admin_id')} admin_name={session.get('admin_name')}\n")
                fh.write(traceback.format_exc())
        except Exception:
            pass
        return "Internal Server Error", 500

    @app.context_processor
    def inject_version():
        permissions = current_permissions()
        nav_items = [item for item in PERMISSION_ITEMS if item["key"] in permissions]
        if is_lite_mode():
            nav_items = [item for item in nav_items if item["key"] in LITE_NAV_KEYS]
        return {
            "app_version": APP_VERSION,
            "is_lite_mode": is_lite_mode(),
            "permission_items": PERMISSION_ITEMS,
            "current_permissions": permissions,
            "nav_items": nav_items,
        }

    @app.after_request
    def prevent_stale_panel_assets(response):
        path = request.path or ""
        content_type = response.content_type or ""
        if content_type.startswith("text/html"):
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"
        elif path.startswith("/static/vendor/"):
            response.headers["Cache-Control"] = "public, max-age=604800, immutable"
            response.headers.pop("Pragma", None)
            response.headers.pop("Expires", None)
        elif path.startswith("/static/"):
            response.headers["Cache-Control"] = "public, max-age=3600"
            response.headers.pop("Pragma", None)
            response.headers.pop("Expires", None)
        return response

    app.register_blueprint(auth_bp)
    app.register_blueprint(center_bp)
    app.register_blueprint(ips_bp)
    app.register_blueprint(users_bp)
    app.register_blueprint(monitor_bp)
    app.register_blueprint(hyperv_bp)
    app.register_blueprint(pve_bp)
    app.register_blueprint(servers_bp)

    @app.route("/")
    def root():
        if not session.get("admin_id"):
            return redirect(url_for("auth.login_page"))
        return redirect(url_for("main_dashboard"))

    @app.route("/dashboard")
    @permission_required("dashboard")
    def main_dashboard():
        return render_template("dashboard.html", admin=session.get("admin_name"))

    @app.route("/lines")
    @permission_required("lines")
    def page_lines():
        if is_lite_mode():
            return redirect(url_for("page_users"))
        return render_template("lines.html", admin=session.get("admin_name"))

    @app.route("/nodes")
    @app.route("/users")
    @app.route("/inbounds")
    @app.route("/inbound")
    @permission_required("nodes")
    def page_users():
        return render_template("users.html", admin=session.get("admin_name"), group_mode=False)

    @app.route("/admin-users")
    @permission_required("admin_users")
    def page_admin_users():
        return render_template("system_users.html", admin=session.get("admin_name"))

    @app.route("/group-control")
    @permission_required("group_control")
    def page_group_control():
        return render_template("servers.html", admin=session.get("admin_name"))

    @app.route("/customers")
    @permission_required("customers")
    def page_customers():
        if is_lite_mode():
            return redirect(url_for("page_users"))
        return render_template("admin_users.html", admin=session.get("admin_name"))

    @app.route("/operation-logs")
    @permission_required("logs")
    def page_operation_logs():
        return render_template("operation_logs.html", admin=session.get("admin_name"))

    @app.route("/pve")
    @app.route("/hyperv")
    @permission_required("pve")
    def page_pve():
        if is_lite_mode():
            return redirect(url_for("page_users"))
        return render_template("hyperv.html", admin=session.get("admin_name"))

    @app.route("/settings")
    @permission_required("settings")
    def page_settings():
        return render_template("settings.html", admin=session.get("admin_name"))

    return app


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--init", action="store_true", help="初始化数据库")
    parser.add_argument("--no-browser", action="store_true", help="不自动打开浏览器")
    parser.add_argument("--lite", action="store_true", help="轻量模式：启动 sing-box，关闭后台流量采集")
    parser.add_argument("--no-collector", action="store_true", help="不启动后台流量采集")
    parser.add_argument("--singbox-watchdog", action="store_true", help="后台看护 sing-box，异常退出后自动拉起")
    args = parser.parse_args()
    lite_mode = args.lite or os.environ.get("IPWIN42_LITE") == "1" or os.environ.get("42IPWIN_LITE") == "1"
    no_collector = args.no_collector or os.environ.get("IPWIN42_NO_COLLECTOR") == "1" or os.environ.get("42IPWIN_NO_COLLECTOR") == "1"
    singbox_watchdog = args.singbox_watchdog or os.environ.get("IPWIN42_PANEL_SINGBOX_WATCHDOG", "0") == "1"

    if args.init:
        init_db()
        print("数据库已初始化")
        return

    init_db()
    if singbox_watchdog:
        try:
            proxy_manager.ensure_running()
        except Exception as exc:
            print(f"[sing-box] ensure running failed: {exc}")

    if singbox_watchdog:
        def keep_singbox_alive():
            while True:
                try:
                    proxy_manager.ensure_healthy()
                except Exception as exc:
                    print(f"[sing-box watchdog] {exc}")
                threading.Event().wait(10)
        threading.Thread(target=keep_singbox_alive, daemon=True).start()

    def protect_runtime_resources():
        while True:
            try:
                result = protection_manager.enforce_runtime_protection()
                for message in result.get("messages") or []:
                    print(f"[runtime protection] {message}")
            except Exception as exc:
                print(f"[runtime protection] {exc}")
            threading.Event().wait(protection_manager.NODE_SAMPLE_SECONDS)
    threading.Thread(target=protect_runtime_resources, daemon=True).start()

    if no_collector:
        print("[lite] 后台流量采集已关闭，sing-box 保持在线")
    else:
        try:
            threading.Thread(target=start_collector, args=(5,), daemon=True).start()
        except Exception as exc:
            print(f"[traffic] collector start failed: {exc}")

    app = create_app()
    bind_ip = get_panel_bind_ip()
    url = f"http://{bind_ip if bind_ip != '0.0.0.0' else '127.0.0.1'}:{PANEL_PORT}"

    print("=" * 60)
    print("  42IPwin 管理后台已启动")
    print(f"  访问地址: {url}")
    print(f"  监听 IP: {bind_ip} (0.0.0.0=所有网卡)")
    print("  代理内核: sing-box")
    print(f"  运行模式: {'lite' if lite_mode else 'full'}")
    print(f"  sing-box 看护: {'on' if singbox_watchdog else 'off'}")
    print("=" * 60)

    if not args.no_browser:
        try:
            threading.Timer(1.5, lambda: webbrowser.open(url)).start()
        except Exception:
            pass

    app.run(host=bind_ip, port=PANEL_PORT, debug=False, use_reloader=False, threaded=True)


if __name__ == "__main__":
    main()
