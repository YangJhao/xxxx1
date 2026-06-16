"""42IPwin web panel entrypoint."""
import argparse
import os
import sys
import threading
import webbrowser
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

from flask import Flask, redirect, render_template, session, url_for

from config import APP_VERSION, PANEL_PORT, PANEL_SECRET_KEY, get_panel_bind_ip
from models import init_db
from routes.auth import bp as auth_bp
from routes.auth import login_required
from routes.auth import permission_required
from routes.auth import PERMISSION_ITEMS, current_permissions
from routes.hyperv import bp as hyperv_bp
from routes.ips import bp as ips_bp
from routes.monitor import bp as monitor_bp
from routes.pve import bp as pve_bp
from routes.users import bp as users_bp
from services import proxy_manager
from services.traffic_collector import start_daemon as start_collector


def create_app() -> Flask:
    app = Flask(
        __name__,
        template_folder=str(BASE_DIR / "templates"),
        static_folder=str(BASE_DIR / "static"),
    )
    app.secret_key = PANEL_SECRET_KEY
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["JSON_AS_ASCII"] = False

    @app.context_processor
    def inject_version():
        return {"app_version": APP_VERSION, "permission_items": PERMISSION_ITEMS, "current_permissions": current_permissions()}

    app.register_blueprint(auth_bp)
    app.register_blueprint(ips_bp)
    app.register_blueprint(users_bp)
    app.register_blueprint(monitor_bp)
    app.register_blueprint(hyperv_bp)
    app.register_blueprint(pve_bp)

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
        return render_template("lines.html", admin=session.get("admin_name"))

    @app.route("/nodes")
    @app.route("/users")
    @permission_required("nodes")
    def page_users():
        return render_template("users.html", admin=session.get("admin_name"))

    @app.route("/admin-users")
    @permission_required("admin_users")
    def page_admin_users():
        return render_template("system_users.html", admin=session.get("admin_name"))

    @app.route("/customers")
    @permission_required("customers")
    def page_customers():
        return render_template("admin_users.html", admin=session.get("admin_name"))

    @app.route("/operation-logs")
    @permission_required("logs")
    def page_operation_logs():
        return render_template("operation_logs.html", admin=session.get("admin_name"))

    @app.route("/pve")
    @app.route("/hyperv")
    @permission_required("pve")
    def page_pve():
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
    no_collector = lite_mode or args.no_collector or os.environ.get("IPWIN42_NO_COLLECTOR") == "1" or os.environ.get("42IPWIN_NO_COLLECTOR") == "1"
    singbox_watchdog = args.singbox_watchdog or os.environ.get("IPWIN42_SINGBOX_WATCHDOG") == "1" or os.environ.get("42IPWIN_SINGBOX_WATCHDOG") == "1"

    if args.init:
        init_db()
        print("数据库已初始化")
        return

    init_db()
    try:
        proxy_manager.ensure_running()
    except Exception as exc:
        print(f"[sing-box] ensure running failed: {exc}")

    if singbox_watchdog:
        def keep_singbox_alive():
            while True:
                try:
                    proxy_manager.ensure_running()
                except Exception as exc:
                    print(f"[sing-box watchdog] {exc}")
                threading.Event().wait(10)
        threading.Thread(target=keep_singbox_alive, daemon=True).start()

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

    app.run(host=bind_ip, port=PANEL_PORT, debug=False, use_reloader=False)


if __name__ == "__main__":
    main()
