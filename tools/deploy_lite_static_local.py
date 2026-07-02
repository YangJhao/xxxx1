import argparse
import os
import posixpath
import shlex
import sys
import time

import paramiko


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

FILES = [
    ("panel/app.py", "panel/app.py"),
    ("panel/config.py", "panel/config.py"),
    ("panel/models.py", "panel/models.py"),
    ("panel/requirements.txt", "panel/requirements.txt"),
    ("panel/routes/auth.py", "panel/routes/auth.py"),
    ("panel/routes/servers.py", "panel/routes/servers.py"),
    ("panel/routes/users.py", "panel/routes/users.py"),
    ("panel/services/audit_logger.py", "panel/services/audit_logger.py"),
    ("panel/services/cfg_generator.py", "panel/services/cfg_generator.py"),
    ("panel/services/limit_manager.py", "panel/services/limit_manager.py"),
    ("panel/services/protection_manager.py", "panel/services/protection_manager.py"),
    ("panel/services/proxy_manager.py", "panel/services/proxy_manager.py"),
    ("panel/services/traffic_collector.py", "panel/services/traffic_collector.py"),
    ("panel/services/wireguard_manager.py", "panel/services/wireguard_manager.py"),
    ("panel/templates/base.html", "panel/templates/base.html"),
    ("panel/templates/login.html", "panel/templates/login.html"),
    ("panel/templates/dashboard.html", "panel/templates/dashboard.html"),
    ("panel/templates/servers.html", "panel/templates/servers.html"),
    ("panel/templates/users.html", "panel/templates/users.html"),
    ("panel/templates/operation_logs.html", "panel/templates/operation_logs.html"),
    ("panel/templates/settings.html", "panel/templates/settings.html"),
    ("panel/templates/system_users.html", "panel/templates/system_users.html"),
    ("panel/static/js/common.js", "panel/static/js/common.js"),
    ("panel/static/css/app.css", "panel/static/css/app.css"),
    ("install_lite.sh", "install_lite.sh"),
]

VENDOR_DOWNLOADS = [
    (
        "panel/static/vendor/bootstrap/bootstrap.min.css",
        [
            "https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css",
            "https://unpkg.com/bootstrap@5.3.2/dist/css/bootstrap.min.css",
        ],
    ),
    (
        "panel/static/vendor/bootstrap/bootstrap.bundle.min.js",
        [
            "https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js",
            "https://unpkg.com/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js",
        ],
    ),
    (
        "panel/static/vendor/jquery/jquery.min.js",
        [
            "https://cdn.jsdelivr.net/npm/jquery@3.7.1/dist/jquery.min.js",
            "https://unpkg.com/jquery@3.7.1/dist/jquery.min.js",
        ],
    ),
    (
        "panel/static/vendor/echarts/echarts.min.js",
        [
            "https://cdn.jsdelivr.net/npm/echarts@5.4.3/dist/echarts.min.js",
            "https://unpkg.com/echarts@5.4.3/dist/echarts.min.js",
        ],
    ),
    (
        "panel/static/vendor/bootstrap-icons/font/bootstrap-icons.min.css",
        [
            "https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.2/font/bootstrap-icons.min.css",
            "https://unpkg.com/bootstrap-icons@1.11.2/font/bootstrap-icons.min.css",
        ],
    ),
    (
        "panel/static/vendor/bootstrap-icons/font/fonts/bootstrap-icons.woff2",
        [
            "https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.2/font/fonts/bootstrap-icons.woff2",
            "https://unpkg.com/bootstrap-icons@1.11.2/font/fonts/bootstrap-icons.woff2",
        ],
    ),
    (
        "panel/static/vendor/bootstrap-icons/font/fonts/bootstrap-icons.woff",
        [
            "https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.2/font/fonts/bootstrap-icons.woff",
            "https://unpkg.com/bootstrap-icons@1.11.2/font/fonts/bootstrap-icons.woff",
        ],
    ),
]


def run(ssh, command, timeout=180, check=True):
    stdin, stdout, stderr = ssh.exec_command(command, timeout=timeout)
    out = stdout.read().decode("utf-8", "replace")
    err = stderr.read().decode("utf-8", "replace")
    code = stdout.channel.recv_exit_status()
    if check and code != 0:
        raise RuntimeError(f"command failed ({code}): {command}\nSTDOUT:\n{out}\nSTDERR:\n{err}")
    return code, out, err


def mkdir_p(sftp, path):
    parts = [p for p in path.split("/") if p]
    current = ""
    for part in parts:
        current += "/" + part
        try:
            sftp.stat(current)
        except IOError:
            sftp.mkdir(current)


def upload_file(sftp, app_dir, local_rel, remote_rel):
    local_path = os.path.join(ROOT, local_rel.replace("/", os.sep))
    remote_path = posixpath.join(app_dir, remote_rel)
    mkdir_p(sftp, posixpath.dirname(remote_path))
    sftp.put(local_path, remote_path)
    return remote_path


def download_vendor(ssh, app_dir):
    results = []
    for rel, urls in VENDOR_DOWNLOADS:
        remote = posixpath.join(app_dir, rel)
        run(ssh, f"mkdir -p {shlex.quote(posixpath.dirname(remote))}")
        ok = False
        last_error = ""
        for url in urls:
            cmd = (
                f"curl -fL --connect-timeout 20 --max-time 120 --retry 2 "
                f"-o {shlex.quote(remote)} {shlex.quote(url)}"
            )
            code, out, err = run(ssh, cmd, timeout=160, check=False)
            if code == 0:
                ok = True
                break
            last_error = (err or out).strip()
        results.append((rel, ok, last_error[-300:]))
    return results


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--user", required=True)
    parser.add_argument("--password", required=True)
    args = parser.parse_args()

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(
        args.host,
        port=args.port,
        username=args.user,
        password=args.password,
        timeout=20,
        banner_timeout=30,
        auth_timeout=20,
        look_for_keys=False,
        allow_agent=False,
    )
    try:
        _, app_dir_out, _ = run(
            ssh,
            "if [ -d /opt/42IPwin ]; then printf /opt/42IPwin; elif [ -d /root/42IPwin ]; then printf /root/42IPwin; else pwd; fi",
        )
        app_dir = app_dir_out.strip()
        if not app_dir:
            raise RuntimeError("could not determine app dir")

        stamp = time.strftime("%Y%m%d-%H%M%S")
        backup_dir = posixpath.join(app_dir, "data", "backups")
        backup_file = posixpath.join(backup_dir, f"before-static-local-{stamp}.tar.gz")
        quoted_files = " ".join(shlex.quote(rel) for _, rel in FILES)
        run(ssh, f"mkdir -p {shlex.quote(backup_dir)}")
        run(
            ssh,
            f"cd {shlex.quote(app_dir)} && tar -czf {shlex.quote(backup_file)} {quoted_files} panel/static/vendor 2>/dev/null || true",
        )

        sftp = ssh.open_sftp()
        try:
            uploaded = [upload_file(sftp, app_dir, local, remote) for local, remote in FILES]
        finally:
            sftp.close()

        vendor = download_vendor(ssh, app_dir)
        failed = [item for item in vendor if not item[1]]
        if failed:
            print("APP_DIR", app_dir)
            print("BACKUP", backup_file)
            print("UPLOADED", *uploaded, sep="\n")
            print("VENDOR_FAILED")
            for rel, _, err in failed:
                print(rel, err)
            return 2

        run(
            ssh,
            f"cd {shlex.quote(app_dir)} && "
            "(.venv/bin/python -c 'import paramiko' 2>/dev/null || "
            ".venv/bin/python -m pip install paramiko==3.4.0 || "
            "(apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y python3-paramiko))",
            timeout=420,
        )
        compile_targets = [
            posixpath.join(app_dir, "panel", "app.py"),
            posixpath.join(app_dir, "panel", "models.py"),
            posixpath.join(app_dir, "panel", "routes", "servers.py"),
        ]
        run(ssh, "python3 -m py_compile " + " ".join(shlex.quote(p) for p in compile_targets), timeout=120)
        run(ssh, "systemctl restart 42ipwin", timeout=120)
        _, active, _ = run(ssh, "systemctl is-active 42ipwin", timeout=60)
        checks = [
            "/static/vendor/bootstrap/bootstrap.min.css",
            "/static/vendor/bootstrap/bootstrap.bundle.min.js",
            "/static/vendor/jquery/jquery.min.js",
            "/static/vendor/echarts/echarts.min.js",
            "/static/vendor/bootstrap-icons/font/bootstrap-icons.min.css",
            "/static/vendor/bootstrap-icons/font/fonts/bootstrap-icons.woff2",
        ]
        status = []
        for path in checks:
            code, out, err = run(
                ssh,
                f"curl -sS -o /dev/null -w '%{{http_code}} %{{size_download}}' http://127.0.0.1:18080{path}",
                timeout=60,
                check=False,
            )
            status.append((path, out.strip(), code, err.strip()))
        code, login_head, login_err = run(
            ssh,
            "curl -sS -I --max-time 10 http://127.0.0.1:18080/ | head -n 5",
            timeout=60,
            check=False,
        )

        print("APP_DIR", app_dir)
        print("BACKUP", backup_file)
        print("SERVICE", active.strip())
        print("UPLOADED", *uploaded, sep="\n")
        print("VENDOR")
        for rel, ok, _ in vendor:
            print(rel, "ok" if ok else "failed")
        print("STATIC_CHECKS")
        for item in status:
            print(*item, sep=" | ")
        print("ROOT_HEAD")
        print(login_head.strip() or login_err.strip())
    finally:
        ssh.close()


if __name__ == "__main__":
    sys.exit(main())
