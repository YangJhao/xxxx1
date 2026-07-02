import os
import posixpath
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

import paramiko


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CENTER = {
    "host": "59.2.213.203",
    "port": 8088,
    "username": "root",
    "password": "ping99!!",
}
FILES = [
    ("panel/routes/users.py", "panel/routes/users.py"),
    ("panel/services/cfg_generator.py", "panel/services/cfg_generator.py"),
    ("panel/services/limit_manager.py", "panel/services/limit_manager.py"),
    ("panel/services/proxy_manager.py", "panel/services/proxy_manager.py"),
    ("panel/services/traffic_collector.py", "panel/services/traffic_collector.py"),
    ("panel/templates/base.html", "panel/templates/base.html"),
    ("panel/templates/users.html", "panel/templates/users.html"),
]


def connect(host, port, username, password, timeout=18):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        host,
        port=int(port or 22),
        username=username or "root",
        password=password or "",
        timeout=timeout,
        banner_timeout=timeout,
        auth_timeout=timeout,
        look_for_keys=False,
        allow_agent=False,
    )
    return client


def run(client, command, timeout=120, check=True):
    _stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
    out = stdout.read().decode("utf-8", "replace")
    err = stderr.read().decode("utf-8", "replace")
    code = stdout.channel.recv_exit_status()
    if check and code != 0:
        raise RuntimeError((err or out or f"exit {code}")[-1000:])
    return code, out, err


def center_servers():
    script = r"""
cd /opt/42IPwin
python3 - <<'PY'
import sys
sys.path.insert(0, '/opt/42IPwin/panel')
from models import ManagedServer, get_session
s = get_session()
try:
    for row in s.query(ManagedServer).filter(ManagedServer.install_status == 'installed').order_by(ManagedServer.id).all():
        print('|'.join([str(row.id), row.ip, str(row.ssh_port or 22), row.username or 'root', row.password or '']))
finally:
    s.close()
PY
"""
    client = connect(**CENTER)
    try:
        _code, out, _err = run(client, script, timeout=90)
        rows = []
        for line in out.splitlines():
            parts = line.split("|", 4)
            if len(parts) == 5 and parts[1] != CENTER["host"]:
                rows.append({"id": parts[0], "ip": parts[1], "port": int(parts[2]), "username": parts[3], "password": parts[4]})
        return rows
    finally:
        client.close()


def mkdir_p(sftp, path):
    current = ""
    for part in [p for p in path.split("/") if p]:
        current += "/" + part
        try:
            sftp.stat(current)
        except IOError:
            sftp.mkdir(current)


def sync_one(server):
    client = connect(server["ip"], server["port"], server["username"], server["password"])
    try:
        _code, app_dir, _err = run(
            client,
            "if [ -d /opt/42IPwin ]; then printf /opt/42IPwin; elif [ -d /root/42IPwin ]; then printf /root/42IPwin; else pwd; fi",
        )
        app_dir = app_dir.strip() or "/opt/42IPwin"
        run(client, f"mkdir -p {app_dir}/data/backups && cd {app_dir} && tar -czf data/backups/before-lite19-child-$(date +%Y%m%d-%H%M%S).tar.gz panel/routes/users.py panel/services/cfg_generator.py panel/services/limit_manager.py panel/services/proxy_manager.py panel/services/traffic_collector.py panel/templates/base.html panel/templates/users.html 2>/dev/null || true")
        sftp = client.open_sftp()
        try:
            for local_rel, remote_rel in FILES:
                local_path = os.path.join(ROOT, local_rel.replace("/", os.sep))
                remote_path = posixpath.join(app_dir, remote_rel)
                mkdir_p(sftp, posixpath.dirname(remote_path))
                sftp.put(local_path, remote_path)
        finally:
            sftp.close()
        run(client, f"cd {app_dir} && python3 -m py_compile panel/routes/users.py panel/services/cfg_generator.py panel/services/limit_manager.py panel/services/proxy_manager.py panel/services/traffic_collector.py", timeout=90)
        run(client, "systemctl restart 42ipwin", timeout=90, check=False)
        _code, active, _err = run(client, "systemctl is-active 42ipwin", timeout=60, check=False)
        return server["ip"], active.strip()
    finally:
        client.close()


def main():
    servers = center_servers()
    print("SERVERS", len(servers), " ".join(item["ip"] for item in servers))
    ok = 0
    with ThreadPoolExecutor(max_workers=min(10, max(1, len(servers)))) as executor:
        futures = [executor.submit(sync_one, server) for server in servers]
        for future in as_completed(futures):
            try:
                ip, active = future.result()
                print("OK", ip, active)
                ok += 1
            except Exception as exc:
                print("FAIL", exc)
    print("DONE", ok, "/", len(servers))
    return 0 if ok == len(servers) else 1


if __name__ == "__main__":
    sys.exit(main())
