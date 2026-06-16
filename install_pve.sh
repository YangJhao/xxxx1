#!/usr/bin/env bash
set -euo pipefail

APP_DIR="${APP_DIR:-/opt/42IPwin}"
SERVICE_USER="${SERVICE_USER:-root}"
PYTHON_BIN="${PYTHON_BIN:-python3}"
VENV_DIR="${VENV_DIR:-${APP_DIR}/.venv}"
SING_BOX_VERSION="${SING_BOX_VERSION:-1.10.7}"
PANEL_PORT="${PANEL_PORT:-8080}"
GIT_REPO="${GIT_REPO:-}"

if [[ $EUID -ne 0 ]]; then
  echo "请用 root 执行: bash install_pve.sh"
  exit 1
fi

if ! command -v qm >/dev/null 2>&1; then
  echo "当前机器不是 Proxmox VE 宿主机，未找到 qm 命令。"
  echo "请在 PVE 8.x 宿主机执行本脚本，不要在普通 Ubuntu/Debian 虚拟机里执行。"
  exit 2
fi

if ! command -v pvesh >/dev/null 2>&1; then
  echo "警告: 未找到 pvesh，PVE 高级 API 功能可能不可用。"
fi

install_packages() {
  apt-get update
  apt-get install -y python3 python3-pip python3-venv curl unzip iproute2 iptables procps rsync git ca-certificates
}

copy_project() {
  mkdir -p "$APP_DIR"
  if [[ -n "$GIT_REPO" ]]; then
    tmp="/tmp/42ipwin-pve-src"
    rm -rf "$tmp"
    git clone "$GIT_REPO" "$tmp"
    rsync -a --delete --exclude ".git" --exclude "data/backups" --exclude "__pycache__" "$tmp/" "$APP_DIR/"
    rm -rf "$tmp"
    return
  fi
  if [[ -f "./panel/app.py" ]]; then
    rsync -a --delete \
      --exclude ".git" \
      --exclude "data/backups" \
      --exclude "__pycache__" \
      ./ "$APP_DIR/"
  else
    echo "未找到项目文件。请在 42IPwin 项目目录执行，或使用: GIT_REPO=https://xxx bash install_pve.sh"
    exit 3
  fi
}

install_python_deps() {
  cd "$APP_DIR"
  "$PYTHON_BIN" -m venv "$VENV_DIR"
  "$VENV_DIR/bin/python" -m pip install --upgrade pip
  "$VENV_DIR/bin/python" -m pip install flask sqlalchemy psutil requests
  "$VENV_DIR/bin/python" -m compileall -q panel
}

install_sing_box() {
  cd "$APP_DIR"
  mkdir -p sing-box
  if [[ -x sing-box/sing-box ]]; then
    return
  fi
  arch="$(uname -m)"
  case "$arch" in
    x86_64|amd64) sb_arch="amd64" ;;
    aarch64|arm64) sb_arch="arm64" ;;
    *) echo "不支持的 CPU 架构: $arch"; exit 1 ;;
  esac
  url="https://github.com/SagerNet/sing-box/releases/download/v${SING_BOX_VERSION}/sing-box-${SING_BOX_VERSION}-linux-${sb_arch}.tar.gz"
  tmp="/tmp/sing-box-${SING_BOX_VERSION}.tar.gz"
  curl -L "$url" -o "$tmp"
  tar -xzf "$tmp" -C /tmp
  cp "/tmp/sing-box-${SING_BOX_VERSION}-linux-${sb_arch}/sing-box" sing-box/sing-box
  chmod +x sing-box/sing-box
}

install_service() {
  cat >/etc/systemd/system/42ipwin.service <<EOF
[Unit]
Description=42IPwin PVE Panel
After=network-online.target pve-guests.service
Wants=network-online.target

[Service]
Type=simple
User=${SERVICE_USER}
WorkingDirectory=${APP_DIR}
ExecStart=${VENV_DIR}/bin/python ${APP_DIR}/panel/app.py --no-browser
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now 42ipwin
}

show_result() {
  ip="$(hostname -I | awk '{print $1}')"
  echo
  echo "42IPwin PVE 版安装完成"
  echo "PVE 检测: $(qm list >/dev/null 2>&1 && echo OK || echo FAIL)"
  echo "服务状态: $(systemctl is-active 42ipwin || true)"
  echo "访问地址: http://${ip:-服务器IP}:${PANEL_PORT}"
  echo
  echo "常用命令:"
  echo "  systemctl status 42ipwin --no-pager"
  echo "  journalctl -u 42ipwin -f"
}

install_packages
copy_project
install_python_deps
install_sing_box
install_service
show_result
