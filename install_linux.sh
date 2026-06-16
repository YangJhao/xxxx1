#!/usr/bin/env bash
set -euo pipefail

APP_DIR="${APP_DIR:-/opt/42IPwin}"
SERVICE_USER="${SERVICE_USER:-root}"
PYTHON_BIN="${PYTHON_BIN:-python3}"
VENV_DIR="${VENV_DIR:-${APP_DIR}/.venv}"
SING_BOX_VERSION="${SING_BOX_VERSION:-1.10.7}"

if [[ $EUID -ne 0 ]]; then
  echo "请用 root 执行: sudo bash install_linux.sh"
  exit 1
fi

if [[ -f /etc/os-release ]]; then
  . /etc/os-release
else
  ID=linux
fi

install_packages() {
  case "${ID,,}" in
    debian|ubuntu)
      apt-get update
      apt-get install -y python3 python3-pip python3-venv curl unzip iproute2 iptables procps rsync
      ;;
    centos|rhel|rocky|almalinux)
      if command -v dnf >/dev/null 2>&1; then
        dnf install -y python3 python3-pip curl unzip iproute iptables procps-ng rsync
      else
        yum install -y python3 python3-pip curl unzip iproute iptables procps-ng rsync
      fi
      ;;
    *)
      echo "未知系统 ${ID}，请手动安装 python3/pip/curl/unzip/iproute2/iptables"
      ;;
  esac
}

copy_project() {
  mkdir -p "$APP_DIR"
  if command -v rsync >/dev/null 2>&1; then
    rsync -a --delete \
      --exclude ".git" \
      --exclude "data/backups" \
      --exclude "__pycache__" \
      ./ "$APP_DIR/"
  else
    tar --exclude=".git" --exclude="data/backups" --exclude="__pycache__" -cf - . | tar -xf - -C "$APP_DIR"
  fi
}

install_python_deps() {
  cd "$APP_DIR"
  "$PYTHON_BIN" -m venv "$VENV_DIR"
  "$VENV_DIR/bin/python" -m pip install --upgrade pip
  "$VENV_DIR/bin/python" -m pip install flask sqlalchemy psutil requests
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
Description=42IPwin Panel
After=network-online.target
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

open_firewall_hint() {
  echo "如启用了防火墙，请放行面板和节点端口，例如："
  echo "  ufw allow 8080/tcp"
  echo "  firewall-cmd --permanent --add-port=8080/tcp && firewall-cmd --reload"
}

install_packages
copy_project
install_python_deps
install_sing_box
install_service
open_firewall_hint
echo "42IPwin Linux/PVE 版安装完成: http://服务器IP:8080"
