#!/usr/bin/env bash
set -euo pipefail

APP_DIR="${APP_DIR:-/opt/42IPwin}"
SERVICE_USER="${SERVICE_USER:-root}"
PYTHON_BIN="${PYTHON_BIN:-python3}"
SWAP_SIZE="${SWAP_SIZE:-2G}"
PANEL_PORT="${PANEL_PORT:-8080}"

if [[ $EUID -ne 0 ]]; then
  echo "请用 root 执行: bash install_lite.sh"
  exit 1
fi

ensure_swap() {
  if swapon --show | grep -q .; then
    return
  fi
  echo "[lite] 未检测到 swap，创建 ${SWAP_SIZE} swapfile"
  if command -v fallocate >/dev/null 2>&1; then
    fallocate -l "$SWAP_SIZE" /swapfile
  else
    dd if=/dev/zero of=/swapfile bs=1M count=2048
  fi
  chmod 600 /swapfile
  mkswap /swapfile
  swapon /swapfile
  grep -q "^/swapfile " /etc/fstab || echo "/swapfile none swap sw 0 0" >> /etc/fstab
}

install_packages() {
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    python3 python3-flask python3-sqlalchemy python3-psutil python3-requests \
    curl iproute2 iptables procps rsync ca-certificates
}

copy_project() {
  mkdir -p "$APP_DIR"
  if [[ ! -f "./panel/app.py" ]]; then
    echo "未找到项目文件，请在 42IPwin 项目目录执行。"
    exit 2
  fi
  rsync -a --delete \
    --exclude ".git" \
    --exclude "data/backups" \
    --exclude "__pycache__" \
    ./ "$APP_DIR/"
}

install_sing_box_optional() {
  cd "$APP_DIR"
  mkdir -p sing-box
  if [[ -x sing-box/sing-box ]]; then
    return
  fi
  arch="$(uname -m)"
  case "$arch" in
    x86_64|amd64) sb_arch="amd64" ;;
    aarch64|arm64) sb_arch="arm64" ;;
    *) echo "[lite] 不支持自动下载 sing-box 架构: $arch"; return ;;
  esac
  version="${SING_BOX_VERSION:-1.10.7}"
  url="https://github.com/SagerNet/sing-box/releases/download/v${version}/sing-box-${version}-linux-${sb_arch}.tar.gz"
  tmp="/tmp/sing-box-${version}.tar.gz"
  echo "[lite] 下载 sing-box"
  if curl --connect-timeout 15 -L "$url" -o "$tmp"; then
    tar -xzf "$tmp" -C /tmp
    cp "/tmp/sing-box-${version}-linux-${sb_arch}/sing-box" sing-box/sing-box
    chmod +x sing-box/sing-box
  else
    echo "[lite] sing-box 下载失败，面板仍会安装；之后可在系统设置里再启动代理。"
  fi
}

install_service() {
  cat >/etc/systemd/system/42ipwin.service <<EOF
[Unit]
Description=42IPwin Small Panel
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${SERVICE_USER}
Environment=42IPWIN_LITE=1
Environment=42IPWIN_NO_COLLECTOR=1
Environment=42IPWIN_SINGBOX_WATCHDOG=1
WorkingDirectory=${APP_DIR}
ExecStart=/usr/bin/${PYTHON_BIN} ${APP_DIR}/panel/app.py --no-browser --lite --singbox-watchdog
Restart=always
RestartSec=5
OOMScoreAdjust=500

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now 42ipwin
}

show_result() {
  ip="$(hostname -I | awk '{print $1}')"
  echo
  echo "42IPwin 小内存版安装完成"
  echo "服务状态: $(systemctl is-active 42ipwin || true)"
  echo "内存状态:"
  free -h
  echo "访问地址: http://${ip:-服务器IP}:${PANEL_PORT}"
  echo
  echo "小内存版会保持 sing-box 在线，只关闭后台流量采集，避免 512M 小机器卡死。"
}

ensure_swap
install_packages
copy_project
install_sing_box_optional
install_service
show_result
