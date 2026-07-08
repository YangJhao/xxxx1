#!/usr/bin/env bash
set -euo pipefail

APP_DIR="${APP_DIR:-/opt/42IPwin-single}"
SERVICE_USER="${SERVICE_USER:-root}"
PYTHON_BIN="${PYTHON_BIN:-python3}"
SWAP_SIZE="${SWAP_SIZE:-1G}"
PANEL_PORT="${PANEL_PORT:-18080}"
PUBLIC_IP="${PUBLIC_IP:-${IPWIN42_PUBLIC_IP:-}}"

if [[ $EUID -ne 0 ]]; then
  echo "Please run as root: bash install_single_ip.sh"
  exit 1
fi

ensure_swap() {
  if swapon --show | grep -q .; then
    return
  fi
  echo "[single-ip] creating ${SWAP_SIZE} swapfile"
  if command -v fallocate >/dev/null 2>&1; then
    fallocate -l "$SWAP_SIZE" /swapfile
  else
    dd if=/dev/zero of=/swapfile bs=1M count=1024
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
    python3-paramiko curl iproute2 iptables procps rsync ca-certificates openssl
}

copy_project() {
  mkdir -p "$APP_DIR"
  if [[ ! -f "./panel/app.py" ]]; then
    echo "Project files not found. Run this script from the 42IPwin repository root."
    exit 2
  fi
  rsync -a --delete \
    --exclude ".git" \
    --exclude "data" \
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
    *) echo "[single-ip] unsupported sing-box arch: $arch"; return ;;
  esac
  version="${SING_BOX_VERSION:-1.10.7}"
  url="https://github.com/SagerNet/sing-box/releases/download/v${version}/sing-box-${version}-linux-${sb_arch}.tar.gz"
  tmp="/tmp/sing-box-${version}.tar.gz"
  echo "[single-ip] downloading sing-box"
  if curl --connect-timeout 15 --fail -L "$url" -o "$tmp"; then
    tar -xzf "$tmp" -C /tmp
    cp "/tmp/sing-box-${version}-linux-${sb_arch}/sing-box" sing-box/sing-box
    chmod +x sing-box/sing-box
  else
    echo "[single-ip] sing-box download failed; panel still installs, but nodes need sing-box later."
  fi
}

install_service() {
  cat >/etc/systemd/system/42ipwin-single.service <<EOF
[Unit]
Description=42IPwin Single Public IP Panel
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${SERVICE_USER}
Environment=IPWIN42_SINGLE_IP=1
Environment=IPWIN42_LITE=1
Environment=IPWIN42_NO_COLLECTOR=1
Environment=IPWIN42_NO_PROTECTION=1
Environment=IPWIN42_SINGBOX_WATCHDOG=0
Environment=IPWIN42_PANEL_PORT=${PANEL_PORT}
Environment=IPWIN42_PUBLIC_IP=${PUBLIC_IP}
WorkingDirectory=${APP_DIR}
ExecStart=/usr/bin/${PYTHON_BIN} ${APP_DIR}/panel/app.py --no-browser --single-ip
Restart=always
RestartSec=5
KillMode=process
OOMScoreAdjust=500

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now 42ipwin-single
}

show_result() {
  ip="${PUBLIC_IP}"
  if [[ -z "$ip" ]]; then
    ip="$(curl -fsS --max-time 5 https://api.ipify.org || hostname -I | awk '{print $1}')"
  fi
  echo
  echo "42IPwin single public IP version installed"
  echo "Service: $(systemctl is-active 42ipwin-single || true)"
  echo "Panel: http://${ip:-SERVER_IP}:${PANEL_PORT}"
  echo "Default login: admin / admin123"
  echo
}

ensure_swap
install_packages
copy_project
install_sing_box_optional
install_service
show_result
