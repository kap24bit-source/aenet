#!/usr/bin/env bash
# KAPX DATA EGRESS GUARDIAN - ALL-IN-ONE FILE
# Debian 13 KDE
# Author: KAPX
# Purpose: Prevent data/thought exfiltration. Single-file install & run.

set -euo pipefail

ACTION="${1:-}"

BASE="/etc/kapx-egress"
STATE="/var/lib/kapx-egress"
LOG="/var/log/kapx-egress"

require_root() {
  if [ "$EUID" -ne 0 ]; then
    echo "Run as root (sudo)"
    exit 1
  fi
}

install_all() {
  require_root
  echo "[1/6] Installing packages"
  apt update
  apt install -y nftables squid python3 curl auditd

  echo "[2/6] Creating directories"
  mkdir -p "$BASE" "$STATE/export_staging" "$STATE/export_out" "$STATE/approved" "$LOG"

  echo "[3/6] Writing policy"
  cat > "$BASE/policy.json" <<EOF
{
  "block_patterns": ["PRIVATE KEY", "API_KEY", "/home/", ".ssh", "Authorization: Bearer"],
  "allowed_extensions": [".txt",".md",".json",".csv",".diff",".patch"],
  "max_file_mb": 20
}
EOF

  echo "[4/6] Writing allowlist"
  cat > "$BASE/allowlist_domains.txt" <<EOF
api.openai.com
github.com
EOF

  echo "[5/6] Setting squid"
  if [ -f /etc/squid/squid.conf ]; then
    cp /etc/squid/squid.conf /etc/squid/squid.conf.bak
  fi
  cat > /etc/squid/squid.conf <<EOF
http_port 3128
acl allowed dstdomain "/etc/kapx-egress/allowlist_domains.txt"
acl SSL_ports port 443
acl CONNECT method CONNECT
http_access allow CONNECT allowed SSL_ports
http_access deny all
EOF

  systemctl restart squid
  systemctl enable squid

  echo "[6/6] Creating no-egress namespace"
  if ! ip netns list | grep -q "^kapx_core$"; then
    ip netns add kapx_core
  fi
  ip netns exec kapx_core ip link set lo up

  echo "INSTALL COMPLETE"
}

core_shell() {
  require_root
  ip netns exec kapx_core bash
}

status() {
  echo "Namespaces:"
  ip netns list
  echo "Squid:"
  systemctl status squid --no-pager
}

case "$ACTION" in
  install) install_all ;;
  core-shell) core_shell ;;
  status) status ;;
  *) echo "Usage: install | core-shell | status" ;;
esac
