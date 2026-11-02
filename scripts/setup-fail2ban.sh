#!/usr/bin/env bash
#
# Sets up fail2ban for:
#   - SSH (standard sshd jail)
#   - The admin panel and DDNS token endpoints (custom jails, reading
#     ./logs/auth.log — the app writes real client IPs there, resolved
#     via X-Forwarded-For, since ddns-api normally only sees the reverse
#     proxy's IP in its own logs)
#
# Safe to re-run.
#
# Usage:
#   sudo SSH_PORT=22 ./scripts/setup-fail2ban.sh

set -euo pipefail

info() { printf '\033[36m%s\033[0m\n' "$1"; }
ok()   { printf '\033[32m%s\033[0m\n' "$1"; }
err()  { printf '\033[31m%s\033[0m\n' "$1" >&2; }

if [ "$(id -u)" -ne 0 ]; then
    err "Run as root (sudo ./scripts/setup-fail2ban.sh)"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"

SSH_PORT="${SSH_PORT:-22}"
LOG_PATH="${SCRIPT_DIR}/logs/auth.log"

# ---------------------------------------------------------------------
# 1. Log directory the app writes to (bind-mounted into ddns-api)
# ---------------------------------------------------------------------

info "Готовлю каталог логов ($SCRIPT_DIR/logs)..."
mkdir -p "$SCRIPT_DIR/logs"
touch "$LOG_PATH"
chown -R 1000:1000 "$SCRIPT_DIR/logs"

if ! docker compose ps ddns-api 2>/dev/null | grep -q ddns-api; then
    err "Контейнер ddns-api не запущен. Подними стек и перезапусти этот скрипт:"
    err "  docker compose up -d"
    exit 1
fi

# Убедиться, что образ реально монтирует ./logs (нужно docker-compose.yml
# с добавленным volume ./logs:/app/logs — пересоздать контейнер, если нет)
if ! docker compose exec -T ddns-api sh -c 'test -w /app/logs' 2>/dev/null; then
    info "Пересоздаю ddns-api, чтобы подключить volume с логами..."
    docker compose up -d --force-recreate ddns-api
fi

# ---------------------------------------------------------------------
# 2. fail2ban
# ---------------------------------------------------------------------

info "Устанавливаю fail2ban..."
apt-get update -qq
apt-get install -y fail2ban >/dev/null

info "Создаю фильтры..."

cat > /etc/fail2ban/filter.d/ddns-admin.conf << 'EOF'
[Definition]
failregex = ^.*AUTH_FAIL ip=<HOST> kind=admin\s*$
ignoreregex =
EOF

cat > /etc/fail2ban/filter.d/ddns-token.conf << 'EOF'
[Definition]
failregex = ^.*AUTH_FAIL ip=<HOST> kind=token\s*$
ignoreregex =
EOF

info "Настраиваю jail'ы (sshd + ddns-admin + ddns-token)..."

cat > /etc/fail2ban/jail.d/ddns.conf << EOF
[sshd]
enabled = true
backend = systemd
port = ${SSH_PORT}
bantime = -1
findtime = 10m
maxretry = 5

[ddns-admin]
enabled = true
filter = ddns-admin
backend = auto
logpath = ${LOG_PATH}
bantime = -1
findtime = 10m
maxretry = 5

[ddns-token]
enabled = true
filter = ddns-token
backend = auto
logpath = ${LOG_PATH}
bantime = -1
findtime = 10m
maxretry = 3
EOF

systemctl enable fail2ban >/dev/null 2>&1 || true
systemctl restart fail2ban

sleep 2

ok "Готово. Статус:"
fail2ban-client status
echo
fail2ban-client status sshd || true
echo
fail2ban-client status ddns-admin || true
echo
fail2ban-client status ddns-token || true

echo
info "Проверить бан вручную:      fail2ban-client status ddns-admin"
info "Разбанить IP:                fail2ban-client set ddns-admin unbanip <IP>"
info "Тест фильтра на реальном логе: fail2ban-regex ${LOG_PATH} /etc/fail2ban/filter.d/ddns-admin.conf"
