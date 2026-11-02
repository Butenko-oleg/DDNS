#!/usr/bin/env bash
#
# Sets up nginx as a reverse proxy in front of ddns-api (127.0.0.1:8000)
# and gets a Let's Encrypt certificate via certbot's nginx plugin —
# reproduces the exact pattern `certbot --nginx` produces.
#
# Run this AFTER your domain's NS delegation at the registrar has
# propagated (this script refuses to proceed otherwise, to avoid
# wasting Let's Encrypt's rate limit on a domain that can't be
# validated yet).
#
# Usage:
#   sudo DOMAIN=ddns.example.com EMAIL=you@example.com ./scripts/setup-reverse-proxy.sh

set -euo pipefail

info() { printf '\033[36m%s\033[0m\n' "$1"; }
warn() { printf '\033[33m%s\033[0m\n' "$1"; }
ok()   { printf '\033[32m%s\033[0m\n' "$1"; }
err()  { printf '\033[31m%s\033[0m\n' "$1" >&2; }

if [ "$(id -u)" -ne 0 ]; then
    err "Run as root (sudo ./scripts/setup-reverse-proxy.sh)"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"

DOMAIN="${DOMAIN:-}"
if [ -z "$DOMAIN" ] && [ -f .env ]; then
    DOMAIN=$(grep ^DDNS_ZONE= .env 2>/dev/null | cut -d= -f2- || true)
fi
if [ -z "$DOMAIN" ]; then
    read -r -p "Домен для reverse proxy (например ddns.example.com): " DOMAIN
fi
[ -n "$DOMAIN" ] || { err "Домен обязателен."; exit 1; }

EMAIL="${EMAIL:-}"
if [ -z "$EMAIL" ]; then
    read -r -p "Email для Let's Encrypt (Enter — пропустить, без уведомлений об истечении): " EMAIL
fi

# ---------------------------------------------------------------------
# Preflight: домен должен уже резолвиться на этот сервер
# ---------------------------------------------------------------------

info "Проверяю, что $DOMAIN резолвится на этот сервер..."

SERVER_IP=$(curl -fsSL --max-time 5 https://api.ipify.org 2>/dev/null || true)
RESOLVED_IP=$(getent ahostsv4 "$DOMAIN" 2>/dev/null | awk '{print $1; exit}' || true)

if [ -z "$RESOLVED_IP" ]; then
    err "Домен $DOMAIN пока не резолвится вообще."
    err "Проверь делегацию NS у регистратора (см. README) и попробуй ещё раз позже —"
    err "распространение делегации может занимать от минут до нескольких часов."
    exit 1
fi

if [ -n "$SERVER_IP" ] && [ "$RESOLVED_IP" != "$SERVER_IP" ]; then
    warn "Домен резолвится в $RESOLVED_IP, а этот сервер видит свой IP как $SERVER_IP."
    warn "Если это ожидаемо (CDN, несколько IP и т.п.) — можно продолжить."
    read -r -p "Продолжить всё равно? (y/N): " CONT
    [[ "$CONT" =~ ^[Yy]$ ]] || exit 1
fi

ok "Домен резолвится, продолжаю."

# ---------------------------------------------------------------------
# nginx + certbot
# ---------------------------------------------------------------------

info "Устанавливаю nginx и certbot..."
apt-get update -qq
apt-get install -y nginx certbot python3-certbot-nginx >/dev/null

CONF_PATH="/etc/nginx/sites-available/${DOMAIN}"

if [ -f "$CONF_PATH" ]; then
    warn "$CONF_PATH уже существует, не трогаю."
else
    info "Создаю базовый конфиг nginx (пока без TLS — его добавит certbot)..."
    cat > "$CONF_PATH" << EOF
server {
    listen 80;
    server_name ${DOMAIN};

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
}
EOF
    ln -sf "$CONF_PATH" "/etc/nginx/sites-enabled/${DOMAIN}"
    nginx -t
    systemctl reload nginx
    ok "nginx настроен на порту 80."
fi

info "Запрашиваю сертификат Let's Encrypt (certbot --nginx)..."

CERTBOT_ARGS=(--nginx -d "$DOMAIN" --non-interactive --agree-tos --redirect)
if [ -n "$EMAIL" ]; then
    CERTBOT_ARGS+=(-m "$EMAIL")
else
    CERTBOT_ARGS+=(--register-unsafely-without-email)
fi

certbot "${CERTBOT_ARGS[@]}"

ok "Готово: https://${DOMAIN} настроен, сертификат получен."
info "Автопродление certbot настраивает сам (systemd timer certbot.timer)."
echo
info "Проверь снаружи: curl -I https://${DOMAIN}/admin"
