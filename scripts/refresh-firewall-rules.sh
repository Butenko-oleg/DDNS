#!/usr/bin/env bash
#
# Re-applies ufw-docker rules for the PowerDNS container.
#
# ufw-docker's "allow" rules pin to the container's CURRENT internal
# Docker network IP. If the container gets recreated (docker compose up
# --force-recreate, image rebuild, docker compose down/up, etc.), that
# IP can change — and the old rule silently stops matching, blocking
# DNS traffic to the new IP without any obvious error.
#
# Run this any time after recreating the powerdns container (or just
# routinely after any `docker compose up -d`, it's harmless to re-run).
#
# Usage:
#   sudo POWERDNS_CONTAINER=buten-powerdns ./scripts/refresh-firewall-rules.sh

set -euo pipefail

info() { printf '\033[36m%s\033[0m\n' "$1"; }
ok()   { printf '\033[32m%s\033[0m\n' "$1"; }
err()  { printf '\033[31m%s\033[0m\n' "$1" >&2; }

if [ "$(id -u)" -ne 0 ]; then
    err "Run as root (sudo ./scripts/refresh-firewall-rules.sh)"
    exit 1
fi

POWERDNS_CONTAINER="${POWERDNS_CONTAINER:-ddns-powerdns}"

if ! docker ps --format '{{.Names}}' | grep -qx "${POWERDNS_CONTAINER}"; then
    err "Container '${POWERDNS_CONTAINER}' not found/running."
    exit 1
fi

CURRENT_IP=$(docker inspect "${POWERDNS_CONTAINER}" \
    --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')

info "Текущий IP ${POWERDNS_CONTAINER} в docker-сети: ${CURRENT_IP}"

EXISTING_IP=$(ufw status verbose \
    | grep "allow ${POWERDNS_CONTAINER} 53/tcp" \
    | awk '{print $1}' || true)

if [ "$EXISTING_IP" = "$CURRENT_IP" ]; then
    ok "Правило файервола уже указывает на актуальный IP — ничего делать не нужно."
    exit 0
fi

if [ -n "$EXISTING_IP" ]; then
    info "Старое правило указывало на ${EXISTING_IP} — удаляю..."
    ufw-docker delete allow "${POWERDNS_CONTAINER}" || true
fi

info "Создаю правило для ${CURRENT_IP}..."
ufw-docker allow "${POWERDNS_CONTAINER}" 53/tcp
ufw-docker allow "${POWERDNS_CONTAINER}" 53/udp

ok "Готово:"
ufw status verbose | grep 53
