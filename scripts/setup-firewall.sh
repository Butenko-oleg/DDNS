#!/usr/bin/env bash
#
# Sets up UFW so that only the ports this stack actually needs are
# reachable from outside: SSH, DNS (53/tcp+udp), and your reverse proxy's
# HTTP/HTTPS ports. Everything else stays blocked, including Postgres and
# the PowerDNS API — those are never published to the host at all, but
# this script also makes sure nothing else on the box leaks out by
# accident.
#
# Safe to re-run. Must run as root. Run this AFTER `docker compose up -d`
# has created the containers at least once (so ufw-docker can find them).
#
# Override defaults if needed, e.g.:
#   SSH_PORT=2222 HTTP_PORT=8080 ./scripts/setup-firewall.sh

set -euo pipefail

SSH_PORT="${SSH_PORT:-22}"
HTTP_PORT="${HTTP_PORT:-80}"
HTTPS_PORT="${HTTPS_PORT:-443}"
POWERDNS_CONTAINER="${POWERDNS_CONTAINER:-ddns-powerdns}"

if [ "$(id -u)" -ne 0 ]; then
    echo "Run this as root (sudo ./scripts/setup-firewall.sh)" >&2
    exit 1
fi

echo "==> Installing ufw"
apt-get update -qq
apt-get install -y ufw >/dev/null

echo "==> Allowing required ports (before enabling — so we don't lock ourselves out)"
ufw allow "${SSH_PORT}/tcp"   comment 'SSH'
ufw allow "${HTTP_PORT}/tcp"  comment 'reverse proxy HTTP'
ufw allow "${HTTPS_PORT}/tcp" comment 'reverse proxy HTTPS'
ufw allow 53/tcp              comment 'DNS'
ufw allow 53/udp              comment 'DNS'

echo "==> Enabling ufw"
ufw --force enable

echo "==> Installing ufw-docker (fixes UFW/Docker iptables interaction)"
if [ ! -x /usr/local/bin/ufw-docker ]; then
    curl -fsSL -o /usr/local/bin/ufw-docker \
        https://github.com/chaifeng/ufw-docker/raw/master/ufw-docker
    chmod +x /usr/local/bin/ufw-docker
fi
ufw-docker install
systemctl restart ufw

echo "==> Allowing the PowerDNS container specifically"
if docker ps --format '{{.Names}}' | grep -qx "${POWERDNS_CONTAINER}"; then
    ufw-docker allow "${POWERDNS_CONTAINER}" 53/tcp
    ufw-docker allow "${POWERDNS_CONTAINER}" 53/udp
else
    echo "WARNING: container '${POWERDNS_CONTAINER}' not found/running." >&2
    echo "Start the stack first (docker compose up -d), then re-run this script." >&2
fi

echo
echo "==> Done. Current rules:"
ufw status verbose

echo
echo "Verify from a DIFFERENT machine (not this server):"
echo "  nmap -Pn <this-server-IP>"
echo "Expected open: ${SSH_PORT}, 53, ${HTTP_PORT}, ${HTTPS_PORT}. Nothing else."
