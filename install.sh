#!/usr/bin/env bash
#
# Interactive installer for Self-hosted DDNS.
#
# Asks only for what actually needs a human decision (zone name, NS
# hostnames, server IP, admin login, ports) — generates every secret
# itself, brings up the stack, configures the DNS zone, optionally sets
# up the firewall, and prints a summary of everything you'll need
# afterwards (domain, admin login, passwords, what to configure at your
# registrar).
#
# Safe to re-run: it asks before overwriting .env / powerdns/pdns.conf,
# and skips zone creation if the zone already exists.

set -euo pipefail

bold() { printf '\033[1m%s\033[0m\n' "$1"; }
info() { printf '\033[36m%s\033[0m\n' "$1"; }
warn() { printf '\033[33m%s\033[0m\n' "$1"; }
ok()   { printf '\033[32m%s\033[0m\n' "$1"; }
err()  { printf '\033[31m%s\033[0m\n' "$1" >&2; }

ask() {
    local prompt="$1" default="${2:-}" reply
    if [ -n "$default" ]; then
        read -r -p "$prompt [$default]: " reply
        echo "${reply:-$default}"
    else
        read -r -p "$prompt: " reply
        echo "$reply"
    fi
}

ask_yes_no() {
    local prompt="$1" default="${2:-y}" reply
    read -r -p "$prompt $( [ "$default" = y ] && echo "(Y/n)" || echo "(y/N)" ): " reply
    reply="${reply:-$default}"
    [[ "$reply" =~ ^[Yy] ]]
}

gen_secret() {
    openssl rand -base64 32 | tr -d '/+=\n'
}

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || { err "Не найдена команда: $1"; exit 1; }
}

# ---------------------------------------------------------------------
# 0. Проверки
# ---------------------------------------------------------------------

if [ "$(id -u)" -ne 0 ]; then
    err "Запусти скрипт от root (sudo ./install.sh)"
    exit 1
fi

require_cmd openssl
require_cmd curl

if ! command -v docker >/dev/null 2>&1; then
    warn "Docker не найден."
    ask_yes_no "Установить Docker сейчас (официальный скрипт get.docker.com)?" y || {
        err "Без Docker установка невозможна."
        exit 1
    }
    curl -fsSL https://get.docker.com | sh
    ok "Docker установлен."
fi

if ! docker compose version >/dev/null 2>&1; then
    err "Не найден 'docker compose' (плагин Docker Compose v2). Обнови Docker."
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

bold "=== Установка Self-hosted DDNS ==="
echo

# ---------------------------------------------------------------------
# 1. .env — спросить, если уже есть
# ---------------------------------------------------------------------

if [ -f .env ]; then
    warn ".env уже существует."
    ask_yes_no "Перезаписать и пройти установку заново?" n || {
        info "Оставляю .env как есть, пропускаю сбор данных."
        SKIP_ENV=1
    }
fi

if [ -z "${SKIP_ENV:-}" ]; then

    echo
    ZONE=""
    while [ -z "$ZONE" ]; do
        ZONE=$(ask "Домен/зона для DDNS (например ddns.example.com)" "")
        [ -n "$ZONE" ] || warn "Зона обязательна."
    done

    NS1=$(ask "Имя первого нейм-сервера" "ns1.$ZONE")
    NS2=$(ask "Имя второго нейм-сервера (Enter — пропустить)" "ns2.$ZONE")

    DETECTED_IP=$(curl -fsSL --max-time 5 https://api.ipify.org 2>/dev/null || true)
    SERVER_IP=""
    while [ -z "$SERVER_IP" ]; do
        SERVER_IP=$(ask "Публичный IP этого сервера" "$DETECTED_IP")
        [ -n "$SERVER_IP" ] || warn "IP обязателен."
    done

    ADMIN_USER=$(ask "Логин админ-панели" "admin")

    read -r -p "Пароль админ-панели (Enter — сгенерировать случайный): " ADMIN_PASSWORD
    if [ -z "$ADMIN_PASSWORD" ]; then
        ADMIN_PASSWORD=$(gen_secret)
        info "Сгенерирован пароль админки (покажу в итоговой сводке)."
    fi

    ask_yes_no "Тестируешь локально, без TLS reverse proxy?" n && PUBLIC_SCHEME=http || PUBLIC_SCHEME=https

    echo
    info "Порты для файервола (сейчас или позже — можно пропустить настройку файервола ниже):"
    SSH_PORT=$(ask "SSH порт" "22")
    HTTP_PORT=$(ask "HTTP порт reverse proxy" "80")
    HTTPS_PORT=$(ask "HTTPS порт reverse proxy" "443")

    DB_PASSWORD=$(gen_secret)
    PDNS_API_KEY=$(gen_secret)

    echo
    bold "Проверь введённые данные:"
    echo "  Зона:              $ZONE"
    echo "  NS1:                $NS1"
    echo "  NS2:                ${NS2:-(нет)}"
    echo "  IP сервера:         $SERVER_IP"
    echo "  Admin логин:        $ADMIN_USER"
    echo "  Admin пароль:       $ADMIN_PASSWORD"
    echo "  Схема (PUBLIC_SCHEME): $PUBLIC_SCHEME"
    echo "  Порты для файервола: SSH=$SSH_PORT HTTP=$HTTP_PORT HTTPS=$HTTPS_PORT"
    echo
    ask_yes_no "Всё верно, продолжить установку?" y || { info "Отменено."; exit 0; }

    cat > .env << EOF
ADMIN_USER=$ADMIN_USER
ADMIN_PASSWORD=$ADMIN_PASSWORD
DDNS_ZONE=$ZONE
PDNS_API_KEY=$PDNS_API_KEY
DB_NAME=powerdns
DB_USER=pdns
DB_PASSWORD=$DB_PASSWORD
PUBLIC_SCHEME=$PUBLIC_SCHEME
EOF
    chmod 600 .env
    ok ".env создан."

else
    # .env уже существовал и мы его не трогаем — подтянуть значения из него
    # для последующих шагов (zone setup, firewall, summary).
    set -a
    # shellcheck disable=SC1091
    source .env
    set +a
    ZONE="$DDNS_ZONE"
    NS1=$(ask "Имя первого нейм-сервера" "ns1.$ZONE")
    NS2=$(ask "Имя второго нейм-сервера (Enter — пропустить)" "ns2.$ZONE")
    DETECTED_IP=$(curl -fsSL --max-time 5 https://api.ipify.org 2>/dev/null || true)
    SERVER_IP=$(ask "Публичный IP этого сервера" "$DETECTED_IP")
    SSH_PORT=$(ask "SSH порт" "22")
    HTTP_PORT=$(ask "HTTP порт reverse proxy" "80")
    HTTPS_PORT=$(ask "HTTPS порт reverse proxy" "443")
fi

# ---------------------------------------------------------------------
# 2. powerdns/pdns.conf
# ---------------------------------------------------------------------

echo
if [ -f powerdns/pdns.conf ]; then
    warn "powerdns/pdns.conf уже существует."
    ask_yes_no "Перезаписать?" n && REGEN_PDNS_CONF=1 || REGEN_PDNS_CONF=0
else
    REGEN_PDNS_CONF=1
fi

if [ "$REGEN_PDNS_CONF" = 1 ]; then
    cp powerdns/pdns.conf.example powerdns/pdns.conf
    sed -i "s/CHANGE_ME_MATCH_DB_PASSWORD_IN_ENV/${DB_PASSWORD:-$(grep ^DB_PASSWORD= .env | cut -d= -f2-)}/" powerdns/pdns.conf
    sed -i "s/CHANGE_ME_MATCH_PDNS_API_KEY_IN_ENV/${PDNS_API_KEY:-$(grep ^PDNS_API_KEY= .env | cut -d= -f2-)}/" powerdns/pdns.conf
    chmod 600 powerdns/pdns.conf
    ok "powerdns/pdns.conf создан из шаблона."
fi

# ---------------------------------------------------------------------
# 3. Поднять стек
# ---------------------------------------------------------------------

echo
info "Поднимаю контейнеры (docker compose up -d)..."
docker compose up -d

# ---------------------------------------------------------------------
# 4. Ждать готовности PowerDNS API
# ---------------------------------------------------------------------

info "Жду готовности PowerDNS..."
READY=0
for _ in $(seq 1 30); do
    if docker compose exec -T ddns-api python3 -c "
import os, sys, requests
try:
    r = requests.get(
        os.environ['PDNS_API_URL'] + '/api/v1/servers/localhost',
        headers={'X-API-Key': os.environ['PDNS_API_KEY']},
        timeout=2,
    )
    sys.exit(0 if r.status_code == 200 else 1)
except Exception:
    sys.exit(1)
" >/dev/null 2>&1; then
        READY=1
        break
    fi
    sleep 2
done

if [ "$READY" = 1 ]; then
    ok "PowerDNS готов."
else
    warn "PowerDNS не ответил за 60 секунд — проверь: docker compose logs powerdns"
    warn "Продолжаю всё равно, но настройка зоны ниже может не пройти."
fi

# ---------------------------------------------------------------------
# 5. Настроить зону
# ---------------------------------------------------------------------

echo
info "Настраиваю зону $ZONE..."

if docker compose exec -T powerdns pdnsutil list-zone "$ZONE" >/dev/null 2>&1; then
    info "Зона уже существует, пропускаю create-zone."
else
    docker compose exec -T powerdns pdnsutil create-zone "$ZONE" "$NS1"
fi

ns_records=("${NS1}.")
[ -n "${NS2:-}" ] && ns_records+=("${NS2}.")

docker compose exec -T powerdns pdnsutil replace-rrset "$ZONE" @ NS "${ns_records[@]}"
docker compose exec -T powerdns pdnsutil replace-rrset "$ZONE" "$NS1" A "$SERVER_IP"
[ -n "${NS2:-}" ] && docker compose exec -T powerdns pdnsutil replace-rrset "$ZONE" "$NS2" A "$SERVER_IP"

# Explicit SOA with a short negative-caching TTL (the last field, aka
# "MINIMUM"). PowerDNS's own default here tends to be an hour — meaning
# any client resolver (e.g. a MikroTik router) that queries a hostname
# a moment too early caches "doesn't exist" for a full hour, requiring
# a manual cache flush before it works. 300s matches the TTL DDNS
# records themselves use, so a brief miss self-corrects quickly instead.
SOA_SERIAL="$(date +%Y%m%d)01"
docker compose exec -T powerdns pdnsutil replace-rrset "$ZONE" @ SOA \
    "${NS1}. hostmaster.${ZONE}. ${SOA_SERIAL} 10800 3600 604800 300"

echo
docker compose exec -T powerdns pdnsutil check-zone "$ZONE" || warn "check-zone нашёл проблемы — см. вывод выше."

# ---------------------------------------------------------------------
# 6. Файервол (по желанию)
# ---------------------------------------------------------------------

echo
if ask_yes_no "Настроить файервол (UFW) сейчас?" y; then
    SSH_PORT="$SSH_PORT" HTTP_PORT="$HTTP_PORT" HTTPS_PORT="$HTTPS_PORT" ./scripts/setup-firewall.sh
else
    info "Пропускаю настройку файервола — сделай это позже: ./scripts/setup-firewall.sh"
fi

# ---------------------------------------------------------------------
# 7. Reverse proxy + TLS (по желанию, только если делегация уже прошла)
# ---------------------------------------------------------------------

echo
REVERSE_PROXY_DONE=0
warn "Reverse proxy с TLS (nginx + Let's Encrypt) можно настроить только"
warn "после того, как делегация NS у регистратора домена уже распространилась —"
warn "иначе Let's Encrypt не сможет провалидировать домен."
if ask_yes_no "NS у регистратора уже настроены и распространились — настроить reverse proxy сейчас?" n; then
    if DOMAIN="$ZONE" ./scripts/setup-reverse-proxy.sh; then
        REVERSE_PROXY_DONE=1
    else
        warn "Не получилось — можно повторить позже: sudo DOMAIN=$ZONE ./scripts/setup-reverse-proxy.sh"
    fi
else
    info "Пропускаю — когда делегация распространится, запусти:"
    info "  sudo DOMAIN=$ZONE ./scripts/setup-reverse-proxy.sh"
fi

# ---------------------------------------------------------------------
# 8. fail2ban (по желанию)
# ---------------------------------------------------------------------

echo
if ask_yes_no "Настроить fail2ban для SSH и админ-панели сейчас?" y; then
    SSH_PORT="$SSH_PORT" ./scripts/setup-fail2ban.sh
else
    info "Пропускаю — сделай это позже: sudo ./scripts/setup-fail2ban.sh"
fi

# ---------------------------------------------------------------------
# 9. Итоговая сводка
# ---------------------------------------------------------------------

CUR_ADMIN_USER=$(grep ^ADMIN_USER= .env | cut -d= -f2-)
CUR_ADMIN_PASSWORD=$(grep ^ADMIN_PASSWORD= .env | cut -d= -f2-)
CUR_DB_PASSWORD=$(grep ^DB_PASSWORD= .env | cut -d= -f2-)
CUR_PDNS_KEY=$(grep ^PDNS_API_KEY= .env | cut -d= -f2-)

if [ "$REVERSE_PROXY_DONE" = 1 ]; then
    PROXY_LINE="Reverse proxy настроен — https://$ZONE уже должен работать."
else
    PROXY_LINE="Reverse proxy НЕ настроен. Когда делегация распространится:
     sudo DOMAIN=$ZONE ./scripts/setup-reverse-proxy.sh"
fi

SUMMARY_FILE="./install-summary.txt"

cat > "$SUMMARY_FILE" << EOF
=== Self-hosted DDNS — итоги установки ===
Сгенерировано: $(date)

Админ-панель:        https://$ZONE/admin
Логин:                $CUR_ADMIN_USER
Пароль:               $CUR_ADMIN_PASSWORD

DNS-зона:             $ZONE
NS1:                  $NS1 -> $SERVER_IP
NS2:                  ${NS2:+$NS2 -> $SERVER_IP}

PowerDNS API-ключ:    $CUR_PDNS_KEY
Пароль БД:            $CUR_DB_PASSWORD

--- Что нужно сделать ещё руками ---

1. У регистратора домена пропиши нейм-серверы зоны (glue-записи):
     $NS1 -> $SERVER_IP
     ${NS2:+$NS2 -> $SERVER_IP}
   Этот шаг вне твоего сервера, автоматизировать нельзя.

2. $PROXY_LINE

3. Этот файл содержит все секреты открытым текстом.
   Сохрани куда-то в надёжное место (менеджер паролей) и удали с сервера:
     shred -u $SUMMARY_FILE
EOF
chmod 600 "$SUMMARY_FILE"

echo
bold "=== Установка завершена ==="
cat "$SUMMARY_FILE"
