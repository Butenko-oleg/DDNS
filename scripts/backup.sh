#!/usr/bin/env bash
#
# backup.sh — офлайн-бэкап DDNS-стека (PowerDNS + PostgreSQL + ddns-api + monitor).
#
# Собирает в один архив всё, без чего сервер не поднять заново:
#   - дамп БД PostgreSQL (зоны PowerDNS, хосты ddns_clients, токены, пароль админки)
#   - текстовую выгрузку зон (BIND-формат, читается глазами и грузится обратно)
#   - конфиги стека (.env, docker-compose.yml, pdns.conf, init.sql, init-скрипты)
#   - nginx, сертификаты Let's Encrypt, crontab, правила fail2ban
#   - манифест: версии образов, serial зоны, число записей, чек-суммы
#
# Результат: /opt/backups/ddns-backup-ГГГГ-ММ-ДД_ЧЧММСС.tar.gz[.gpg]
# Шифрование (AES-256, пароль из /etc/ddns-backup.pass) — по умолчанию включено,
# потому что в архиве лежат токены всех хостов и пароль админки.
#
# Использование:
#   sudo ./scripts/backup.sh              # создать бэкап
#   sudo ./scripts/backup.sh --no-encrypt # без шифрования (не рекомендуется)
#   sudo ./scripts/backup.sh --keep 60    # сколько архивов хранить (по умолчанию 30)
#
# Код возврата 0 — бэкап создан и проверен (архив читается, дамп непустой).

set -euo pipefail

PROJECT_DIR="${PROJECT_DIR:-/opt/buten-ddns}"
BACKUP_DIR="${BACKUP_DIR:-/opt/backups}"
PASS_FILE="${PASS_FILE:-/etc/ddns-backup.pass}"
KEEP="${KEEP:-30}"
ENCRYPT=1
STAMP="$(date +%Y-%m-%d_%H%M%S)"

while [ $# -gt 0 ]; do
    case "$1" in
        --no-encrypt) ENCRYPT=0 ;;
        --keep)       KEEP="${2:?--keep требует число}"; shift ;;
        -h|--help)    sed -n '2,30p' "$0"; exit 0 ;;
        *) echo "Неизвестный аргумент: $1" >&2; exit 2 ;;
    esac
    shift
done

info() { printf '\033[36m%s\033[0m\n' "$*"; }
ok()   { printf '\033[32m%s\033[0m\n' "$*"; }
warn() { printf '\033[33m%s\033[0m\n' "$*" >&2; }
err()  { printf '\033[31m%s\033[0m\n' "$*" >&2; }

[ "$(id -u)" -eq 0 ] || { err "Запускать от root: sudo $0"; exit 1; }
[ -d "$PROJECT_DIR" ] || { err "Нет каталога проекта: $PROJECT_DIR"; exit 1; }

WORK="$(mktemp -d /tmp/ddns-backup.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

BUNDLE_ROOT="$WORK/ddns-backup-$STAMP"
mkdir -p "$BUNDLE_ROOT"/{db,zones,config,scripts,system,nginx,letsencrypt}

# ---------- 1. PostgreSQL ----------
info "Дамп PostgreSQL…"
if ! docker exec buten-postgres pg_dump -U pdns -d powerdns -Fc > "$BUNDLE_ROOT/db/powerdns.dump"; then
    err "pg_dump упал — бэкап прерван"
    exit 1
fi
DUMP_SIZE=$(stat -c %s "$BUNDLE_ROOT/db/powerdns.dump")
[ "$DUMP_SIZE" -gt 10000 ] || { err "Дамп подозрительно мал ($DUMP_SIZE байт)"; exit 1; }
ok "  дамп: $(numfmt --to=iec "$DUMP_SIZE" 2>/dev/null || echo "$DUMP_SIZE байт")"

# Текстовая выгрузка ключевых таблиц — чтобы данные можно было прочитать
# и восстановить руками, если pg_restore недоступен.
docker exec buten-postgres psql -U pdns -d powerdns -At -F $'\t' \
    -c "COPY (SELECT id, hostname, token, host(last_ip), last_update, active, description FROM ddns_clients ORDER BY id) TO STDOUT" \
    > "$BUNDLE_ROOT/db/ddns_clients.tsv" 2>/dev/null || warn "  не удалось выгрузить ddns_clients.tsv"

# ---------- 2. Зоны PowerDNS ----------
info "Выгрузка зон PowerDNS…"
ZONES="$(docker exec buten-powerdns pdnsutil list-all-zones 2>/dev/null | tr -d '\r')"
[ -n "$ZONES" ] || { err "PowerDNS не вернул список зон"; exit 1; }
for z in $ZONES; do
    docker exec buten-powerdns pdnsutil list-zone "$z" > "$BUNDLE_ROOT/zones/${z}.zone" 2>/dev/null || {
        err "  не удалось выгрузить зону $z"; exit 1; }
    printf '%-30s %s записей\n' "$z" "$(wc -l < "$BUNDLE_ROOT/zones/${z}.zone")"
done
docker exec buten-powerdns pdnsutil check-all-zones > "$BUNDLE_ROOT/zones/check-zones.txt" 2>&1 || true

# ---------- 3. Конфиги стека ----------
info "Конфиги стека…"
for f in .env docker-compose.yml init.sql schema.pgsql.sql powerdns/pdns.conf monitor/agents.yaml; do
    if [ -f "$PROJECT_DIR/$f" ]; then
        install -m 600 "$PROJECT_DIR/$f" "$BUNDLE_ROOT/config/$(basename "$f")"
    fi
done
if [ -f "$PROJECT_DIR/monitor/data/status.json" ]; then
    install -m 600 "$PROJECT_DIR/monitor/data/status.json" "$BUNDLE_ROOT/config/monitor-status.json"
fi
cp -a "$PROJECT_DIR/scripts" "$BUNDLE_ROOT/scripts/" 2>/dev/null || true
cp -a "$PROJECT_DIR/api" "$BUNDLE_ROOT/config/api-src" 2>/dev/null || true
cp -a "$PROJECT_DIR/monitor" "$BUNDLE_ROOT/config/monitor-src" 2>/dev/null || true
rm -rf "$BUNDLE_ROOT/config/api-src/__pycache__" 2>/dev/null || true

# ---------- 4. Системная часть ----------
info "nginx, сертификаты, cron, fail2ban…"
cp -a /etc/nginx/sites-available "$BUNDLE_ROOT/nginx/" 2>/dev/null || true
cp -a /etc/letsencrypt/live "$BUNDLE_ROOT/letsencrypt/" 2>/dev/null || true
cp -a /etc/letsencrypt/archive "$BUNDLE_ROOT/letsencrypt/" 2>/dev/null || true
cp -a /etc/letsencrypt/renewal "$BUNDLE_ROOT/letsencrypt/" 2>/dev/null || true
crontab -l > "$BUNDLE_ROOT/system/crontab-root.txt" 2>/dev/null || true
cp -a /etc/fail2ban/jail.d "$BUNDLE_ROOT/system/" 2>/dev/null || true
cp -a /etc/ufw-ssh-hosts.state "$BUNDLE_ROOT/system/" 2>/dev/null || true
ufw status verbose > "$BUNDLE_ROOT/system/ufw-status.txt" 2>/dev/null || true
cp -a /etc/ssh/sshd_config "$BUNDLE_ROOT/system/sshd_config" 2>/dev/null || true

# ---------- 5. Манифест ----------
info "Манифест…"
{
    echo "DDNS backup manifest"
    echo "host:        $(hostname) ($(curl -s -m 5 ifconfig.me || echo '?') )"
    echo "created:     $(date -Is)"
    echo "project:     $PROJECT_DIR"
    echo
    echo "== версии"
    echo "os:          $(. /etc/os-release; echo "$PRETTY_NAME")"
    echo "kernel:      $(uname -r)"
    echo "docker:      $(docker --version)"
    echo "compose:     $(docker compose version --short 2>/dev/null || echo '?')"
    echo "pdns:        $(docker exec buten-powerdns pdns_server --version 2>&1 | head -1 | sed 's/^.*Server //')"
    echo "postgres:    $(docker exec buten-postgres postgres --version)"
    echo
    echo "== образы"
    docker ps -a --format '{{.Names}}\t{{.Image}}\t{{.Status}}' 2>/dev/null || true
    docker image ls --digests --format '{{.Repository}}:{{.Tag}}\t{{.Digest}}\t{{.ID}}' 2>/dev/null || true
    echo
    echo "== образ приложения"
    echo "app.py md5:  $(md5sum "$PROJECT_DIR/api/app.py" | cut -d' ' -f1)"
    echo
    echo "== данные"
    docker exec buten-postgres psql -U pdns -d powerdns -At -F' ' -c \
        "SELECT 'domains='||(SELECT count(*) FROM domains)||' records='||(SELECT count(*) FROM records)||' clients='||(SELECT count(*) FROM ddns_clients)||' active='||(SELECT count(*) FROM ddns_clients WHERE active);"
    echo "zone serial: $(docker exec buten-postgres psql -U pdns -d powerdns -At -c \
        "SELECT split_part(content,' ',3) FROM records WHERE type='SOA' LIMIT 1;" 2>/dev/null)"
    echo
    echo "== сертификаты"
    nginx -T 2>/dev/null | grep -E "ssl_certificate " | awk '{print $2}' | sort -u | while read -r c; do
        if [ -f "$c" ]; then
            echo "$c истекает $(openssl x509 -enddate -noout -in "$c" | cut -d= -f2)"
        fi
    done
} > "$BUNDLE_ROOT/MANIFEST.txt" 2>/dev/null

# ---------- 6. Сборка архива ----------
info "Упаковка…"
( cd "$WORK" && tar czf "ddns-backup-$STAMP.tar.gz" "ddns-backup-$STAMP" )
ARCHIVE="$WORK/ddns-backup-$STAMP.tar.gz"
tar tzf "$ARCHIVE" > /dev/null || { err "архив не читается"; exit 1; }

mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"

if [ "$ENCRYPT" -eq 1 ]; then
    if [ ! -s "$PASS_FILE" ]; then
        umask 077
        openssl rand -base64 32 > "$PASS_FILE"
        warn "Создан новый пароль шифрования: $PASS_FILE — сохраните его отдельно, без него бэкап не расшифровать"
    fi
    openssl enc -aes-256-cbc -pbkdf2 -salt -in "$ARCHIVE" \
        -pass "file:$PASS_FILE" -out "$BACKUP_DIR/ddns-backup-$STAMP.tar.gz.gpg"
    FINAL="$BACKUP_DIR/ddns-backup-$STAMP.tar.gz.gpg"
    # Проверка: расшифровывается и читается как tar
    openssl enc -d -aes-256-cbc -pbkdf2 -in "$FINAL" -pass "file:$PASS_FILE" \
        | tar tzf - > /dev/null || { err "зашифрованный архив не проверяется"; exit 1; }
else
    install -m 600 "$ARCHIVE" "$BACKUP_DIR/ddns-backup-$STAMP.tar.gz"
    FINAL="$BACKUP_DIR/ddns-backup-$STAMP.tar.gz"
    tar tzf "$FINAL" > /dev/null
fi

sha256sum "$FINAL" | sed "s|$BACKUP_DIR/||" > "$FINAL.sha256"
SIZE=$(stat -c %s "$FINAL")

# ---------- 7. Ротация ----------
mapfile -t OLD < <(ls -1t "$BACKUP_DIR"/ddns-backup-* 2>/dev/null | grep -v '\.sha256$' | tail -n +$((KEEP+1)))
for f in "${OLD[@]:-}"; do
    [ -n "$f" ] && rm -f "$f" "$f.sha256"
done
if [ "${#OLD[@]}" -gt 0 ] && [ -n "${OLD[0]:-}" ]; then
    info "Удалено старых архивов: ${#OLD[@]} (храним $KEEP)"
fi

# ---------- 8. Итог ----------
ok "Бэкап готов: $FINAL"
ok "  размер: $(numfmt --to=iec "$SIZE" 2>/dev/null || echo "$SIZE")"
ok "  sha256: $(cut -d' ' -f1 "$FINAL.sha256")"
echo
echo "Забрать к себе (с Mac):"
echo "  scp root@${SSH_HOST:-<IP-сервера>}:$FINAL ."
echo "Восстановить:"
echo "  sudo ./scripts/restore.sh --bundle $FINAL"
