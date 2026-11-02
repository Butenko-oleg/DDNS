#!/usr/bin/env bash
#
# restore.sh — восстановление DDNS-стека из офлайн-бэкапа.
#
# Режимы:
#   --verify-only            проверить архив, не трогая рабочий сервер:
#                            расшифровать, сверить sha256, развернуть дамп
#                            во временный контейнер postgres и посчитать строки.
#                            Это единственный способ убедиться, что бэкап живой.
#   --dest DIR               распаковать архив в каталог DIR (конфиги + дамп),
#                            ничего не устанавливая.
#   --in-place               восстановить поверх /opt/buten-ddns (ОПАСНО: заменит
#                            .env, конфиги и базу; требует --yes).
#
# Примеры:
#   sudo ./scripts/restore.sh --bundle /opt/backups/ddns-backup-2026-11-02_030000.tar.gz.gpg --verify-only
#   sudo ./scripts/restore.sh --bundle ... --dest /root/restore-test
#   sudo ./scripts/restore.sh --bundle ... --in-place --yes

set -euo pipefail

PROJECT_DIR="${PROJECT_DIR:-/opt/buten-ddns}"
PASS_FILE="${PASS_FILE:-/etc/ddns-backup.pass}"
BUNDLE=""
MODE=""
DEST=""
ASSUME_YES=0

while [ $# -gt 0 ]; do
    case "$1" in
        --bundle)      BUNDLE="${2:?}"; shift ;;
        --verify-only) MODE=verify ;;
        --dest)        MODE=dest; DEST="${2:?}"; shift ;;
        --in-place)    MODE=inplace ;;
        --yes)         ASSUME_YES=1 ;;
        -h|--help)     sed -n '2,25p' "$0"; exit 0 ;;
        *) echo "Неизвестный аргумент: $1" >&2; exit 2 ;;
    esac
    shift
done

info() { printf '\033[36m%s\033[0m\n' "$*"; }
ok()   { printf '\033[32m%s\033[0m\n' "$*"; }
warn() { printf '\033[33m%s\033[0m\n' "$*" >&2; }
err()  { printf '\033[31m%s\033[0m\n' "$*" >&2; }

[ -n "$BUNDLE" ] || { err "Укажи --bundle <файл>"; exit 2; }
[ -f "$BUNDLE" ] || { err "Нет файла: $BUNDLE"; exit 1; }
[ -n "$MODE" ]   || { err "Укажи режим: --verify-only | --dest DIR | --in-place"; exit 2; }
[ "$(id -u)" -eq 0 ] || { err "Запускать от root"; exit 1; }

WORK="$(mktemp -d /tmp/ddns-restore.XXXXXX)"
TMP_CLEAN=""
cleanup() {
    rm -rf "$WORK"
    if [ -n "$TMP_CLEAN" ]; then docker rm -f "$TMP_CLEAN" >/dev/null 2>&1 || true; fi
}
trap cleanup EXIT

# ---------- 1. Расшифровка и проверка целостности ----------
info "Проверка архива…"
ARCHIVE="$BUNDLE"
case "$BUNDLE" in
    *.gpg)
        [ -s "$PASS_FILE" ] || { err "Нет файла с паролем: $PASS_FILE"; exit 1; }
        openssl enc -d -aes-256-cbc -pbkdf2 -in "$BUNDLE" -pass "file:$PASS_FILE" \
            -out "$WORK/bundle.tar.gz" || { err "Не расшифровывается (неверный пароль?)"; exit 1; }
        ARCHIVE="$WORK/bundle.tar.gz"
        ok "  расшифровано"
        ;;
esac

if [ -f "$BUNDLE.sha256" ]; then
    EXPECT="$(cut -d' ' -f1 "$BUNDLE.sha256")"
    ACTUAL="$(sha256sum "$BUNDLE" | cut -d' ' -f1)"
    if [ "$EXPECT" = "$ACTUAL" ]; then ok "  sha256 совпадает"; else
        err "  sha256 НЕ совпадает (ожидалось $EXPECT, получено $ACTUAL)"; exit 1
    fi
else
    warn "  файла .sha256 нет — целостность не проверить"
fi

mkdir -p "$WORK/x"
tar xzf "$ARCHIVE" -C "$WORK/x" || { err "архив не распаковывается"; exit 1; }
ROOT="$(find "$WORK/x" -maxdepth 1 -mindepth 1 -type d | head -1)"
[ -n "$ROOT" ] || { err "в архиве нет каталога"; exit 1; }
ok "  внутри: $(basename "$ROOT")"

if [ -f "$ROOT/MANIFEST.txt" ]; then
    sed 's/^/    /' "$ROOT/MANIFEST.txt" | head -30
fi

DUMP="$ROOT/db/powerdns.dump"
[ -s "$DUMP" ] || { err "в архиве нет дампа БД"; exit 1; }

# ---------- 2. Режим проверки ----------
if [ "$MODE" = verify ]; then
    info "Разворачиваю дамп во временный PostgreSQL для проверки…"
    TMP_CLEAN="ddns-restore-test"
    docker rm -f "$TMP_CLEAN" >/dev/null 2>&1 || true
    docker run -d --rm --name "$TMP_CLEAN" \
        -e POSTGRES_PASSWORD=test -e POSTGRES_DB=powerdns postgres:16 >/dev/null

    for _ in $(seq 1 60); do
        docker exec "$TMP_CLEAN" pg_isready -U postgres >/dev/null 2>&1 && break
        sleep 1
    done
    docker exec "$TMP_CLEAN" pg_isready -U postgres >/dev/null 2>&1 || { err "тестовый postgres не поднялся"; exit 1; }

    docker cp "$DUMP" "$TMP_CLEAN":/tmp/powerdns.dump >/dev/null
    docker exec "$TMP_CLEAN" pg_restore -U postgres -d powerdns --no-owner --no-privileges /tmp/powerdns.dump >/dev/null 2>&1 || true

    echo
    docker exec "$TMP_CLEAN" psql -U postgres -d powerdns -At -F' | ' -c \
        "SELECT 'domains', count(*) FROM domains UNION ALL SELECT 'records', count(*) FROM records UNION ALL SELECT 'ddns_clients', count(*) FROM ddns_clients UNION ALL SELECT 'admin_credentials', count(*) FROM admin_credentials;"
    echo
    docker exec "$TMP_CLEAN" psql -U postgres -d powerdns -c \
        "SELECT name, type, count(*) FROM records GROUP BY 1,2 ORDER BY 1,2 LIMIT 10;" 2>/dev/null || true

    RECORDS="$(docker exec "$TMP_CLEAN" psql -U postgres -d powerdns -At -c "SELECT count(*) FROM records;" | tr -d '\r')"
    CLIENTS="$(docker exec "$TMP_CLEAN" psql -U postgres -d powerdns -At -c "SELECT count(*) FROM ddns_clients;" | tr -d '\r')"
    [ "${RECORDS:-0}" -gt 0 ] || { err "в дампе 0 записей DNS — бэкап пустой"; exit 1; }
    [ "${CLIENTS:-0}" -gt 0 ] || { err "в дампе 0 хостов — бэкап пустой"; exit 1; }

    ok "Дамп разворачивается: $RECORDS записей DNS, $CLIENTS хостов — бэкап пригоден к восстановлению"
    exit 0
fi

# ---------- 3. Распаковка в каталог ----------
if [ "$MODE" = dest ]; then
    mkdir -p "$DEST"
    cp -a "$ROOT/." "$DEST/"
    ok "Распаковано в $DEST"
    echo "  конфиги:  $DEST/config"
    echo "  зоны:     $DEST/zones"
    echo "  дамп БД:  $DEST/db/powerdns.dump"
    echo
    echo "Восстановить вручную на новом сервере:"
    echo "  1) cp $DEST/config/.env $DEST/config/docker-compose.yml $PROJECT_DIR/"
    echo "  2) cp $DEST/config/pdns.conf $PROJECT_DIR/powerdns/"
    echo "  3) docker compose up -d postgres"
    echo "  4) docker exec -i buten-postgres pg_restore -U pdns -d powerdns --clean --if-exists < $DEST/db/powerdns.dump"
    echo "  5) docker compose up -d"
    exit 0
fi

# ---------- 4. Восстановление на месте ----------
if [ "$MODE" = inplace ]; then
    if [ "$ASSUME_YES" -ne 1 ]; then
        warn "Это заменит базу и конфиги в $PROJECT_DIR."
        read -r -p "Продолжить? введи 'restore': " a
        [ "$a" = restore ] || { err "Отменено"; exit 1; }
    fi

    info "Останавливаю сервисы…"
    ( cd "$PROJECT_DIR" && docker compose down ) || true

    info "Возвращаю конфиги…"
    install -m 600 "$ROOT/config/.env" "$PROJECT_DIR/.env"
    install -m 644 "$ROOT/config/docker-compose.yml" "$PROJECT_DIR/docker-compose.yml"
    install -m 600 "$ROOT/config/pdns.conf" "$PROJECT_DIR/powerdns/pdns.conf"
    if [ -f "$ROOT/config/init.sql" ]; then
        install -m 644 "$ROOT/config/init.sql" "$PROJECT_DIR/init.sql"
    fi

    info "Поднимаю PostgreSQL…"
    ( cd "$PROJECT_DIR" && docker compose up -d postgres )
    for _ in $(seq 1 60); do
        docker exec buten-postgres pg_isready -U pdns >/dev/null 2>&1 && break
        sleep 1
    done
    docker exec buten-postgres pg_isready -U pdns >/dev/null 2>&1 || { err "postgres не поднялся"; exit 1; }

    info "Заливаю дамп…"
    docker exec -i buten-postgres pg_restore -U pdns -d powerdns --clean --if-exists --no-owner < "$DUMP" || \
        warn "pg_restore вернул предупреждения (обычно это нормально для --clean)"

    info "Поднимаю остальные сервисы…"
    ( cd "$PROJECT_DIR" && docker compose up -d )

    sleep 5
    RECORDS="$(docker exec buten-postgres psql -U pdns -d powerdns -At -c "SELECT count(*) FROM records;" | tr -d '\r')"
    ok "Восстановлено. Записей DNS: $RECORDS"
    [ "${RECORDS:-0}" -gt 0 ] || { err "после восстановления 0 записей — проверьте логи"; exit 1; }
    docker exec buten-powerdns pdnsutil check-all-zones 2>&1 | tail -3
    exit 0
fi
