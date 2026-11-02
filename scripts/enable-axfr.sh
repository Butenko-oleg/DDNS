#!/usr/bin/env bash
#
# enable-axfr.sh — на ПЕРВИЧНОМ сервере (ns1): разрешить отдачу зоны второму NS.
#
# Что делает:
#   1. делает бэкап pdns.conf;
#   2. добавляет primary=yes, allow-axfr-ips=<IP ns2>, also-notify=<IP ns2>;
#   3. создаёт TSIG-ключ (если ещё нет) и разрешает AXFR только по нему;
#   4. перезапускает контейнер powerdns и проверяет, что он поднялся;
#   5. печатает имя и secret ключа — их надо внести в ns2.env на втором сервере.
#
# Перезапуск PowerDNS занимает 2-3 секунды. TTL записей 300 с, поэтому для
# клиентов это незаметно; но запускать лучше не в момент активной работы.
#
# Использование:
#   sudo ./enable-axfr.sh --peer 10.20.30.40 [--tsig-name axfr-ns2] [--yes]
#
# --peer принимает и список через запятую — это нужно, когда второй NS стоит
# в офисе с двумя каналами: адрес источника может быть и 91.228.63.159,
# и 91.228.63.183. Пример:
#   sudo ./enable-axfr.sh --peer 91.228.63.159,91.228.63.183
#
# Откат: рядом остаётся pdns.conf.bak-<дата>, вернуть его и перезапустить контейнер.

set -euo pipefail

PROJECT_DIR="${PROJECT_DIR:-/opt/buten-ddns}"
CONF="$PROJECT_DIR/powerdns/pdns.conf"
ZONE="${ZONE:-buten-ko.ru}"
PEER=""
TSIG_NAME="axfr-ns2"
ASSUME_YES=0

while [ $# -gt 0 ]; do
    case "$1" in
        --peer)      PEER="${2:?}"; shift ;;
        --tsig-name) TSIG_NAME="${2:?}"; shift ;;
        --yes)       ASSUME_YES=1 ;;
        -h|--help)   sed -n '2,22p' "$0"; exit 0 ;;
        *) echo "Неизвестный аргумент: $1" >&2; exit 2 ;;
    esac
    shift
done

info() { printf '\033[36m%s\033[0m\n' "$*"; }
ok()   { printf '\033[32m%s\033[0m\n' "$*"; }
warn() { printf '\033[33m%s\033[0m\n' "$*" >&2; }
err()  { printf '\033[31m%s\033[0m\n' "$*" >&2; }

[ "$(id -u)" -eq 0 ] || { err "Запускать от root"; exit 1; }
[ -n "$PEER" ] || { err "Укажи --peer <IP второго NS> (можно список через запятую)"; exit 2; }
PEER="${PEER// /}"     # на случай пробелов после запятых
[ -f "$CONF" ] || { err "Нет файла $CONF"; exit 1; }

info "Что будет сделано:"
echo "  зона:            $ZONE"
echo "  адреса второго NS: $PEER"
echo "  TSIG-ключ:       $TSIG_NAME (hmac-sha256)"
echo "  файл:            $CONF"
echo "  перезапуск:      контейнер buten-powerdns (2-3 секунды)"
if [ "$ASSUME_YES" -ne 1 ]; then
    read -r -p "Продолжить? введи 'yes': " a
    [ "$a" = yes ] || { err "Отменено"; exit 1; }
fi

BAK="$CONF.bak-$(date +%Y%m%d-%H%M%S)"
cp -a "$CONF" "$BAK"
ok "бэкап: $BAK"

python3 - "$CONF" "$PEER" <<'PY'
import sys, re
conf, peer = sys.argv[1], sys.argv[2]
lines = open(conf, encoding="utf-8").read().splitlines()
out, have = [], set()
for ln in lines:
    key = ln.split("=", 1)[0].strip() if "=" in ln and not ln.strip().startswith("#") else None
    if key in ("primary", "allow-axfr-ips", "also-notify"):
        continue                      # старые значения выкидываем, впишем свежие
    out.append(ln)
block = [
    "",
    "# --- отдача зоны второму нейм-серверу (добавлено enable-axfr.sh) ---",
    "primary=yes",
    f"allow-axfr-ips={peer}",
    f"also-notify={peer}",
]
open(conf, "w", encoding="utf-8").write("\n".join(out + block) + "\n")
print("pdns.conf обновлён")
PY

info "TSIG-ключ…"
SECRET=""
EXISTING="$(docker exec buten-postgres psql -U pdns -d powerdns -At -c \
    "SELECT content FROM tsigkeys WHERE name='$TSIG_NAME';" 2>/dev/null | tr -d '\r')"
if [ -z "$EXISTING" ]; then
    docker exec buten-powerdns pdnsutil generate-tsig-key "$TSIG_NAME" hmac-sha256 >/dev/null
    EXISTING="$(docker exec buten-postgres psql -U pdns -d powerdns -At -c \
        "SELECT content FROM tsigkeys WHERE name='$TSIG_NAME';" 2>/dev/null | tr -d '\r')"
    ok "  ключ создан"
else
    warn "  ключ $TSIG_NAME уже был — использую существующий"
fi
[ -n "$EXISTING" ] || { err "не удалось получить TSIG-ключ"; exit 1; }
SECRET="${EXISTING#*.}"     # формат в базе: hmac-sha256.<base64>

docker exec buten-powerdns pdnsutil set-meta "$ZONE" TSIG-ALLOW-AXFR "$TSIG_NAME" >/dev/null
ok "  зоне $ZONE разрешён AXFR по ключу $TSIG_NAME"

info "Перезапускаю PowerDNS…"
( cd "$PROJECT_DIR" && docker compose up -d --force-recreate powerdns ) >/dev/null
sleep 4

for i in $(seq 1 20); do
    if docker exec buten-powerdns pdns_control ping >/dev/null 2>&1; then break; fi
    sleep 1
done
if docker exec buten-powerdns pdns_control ping >/dev/null 2>&1; then
    ok "  PowerDNS поднялся"
else
    err "  PowerDNS не отвечает! Смотри: docker logs buten-powerdns --tail 30"
    err "  Откат: cp $BAK $CONF && cd $PROJECT_DIR && docker compose up -d --force-recreate powerdns"
    exit 1
fi

docker exec buten-powerdns pdnsutil check-zone "$ZONE" 2>&1 | tail -1

echo
ok "Готово. Внеси эти значения в ns2.env на втором сервере:"
echo "  TSIG_NAME=$TSIG_NAME"
echo "  TSIG_SECRET=$SECRET"
echo
echo "Проверка, что ключ на месте:"
echo "  docker exec buten-powerdns pdnsutil list-tsig-keys"
