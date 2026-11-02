#!/usr/bin/env bash
#
# check-ns2.sh — проверка вторичного DNS.
#
# Что проверяет:
#   1. контейнеры живы;
#   2. dnsdist отвечает на 53 локально;
#   3. serial зоны на ns2 совпадает с ns1 (значит AXFR/NOTIFY работают);
#   4. число записей в зоне;
#   5. конкретные имена резолвятся и совпадают с ns1;
#   6. TCP-запросы тоже работают;
#   7. если задан NS2_PUBLIC_IP — сервер отвечает и по публичному адресу.
#
# Код возврата 0 — всё в порядке.

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${ENV_FILE:-$HERE/ns2.env}"
[ -f "$ENV_FILE" ] && { set -a; . "$ENV_FILE"; set +a; }

ZONE="${ZONE:-buten-ko.ru}"
NS1_IP="${NS1_IP:-89.108.83.88}"
TEST_NAMES="${TEST_NAMES:-prometall.buten-ko.ru ddns.buten-ko.ru status.buten-ko.ru}"

FAIL=0
ok()   { printf '\033[32m  OK  \033[0m %s\n' "$*"; }
bad()  { printf '\033[31m FAIL \033[0m %s\n' "$*"; FAIL=1; }
info() { printf '\033[36m%s\033[0m\n' "$*"; }

info "1. Контейнеры"
for c in ns2-dnsdist ns2-powerdns; do
    if docker ps --format '{{.Names}}' | grep -qx "$c"; then ok "$c запущен"; else bad "$c не запущен"; fi
done

info "2. dnsdist отвечает локально"
if dig +time=3 +tries=1 @127.0.0.1 "$ZONE" SOA +short | grep -q .; then
    ok "ответ на SOA есть"
else
    bad "нет ответа от 127.0.0.1:53"
fi

info "3. serial: ns2 против ns1"
S2="$(dig +time=3 +tries=1 @127.0.0.1 "$ZONE" SOA +short | awk '{print $3}')"
S1="$(dig +time=5 +tries=1 @"$NS1_IP" "$ZONE" SOA +short | awk '{print $3}')"
echo "     ns1: ${S1:-нет ответа}   ns2: ${S2:-нет ответа}"
# Роутеры обновляют записи каждую минуту, и serial на ns1 растёт постоянно.
# Поэтому точное совпадение — редкость; нормой считается небольшое отставание.
if [ -n "$S1" ] && [ -n "$S2" ]; then
    DIFF=$((S1 - S2))
    if [ "$DIFF" -eq 0 ]; then
        ok "serial совпадает"
    elif [ "$DIFF" -gt 0 ] && [ "$DIFF" -le 20 ]; then
        ok "ns2 отстаёт на $DIFF — норма при частых обновлениях"
    elif [ "$DIFF" -lt 0 ]; then
        bad "ns2 впереди ns1 на $((-DIFF)) — это ненормально"
    else
        bad "ns2 отстаёт на $DIFF — похоже, передача встала"
    fi
else
    bad "не удалось сравнить serial (ns1=${S1:-нет}, ns2=${S2:-нет})"
fi

info "4. число записей в зоне на ns2"
N="$(docker exec ns2-powerdns pdnsutil list-zone "$ZONE" 2>/dev/null | wc -l | tr -d ' ')"
if [ "${N:-0}" -gt 10 ]; then ok "записей: $N"; else bad "записей: ${N:-0} — зона не приехала"; fi

info "5. имена резолвятся одинаково"
for n in $TEST_NAMES; do
    A1="$(dig +short +time=3 +tries=1 @"$NS1_IP" "$n" A | sort | tr '\n' ' ')"
    A2="$(dig +short +time=3 +tries=1 @127.0.0.1 "$n" A | sort | tr '\n' ' ')"
    if [ -n "$A2" ] && [ "$A1" = "$A2" ]; then
        ok "$n → $A2"
    else
        bad "$n: ns1='$A1' ns2='$A2'"
    fi
done

info "6. TCP"
if dig +tcp +time=3 +tries=1 @127.0.0.1 "$ZONE" SOA +short | grep -q .; then
    ok "TCP отвечает"
else
    bad "TCP не отвечает"
fi

if [ -n "${NS2_PUBLIC_IP:-}" ]; then
    info "7. публичный адрес $NS2_PUBLIC_IP"
    if dig +time=5 +tries=1 @"$NS2_PUBLIC_IP" "$ZONE" SOA +short | grep -q .; then
        ok "отвечает извне"
    else
        bad "по публичному адресу не отвечает (проброс 53 на роутере?)"
    fi
else
    info "7. публичный адрес не задан (NS2_PUBLIC_IP) — пропускаю"
fi

echo
if [ "$FAIL" -eq 0 ]; then
    printf '\033[32mВсё в порядке.\033[0m\n'; exit 0
else
    printf '\033[31mЕсть проблемы — см. выше.\033[0m\n'; exit 1
fi
