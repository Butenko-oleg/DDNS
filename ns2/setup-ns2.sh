#!/usr/bin/env bash
#
# setup-ns2.sh — установка вторичного DNS на чистой Ubuntu 24.04.
#
# Делает всё, что нужно после создания виртуалки: Docker, UFW, fail2ban,
# автообновления, конфиги, запуск dnsdist + PowerDNS, импорт TSIG,
# создание зоны как вторичной и ожидание первой передачи с ns1.
#
# Запуск:
#   cp ns2.env.example ns2.env && nano ns2.env
#   sudo ./setup-ns2.sh
#
# Скрипт идемпотентен: повторный запуск не ломает уже настроенное.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${ENV_FILE:-$HERE/ns2.env}"
DEST="${DEST:-/opt/ns2}"

info() { printf '\033[36m%s\033[0m\n' "$*"; }
ok()   { printf '\033[32m%s\033[0m\n' "$*"; }
warn() { printf '\033[33m%s\033[0m\n' "$*" >&2; }
err()  { printf '\033[31m%s\033[0m\n' "$*" >&2; }
die()  { err "$*"; exit 1; }

[ "$(id -u)" -eq 0 ] || die "Запускать от root: sudo $0"
[ -f "$ENV_FILE" ] || die "Нет файла $ENV_FILE. Скопируй ns2.env.example в ns2.env и заполни."

# shellcheck disable=SC1090
set -a; . "$ENV_FILE"; set +a

: "${ZONE:?ZONE не задан в ns2.env}"
: "${NS1_IP:?NS1_IP не задан в ns2.env}"
: "${TSIG_NAME:?TSIG_NAME не задан в ns2.env}"
: "${TSIG_SECRET:?TSIG_SECRET не задан — его печатает enable-axfr.sh на ns1}"
SSH_ALLOW="${SSH_ALLOW:-192.168.88.0/24}"

info "Площадка ns2"
echo "  зона:        $ZONE"
echo "  ns1:         $NS1_IP"
echo "  TSIG:        $TSIG_NAME"
echo "  каталог:     $DEST"
echo "  SSH с:       ${SSH_ALLOW:-<не задано>}"
echo

# ---------- 1. Пакеты ----------
info "Пакеты…"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
# Ставим пакеты по отдельности: если в репозитории нет одного (например,
# docker-compose-v2 в новом выпуске), остальные всё равно должны встать.
apt-get install -y -qq docker.io ufw fail2ban unattended-upgrades dnsutils curl ca-certificates >/dev/null 2>&1 || \
    warn "  часть пакетов не установилась — проверьте вывод выше"
apt-get install -y -qq docker-compose-v2 >/dev/null 2>&1 || true

# На части выпусков пакета docker-compose-v2 может не быть — тогда ставим Docker CE из официального репозитория
if ! docker compose version >/dev/null 2>&1; then
    warn "  docker compose из репозитория Ubuntu недоступен — ставлю Docker CE"
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
    chmod a+r /etc/apt/keyrings/docker.asc
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
        > /etc/apt/sources.list.d/docker.list
    apt-get update -qq
    apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-compose-plugin >/dev/null
fi
ok "  установлены docker, compose, ufw, fail2ban, dnsutils"

systemctl enable --now docker >/dev/null 2>&1 || true

# ---------- 2. Файлы ----------
info "Конфиги в ${DEST}…"
mkdir -p "$DEST/data"
# PowerDNS в официальном образе работает не от root (uid 953, пользователь pdns).
# Каталог под LMDB должен быть ему доступен, иначе контейнер падает с
# "Unable to open database file ... Permission denied".
chown 953:953 "$DEST/data" 2>/dev/null || chmod 777 "$DEST/data"
install -m 644 "$HERE/docker-compose.yml" "$DEST/docker-compose.yml"
install -m 644 "$HERE/dnsdist.conf"      "$DEST/dnsdist.conf"
sed -e "s|@ZONE@|$ZONE|g" -e "s|@NS1_IP@|$NS1_IP|g" "$HERE/pdns.conf" > "$DEST/pdns.conf"
chmod 644 "$DEST/pdns.conf"
ok "  разложены compose, dnsdist.conf, pdns.conf"

# ---------- 3. UFW ----------
info "Файрвол…"
ufw --force reset >/dev/null 2>&1 || true
ufw default deny incoming >/dev/null
ufw default allow outgoing >/dev/null
ufw allow 53/tcp comment 'DNS' >/dev/null
ufw allow 53/udp comment 'DNS' >/dev/null

add_ssh() {
    [ -n "$1" ] || return 0
    ufw allow from "$1" to any port 22 proto tcp comment "ssh: $1" >/dev/null 2>&1 || true
}
for ip in $SSH_ALLOW; do add_ssh "$ip"; done

# страховка от самоблокировки: если текущий адрес не попадает ни в одну
# из разрешённых сетей — добавляем его отдельным правилом, иначе доступ потеряется
CUR_IP="$(echo "${SSH_CLIENT:-}" | awk '{print $1}')"
if [ -n "$CUR_IP" ]; then
    COVERED="$(python3 - "$CUR_IP" $SSH_ALLOW <<'PYX'
import sys, ipaddress
try:
    ip = ipaddress.ip_address(sys.argv[1])
except ValueError:
    print("no"); sys.exit()
for a in sys.argv[2:]:
    try:
        if ip in ipaddress.ip_network(a, strict=False):
            print("yes"); sys.exit()
    except ValueError:
        pass
print("no")
PYX
)"
    if [ "$COVERED" != "yes" ]; then
        warn "  текущий адрес $CUR_IP не входит в список — добавил правило, иначе можно потерять доступ"
        warn "  после настройки это правило можно убрать: ufw delete allow from $CUR_IP to any port 22 proto tcp"
        add_ssh "$CUR_IP"
    fi
fi

ufw --force enable >/dev/null
ok "  открыт только 53 и SSH с разрешённых адресов"

# ---------- 4. fail2ban и автообновления ----------
info "fail2ban и автообновления…"
cat > /etc/fail2ban/jail.d/sshd.local <<'EOF'
[sshd]
enabled = true
backend = systemd
maxretry = 5
findtime = 10m
bantime = 1h
EOF
systemctl enable --now fail2ban >/dev/null 2>&1 || true

cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
ok "  включены"

# ---------- 5. Освобождаем 53-й порт ----------
# systemd-resolved слушает 127.0.0.53:53 и не даёт опубликовать 53 наружу:
# docker упадёт с "address already in use". Отключаем stub-слушатель,
# а resolv.conf переключаем на не-stub версию, иначе сервер останется без DNS.
info "Освобождаю 53-й порт (systemd-resolved)…"
if systemctl is-enabled systemd-resolved >/dev/null 2>&1; then
    mkdir -p /etc/systemd/resolved.conf.d
    cat > /etc/systemd/resolved.conf.d/90-dnsdist.conf <<'EOF'
[Resolve]
DNSStubListener=no
EOF
    systemctl restart systemd-resolved
    ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
    sleep 2
    if ! getent hosts archive.ubuntu.com >/dev/null 2>&1; then
        warn "  DNS после отключения stub не отвечает — прописываю резолвер вручную"
        rm -f /etc/resolv.conf
        printf 'nameserver 1.1.1.1\nnameserver 8.8.8.8\n' > /etc/resolv.conf
    fi
    ok "  53-й порт свободен"
else
    ok "  systemd-resolved не используется — порт свободен"
fi

# ---------- 6. Запуск ----------
info "Поднимаю контейнеры…"
( cd "$DEST" && docker compose up -d ) >/dev/null

for _ in $(seq 1 40); do
    docker exec ns2-powerdns pdns_control rping >/dev/null 2>&1 && break
    sleep 1
done
if ! docker exec ns2-powerdns pdns_control rping >/dev/null 2>&1; then
    err "PowerDNS не поднялся. Логи:"
    docker logs --tail 30 ns2-powerdns 2>&1 | sed 's/^/    /'
    die "Остановился"
fi
ok "  PowerDNS отвечает"
ok "  версия: $(docker exec ns2-powerdns pdns_server --version 2>&1 | head -1 | grep -oE 'Server [0-9.]+')"

# ---------- 7. TSIG и зона ----------
info "Ключ TSIG и создание вторичной зоны…"
docker exec ns2-powerdns pdnsutil import-tsig-key "$TSIG_NAME" hmac-sha256 "$TSIG_SECRET" >/dev/null 2>&1 || \
    warn "  ключ, возможно, уже был"

# Порядок важен: set-meta работает только с существующей зоной,
# поэтому сначала создаём вторичную зону, и только потом вешаем на неё ключ.
if ! docker exec ns2-powerdns pdnsutil list-all-zones 2>/dev/null | grep -qx "$ZONE"; then
    docker exec ns2-powerdns pdnsutil create-secondary-zone "$ZONE" "$NS1_IP" >/dev/null 2>&1 || \
        docker exec ns2-powerdns pdnsutil create-slave-zone "$ZONE" "$NS1_IP" >/dev/null 2>&1 || \
        die "не удалось создать вторичную зону"
    ok "  зона $ZONE создана как вторичная"
else
    ok "  зона $ZONE уже существует"
fi

docker exec ns2-powerdns pdnsutil set-meta "$ZONE" AXFR-MASTER-TSIG "$TSIG_NAME" >/dev/null 2>&1 || \
    die "не удалось привязать TSIG-ключ к зоне"
ok "  ключ $TSIG_NAME привязан к зоне"

# Без rediscover уже запущенный PowerDNS не видит только что созданную зону
# и отвечает REFUSED на все запросы по ней (проверено на живом сервере).
docker exec ns2-powerdns pdns_control rediscover >/dev/null 2>&1 || true

info "Жду передачу зоны с ns1 (до 90 секунд)…"
COUNT=0
for _ in $(seq 1 45); do
    COUNT="$(docker exec ns2-powerdns pdnsutil list-zone "$ZONE" 2>/dev/null | wc -l | tr -d ' ')" || COUNT=0
    [ "${COUNT:-0}" -gt 5 ] && break
    sleep 2
done

if [ "${COUNT:-0}" -le 5 ]; then
    err "Зона не приехала (записей: $COUNT)."
    err "Проверь на ns1: primary=yes, allow-axfr-ips=$NS1_IP... то есть IP этого сервера,"
    err "и что TSIG-ключ совпадает. Логи:  docker logs --tail 30 ns2-powerdns"
    exit 1
fi

ok "  зона приехала: $COUNT строк"
docker exec ns2-powerdns pdnsutil check-zone "$ZONE" 2>&1 | tail -1

echo
echo "Проверка снаружи (с другой машины, не из офиса):"
echo "  dig @${NS2_PUBLIC_IP:-<публичный IP>} $ZONE SOA"
echo "  dig @${NS2_PUBLIC_IP:-<публичный IP>} <любой-хост>.$ZONE A"
echo
echo "Дальше: проброс 53 на MikroTik и glue-запись у регистратора — см. README.md"
