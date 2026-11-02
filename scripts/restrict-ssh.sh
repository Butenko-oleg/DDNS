#!/usr/bin/env bash
#
# Restricts SSH (port 22 by default) to a fixed set of hostnames, by
# resolving them and allowing only their current IPs through UFW.
# Since these hostnames may have dynamic IPs, this is safe to re-run
# periodically (e.g. via cron) — it only touches rules for hosts whose
# resolved IP actually changed.
#
# TWO-PHASE ON PURPOSE, to avoid locking yourself out:
#   1) Default run: adds/refreshes "allow from <ip>" rules for each
#      hostname, but leaves the existing "22/tcp from Anywhere" rule
#      in place. Nothing is restricted yet.
#   2) Only after you've confirmed SSH still works through one of the
#      allowed hostnames (test in a NEW terminal, don't close your
#      current session), run again with --remove-anywhere to actually
#      drop the open rule.
#
# Usage:
#   sudo ./scripts/restrict-ssh.sh
#   ... verify access from an allowed host in a new session ...
#   sudo ./scripts/restrict-ssh.sh --remove-anywhere
#
# Re-run any time (e.g. from cron) to pick up IP changes:
#   sudo ./scripts/restrict-ssh.sh

set -euo pipefail

info() { printf '\033[36m%s\033[0m\n' "$1"; }
warn() { printf '\033[33m%s\033[0m\n' "$1"; }
ok()   { printf '\033[32m%s\033[0m\n' "$1"; }
err()  { printf '\033[31m%s\033[0m\n' "$1" >&2; }

if [ "$(id -u)" -ne 0 ]; then
    err "Run as root (sudo ./scripts/restrict-ssh.sh)"
    exit 1
fi

SSH_PORT="${SSH_PORT:-22}"
HOSTS=(ejik.site backup.ejik.site 3x.ejik.site vps.ejik.site mp.ejik.site)
STATE_FILE="/etc/ufw-ssh-hosts.state"
REMOVE_ANYWHERE=0

[ "${1:-}" = "--remove-anywhere" ] && REMOVE_ANYWHERE=1

touch "$STATE_FILE"

# ---------------------------------------------------------------------
# Resolve current IPs
# ---------------------------------------------------------------------

declare -A NEW_IPS

info "Резолвлю хосты..."
for h in "${HOSTS[@]}"; do
    ip=$(dig +short "$h" @8.8.8.8 2>/dev/null | grep -E '^[0-9]+\.' | tail -n1 || true)
    if [ -z "$ip" ]; then
        warn "  $h — не резолвится, пропускаю (не трогаю его текущее правило, если оно есть)"
        continue
    fi
    NEW_IPS["$h"]="$ip"
    echo "  $h -> $ip"
done

if [ ${#NEW_IPS[@]} -eq 0 ]; then
    err "Ни один хост не зарезолвился — ничего не меняю, чтобы не потерять доступ."
    exit 1
fi

# ---------------------------------------------------------------------
# Load previous state, diff, update only what changed
# ---------------------------------------------------------------------

declare -A OLD_IPS
if [ -s "$STATE_FILE" ]; then
    while IFS='=' read -r h ip; do
        [ -n "$h" ] && OLD_IPS["$h"]="$ip"
    done < "$STATE_FILE"
fi

CHANGED=0
for h in "${!NEW_IPS[@]}"; do
    new_ip="${NEW_IPS[$h]}"
    old_ip="${OLD_IPS[$h]:-}"

    if [ "$new_ip" = "$old_ip" ]; then
        continue
    fi

    CHANGED=1

    if [ -n "$old_ip" ]; then
        info "IP для $h изменился ($old_ip -> $new_ip), обновляю правило..."
        ufw delete allow from "$old_ip" to any port "$SSH_PORT" proto tcp >/dev/null 2>&1 || true
    else
        info "Новый хост $h -> $new_ip, добавляю правило..."
    fi

    ufw allow from "$new_ip" to any port "$SSH_PORT" proto tcp comment "ssh: ${h}"
done

if [ "$CHANGED" = 0 ]; then
    ok "IP всех хостов не изменились — правила уже актуальны."
fi

# Persist state (merge: keep unresolved-this-run hosts as-is)
{
    for h in "${!OLD_IPS[@]}"; do
        [ -z "${NEW_IPS[$h]:-}" ] && echo "$h=${OLD_IPS[$h]}"
    done
    for h in "${!NEW_IPS[@]}"; do
        echo "$h=${NEW_IPS[$h]}"
    done
} > "$STATE_FILE"

# ---------------------------------------------------------------------
# Phase 2: remove the open "from Anywhere" rule, only if asked to
# ---------------------------------------------------------------------

if [ "$REMOVE_ANYWHERE" = 1 ]; then
    info "Удаляю общее правило '${SSH_PORT}/tcp from Anywhere'..."
    ufw delete allow "${SSH_PORT}/tcp" >/dev/null 2>&1 || true
    ok "Готово — SSH теперь доступен только с адресов разрешённых хостов."
else
    warn "Правило '${SSH_PORT}/tcp from Anywhere' пока НЕ тронуто."
    warn "Проверь доступ через один из разрешённых хостов в НОВОМ окне терминала,"
    warn "не закрывая текущую сессию, и только потом запусти:"
    warn "  sudo $0 --remove-anywhere"
fi

echo
ok "Текущие правила для порта ${SSH_PORT}:"
ufw status verbose | grep -E "${SSH_PORT}/tcp|ssh:"
