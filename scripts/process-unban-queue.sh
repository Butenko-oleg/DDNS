#!/usr/bin/env bash
#
# Processes unban requests queued by the admin panel (the "Разбанить"
# button writes "jail ip" lines to ./logs/unban-queue.txt since ddns-api
# can't call fail2ban-client directly from inside its container).
#
# Meant to run from cron, right before export-fail2ban-status.sh so the
# freshly-unbanned IP disappears from the admin panel's list in the same
# cycle:
#
#   * * * * * /opt/buten-ddns/scripts/process-unban-queue.sh && /opt/buten-ddns/scripts/export-fail2ban-status.sh >/dev/null 2>&1

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
QUEUE_FILE="$SCRIPT_DIR/logs/unban-queue.txt"

[ -f "$QUEUE_FILE" ] || exit 0
[ -s "$QUEUE_FILE" ] || exit 0

# Atomically claim the current queue so anything the app appends while
# we're processing lands in a fresh file, not the one we're reading.
PROCESSING_FILE="${QUEUE_FILE}.processing.$$"
mv "$QUEUE_FILE" "$PROCESSING_FILE"
touch "$QUEUE_FILE"
# Must stay owned by the container's non-root app user (uid 1000) —
# this script runs as root via cron, so a bare `touch` would otherwise
# leave the file root-owned and unwritable by the app on its next
# unban request.
chown 1000:1000 "$QUEUE_FILE"
chmod 644 "$QUEUE_FILE"

while read -r jail ip; do
    [ -z "${jail:-}" ] && continue
    [ -z "${ip:-}" ] && continue
    fail2ban-client set "$jail" unbanip "$ip" >/dev/null 2>&1 || true
done < "$PROCESSING_FILE"

rm -f "$PROCESSING_FILE"
