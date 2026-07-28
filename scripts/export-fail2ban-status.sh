#!/usr/bin/env bash
#
# Exports the current banned-IP list from fail2ban to a JSON file that
# ddns-api reads to show it in the admin panel. fail2ban runs on the
# host, not in Docker, so this bridges the gap — meant to run from cron
# every minute or so.
#
# Usage (crontab -e):
#   * * * * * /opt/buten-ddns/scripts/export-fail2ban-status.sh >/dev/null 2>&1

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_FILE="${OUT_FILE:-$SCRIPT_DIR/logs/banned-ips.json}"
JAILS=(sshd ddns-admin ddns-token)

mkdir -p "$(dirname "$OUT_FILE")"

python3 - "$OUT_FILE" "${JAILS[@]}" << 'PYEOF'
import json
import os
import subprocess
import sys
import datetime

out_file = sys.argv[1]
jails = sys.argv[2:]

result = {
    "generated_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    "jails": {},
}

for jail in jails:
    try:
        proc = subprocess.run(
            ["fail2ban-client", "status", jail],
            capture_output=True, text=True, timeout=5
        )
        output = proc.stdout
    except Exception:
        result["jails"][jail] = []
        continue

    ips = []
    for line in output.splitlines():
        if "Banned IP list" in line:
            part = line.split(":", 1)[-1].strip()
            ips = part.split() if part else []

    result["jails"][jail] = ips

tmp_file = out_file + ".tmp"
with open(tmp_file, "w") as f:
    json.dump(result, f, indent=2, ensure_ascii=False)

os.replace(tmp_file, out_file)
os.chmod(out_file, 0o644)
PYEOF
