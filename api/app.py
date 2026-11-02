import os
import secrets
import base64
import re
import time
import ipaddress
import logging
import json
from collections import defaultdict
from urllib.parse import urlparse, quote_plus
from datetime import datetime, timezone

import psycopg2
import requests
import bcrypt as bcrypt_lib

from fastapi import (
    FastAPI,
    HTTPException,
    Header,
    Request,
    Depends,
    Form,
)
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates


app = FastAPI(
    title="Buten DDNS API"
)

ADMIN_USER = os.getenv(
    "ADMIN_USER",
    "admin"
)

ADMIN_PASSWORD = os.getenv(
    "ADMIN_PASSWORD",
    "change-me"
)


def hash_password(password: str) -> str:
    return bcrypt_lib.hashpw(
        password.encode("utf-8"),
        bcrypt_lib.gensalt()
    ).decode("utf-8")


def verify_password(password: str, stored: str) -> bool:
    try:
        return bcrypt_lib.checkpw(
            password.encode("utf-8"),
            stored.encode("utf-8")
        )
    except (ValueError, TypeError):
        return False


def get_stored_admin_credentials():
    """Returns (username, password_hash) from the DB, or None if not set yet."""

    conn = get_db()

    try:
        cur = conn.cursor()

        cur.execute(
            """
            SELECT username, password_hash
            FROM admin_credentials
            ORDER BY id DESC
            LIMIT 1
            """
        )

        return cur.fetchone()

    finally:
        conn.close()


@app.on_event("startup")
def ensure_admin_table():
    conn = get_db()

    try:
        cur = conn.cursor()

        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS admin_credentials (
                id SERIAL PRIMARY KEY,
                username TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                updated_at TIMESTAMP DEFAULT now()
            )
            """
        )

        conn.commit()

    finally:
        conn.close()


# ---------- Session-cookie auth ----------
# Plain HTTP Basic Auth used to be used here, but it has real problems on
# iOS "Add to Home Screen" apps specifically: the native credential
# prompt can't be styled at all, isn't saved to Keychain, doesn't offer
# autofill, and the cached credentials get dropped whenever the app is
# purged from memory — meaning the login prompt reappears constantly.
# A real login form + a normal session cookie fixes all of that: iOS
# treats it like any other website login (offers to save/autofill it),
# and the cookie persists in WebKit's cookie jar across app restarts.
#
# Sessions are opaque random tokens kept in memory (not a signed JWT —
# no secret key to manage, and losing sessions on a server restart just
# means everyone logs in again, which is a fine trade-off here). A
# server restart invalidates all sessions; a client-side app relaunch
# does not, since the cookie itself is what's evaluated here, not any
# in-app state.

SESSION_COOKIE_NAME = "ddns_session"
SESSION_MAX_AGE = 60 * 60 * 24 * 30  # 30 days

_sessions = {}  # token -> (username, expires_at)


def create_session(username: str) -> str:
    token = secrets.token_urlsafe(32)
    _sessions[token] = (username, time.time() + SESSION_MAX_AGE)
    return token


def get_session_username(token: str):
    entry = _sessions.get(token)

    if not entry:
        return None

    username, expires_at = entry

    if time.time() > expires_at:
        _sessions.pop(token, None)
        return None

    return username


def destroy_session(token: str):
    _sessions.pop(token, None)


class NotAuthenticated(Exception):
    pass


@app.exception_handler(NotAuthenticated)
def handle_not_authenticated(request: Request, exc: NotAuthenticated):
    return RedirectResponse("/login", status_code=303)


def admin_auth(request: Request):
    token = request.cookies.get(SESSION_COOKIE_NAME)
    username = get_session_username(token) if token else None

    if not username:
        raise NotAuthenticated()

    return True


templates = Jinja2Templates(
    directory="templates"
)

PDNS_API = os.getenv("PDNS_API_URL", "http://powerdns:8081")
# Секретов в коде быть не должно: значения приходят только из .env.
PDNS_KEY = os.getenv("PDNS_API_KEY", "")

ZONE = os.getenv("DDNS_ZONE", "buten-ko.ru")

DB = {
    "host": os.getenv("DB_HOST", "postgres"),
    "database": os.getenv("DB_NAME", "powerdns"),
    "user": os.getenv("DB_USER", "pdns"),
    "password": os.getenv("DB_PASSWORD", "")
}

# Без секретов приложение не стартует: лучше упасть сразу и с понятным текстом,
# чем молча работать с паролем по умолчанию, который лежит в открытом репозитории.
_missing = [
    name for name, value in (
        ("PDNS_API_KEY", PDNS_KEY),
        ("DB_PASSWORD", DB["password"]),
    ) if not value
]
if _missing:
    raise RuntimeError(
        "Не заданы обязательные переменные окружения: " + ", ".join(_missing)
        + ". Проверь .env и docker-compose.yml."
    )

# Scheme to assume when a reverse proxy doesn't forward X-Forwarded-Proto.
# Almost every real deployment sits behind TLS, so default to https.
PUBLIC_SCHEME_DEFAULT = os.getenv("PUBLIC_SCHEME", "https")


def get_db():
    return psycopg2.connect(**DB)


def human_relative(dt):
    """Render a datetime as a short relative string, e.g. '3m ago'."""

    if dt is None:
        return "never"

    now = datetime.now()
    delta = now - dt
    seconds = int(delta.total_seconds())

    if seconds < 0:
        seconds = 0

    if seconds < 60:
        return "just now"
    if seconds < 3600:
        return f"{seconds // 60}m ago"
    if seconds < 86400:
        return f"{seconds // 3600}h ago"
    if seconds < 604800:
        return f"{seconds // 86400}d ago"

    return dt.strftime("%d.%m.%Y")


def freshness_bucket(dt, active):
    """Classify a client's sync freshness for the admin UI."""

    if not active:
        return "disabled"

    if dt is None:
        return "never"

    seconds = int((datetime.now() - dt).total_seconds())

    if seconds < 900:
        return "live"
    if seconds < 86400:
        return "recent"
    if seconds < 604800:
        return "stale"

    return "old"


# Sort order for the admin dashboard: things that need attention first
# (offline, then stale), healthy/live hosts last. Matches how most
# uptime/monitoring dashboards surface problems.
STATUS_SORT_WEIGHT = {
    "disabled": 0,
    "never": 1,
    "old": 2,
    "stale": 3,
    "recent": 4,
    "live": 5,
}


def get_base_url(request: Request) -> str:
    """
    Public base URL of this API, as seen by the browser/router.

    The scheme is always PUBLIC_SCHEME (https by default) — plain HTTP
    isn't reachable from outside this deployment at all, so there's no
    reverse-proxy header worth trusting for that part. Only the host is
    taken from forwarded headers, since that part can legitimately vary.
    """

    host = request.headers.get(
        "X-Forwarded-Host",
        request.headers.get("host", request.url.netloc)
    )

    return f"{PUBLIC_SCHEME_DEFAULT}://{host}"


def parse_basic_auth(request: Request):
    """
    Extract username/password from an HTTP Basic Authorization header.
    Many DDNS clients (routers, RouterOS, curl -u, etc.) send credentials
    this way instead of as query parameters.
    """

    auth = request.headers.get("Authorization", "")

    if not auth.lower().startswith("basic "):
        return None, None

    try:
        decoded = base64.b64decode(auth[6:].strip()).decode("utf-8", "ignore")
    except Exception:
        return None, None

    if ":" not in decoded:
        return None, None

    user, _, passwd = decoded.partition(":")

    return user, passwd


def get_client_ip(request):

    forwarded = request.headers.get(
        "X-Forwarded-For"
    )

    if forwarded:
        return forwarded.split(",")[0].strip()

    return request.client.host


HOSTNAME_LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")


def is_valid_hostname_label(hostname: str) -> bool:
    """A single DNS label: letters/digits/hyphens, 1-63 chars, no leading/trailing hyphen."""
    return bool(hostname) and bool(HOSTNAME_LABEL_RE.match(hostname))


def is_valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except (ValueError, TypeError):
        return False


# ---------- Brute-force protection ----------
# Simple in-process fixed-window limiter. Resets on restart; good enough
# to slow down credential/token guessing on a single-instance deployment.
# For public-internet deployments, pairing this with a reverse-proxy rate
# limiter (nginx limit_req, Cloudflare, etc.) is recommended too.
#
# Failures are also written to a dedicated log file (not just stdout) so
# fail2ban can watch it and ban at the firewall level. This matters
# specifically because ddns-api sits behind a reverse proxy: its own
# stdout/access logs would show the proxy's IP, not the real client —
# get_client_ip() already resolves the real IP via X-Forwarded-For, and
# that's what gets written here.

_failed_attempts = defaultdict(list)
RATE_LIMIT_WINDOW = 300   # seconds
RATE_LIMIT_MAX = 10       # attempts per window

AUTH_LOG_DIR = os.getenv("AUTH_LOG_DIR", "/app/logs")
os.makedirs(AUTH_LOG_DIR, exist_ok=True)

auth_logger = logging.getLogger("auth_fail")
auth_logger.setLevel(logging.INFO)
auth_logger.propagate = False
_auth_log_handler = logging.FileHandler(
    os.path.join(AUTH_LOG_DIR, "auth.log")
)
_auth_log_handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
auth_logger.addHandler(_auth_log_handler)


def check_rate_limit(kind: str, ip: str):
    if is_rate_limited(kind, ip):
        raise HTTPException(
            status_code=429,
            detail="Too many attempts, try again later"
        )


def is_rate_limited(kind: str, ip: str) -> bool:
    now = time.time()
    key = f"{kind}:{ip}"
    attempts = _failed_attempts[key]
    attempts[:] = [t for t in attempts if now - t < RATE_LIMIT_WINDOW]
    return len(attempts) >= RATE_LIMIT_MAX


def record_failure(kind: str, ip: str):
    _failed_attempts[f"{kind}:{ip}"].append(time.time())
    auth_logger.info(f"AUTH_FAIL ip={ip} kind={kind}")


# ---------- fail2ban banned-IP list ----------
# fail2ban runs on the HOST, not in this container, so we can't call
# fail2ban-client directly. A cron job on the host (see
# scripts/export-fail2ban-status.sh) periodically writes the current
# banned-IP list per jail to this file, which we just read here.

BANNED_IPS_FILE = os.path.join(AUTH_LOG_DIR, "banned-ips.json")
UNBAN_QUEUE_FILE = os.path.join(AUTH_LOG_DIR, "unban-queue.txt")
KNOWN_JAILS = ("sshd", "ddns-admin", "ddns-token")

# Static content served for download in the admin panel Quick Config
# (Windows tab) — the interactive scheduled-task installer, plus a .bat
# wrapper (self-elevates + bypasses ExecutionPolicy, so double-clicking
# it just works even if the .ps1 alone gets blocked by Windows).
WINDOWS_INSTALLER_SCRIPT = r"""<#
.SYNOPSIS
    Creates a Windows Scheduled Task that runs ddns-update.ps1 with no
    visible console window, then runs it once immediately.

.PARAMETER IntervalMinutes
    How often to run the update, in minutes. 0 = run only at system
    startup, once network connectivity is available (no repeating
    schedule). If omitted, you'll be asked.

.PARAMETER ScriptPath
    Path to ddns-update.ps1. Defaults to the same folder as this installer.

.EXAMPLE
    .\install-ddns-task.ps1 -IntervalMinutes 10
.EXAMPLE
    .\install-ddns-task.ps1 -IntervalMinutes 0
.EXAMPLE
    .\install-ddns-task.ps1
    # prompts: "Update interval in minutes (Enter = 5, 0 = only at startup):"
#>

param(
    [int]$IntervalMinutes = -1,
    [string]$ScriptPath = (Join-Path $PSScriptRoot "ddns-update.ps1")
)

$ErrorActionPreference = "Stop"

# Force UTF-8 console output regardless of system codepage, so this
# still displays correctly even if non-ASCII text is added later.
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}

# --- must run elevated: registering a task that runs whether logged on
#     or not requires administrator rights ---
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "Please run this as Administrator and try again." -ForegroundColor Red
    Write-Host "(Right-click install-ddns-task.bat -> 'Run as administrator', or right-click PowerShell -> 'Run as administrator')" -ForegroundColor Yellow
    exit 1
}

if (-not (Test-Path $ScriptPath)) {
    Write-Host "Could not find: $ScriptPath" -ForegroundColor Red
    Write-Host "Put ddns-update.ps1 in the same folder as this installer, or pass -ScriptPath `"C:\path\ddns-update.ps1`"" -ForegroundColor Yellow
    exit 1
}

if ($IntervalMinutes -eq -1) {
    $userInput = Read-Host "Update interval in minutes (Enter = 5, 0 = only at startup when network is available)"
    if ([string]::IsNullOrWhiteSpace($userInput)) {
        $IntervalMinutes = 5
    } else {
        $IntervalMinutes = [int]$userInput
    }
}

if ($IntervalMinutes -lt 0) {
    Write-Host "Interval must be 0 or greater." -ForegroundColor Red
    exit 1
}

$taskName = "DDNS Update"

$action = New-ScheduledTaskAction `
    -Execute "powershell.exe" `
    -Argument "-WindowStyle Hidden -NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`""

if ($IntervalMinutes -eq 0) {

    $trigger = New-ScheduledTaskTrigger -AtStartup

    $settings = New-ScheduledTaskSettingsSet `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries `
        -StartWhenAvailable `
        -RunOnlyIfNetworkAvailable `
        -ExecutionTimeLimit (New-TimeSpan -Minutes 2)

    $taskDescription = "Updates DDNS IP once at startup, when network is available."

} else {

    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) `
        -RepetitionInterval (New-TimeSpan -Minutes $IntervalMinutes) `
        -RepetitionDuration (New-TimeSpan -Days 3650)

    $settings = New-ScheduledTaskSettingsSet `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries `
        -StartWhenAvailable `
        -ExecutionTimeLimit (New-TimeSpan -Minutes 2)

    $taskDescription = "Updates DDNS IP every $IntervalMinutes min. (ddns-update.ps1)"
}

# LogonType S4U: runs whether the user is logged on or not, without
# needing to store a Windows password anywhere -- and, since it's a
# non-interactive session, no console window ever appears (this is the
# actual fix for the blue-flash flicker; -WindowStyle Hidden alone
# often isn't enough on its own).
$principal = New-ScheduledTaskPrincipal `
    -UserId "$env:USERDOMAIN\$env:USERNAME" `
    -LogonType S4U `
    -RunLevel Highest

if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
    Write-Host "Task '$taskName' already exists, recreating..." -ForegroundColor Yellow
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
}

Register-ScheduledTask `
    -TaskName $taskName `
    -Action $action `
    -Trigger $trigger `
    -Settings $settings `
    -Principal $principal `
    -Description $taskDescription | Out-Null

Write-Host ""
Write-Host "Done: task '$taskName' created." -ForegroundColor Green
if ($IntervalMinutes -eq 0) {
    Write-Host "Runs once at system startup (when network is available), with no visible window."
} else {
    Write-Host "Runs every $IntervalMinutes min., with no visible window, whether or not you're logged in."
}

Write-Host ""
Write-Host "Running it once now, so the DNS record is up to date immediately..."
Start-ScheduledTask -TaskName $taskName
Start-Sleep -Seconds 3
$info = Get-ScheduledTaskInfo -TaskName $taskName
Write-Host "Last run result: $($info.LastTaskResult) (0 = success)"

Write-Host ""
Write-Host "Run it again manually any time: Start-ScheduledTask -TaskName '$taskName'"
Write-Host "View it in the UI:              Task Scheduler -> Task Scheduler Library -> '$taskName'"
"""

WINDOWS_INSTALLER_BAT = r"""@echo off
:: Double-click this file to install the DDNS scheduled task.
:: Automatically asks for administrator rights (UAC prompt) and bypasses
:: PowerShell's script-execution restrictions -- you don't need to change
:: any Windows settings yourself.

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting administrator privileges...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -ArgumentList '%*' -Verb RunAs"
    exit /b
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install-ddns-task.ps1" %*

echo.
pause
"""

# Python normalizes CRLF -> LF when it reads its own source file, even
# inside a raw triple-quoted string — so the literals above end up as
# plain \n by the time this module is imported, regardless of what's on
# disk. Windows .ps1/.bat files should be CRLF; force it explicitly
# here rather than relying on how the source file happens to be read.
WINDOWS_INSTALLER_SCRIPT = WINDOWS_INSTALLER_SCRIPT.replace("\r\n", "\n").replace("\n", "\r\n")
WINDOWS_INSTALLER_BAT = WINDOWS_INSTALLER_BAT.replace("\r\n", "\n").replace("\n", "\r\n")


def read_banned_ips():
    try:
        with open(BANNED_IPS_FILE) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {"generated_at": None, "jails": {}}


# ---------- CSRF protection for admin POST endpoints ----------
# HTTP Basic Auth credentials are cached by the browser and re-sent
# automatically on same-origin requests, which makes admin POST endpoints
# vulnerable to CSRF. Reject any request whose Origin/Referer points at a
# different host.

def verify_same_origin(request: Request):

    source = request.headers.get("Origin") or request.headers.get("Referer")

    if source:

        source_host = urlparse(source).netloc
        own_host = request.headers.get("host", request.url.netloc)

        if source_host and source_host != own_host:
            raise HTTPException(
                status_code=403,
                detail="Cross-origin request blocked"
            )

    return True


def make_fqdn(hostname: str) -> str:

    hostname = hostname.strip().rstrip(".")
    zone = ZONE.rstrip(".")

    if hostname.endswith(zone):
        return hostname + "."

    return f"{hostname}.{zone}."


def update_dns_record(hostname: str, ip: str):

    fqdn = make_fqdn(hostname)

    payload = {
        "rrsets": [
            {
                "name": fqdn,
                "type": "A",
                "ttl": 300,
                "changetype": "REPLACE",
                "records": [
                    {
                        "content": ip,
                        "disabled": False
                    }
                ]
            }
        ]
    }

    r = requests.patch(
        f"{PDNS_API}/api/v1/servers/localhost/zones/{ZONE}.",
        headers={
            "X-API-Key": PDNS_KEY,
            "Content-Type": "application/json"
        },
        json=payload
    )

    if r.status_code not in (200, 204):

        raise HTTPException(
            status_code=500,
            detail=r.text
        )

    return fqdn


SYSTEM_RECORD_TYPES = ["A", "AAAA", "CNAME", "TXT", "MX"]

# Эти записи держат зону: NS и SOA в апексе. Их нельзя менять из панели —
# ошибка здесь означает, что домен перестанет резолвиться вообще.
SYSTEM_PROTECTED_KEYS = {("@", "NS"), ("@", "SOA")}


def short_from_fqdn(name: str) -> str:
    """buten-ko.ru. -> @ ; ddns.buten-ko.ru -> ddns (как показывает reg.ru)."""
    name = (name or "").strip().rstrip(".").lower()
    zone = ZONE.rstrip(".").lower()
    if name == zone:
        return "@"
    if name.endswith("." + zone):
        return name[: -len(zone) - 1]
    return name


def fqdn_from_short(short: str) -> str:
    short = (short or "").strip().rstrip(".").lower()
    if short in ("", "@"):
        return ZONE.rstrip(".") + "."
    return f"{short}.{ZONE.rstrip('.')}."


def load_system_records():
    """
    Все записи зоны, которыми DDNS не управляет: NS и SOA в апексе, статические
    A (ns1, ns2, ddns, status), TXT и прочее. Возвращает короткие имена и
    признаки «защищена» и «несколько значений».
    """
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT r.name, r.type, r.content, r.ttl, r.prio
        FROM records r
        JOIN domains d ON d.id = r.domain_id
        WHERE d.name = %s
          AND r.name NOT IN (SELECT hostname || '.' || %s FROM ddns_clients)
        ORDER BY r.name, r.type, r.content
        """,
        (ZONE, ZONE),
    )
    rows = cur.fetchall()
    cur.close()
    conn.close()

    counts = defaultdict(int)
    for (name, rtype, _c, _t, _p) in rows:
        counts[(name.lower(), rtype)] += 1

    out = []
    for (name, rtype, content, ttl, prio) in rows:
        short = short_from_fqdn(name)
        out.append({
            "name": name,
            "short": short,
            "type": rtype,
            "content": content,
            "ttl": ttl,
            "prio": prio,
            "multi": counts[(name.lower(), rtype)] > 1,
            "protected": (short, rtype) in SYSTEM_PROTECTED_KEYS,
        })
    return out


def pdns_apply_rrsets(rrsets):
    """Одна точка записи в PowerDNS: и создание, и правка, и удаление."""
    r = requests.patch(
        f"{PDNS_API}/api/v1/servers/localhost/zones/{ZONE}.",
        headers={"X-API-Key": PDNS_KEY, "Content-Type": "application/json"},
        json={"rrsets": rrsets},
        timeout=10,
    )
    if r.status_code not in (200, 204):
        raise HTTPException(status_code=500, detail=r.text)


def system_record_error(msg: str):
    return RedirectResponse("/admin?sys=1&error=" + quote_plus(msg), status_code=303)


def system_record_ok(msg: str):
    return RedirectResponse("/admin?sys=1&msg=" + quote_plus(msg), status_code=303)


def validate_system_record(short: str, rtype: str, content: str, ttl: int, prio: str):
    """Возвращает (нормализованное содержимое, ошибка или None)."""
    short = (short or "").strip().rstrip(".").lower()

    if short and short != "@":
        for label in short.split("."):
            if not label or len(label) > 63 or not re.fullmatch(r"[a-z0-9_]([a-z0-9_-]*[a-z0-9])?", label):
                return None, "Имя записи: только латиница, цифры и дефис, без пробелов."

    if rtype not in SYSTEM_RECORD_TYPES:
        return None, "Такой тип записи панель не поддерживает."

    if ttl < 60 or ttl > 604800:
        return None, "TTL должен быть от 60 до 604800 секунд."

    content = content.strip()
    if not content:
        return None, "Значение записи не заполнено."

    if rtype == "A":
        if not is_valid_ip(content):
            return None, "Для A нужен корректный IPv4-адрес."
    elif rtype == "AAAA":
        try:
            ipaddress.IPv6Address(content)
        except ValueError:
            return None, "Для AAAA нужен корректный IPv6-адрес."
    elif rtype == "CNAME":
        content = content.rstrip(".") + "."
        if not re.fullmatch(r"[a-z0-9_.-]+", content.lower()):
            return None, "Для CNAME нужно доменное имя."
    elif rtype == "MX":
        host = content.rstrip(".") + "."
        if not re.fullmatch(r"[a-z0-9_.-]+", host.lower()):
            return None, "Для MX нужно доменное имя почтового сервера."
        try:
            p = int(prio) if str(prio).strip() else 10
        except ValueError:
            return None, "Приоритет MX должен быть числом."
        if p < 0 or p > 65535:
            return None, "Приоритет MX — от 0 до 65535."
        content = f"{p} {host}"
    elif rtype == "TXT":
        content = content.replace('"', '')
        content = f'"{content}"'

    return content, None


@app.get("/")
def root():

    return {
        "status": "ok",
        "service": "ddns-api"
    }


@app.get("/update")
@app.post("/update")
def update(
    request: Request,
    x_token: str = Header(None)
):

    client_ip = get_client_ip(request)
    check_rate_limit("token", client_ip)

    if not x_token:
        raise HTTPException(
            status_code=401,
            detail="Token required"
        )

    conn = get_db()

    try:

        cur = conn.cursor()

        cur.execute(
            """
            SELECT hostname
            FROM ddns_clients
            WHERE token=%s
            AND active=true
            """,
            (x_token,)
        )

        client = cur.fetchone()

        if not client:
            record_failure("token", client_ip)
            raise HTTPException(
                status_code=403,
                detail="Invalid token"
            )

        hostname = client[0]

        ip = get_client_ip(request)

        if not is_valid_ip(ip):
            raise HTTPException(
                status_code=400,
                detail="Could not determine a valid client IP"
            )

        fqdn = update_dns_record(
            hostname,
            ip
        )

        cur.execute(
            """
            UPDATE ddns_clients
            SET
                last_ip=%s,
                last_update=%s
            WHERE token=%s
            """,
            (
                ip,
                datetime.now(),
                x_token
            )
        )

        conn.commit()

        return {
            "status": "updated",
            "hostname": fqdn,
            "ip": ip
        }

    finally:

        conn.close()


@app.get("/login")
def login_page(
    request: Request,
    error: str = None
):

    # Already logged in — no reason to show the form again.
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if token and get_session_username(token):
        return RedirectResponse("/admin", status_code=303)

    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={
            "zone": ZONE,
            "error": error,
        }
    )


@app.post("/login")
def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...)
):

    client_ip = get_client_ip(request)

    if is_rate_limited("admin", client_ip):
        return RedirectResponse(
            "/login?error=Too+many+attempts%2C+try+again+later",
            status_code=303
        )

    stored = get_stored_admin_credentials()

    if stored:
        db_user, db_hash = stored
        ok = (
            secrets.compare_digest(username, db_user)
            and verify_password(password, db_hash)
        )
    else:
        ok = (
            secrets.compare_digest(username, ADMIN_USER)
            and secrets.compare_digest(password, ADMIN_PASSWORD)
        )

    if not ok:
        record_failure("admin", client_ip)
        return RedirectResponse(
            "/login?error=Invalid+username+or+password",
            status_code=303
        )

    token = create_session(username)

    response = RedirectResponse("/admin", status_code=303)
    response.set_cookie(
        SESSION_COOKIE_NAME,
        token,
        max_age=SESSION_MAX_AGE,
        httponly=True,
        secure=True,
        samesite="lax",
    )

    return response


@app.post("/logout")
def logout(
    request: Request,
    csrf: bool = Depends(verify_same_origin)
):

    token = request.cookies.get(SESSION_COOKIE_NAME)

    if token:
        destroy_session(token)

    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie(SESSION_COOKIE_NAME)

    return response


@app.get("/admin")
def admin(
    request: Request,
    auth: bool = Depends(admin_auth),
    error: str = None,
    msg: str = None
):
    conn = get_db()
    cur = conn.cursor()

    cur.execute(
        """
        SELECT
            id,
            hostname,
            description,
            token,
            last_ip,
            last_update,
            active
        FROM ddns_clients
        ORDER BY id
        """
    )

    rows = cur.fetchall()

    cur.close()
    conn.close()

    clients = []
    stats = {"total": 0, "live": 0, "stale": 0, "disabled": 0}

    for row in rows:

        (
            client_id,
            hostname,
            description,
            token,
            last_ip,
            last_update,
            active,
        ) = row

        status = freshness_bucket(last_update, active)

        stats["total"] += 1

        if status == "disabled":
            stats["disabled"] += 1
        elif status in ("live", "recent"):
            stats["live"] += 1
        elif status in ("stale", "old"):
            stats["stale"] += 1

        clients.append({
            "id": client_id,
            "hostname": hostname,
            "fqdn": make_fqdn(hostname).rstrip("."),
            "description": description,
            "token": token,
            "last_ip": last_ip,
            "last_update_human": human_relative(last_update),
            "active": active,
            "status": status,
        })

    clients.sort(
        key=lambda c: (
            STATUS_SORT_WEIGHT.get(c["status"], 99),
            c["hostname"].lower()
        )
    )

    stored_creds = get_stored_admin_credentials()
    admin_username = stored_creds[0] if stored_creds else ADMIN_USER

    banned_ips = read_banned_ips()
    system_records = load_system_records()

    return templates.TemplateResponse(
        request=request,
        name="admin.html",
        context={
            "clients": clients,
            "system_records": system_records,
            "record_types": SYSTEM_RECORD_TYPES,
            "stats": stats,
            "zone": ZONE,
            "base_url": get_base_url(request),
            "admin_username": admin_username,
            "banned_ips": banned_ips,
            "windows_installer_script": WINDOWS_INSTALLER_SCRIPT,
            "windows_installer_bat": WINDOWS_INSTALLER_BAT,
            "error": error,
            "msg": msg,
        }
    )


@app.post("/admin/create")
def create_client(

    hostname: str = Form(...),

    description: str = Form(""),

    auth: bool = Depends(admin_auth),
    csrf: bool = Depends(verify_same_origin)
):

    hostname = hostname.strip().lower()

    if hostname.endswith("." + ZONE):
        hostname = hostname[:-(len(ZONE) + 1)]

    if not is_valid_hostname_label(hostname):
        return RedirectResponse(
            "/admin?error=Host+name+must+be+letters%2C+digits+and+hyphens+only",
            status_code=303
        )

    token = secrets.token_hex(32)

    conn = get_db()
    cur = conn.cursor()

    try:

        cur.execute(
            """
            INSERT INTO ddns_clients
            (
                hostname,
                description,
                token,
                active
            )
            VALUES
            (
                %s,
                %s,
                %s,
                true
            )
            """,
            (
                hostname,
                description,
                token
            )
        )

        conn.commit()

    except psycopg2.Error:

        conn.rollback()

        return RedirectResponse(
            "/admin?error=Could+not+create+host+%28name+may+already+exist%29",
            status_code=303
        )

    finally:

        cur.close()
        conn.close()

    return RedirectResponse(
        "/admin?msg=Host+added",
        status_code=303
    )


@app.post("/admin/edit/{client_id}")
def edit_client(

    client_id: int,

    hostname: str = Form(...),

    description: str = Form(""),

    auth: bool = Depends(admin_auth),
    csrf: bool = Depends(verify_same_origin)
):

    hostname = hostname.strip().lower()

    if hostname.endswith("." + ZONE):
        hostname = hostname[:-(len(ZONE) + 1)]

    if not is_valid_hostname_label(hostname):
        return RedirectResponse(
            "/admin?error=Host+name+must+be+letters%2C+digits+and+hyphens+only",
            status_code=303
        )

    conn = get_db()
    cur = conn.cursor()

    # Старое имя нужно знать ДО обновления: если хост переименовали, запись
    # под прежним именем останется в зоне навсегда и будет указывать в никуда.
    cur.execute(
        "SELECT hostname, host(last_ip) FROM ddns_clients WHERE id=%s",
        (client_id,)
    )
    row = cur.fetchone()
    old_hostname, last_ip = row if row else (None, None)

    try:

        cur.execute(
            """
            UPDATE ddns_clients
            SET
                hostname=%s,
                description=%s
            WHERE id=%s
            """,
            (
                hostname,
                description,
                client_id
            )
        )

        conn.commit()

    except psycopg2.Error:

        conn.rollback()

        return RedirectResponse(
            "/admin?error=Could+not+save+changes",
            status_code=303
        )

    finally:

        cur.close()
        conn.close()

    # Переименование: сносим запись под старым именем и сразу заводим новую
    # с последним известным IP, чтобы не ждать следующего обновления от роутера.
    if old_hostname and old_hostname != hostname:

        dns_failed = False

        try:
            pdns_apply_rrsets([{
                "name": make_fqdn(old_hostname),
                "type": "A",
                "changetype": "DELETE",
                "records": [],
            }])
        except Exception:
            dns_failed = True

        if last_ip:
            try:
                update_dns_record(hostname, last_ip)
            except Exception:
                dns_failed = True

        if dns_failed:
            return RedirectResponse(
                "/admin?error=" + quote_plus(
                    "Хост переименован, но зону обновить не удалось — проверь PowerDNS"
                ),
                status_code=303
            )

        return RedirectResponse(
            "/admin?msg=" + quote_plus(f"Хост переименован: {old_hostname} → {hostname}"),
            status_code=303
        )

    return RedirectResponse(
        "/admin?msg=Changes+saved",
        status_code=303
    )


@app.post("/admin/toggle/{client_id}")
def toggle_client(

    client_id: int,

    auth: bool = Depends(admin_auth),
    csrf: bool = Depends(verify_same_origin)
):

    conn = get_db()
    cur = conn.cursor()

    try:

        cur.execute(
            """
            UPDATE ddns_clients
            SET active = NOT active
            WHERE id=%s
            """,
            (client_id,)
        )

        conn.commit()

    finally:

        cur.close()
        conn.close()

    return RedirectResponse(
        "/admin",
        status_code=303
    )


@app.post("/admin/delete/{client_id}")
def delete_client(

    client_id: int,

    auth: bool = Depends(admin_auth),
    csrf: bool = Depends(verify_same_origin)
):

    conn = get_db()
    cur = conn.cursor()

    cur.execute(
        "SELECT hostname FROM ddns_clients WHERE id=%s",
        (client_id,)
    )
    row = cur.fetchone()
    hostname = row[0] if row else None

    try:

        cur.execute(
            """
            DELETE FROM ddns_clients
            WHERE id=%s
            """,
            (client_id,)
        )

        conn.commit()

    finally:

        cur.close()
        conn.close()

    # Удалённый хост не должен оставлять запись в зоне: иначе его имя навсегда
    # указывает на старый IP (а имя могут занять заново).
    if hostname:
        try:
            pdns_apply_rrsets([{
                "name": make_fqdn(hostname),
                "type": "A",
                "changetype": "DELETE",
                "records": [],
            }])
        except Exception:
            return RedirectResponse(
                "/admin?error=" + quote_plus(
                    "Хост удалён, но запись в зоне убрать не удалось — проверь PowerDNS"
                ),
                status_code=303
            )

    return RedirectResponse(
        "/admin?msg=" + quote_plus("Хост удалён, запись из зоны убрана"),
        status_code=303
    )


@app.get("/admin/banned-ips/export")
def export_banned_ips(
    auth: bool = Depends(admin_auth)
):

    data = read_banned_ips()

    lines = [
        "Заблокированные IP (fail2ban)",
        f"Сформировано: {data.get('generated_at') or 'нет данных'}",
        "",
    ]

    jails = data.get("jails", {})

    if not jails:
        lines.append(
            "Нет данных — проверь, настроен ли на сервере "
            "scripts/export-fail2ban-status.sh через cron."
        )
    else:
        for jail, ips in jails.items():
            lines.append(f"[{jail}]")
            lines.extend(ips if ips else ["(нет заблокированных)"])
            lines.append("")

    content = "\n".join(lines)

    return Response(
        content=content,
        media_type="text/plain; charset=utf-8",
        headers={
            "Content-Disposition": "attachment; filename=banned-ips.txt"
        }
    )


@app.get("/admin/system-records")
def system_records(auth: bool = Depends(admin_auth)):
    """
    Записи зоны, которыми DDNS не управляет: NS и SOA в апексе, статические A
    (ns1, ns2, ddns, status и прочие), TXT, MX. Нужны, чтобы в панели была
    видна вся зона, а не только хосты из ddns_clients.
    """
    conn = get_db()
    cur = conn.cursor()

    cur.execute(
        """
        SELECT r.name, r.type, r.content, r.ttl, r.prio
        FROM records r
        JOIN domains d ON d.id = r.domain_id
        WHERE d.name = %s
          AND r.name NOT IN (
              SELECT hostname || '.' || %s FROM ddns_clients
          )
        ORDER BY r.name, r.type, r.content
        """,
        (ZONE, ZONE),
    )

    records = [
        {
            "name": name,
            "type": rtype,
            "content": content,
            "ttl": ttl,
            "prio": prio,
        }
        for (name, rtype, content, ttl, prio) in cur.fetchall()
    ]

    cur.close()
    conn.close()

    for rec in records:
        rec["short"] = short_from_fqdn(rec["name"])

    return {"zone": ZONE, "count": len(records), "records": records}


@app.post("/admin/system-records/save")
def system_record_save(
    name: str = Form(""),
    rtype: str = Form(...),
    content: str = Form(...),
    ttl: int = Form(3600),
    prio: str = Form(""),
    orig_name: str = Form(""),
    orig_type: str = Form(""),
    auth: bool = Depends(admin_auth),
    csrf: bool = Depends(verify_same_origin)
):
    short = (name or "").strip().rstrip(".").lower()
    rtype = (rtype or "").strip().upper()

    if (short, rtype) in SYSTEM_PROTECTED_KEYS or (short, rtype) in (
        ("@", "SOA"), ("@", "NS")
    ):
        return system_record_error("Записи NS и SOA в апексе панель не меняет — это опора зоны.")

    fixed, err = validate_system_record(short, rtype, content, ttl, prio)
    if err:
        return system_record_error(err)

    fqdn = fqdn_from_short(short)

    # Править можно только запись с единственным значением: REPLACE затирает
    # весь набор, а потерять вторую NS-запись или второй MX нельзя.
    existing = [r for r in load_system_records() if r["name"].lower() == fqdn.rstrip(".") and r["type"] == rtype]
    if existing and len(existing) > 1:
        return system_record_error("У этой записи несколько значений — правка из панели отключена.")

    if orig_name and orig_type:
        old_fqdn = fqdn_from_short(orig_name)
        old_type = orig_type.strip().upper()
        if (old_fqdn, old_type) != (fqdn, rtype):
            pdns_apply_rrsets([{
                "name": old_fqdn, "type": old_type,
                "changetype": "DELETE", "records": [],
            }])

    pdns_apply_rrsets([{
        "name": fqdn,
        "type": rtype,
        "ttl": int(ttl),
        "changetype": "REPLACE",
        "records": [{"content": fixed, "disabled": False}],
    }])

    return system_record_ok(f"Запись {short or '@'} {rtype} сохранена")


@app.post("/admin/system-records/delete")
def system_record_delete(
    name: str = Form(...),
    rtype: str = Form(...),
    auth: bool = Depends(admin_auth),
    csrf: bool = Depends(verify_same_origin)
):
    short = (name or "").strip().rstrip(".").lower()
    rtype = (rtype or "").strip().upper()

    if (short, rtype) in (("@", "NS"), ("@", "SOA")):
        return system_record_error("Записи NS и SOA в апексе удалить нельзя.")

    fqdn = fqdn_from_short(short)

    pdns_apply_rrsets([{
        "name": fqdn,
        "type": rtype,
        "changetype": "DELETE",
        "records": [],
    }])

    return system_record_ok(f"Запись {short or '@'} {rtype} удалена")


@app.post("/admin/unban")
def queue_unban(

    jail: str = Form(...),
    ip: str = Form(...),

    auth: bool = Depends(admin_auth),
    csrf: bool = Depends(verify_same_origin)
):

    jail = jail.strip()
    ip = ip.strip()

    if jail not in KNOWN_JAILS or not is_valid_ip(ip):
        return RedirectResponse(
            "/admin?error=Invalid+unban+request",
            status_code=303
        )

    try:
        with open(UNBAN_QUEUE_FILE, "a") as f:
            f.write(f"{jail} {ip}\n")
    except OSError:
        return RedirectResponse(
            "/admin?error=Could+not+queue+unban+request",
            status_code=303
        )

    return RedirectResponse(
        "/admin?msg=Unban+queued+%28takes+up+to+a+minute+to+apply%29",
        status_code=303
    )


@app.post("/admin/change-password")
def change_password(

    request: Request,

    current_password: str = Form(...),
    new_username: str = Form(...),
    new_password: str = Form(""),
    new_password_confirm: str = Form(""),

    auth: bool = Depends(admin_auth),
    csrf: bool = Depends(verify_same_origin)
):

    # Re-check the *current* password explicitly, so a CSRF'd request that
    # merely rides along on the session cookie still can't change it blind.
    stored = get_stored_admin_credentials()

    if stored:
        db_user, db_hash = stored
        current_ok = verify_password(current_password, db_hash)
    else:
        current_ok = secrets.compare_digest(current_password, ADMIN_PASSWORD)

    if not current_ok:
        return RedirectResponse(
            "/admin?error=Current+password+is+incorrect",
            status_code=303
        )

    new_username = new_username.strip()

    if not new_username:
        return RedirectResponse(
            "/admin?error=Username+is+required",
            status_code=303
        )

    changing_password = bool(new_password or new_password_confirm)

    if changing_password:

        if len(new_password) < 10:
            return RedirectResponse(
                "/admin?error=New+password+must+be+at+least+10+characters",
                status_code=303
            )

        if len(new_password.encode("utf-8")) > 72:
            return RedirectResponse(
                "/admin?error=New+password+must+be+under+72+bytes+%28bcrypt+limit%29",
                status_code=303
            )

        if new_password != new_password_confirm:
            return RedirectResponse(
                "/admin?error=New+passwords+do+not+match",
                status_code=303
            )

        password_hash = hash_password(new_password)

    else:

        # Keep the existing password hash — bootstrap one from the env
        # var if nothing's been stored yet (first-ever change here is
        # just a username change).
        password_hash = stored[1] if stored else hash_password(ADMIN_PASSWORD)

    conn = get_db()
    cur = conn.cursor()

    try:

        cur.execute(
            """
            INSERT INTO admin_credentials (username, password_hash)
            VALUES (%s, %s)
            """,
            (new_username, password_hash)
        )

        conn.commit()

    except psycopg2.Error:

        conn.rollback()

        return RedirectResponse(
            "/admin?error=Could+not+save+changes",
            status_code=303
        )

    finally:

        cur.close()
        conn.close()

    msg = "Password+changed" if changing_password else "Login+updated"

    return RedirectResponse(
        f"/admin?msg={msg}",
        status_code=303
    )



@app.get("/nic/update")
def nic_update(
    request: Request,
    hostname: str = None,
    username: str = None,
    password: str = None,
    myip: str = None
):

    client_ip = get_client_ip(request)
    check_rate_limit("token", client_ip)

    if not username or not password:

        basic_user, basic_pass = parse_basic_auth(request)

        username = username or basic_user
        password = password or basic_pass

    if not hostname or not username or not password:
        return "nohost"

    conn = get_db()

    try:

        cur = conn.cursor()

        cur.execute(
            """
            SELECT hostname
            FROM ddns_clients
            WHERE hostname=%s
              AND token=%s
              AND active=true
            """,
            (
                username.strip().lower(),
                password
            )
        )

        client = cur.fetchone()

        if not client:
            record_failure("token", client_ip)
            return "badauth"

        #
        # Берем имя только из базы данных.
        # Параметр hostname из URL игнорируем.
        #
        hostname = client[0]

        # Some routers (e.g. Omada) leave the [IP] placeholder unresolved
        # if they can't determine it themselves — fall back to the request's
        # own source address in that case rather than writing garbage.
        ip = myip if is_valid_ip(myip) else client_ip

        if not is_valid_ip(ip):
            return "911"

        fqdn = update_dns_record(
            hostname,
            ip
        )

        cur.execute(
            """
            UPDATE ddns_clients
            SET
                last_ip=%s,
                last_update=%s
            WHERE hostname=%s
            """,
            (
                ip,
                datetime.now(),
                hostname
            )
        )

        conn.commit()

        return f"good {ip}"

    finally:

        conn.close()
