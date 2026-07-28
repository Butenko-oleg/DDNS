<#
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
