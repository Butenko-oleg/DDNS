@echo off
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
