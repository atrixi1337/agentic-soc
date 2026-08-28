@echo off
rem ============================================================
rem  SOC-SETUP.bat - double-click to harden SOC-Victim lab.
rem  Self-elevates (one UAC prompt), then disables Defender
rem  real-time protection, adds exclusions, and installs Sysmon
rem  with a detection config.
rem ============================================================
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting administrator rights...
    powershell -NoProfile -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)
echo Running SOC-Victim setup...
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0soc-setup.ps1"
echo.
pause >nul