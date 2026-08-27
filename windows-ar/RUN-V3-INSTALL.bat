@echo off
rem ============================================================
rem  RUN-V3-INSTALL.bat - double-click to install the hardened
rem  SOC fetcher into the Wazuh agent and fire the EICAR test.
rem  Self-elevates (one UAC prompt), then runs the PS installer.
rem ============================================================
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting administrator rights...
    powershell -NoProfile -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)
echo Running installer...
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install-v3-shim.ps1"
echo.
echo Press any key to close...
pause >nul