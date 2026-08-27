@echo off
rem SOC-FETCH-SAMPLE - Wazuh active-response wrapper.
rem execd pipes the AR JSON to stdin; stash it and hand off to PowerShell detached
rem so execd is never blocked by network latency.
set INFILE=%TEMP%\soc_fetch_%RANDOM%.json
more > "%INFILE%"
if exist "C:\Quarantine" (start "" /min powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0soc-fetch-sample.ps1" -StdinFile "%INFILE%") else (
  mkdir "C:\Quarantine" >nul 2>&1
  start "" /min powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0soc-fetch-sample.ps1" -StdinFile "%INFILE%"
)
exit /b 0
