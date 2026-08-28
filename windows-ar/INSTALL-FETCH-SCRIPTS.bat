@echo off
rem Launcher: right-click me and choose "Run as administrator",
rem or just double-click - the PowerShell script will ask for rights itself.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install-fetch-scripts.ps1"
