# ============================================================
#  install-fetch-scripts.ps1  -  run me from the Desktop!
#  Copies the Wazuh active-response fetch scripts into the
#  agent's bin directory. Self-elevates via UAC.
# ============================================================
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Requesting administrator rights..." -ForegroundColor Yellow
    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

$src = "C:\Users\victim\soc-ar"
$dst = "C:\Program Files (x86)\ossec-agent\active-response\bin"

Write-Host "Source: $src"
Write-Host "Target: $dst`n"

foreach ($f in @("soc-fetch-sample.exe", "soc-fetch-sample.ps1", "soc-fetch-sample.cmd")) {
    try {
        Copy-Item (Join-Path $src $f) $dst -Force -ErrorAction Stop
        Write-Host "  [OK] $f" -ForegroundColor Green
    } catch {
        Write-Host "  [FAIL] $f : $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Host "`nInstalled files in bin:"
Get-ChildItem "$dst\soc-*" | ForEach-Object { Write-Host ("  " + $_.Name + "  (" + $_.Length + " bytes)") }

Write-Host "`nDone. You can close this window." -ForegroundColor Cyan
Read-Host "Press Enter to exit"
