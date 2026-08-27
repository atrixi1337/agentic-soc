# =====================================================================
#  install-v3-shim.ps1 - run elevated on SOC-Victim (launched by .bat)
#  Copies the hardened fetcher + exe + cmd from staging into the agent
#  bin, restarts the Wazuh service, and posts the EICAR test alert.
# =====================================================================
$src = 'C:\Users\victim\soc-ar'
$dst = 'C:\Program Files (x86)\ossec-agent\active-response\bin'

foreach ($pre in @('soc-fetch-sample.exe', 'soc-fetch-sample.ps1', 'soc-fetch-sample.cmd')) {
    if (-not (Test-Path (Join-Path $src $pre))) { Write-Host "  [MISSING in staging] $pre" }
}

Write-Host '[1/4] Installing into agent bin...'
foreach ($f in @('soc-fetch-sample.exe', 'soc-fetch-sample.ps1', 'soc-fetch-sample.cmd')) {
    try {
        Copy-Item (Join-Path $src $f) $dst -Force -ErrorAction Stop
        Write-Host "  [OK] $f"
    } catch {
        Write-Host "  [FAIL] $f : $($_.Exception.Message)"
    }
}

Write-Host '[2/4] Restarting Wazuh service (clears AR lock)...'
net stop wazuhsvc | Out-Null
net start wazuhsvc | Out-Null
Write-Host '  service restarted.'
Start-Sleep -Seconds 3

Write-Host '[3/4] Writing marker...'
Add-Content -Path "$src\install_marker.txt" -Value "$(Get-Date -Format s) v3 installer run."

Write-Host '[4/4] Posting EICAR test alert...'
$alertBody = @{
    timestamp = '2026-08-25T19:05:00.000+0000'
    rule = @{ level=14; id='100016'; description='Unsigned binary written to user directory then executed - credential access tooling suspected' }
    agent = @{ id='002'; name='SOC-Victim'; ip='192.168.10.123' }
    data = @{ win = @{ eventdata = @{ path='C:\Users\victim\soc-ar\eicar_probe.bin' } } }
    location = 'Eventchannel'
    id = '1787680000.701025'
} | ConvertTo-Json -Compress
Invoke-RestMethod -Uri 'http://192.168.10.101:5678/webhook/e1a80abd-e35b-45cb-958a-e57dad1e144b' -Method Post -ContentType 'application/json' -Body $alertBody | Out-Null
Write-Host '  alert posted.'

Write-Host ''
Get-ChildItem "$dst\soc-*" | Select-Object Name, Length | Format-Table -AutoSize
Write-Host 'DONE. You can close this window.'