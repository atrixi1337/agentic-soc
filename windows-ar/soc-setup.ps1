# =====================================================================
#  soc-setup.ps1 - SOC-Victim one-shot lab hardening (run ELEVATED)
#  1) Disable Defender real-time protection + add exclusions so samples
#     stay on disk for the bridge to collect.
#  2) Install Sysmon with a real detection config (process/file/network)
#     so Wazuh gets rich, versatile alerts.
#  Launched elevated by SOC-SETUP.bat (self-elevates via UAC).
# =====================================================================
$ErrorActionPreference = 'SilentlyContinue'
Write-Host '=== SOC-Victim setup ==='

# ---- 1) Defender: disable real-time + exclusions ----
Write-Host '[1/3] Configuring Defender...'
try {
    Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction Stop
    Set-MpPreference -ExclusionPath @('C:\Users\victim\Downloads','C:\Users\victim\Desktop','C:\Users\victim\Documents') -ErrorAction Stop
    Set-MpPreference -PUAProtection 0 -ErrorAction Stop
    Write-Host '  Defender real-time OFF; Downloads/Desktop/Documents excluded.' -ForegroundColor Green
} catch {
    Write-Host "  [WARN] Defender: $($_.Exception.Message)" -ForegroundColor Yellow
}

# ---- 2) Sysmon install (only if not already present) ----
Write-Host '[2/3] Installing/updating Sysmon...'
$sysDir = "$env:TEMP\Sysmon"
$zip = "$env:TEMP\Sysmon.zip"
if (-not (Test-Path "C:\Windows\Sysmon64.exe")) {
    try {
        if (-not (Test-Path "$sysDir\Sysmon64.exe")) {
            Invoke-WebRequest -Uri 'https://download.sysinternals.com/files/Sysmon.zip' -OutFile $zip
            if (Test-Path $sysDir) { Remove-Item $sysDir -Recurse -Force }
            Expand-Archive $zip -DestinationPath $sysDir -Force
        }
        Copy-Item "$sysDir\Sysmon64.exe" 'C:\Windows\Sysmon64.exe' -Force
        Remove-Item "$sysDir\Sysmon64.exe" -Force
        Write-Host '  Sysmon64.exe downloaded.' -ForegroundColor Green
    } catch {
        Write-Host "  [WARN] Sysmon download: $($_.Exception.Message)" -ForegroundColor Yellow
    }
} else {
    Write-Host '  Sysmon64.exe already present.' -ForegroundColor Green
}

# ---- 3) Real detection config (process create, file create, network, DNS) ----
Write-Host '[3/3] Applying Sysmon detection config...'
$cfgPath = "$sysDir\sysmon-config.xml"
# Inclusive config: log everything Sysmon sees (process, file, network, dns).
$cfg = @'
<Sysmon schemaversion="4.90">
  <EventFiltering>
    <!-- empty = log all events (no exclusions) -->
  </EventFiltering>
</Sysmon>
'@
Set-Content $cfgPath -Value $cfg

# Apply config (full reload)
try {
    & 'C:\Windows\Sysmon64.exe' -accepteula -c $cfgPath
    Write-Host '  Sysmon config applied.' -ForegroundColor Green
} catch {
    Write-Host "  [WARN] Sysmon config: $($_.Exception.Message)" -ForegroundColor Yellow
}

# ---- 3b+4) Point Wazuh at Sysmon channel + add user dirs to Wazuh FIM; restart agent once ----
Write-Host '[3/3] Configuring Wazuh agent (Sysmon channel + FIM dirs)...'
$wconf = 'C:\Program Files (x86)\ossec-agent\ossec.conf'
$didChange = $false
try {
    $raw = Get-Content $wconf -Raw
    # Sysmon event channel
    if ($raw -notmatch 'Sysmon/Operational') {
        $evt = @'
  <localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
'@
        $raw = $raw -replace '</ossec_config>', ($evt + '</ossec_config>')
        $didChange = $true
        Write-Host '  Sysmon event channel added.' -ForegroundColor Green
    } else {
        Write-Host '  Sysmon channel already present.' -ForegroundColor Green
    }
    # FIM dirs
    if ($raw -notmatch 'Downloads') {
        $fim = @'
  <directories check_all="yes" realtime="yes" recursion_level="2">C:\Users\victim\Downloads</directories>
  <directories check_all="yes" realtime="yes" recursion_level="1">C:\Users\victim\Desktop</directories>
  <directories check_all="yes" realtime="yes" recursion_level="2">C:\Users\victim\Documents</directories>
'@
        $raw = $raw -replace '<syscheck>', ("<syscheck>`r`n" + $fim)
        $didChange = $true
        Write-Host '  FIM dirs added (Downloads, Desktop, Documents).' -ForegroundColor Green
    } else {
        Write-Host '  FIM dirs already present.' -ForegroundColor Green
    }
    if ($didChange) {
        $raw | Set-Content $wconf -Encoding ASCII -Force
        net stop wazuhsvc | Out-Null
        net start wazuhsvc | Out-Null
        Start-Sleep -Seconds 3
        Write-Host '  Wazuh agent restarted.' -ForegroundColor Green
    }
} catch {
    Write-Host "  [WARN] Wazuh agent config: $($_.Exception.Message)" -ForegroundColor Yellow
}

# ---- marker ----
Add-Content -Path 'C:\Users\victim\soc-ar\setup_marker.txt' -Value "$(Get-Date -Format s) soc-setup ran."
Write-Host ''
Write-Host 'DONE. Reboot the VM for Defender/sysmon changes to fully apply? (not required for RTM off).'
Write-Host 'You can close this window.'