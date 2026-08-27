# =====================================================================
#  soc-fetch-sample.ps1 - hardened forensic fetcher for the Agentic SOC
#  Robust parser: reads args from argv OR direct JSON fields OR CLI.
#  Lane 1: file still on disk -> ship.
#  Lane 2: Defender quarantined -> restore via MpCmdRun -> ship.
# =====================================================================
param([string]$StdinFile, [string]$Path, [string]$AlertId)

$ErrorActionPreference = 'SilentlyContinue'
$HookUrl  = 'http://192.168.10.101:5678/webhook/yarakin-sample-intake'
$Log      = 'C:\Quarantine\fetch_log.txt'
$MaxBytes = 10485760
$MpCmdRun = Join-Path ${env:ProgramFiles} 'Windows Defender\MpCmdRun.exe'
if (-not (Test-Path $MpCmdRun)) { $MpCmdRun = 'C:\Program Files\Windows Defender\MpCmdRun.exe' }

function Write-Log([string]$m) {
    try {
        if (-not (Test-Path 'C:\Quarantine')) { New-Item -ItemType Directory -Path 'C:\Quarantine' -Force | Out-Null }
        Add-Content -Path $Log -Value ("{0} {1}" -f (Get-Date -Format s), $m)
    } catch {}
}

function Get-Name([string]$p) {
    try { (Split-Path $p -Leaf) } catch { $p }
}
function Get-Sha([string]$f) {
    $bytes = [System.IO.File]::ReadAllBytes($f)
    $hash  = [System.Security.Cryptography.SHA256]::Create().ComputeHash($bytes)
    return [BitConverter]::ToString($hash).Replace('-', '').ToLower()
}

# ---- resolve path + alert id from all possible sources ----
$path = $Path
$alertId = $AlertId

if (-not $path) {
    foreach ($src in @($StdinFile)) {
        if ($src -and (Test-Path $src)) {
            try {
                $j = Get-Content $src -Raw | ConvertFrom-Json
                if ($j.parameters -and $j.parameters.argv -and $j.parameters.argv[0]) {
                    $path = [string]$j.parameters.argv[0]
                    if (-not $alertId -and $j.parameters.argv[1]) { $alertId = [string]$j.parameters.argv[1] }
                }
                elseif ($j.path) { $path = [string]$j.path }
                if (-not $alertId -and $j.alert_id) { $alertId = [string]$j.alert_id }
                Write-Log "parsed path=$path alert=$alertId src=$src"
            } catch {
                # non-JSON: maybe raw text; try to find a windows path
                $raw = (Get-Content $src -Raw)
                $m = [regex]::Match($raw, '[A-Za-z]:[\\][^\"]+$')
                if ($m.Success) { $path = $m.Value.Trim() }
                Write-Log ("JSON-PARSE-FALLBACK " + $_.Exception.Message)
            }
        }
    }
}

if (-not $path) { Write-Log "NO-TARGET"; exit 0 }
Write-Log "FETCH requested path=$path alert=$alertId"

# ---------------- Lane 1: file still on disk ----------------
if (Test-Path -LiteralPath $path) {
    $f = Get-Item -LiteralPath $path
    if ($f.Length -gt $MaxBytes) { Write-Log "TOOBIG $($f.Length)B $path"; exit 0 }
    $sha = Get-Sha $f.FullName
    $body = @{
        alert_id = $alertId; agent = $env:COMPUTERNAME; path = $f.FullName
        size = $f.Length; sha256 = $sha
        data_b64 = [Convert]::ToBase64String([System.IO.File]::ReadAllBytes($f.FullName))
        source = 'live'
    } | ConvertTo-Json -Compress
    Invoke-RestMethod -Uri $HookUrl -Method Post -Body $body -ContentType 'application/json' -TimeoutSec 90 | Out-Null
    Write-Log ("SENT {0}B src=live sha={1} alert={2} path={3}" -f $f.Length, $sha.Substring(0,12), $alertId, $path)
    exit 0
}

# ---------------- Lane 2: Defender quarantine ----------------
Write-Log "NOTFOUND - checking Defender quarantine"
$restored = $false
try {
    $name = Get-Name $path
    $dets = Get-MpThreatDetection -ErrorAction SilentlyContinue | Where-Object {
        ($_.Resources -join ' ') -like "*$path*" -or ($_.Resources -join ' ') -like "*$name*"
    }
    if (-not $dets) { $dets = @(Get-MpThreatDetection -ErrorAction SilentlyContinue | Select -First 1) }
    foreach ($d in $dets) {
        $tid = $d.ThreatID
        if ($tid) {
            Write-Log ("RESTORE attempt threat={0}" -f $tid)
            & $MpCmdRun -Restore -ThreatID $tid | Out-Null
            Start-Sleep -Seconds 4
            if (Test-Path -LiteralPath $path) { $restored = $true; break }
        }
    }
    if (-not $restored) {
        Write-Log "falling back to full restore"
        & $MpCmdRun -Restore -All | Out-Null
        Start-Sleep -Seconds 4
        if (Test-Path -LiteralPath $path) { $restored = $true }
    }
} catch {
    Write-Log ("DEFENDER-LANE-FAIL " + $_.Exception.Message)
}

if (-not $restored -or -not (Test-Path -LiteralPath $path)) {
    Write-Log "UNRECOVERABLE $path"
    exit 0
}

$f = Get-Item -LiteralPath $path
$sha = Get-Sha $f.FullName
$body = @{
    alert_id = $alertId; agent = $env:COMPUTERNAME; path = $f.FullName
    size = $f.Length; sha256 = $sha
    data_b64 = [Convert]::ToBase64String([System.IO.File]::ReadAllBytes($f.FullName))
    source = 'defender-restored'
} | ConvertTo-Json -Compress
Invoke-RestMethod -Uri $HookUrl -Method Post -Body $body -ContentType 'application/json' -TimeoutSec 90 | Out-Null
Write-Log ("SENT {0}B src=defender-restored sha={1} alert={2} path={3}" -f $f.Length, $sha.Substring(0,12), $alertId, $path)
exit 0