# FC Lock wake-window test - self-service runner
# Usage: powershell -File tools\run_wake_test.ps1 [-Minutes 5]
# What it does:
#   1. Restarts the wake watcher inside the Home Assistant container (fresh window)
#   2. Tells you to press the doorbell / 4+# at the lock
#   3. Streams the watcher log LIVE into this window
#   4. Saves the final log to tools\wake_test_output.log for analysis
# When it finishes, go back to the agent chat and say: check

param(
    [int]$Minutes = 5
)

$ErrorActionPreference = "Stop"
$HaHost = "root@192.168.2.113"
$RemoteLog = "/docker/homeassistant/wake_catcher.log"
$SshOpts = @("-o", "BatchMode=yes")

Write-Host "=== FC Lock wake-window test ===" -ForegroundColor Cyan
Write-Host "Restarting watcher (fresh $Minutes-minute window)..."

& ssh @SshOpts $HaHost "docker exec homeassistant sh -c 'pkill -f wake_catcher.py'; rm -f /docker/homeassistant/wake_catcher.log /docker/homeassistant/wake_catcher.err; nohup docker exec -w /config homeassistant python3 wake_catcher.py --minutes $Minutes --max-openlock 10 --try-unlock > /dev/null 2> /docker/homeassistant/wake_catcher.err & sleep 2; head -3 $RemoteLog"

Write-Host ""
Write-Host "********************************************************" -ForegroundColor Yellow
Write-Host "*  GO PRESS THE DOORBELL (or 4 + #) AT THE LOCK NOW!  *" -ForegroundColor Yellow
Write-Host "*  Results stream below. Stand by the door ~60s.      *" -ForegroundColor Yellow
Write-Host "********************************************************" -ForegroundColor Yellow
Write-Host ""

# Stream the watcher log live for the whole window
& ssh @SshOpts $HaHost "timeout $(($Minutes + 1) * 60) tail -n +1 -f $RemoteLog"

Write-Host ""
Write-Host "=== Window closed. Saving final log ===" -ForegroundColor Cyan
& ssh @SshOpts $HaHost "cat $RemoteLog" | Tee-Object -FilePath (Join-Path $PSScriptRoot "wake_test_output.log") | Out-Null
Write-Host "Saved: tools\wake_test_output.log"
Write-Host ""
Write-Host "DONE. Now go back to the agent chat and say:  check" -ForegroundColor Green
