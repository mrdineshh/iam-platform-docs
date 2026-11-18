<#
.SYNOPSIS
  Runs the real IAM endpoint agent on THIS machine against a local demo platform, so you can watch it work.

.DESCRIPTION
  1. Starts the local demo platform (a stand-in for the real one, listening on 127.0.0.1 only).
  2. Opens its dashboard in your browser.
  3. Runs `iam-endpoint-agent.exe --enroll` (opens a sign-in page in your browser; it completes by itself).
  4. Runs the agent in this window. Press Ctrl-C to stop, or pass -Seconds for a timed run.

  Click "Approve this device" on the dashboard and watch the next signed policy change.
  Nothing touches the real platform. All files go in %TEMP%\iam-agent-demo (not %PROGRAMDATA%), removed with -Clean.
  Run it from a PowerShell opened "as administrator" to let the agent read BitLocker, TPM and Secure Boot too;
  without that those three show "Unknown" (the installed service runs as SYSTEM, which can read them).

.EXAMPLE
  .\run_demo.ps1                 # run until Ctrl-C
  .\run_demo.ps1 -Seconds 90     # a 90-second run, then stop
#>
param(
    [int]$Seconds = 0,
    [int]$Port = 8765,
    [switch]$Clean
)
$ErrorActionPreference = 'Stop'

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$exe = Join-Path $here '..\dist\iam-endpoint-agent.exe'
$demo = Join-Path $env:TEMP 'iam-agent-demo'
$dataDir = Join-Path $demo 'IamEndpointAgent'

if (-not (Test-Path $exe)) { throw "Agent not found at $exe. Build it first (see ..\README.md)." }
if (-not (Get-Command python -ErrorAction SilentlyContinue)) { throw 'Python is required for the demo platform.' }
& python -c 'import cryptography' 2>$null
if ($LASTEXITCODE -ne 0) { throw 'The demo platform needs the "cryptography" package:  python -m pip install cryptography' }

# A previous demo platform still running on this port would serve stale state: stop it.
Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue | ForEach-Object {
    $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
    if ($proc -and $proc.ProcessName -like 'python*') { Stop-Process -Id $proc.Id -Force; Start-Sleep -Milliseconds 500 }
}
if (Test-Path $demo) { Remove-Item $demo -Recurse -Force }
New-Item -ItemType Directory -Path $dataDir -Force | Out-Null
if ($Clean) { Write-Host 'Cleaned.'; return }

$platform = Start-Process python -ArgumentList @((Join-Path $here 'mock_platform.py'), '--out', "`"$dataDir`"", '--port', $Port) `
    -PassThru -WindowStyle Hidden -RedirectStandardOutput (Join-Path $demo 'platform.log') -RedirectStandardError (Join-Path $demo 'platform.err')
try {
    for ($i = 0; $i -lt 40; $i++) {
        try { Invoke-RestMethod "http://127.0.0.1:$Port/api/state" -TimeoutSec 2 | Out-Null; break } catch { Start-Sleep -Milliseconds 250 }
    }
    Write-Host "Demo platform running: http://127.0.0.1:$Port/   (a stand-in, not the real platform)" -ForegroundColor Cyan
    Start-Process "http://127.0.0.1:$Port/"

    # Keep the agent's files out of the real %PROGRAMDATA%.
    $env:PROGRAMDATA = $demo
    $env:RUST_LOG = 'agent_core=info,iam_endpoint_agent=info'

    Write-Host "`n[1/2] Enrolling. Your browser opens a demo sign-in page; it finishes by itself." -ForegroundColor Cyan
    & $exe --enroll --ownership=BYOD
    if ($LASTEXITCODE -ne 0) { throw "Enrollment failed (exit $LASTEXITCODE)." }

    Write-Host "`n[2/2] Running the agent. Watch the dashboard; click 'Approve this device'." -ForegroundColor Cyan
    Write-Host '      Ctrl-C stops it.' -ForegroundColor DarkGray
    if ($Seconds -gt 0) {
        $agent = Start-Process $exe -ArgumentList '--console' -PassThru -NoNewWindow
        if (-not $agent.WaitForExit($Seconds * 1000)) { Stop-Process -Id $agent.Id -Force; Write-Host "`nStopped after $Seconds s." }
    } else {
        & $exe --console
    }
}
finally {
    Write-Host "`nLeaving the demo platform running so you can keep looking at the dashboard." -ForegroundColor DarkGray
    Write-Host "Stop it with:  Stop-Process -Id $($platform.Id)     Remove files with:  .\run_demo.ps1 -Clean" -ForegroundColor DarkGray
}
