<#
.SYNOPSIS
  Runs the REAL agent exe against the local demo platform in four update scenarios and reports what each did.
  Nothing touches the installed agent, the real platform or %PROGRAMDATA%: every scenario has its own throwaway folder and port.

.DESCRIPTION
  forged   - offer signed by a key the agent does not trust        -> must be REJECTED before any download
  older    - validly signed, but older than the running version    -> must be REJECTED (no downgrade)
  tampered - validly signed offer, but the file bytes were changed -> must be REJECTED after download, never installed
  good     - validly signed, newer, correct hash (the file is not a real installer) -> must be ACCEPTED and the installer
             started; msiexec then fails on the junk file, which is the safe way to see the whole path run

  The agent's first update check is 5 minutes after it starts, so this takes about 6 minutes. Your default browser opens one
  demo sign-in tab per scenario during enrollment; they finish by themselves and can be closed.
#>
param([int]$WaitSeconds = 345)
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$exe = Join-Path $here '..\dist\iam-endpoint-agent.exe'
$root = Join-Path $env:TEMP 'iam-update-e2e'
$scenarios = @('forged', 'older', 'tampered', 'good')
if (-not (Test-Path $exe)) { throw "Agent not found at $exe" }
if (Test-Path $root) { Remove-Item $root -Recurse -Force }
New-Item -ItemType Directory $root | Out-Null

$runs = @()
$port = 8771
foreach ($name in $scenarios) {
    $dir = Join-Path $root $name
    $data = Join-Path $dir 'IamEndpointAgent'
    New-Item -ItemType Directory $data -Force | Out-Null
    $platform = Start-Process python -ArgumentList @((Join-Path $here 'mock_platform.py'), '--out', "`"$data`"", '--port', $port, '--update-scenario', $name) `
        -PassThru -WindowStyle Hidden -RedirectStandardOutput (Join-Path $dir 'platform.out') -RedirectStandardError (Join-Path $dir 'platform.err')
    for ($i = 0; $i -lt 40; $i++) { try { Invoke-RestMethod "http://127.0.0.1:$port/api/state" -TimeoutSec 2 | Out-Null; break } catch { Start-Sleep -Milliseconds 250 } }

    $env:PROGRAMDATA = $dir
    $env:IAM_AGENT_CONFIG = Join-Path $data 'config.json'
    $env:RUST_LOG = 'agent_core=info,iam_endpoint_agent=info'
    & $exe --enroll --ownership=BYOD | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "enrollment failed for $name (exit $LASTEXITCODE)" }
    $agent = Start-Process $exe -ArgumentList '--console' -PassThru -WindowStyle Hidden -RedirectStandardOutput (Join-Path $dir 'agent.out') -RedirectStandardError (Join-Path $dir 'agent.err')
    $runs += [pscustomobject]@{ Name = $name; Port = $port; Dir = $dir; Platform = $platform; Agent = $agent }
    "enrolled and started: $name (port $port)"
    $port++
}

"waiting $WaitSeconds s for the first update check..."
Start-Sleep -Seconds $WaitSeconds

"`n================ RESULTS ================"
foreach ($r in $runs) {
    "`n--- scenario: $($r.Name)"
    $agentLog = (Get-Content (Join-Path $r.Dir 'agent.err') -Raw -ErrorAction SilentlyContinue) + (Get-Content (Join-Path $r.Dir 'agent.out') -Raw -ErrorAction SilentlyContinue)
    ($agentLog -split "`n" | Where-Object { $_ -match 'update check finished|automatic updates' } | ForEach-Object { '  agent: ' + (($_ -replace '\x1b\[[0-9;]*m', '').Trim()) }) -join "`n"
    $state = Invoke-RestMethod "http://127.0.0.1:$($r.Port)/api/state"
    ($state.log | Where-Object { $_ -match 'update|package|event|CRITICAL|WARNING' } | Select-Object -First 6 | ForEach-Object { '  platform: ' + $_ }) -join "`n"
    $msi = Get-ChildItem (Join-Path $r.Dir 'IamEndpointAgent\updates') -Filter *.msi -ErrorAction SilentlyContinue
    "  installer file left on disk: " + $(if ($msi) { $msi.Name } else { 'none' })
    $ilog = Join-Path $r.Dir 'IamEndpointAgent\updates\install.log'
    "  msiexec was started (install.log exists): " + (Test-Path $ilog)
}

foreach ($r in $runs) { Stop-Process -Id $r.Agent.Id -Force -ErrorAction SilentlyContinue; Stop-Process -Id $r.Platform.Id -Force -ErrorAction SilentlyContinue }
"`nstopped all demo agents and platforms. Installed service untouched: " + (Get-Service IamEndpointAgent -ErrorAction SilentlyContinue).Status
