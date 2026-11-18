<#
.SYNOPSIS
  Installs the IAM endpoint agent on this Windows machine as an auto-starting service, and enrolls the device.

.DESCRIPTION
  Run from an ADMINISTRATOR PowerShell. It:
    1. copies the agent to C:\Program Files\IamEndpointAgent (writable by administrators only),
    2. writes %ProgramData%\IamEndpointAgent\config.json (locked to SYSTEM and administrators),
    3. enrolls the device (opens your browser to sign in; finishes by itself),
    4. registers and starts the "IamEndpointAgent" service (runs as LocalSystem, restarts itself on failure).

  The device then appears in the Admin Console under Endpoint Security as PENDING_APPROVAL.

.EXAMPLE
  .\install.ps1 -TenantId 11111111-2222-3333-4444-555555555555 -PolicyPublicKey "<base64 from device-trust-setup.py>"

.EXAMPLE
  .\install.ps1 -Uninstall          # stops and removes the service and program files (config and device identity kept)
#>
[CmdletBinding()]
param(
    [string]$TenantId,
    [string]$PolicyPublicKey,
    [string]$BackendUrl = 'https://tenant.34-71-129-0.sslip.io',
    [string]$EnrollUrl = 'https://login.34-71-129-0.sslip.io/device-enroll',
    [string]$Exe = (Join-Path $PSScriptRoot '..\dist\iam-endpoint-agent.exe'),
    [ValidateSet('CORPORATE', 'BYOD')][string]$Ownership = 'CORPORATE',
    [string[]]$AllowedIdentityDomains = @(),   # e.g. econz.net : Chrome/Edge may only sign in to accounts at these domains
    [switch]$Uninstall
)
$ErrorActionPreference = 'Stop'
$svc = 'IamEndpointAgent'
$installDir = Join-Path $env:ProgramFiles 'IamEndpointAgent'
$dataDir = Join-Path $env:ProgramData 'IamEndpointAgent'
$installed = Join-Path $installDir 'iam-endpoint-agent.exe'

$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this from an administrator PowerShell (right-click PowerShell, "Run as administrator").'
}

function Stop-AndRemoveService {
    if (Get-Service $svc -ErrorAction SilentlyContinue) {
        Stop-Service $svc -Force -ErrorAction SilentlyContinue
        & sc.exe delete $svc | Out-Null
        Start-Sleep -Seconds 2
    }
}

if ($Uninstall) {
    Stop-AndRemoveService
    # Take back the browser sign-in restriction this agent applied (only if it was configured to apply one).
    $cfgFile = Join-Path $dataDir 'config.json'
    if (Test-Path $cfgFile) {
        $cfg = Get-Content $cfgFile -Raw | ConvertFrom-Json
        if (@($cfg.allowed_identity_domains).Count -gt 0) {
            foreach ($t in @(@('HKLM:\SOFTWARE\Policies\Google\Chrome', 'RestrictSigninToPattern'),
                             @('HKLM:\SOFTWARE\Policies\Google\Chrome', 'AllowedDomainsForApps'),
                             @('HKLM:\SOFTWARE\Policies\Microsoft\Edge', 'RestrictSigninToPattern'))) {
                Remove-ItemProperty -Path $t[0] -Name $t[1] -ErrorAction SilentlyContinue
            }
            Write-Host 'Removed the browser sign-in restriction.' -ForegroundColor Green
        }
    }
    if (Test-Path $installDir) { Remove-Item $installDir -Recurse -Force }
    Write-Host "Removed the service and program files. Config and device identity kept in $dataDir." -ForegroundColor Green
    return
}

if (-not $TenantId) { $TenantId = (Read-Host 'Tenant ID (UUID, from your administrator)').Trim() }
if (-not $PolicyPublicKey) { $PolicyPublicKey = (Read-Host 'Policy public key (from your administrator)').Trim() }
if (-not $TenantId -or $TenantId -notmatch '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') { throw '-TenantId must be the tenant UUID.' }
if (-not $PolicyPublicKey) { throw '-PolicyPublicKey is required (printed by infra/openbao/device-trust-setup.py).' }
if (-not (Test-Path $Exe)) { throw "Agent executable not found at $Exe." }

# 1. program files: administrators/SYSTEM only (inherited from Program Files)
Stop-AndRemoveService
New-Item -ItemType Directory -Path $installDir -Force | Out-Null
Copy-Item $Exe $installed -Force

# 2. config, readable by SYSTEM and administrators only
New-Item -ItemType Directory -Path $dataDir -Force | Out-Null
$configPath = Join-Path $dataDir 'config.json'
[ordered]@{
    backend_base_url                = $BackendUrl
    enrollment_login_url            = $EnrollUrl
    tenant_id                       = $TenantId.ToLower()
    device_policy_public_key_base64 = $PolicyPublicKey
    heartbeat_interval_seconds      = 300
    allowed_identity_domains        = @($AllowedIdentityDomains)
} | ConvertTo-Json | Set-Content -Path $configPath -Encoding ascii
& icacls.exe $dataDir /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'BUILTIN\Administrators:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not lock down the data directory.' }

# 3. enroll (as SYSTEM-readable data written by this administrator; the service reads the same files)
Write-Host 'Enrolling: your browser opens, sign in with your account. It finishes by itself.' -ForegroundColor Cyan
& $installed --enroll "--ownership=$Ownership"
# 3 = already enrolled (a reinstall on a registered machine): keep the identity and carry on.
if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne 3) { throw "Enrollment failed (exit $LASTEXITCODE). Nothing was installed as a service." }

# 4. service: auto-start, restart on failure
& sc.exe create $svc binPath= "`"$installed`"" start= auto DisplayName= 'IAM Endpoint Agent' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'sc create failed.' }
& sc.exe description $svc 'IAM endpoint device trust agent: reports device posture and enforces signed policy.' | Out-Null
& sc.exe failure $svc reset= 86400 actions= restart/5000/restart/30000/restart/60000 | Out-Null
Start-Service $svc
Start-Sleep -Seconds 3
$state = (Get-Service $svc).Status
Write-Host "Service '$svc' is $state. Open the Admin Console > Endpoint Security to see this device." -ForegroundColor Green
if ($state -ne 'Running') { throw "Service is $state, expected Running. Check Event Viewer > Application." }
