<#
.SYNOPSIS
  Run by the MSI (as SYSTEM) after files are installed, and again on uninstall. Not meant to be run by hand.

.DESCRIPTION
  Install:   a FRESH machine gets %ProgramData%\IamEndpointAgent\config.json written from the supplied values and the folder
             locked to SYSTEM and Administrators. An EXISTING config is never overwritten (an upgrade, a repair and an
             automatic update must not replace a working or locally adjusted setup with the build's defaults): only a
             missing release key is added. FORCE_CONFIG=1 on the msiexec line rewrites it on purpose.
  Uninstall: removes the Chrome/Edge sign-in restriction the agent applied (only if its config asked for one). The device
             identity and config stay in %ProgramData%.
#>
param(
    [string]$TenantId,
    [string]$PolicyKey,
    [string]$BackendUrl,
    [string]$EnrollUrl,
    [string]$AllowedDomains,
    [string]$ReleaseKey,
    [string]$ForceConfig,
    [switch]$Uninstall
)
$ErrorActionPreference = 'Stop'
$dataDir = Join-Path $env:ProgramData 'IamEndpointAgent'
$configPath = Join-Path $dataDir 'config.json'

if ($Uninstall) {
    if (Test-Path $configPath) {
        $cfg = Get-Content $configPath -Raw | ConvertFrom-Json
        if (@($cfg.allowed_identity_domains).Count -gt 0) {
            foreach ($t in @(@('HKLM:\SOFTWARE\Policies\Google\Chrome', 'RestrictSigninToPattern'),
                             @('HKLM:\SOFTWARE\Policies\Google\Chrome', 'AllowedDomainsForApps'),
                             @('HKLM:\SOFTWARE\Policies\Microsoft\Edge', 'RestrictSigninToPattern'))) {
                Remove-ItemProperty -Path $t[0] -Name $t[1] -ErrorAction SilentlyContinue
            }
        }
    }
    return
}

# An install that already has a config must NEVER be failed by this step: a failed upgrade makes Windows Installer roll back,
# and a rollback is not guaranteed to restore the previous version (found 2026-11-18). On such a machine every problem here is
# reported and ignored; only a FRESH install, which has nothing to lose, is allowed to fail loudly.
$hadConfig = Test-Path $configPath
try {
$releaseKeyGiven = $ReleaseKey -and $ReleaseKey -ne 'NONE'
if ($releaseKeyGiven) {
    try { $rk = [Convert]::FromBase64String($ReleaseKey) } catch { throw 'RELEASE_KEY is not valid base64.' }
    if ($rk.Length -ne 32) { throw "RELEASE_KEY must be a raw 32-byte Ed25519 public key (got $($rk.Length) bytes)." }
}

# An existing config is kept (upgrade, repair, automatic update). Only the update key is added when the config lacks it, so
# a laptop installed before updates existed can start receiving them without losing its settings.
if ((Test-Path $configPath) -and $ForceConfig -ne '1') {
    $existing = Get-Content $configPath -Raw | ConvertFrom-Json
    $hasKey = $existing.PSObject.Properties.Name -contains 'release_public_key_base64' -and $existing.release_public_key_base64
    if ($releaseKeyGiven -and -not $hasKey) {
        $existing | Add-Member -NotePropertyName release_public_key_base64 -NotePropertyValue $ReleaseKey -Force
        $existing | ConvertTo-Json -Depth 5 | Set-Content -Path $configPath -Encoding ascii
        Write-Output 'Existing config kept; update key added.'
    } else {
        Write-Output 'Existing config kept.'
    }
    return
}
if (-not $TenantId -and -not $PolicyKey) {
    Write-Output 'No settings supplied and no config present; run the installer with TENANT_ID and POLICY_KEY.'
    return
}

# These values come from the MSI command line of an administrator, but they end up in a security configuration, so they
# are checked strictly instead of trusted.
if ($TenantId -notmatch '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') { throw 'TENANT_ID is not a valid UUID.' }
try { $keyBytes = [Convert]::FromBase64String($PolicyKey) } catch { throw 'POLICY_KEY is not valid base64.' }
if ($keyBytes.Length -ne 32) { throw "POLICY_KEY must be a raw 32-byte Ed25519 public key (got $($keyBytes.Length) bytes)." }
foreach ($u in @($BackendUrl, $EnrollUrl)) {
    if ($u -notmatch '^https://[A-Za-z0-9.\-]+(:\d+)?(/[A-Za-z0-9._~/?=&%\-]*)?$') { throw "Not an acceptable https URL: $u" }
}
$domains = @()
if ($AllowedDomains) {
    $domains = @($AllowedDomains -split '[,; ]+' | Where-Object { $_ } | ForEach-Object { $_.Trim().ToLower() })
    foreach ($d in $domains) {
        if ($d -notmatch '^([a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$') { throw "Not a valid domain: $d" }
    }
}

New-Item -ItemType Directory -Path $dataDir -Force | Out-Null
[ordered]@{
    backend_base_url                = $BackendUrl
    enrollment_login_url            = $EnrollUrl
    tenant_id                       = $TenantId.ToLower()
    device_policy_public_key_base64 = $PolicyKey
    heartbeat_interval_seconds      = 300
    allowed_identity_domains        = $domains
    release_public_key_base64       = $(if ($releaseKeyGiven) { $ReleaseKey } else { $null })
} | ConvertTo-Json | Set-Content -Path $configPath -Encoding ascii
& icacls.exe $dataDir /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'BUILTIN\Administrators:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not lock down the data directory.' }
Write-Output "Config written to $configPath"
} catch {
    if ($hadConfig) { Write-Output "configure.ps1 problem ignored because a config already exists: $($_.Exception.Message)"; exit 0 }
    throw
}
