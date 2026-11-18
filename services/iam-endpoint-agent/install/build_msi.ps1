<#
.SYNOPSIS
  Builds dist\IamEndpointAgent-<version>.msi (unsigned) with the portable WiX 3 toolset.

.EXAMPLE
  .\build_msi.ps1 -TenantId ef84fb06-b235-4b25-beb7-90710f800923 -PolicyKey "<base64>" -AllowedDomains econz.net,demo.econz.net

  The values are only DEFAULTS stored in the MSI; a silent install can override every one on the msiexec command line.
#>
param(
    [string]$TenantId = '',
    [string]$PolicyKey = '',
    [string]$AllowedDomains = '',
    [string]$ReleaseKey = '',
    [string]$ExePath = '',
    [switch]$FailInjection,
    [string]$BackendUrl = 'https://tenant.34-71-129-0.sslip.io',
    [string]$EnrollUrl = 'https://login.34-71-129-0.sslip.io/device-enroll?tenant=econz',
    [string]$Version
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$exe = if ($ExePath) { $ExePath } else { Join-Path $root 'dist\iam-endpoint-agent.exe' }
$msiDir = Join-Path $PSScriptRoot 'msi'
$wix = Join-Path $env:LOCALAPPDATA 'iam-build-tools\wix3'
$obj = Join-Path $env:TEMP 'iam-msi-obj'

if (-not (Test-Path $exe)) { throw "Build the Windows exe first: $exe not found." }
foreach ($t in 'candle.exe', 'light.exe', 'WixUtilExtension.dll') { if (-not (Test-Path (Join-Path $wix $t))) { throw "WiX toolset missing ($t) in $wix." } }
# WiX needs a non-empty default. The word NONE means "no update key". It must NOT be '-': a lone dash on a PowerShell
# command line is parsed as a broken parameter name, which crashed the config step and failed the whole install.
if (-not $ReleaseKey) { $ReleaseKey = 'NONE' }
if ($ReleaseKey -ne 'NONE') {
    # Fail at BUILD time, not on a laptop: a malformed key would be silently useless (the agent would reject every release).
    try { $rk = [Convert]::FromBase64String($ReleaseKey) } catch { throw "-ReleaseKey is not valid base64: $ReleaseKey" }
    if ($rk.Length -ne 32) { throw "-ReleaseKey must decode to exactly 32 bytes (a raw Ed25519 public key); got $($rk.Length)." }
}
if (-not $Version) { $Version = ((& $exe --version) -replace '^\S+\s+', '').Trim() }
if ($Version -notmatch '^\d+\.\d+\.\d+$') { throw "Version '$Version' is not x.y.z." }

if (Test-Path $obj) { Remove-Item $obj -Recurse -Force }
New-Item -ItemType Directory -Path $obj | Out-Null
$out = Join-Path $root "dist\IamEndpointAgent-$Version.msi"

# Enroll-Device.cmd runs the exe from its own folder, so it ships next to it.
& (Join-Path $wix 'candle.exe') -nologo -arch x64 -ext (Join-Path $wix 'WixUtilExtension.dll') `
    "-dVersion=$Version" "-dExePath=$exe" "-dScriptsDir=$msiDir" "-dTenantId=$TenantId" "-dPolicyKey=$PolicyKey" `
    "-dAllowedDomains=$AllowedDomains" "-dReleaseKey=$ReleaseKey" "-dFailInjection=$(if ($FailInjection) { 1 } else { 0 })" "-dBackendUrl=$BackendUrl" "-dEnrollUrl=$EnrollUrl" `
    -out "$obj\" (Join-Path $msiDir 'Product.wxs')
if ($LASTEXITCODE -ne 0) { throw "candle failed (exit $LASTEXITCODE)" }
& (Join-Path $wix 'light.exe') -nologo -ext (Join-Path $wix 'WixUtilExtension.dll') -sval -out $out "$obj\Product.wixobj"
if ($LASTEXITCODE -ne 0) { throw "light failed (exit $LASTEXITCODE)" }

"{0}  ({1:N1} MB)" -f $out, ((Get-Item $out).Length / 1MB)
(Get-FileHash $out -Algorithm SHA256).Hash
