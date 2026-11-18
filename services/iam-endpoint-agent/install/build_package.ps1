<#
.SYNOPSIS
  Builds the hand-out package: dist\IamEndpointAgent-Setup.zip (agent exe + installer + double-click launcher).
#>
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$exe = Join-Path $root 'dist\iam-endpoint-agent.exe'
if (-not (Test-Path $exe)) { throw "Build the Windows exe first: $exe not found." }
$stage = Join-Path $root 'dist\IamEndpointAgent-Setup'
if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
New-Item -ItemType Directory -Path (Join-Path $stage 'dist') -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $stage 'install') -Force | Out-Null
Copy-Item $exe (Join-Path $stage 'dist\iam-endpoint-agent.exe')
Copy-Item (Join-Path $PSScriptRoot 'install.ps1') (Join-Path $stage 'install\install.ps1')

@'
@echo off
rem Double-click to install the IAM endpoint agent. Asks for administrator rights, then for the tenant ID and policy key.
net session >nul 2>&1
if %errorlevel% neq 0 (
  powershell -NoProfile -Command "Start-Process -Verb RunAs -FilePath '%~f0'"
  exit /b
)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install\install.ps1" -Ownership BYOD
echo.
pause
'@ | Set-Content -Path (Join-Path $stage 'Install.cmd') -Encoding ascii

@'
@echo off
net session >nul 2>&1
if %errorlevel% neq 0 (
  powershell -NoProfile -Command "Start-Process -Verb RunAs -FilePath '%~f0'"
  exit /b
)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install\install.ps1" -Uninstall
pause
'@ | Set-Content -Path (Join-Path $stage 'Uninstall.cmd') -Encoding ascii

$zip = Join-Path $root 'dist\IamEndpointAgent-Setup.zip'
if (Test-Path $zip) { Remove-Item $zip -Force }
Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $zip
"{0}  ({1:N1} MB)" -f $zip, ((Get-Item $zip).Length / 1MB)
(Get-FileHash $zip -Algorithm SHA256).Hash
