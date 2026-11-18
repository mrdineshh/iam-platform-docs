# Prints ONE compact JSON object of hardware attributes (the agent's HardwareAttributes), used only for
# correlation and risk context (PDF Section 5) -- never as proof of identity. The agent hashes the serial
# number and hardware UUID before sending, so the platform never sees the raw values.
#
# Replaces the earlier `wmic` calls: WMIC is deprecated and is being removed from Windows 11.
# READ-ONLY and input-free, like posture.ps1.

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { }

function Probe([scriptblock]$Block) {
    try { & $Block } catch { $null }
}

$system = Probe { Get-CimInstance -ClassName Win32_ComputerSystem }
$bios = Probe { Get-CimInstance -ClassName Win32_BIOS }
$product = Probe { Get-CimInstance -ClassName Win32_ComputerSystemProduct }
$os = Probe { Get-CimInstance -ClassName Win32_OperatingSystem }

[pscustomobject]@{
    manufacturer = $(if ($system) { $system.Manufacturer })
    model        = $(if ($system) { $system.Model })
    osVersion    = $(if ($os) { "$($os.Caption) $($os.Version)" })
    hardwareUuid = $(if ($product) { $product.UUID })
    serialNumber = $(if ($bios) { $bios.SerialNumber })
} | ConvertTo-Json -Compress
