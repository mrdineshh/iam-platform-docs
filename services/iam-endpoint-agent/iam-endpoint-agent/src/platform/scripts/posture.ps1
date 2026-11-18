# Gathers device posture facts and prints ONE compact JSON object (the agent's PostureSignals).
#
# READ-ONLY: nothing here changes the machine. A fixed script the agent runs with -EncodedCommand; it takes no
# input of any kind, so nothing from the network or the user can end up inside it.
#
# Every probe is isolated: one that fails (no permission, not available on this Windows edition) reports
# UNKNOWN instead of losing the whole report. The server decides what the facts mean; this only states them.

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { }

function Probe([scriptblock]$Block) {
    try { & $Block } catch { $null }
}

function Tri($Value) {
    if ($Value -eq $true) { 'ENABLED' } elseif ($Value -eq $false) { 'DISABLED' } else { 'UNKNOWN' }
}

$os = Probe { Get-CimInstance -ClassName Win32_OperatingSystem }

# Disk encryption: is BitLocker protecting the system drive?
$disk = Probe {
    $status = (Get-BitLockerVolume -MountPoint $env:SystemDrive).ProtectionStatus
    switch ("$status") { 'On' { $true } 'Off' { $false } default { $null } }
}

# Antivirus: is real-time protection on? Windows Security Center knows about every registered product
# (Defender and third-party). productState bits 12-15: 0x1000 = on, 0x0000 = off, 0x2000 = snoozed, 0x3000 = expired.
$global:avName = $null
$av = Probe {
    $products = @(Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName AntiVirusProduct)
    if ($products.Count -eq 0) { return $null }
    $active = @($products | Where-Object { ($_.productState -band 0xF000) -eq 0x1000 })
    if ($active.Count -gt 0) { $global:avName = $active[0].displayName; return $true }
    $global:avName = $products[0].displayName
    return $false
}
if ($null -eq $av) {
    # Security Center does not exist on Windows Server: ask Defender directly.
    $av = Probe {
        $defender = Get-MpComputerStatus
        $global:avName = 'Microsoft Defender'
        return [bool]($defender.AntivirusEnabled -and $defender.RealTimeProtectionEnabled)
    }
}

# Firewall: every profile (domain, private, public) must be on.
$fw = Probe {
    $profiles = @(Get-NetFirewallProfile)
    if ($profiles.Count -eq 0) { return $null }
    return (@($profiles | Where-Object { "$($_.Enabled)" -eq 'False' }).Count -eq 0)
}

$tpm = Probe { (Get-Tpm).TpmPresent }
$secureBoot = Probe { Confirm-SecureBootUEFI }

# Date of the most recently installed update.
$hotfix = Probe {
    $latest = Get-CimInstance -ClassName Win32_QuickFixEngineering |
        Where-Object { $_.InstalledOn } |
        Sort-Object InstalledOn -Descending |
        Select-Object -First 1
    if ($latest) { ([datetime]$latest.InstalledOn).ToString('yyyy-MM-dd', [System.Globalization.CultureInfo]::InvariantCulture) }
}

[pscustomobject]@{
    osName           = $(if ($os) { $os.Caption })
    osVersion        = $(if ($os) { $os.Version })
    osBuild          = $(if ($os) { $os.BuildNumber })
    diskEncryption   = (Tri $disk)
    antivirus        = (Tri $av)
    antivirusProduct = $global:avName
    firewall         = (Tri $fw)
    tpmPresent       = (Tri $tpm)
    secureBoot       = (Tri $secureBoot)
    lastHotfixDate   = $hotfix
} | ConvertTo-Json -Compress
