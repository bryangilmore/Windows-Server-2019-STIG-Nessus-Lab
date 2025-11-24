<#
.SYNOPSIS
    Enables Windows speculative execution mitigations via registry settings
    to remediate the "Windows speculative execution configuration check"
    vulnerability on Windows Server 2019.

.NOTES
    Author           : Bryan Gilmore
    LinkedIn         : https://www.linkedin.com/in/bryan-gilmore-ii-9b13231b9/
    GitHub           : https://github.com/bryangilmore
    Date Created     : 2025-11-24
    Last Modified    : 2025-11-24
    Version          : 1.0
    Compliance Audit : N/A
    CVEs             : Spectre / Meltdown related CVEs (for example CVE-2017-5715, CVE-2017-5753, CVE-2017-5754)
    Plugin IDs       : 132101
    Reference        : Microsoft speculative execution mitigation registry guidance

.TESTED ON
    Date(s) Tested   : 2025-11-24
    Tested By        : Bryan Gilmore
    Systems Tested   : Windows Server 2019 Datacenter - x64 Gen2
    PowerShell Ver.  : 5.1

.USAGE
    Example syntax:
    PS C:\> .\SpeculativeExecution_EnableMitigations.ps1

    A reboot is required after running this script for changes to fully take effect.
#>

function Test-IsAdmin {
    $identity  = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdmin)) {
    Write-Error "Access denied. Please run this script in an elevated PowerShell session."
    exit 1
}

# Registry locations for speculative execution mitigations
$mmPath  = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
$virtPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization"

$fsOverrideName     = "FeatureSettingsOverride"
$fsOverrideMaskName = "FeatureSettingsOverrideMask"

# Microsoft guidance: FeatureSettingsOverrideMask = 3, FeatureSettingsOverride = 0
# This enables mitigations rather than disabling them.
$requiredFsOverride     = 0
$requiredFsOverrideMask = 3

Write-Host "Current speculative execution mitigation values (Memory Management):"
if (Test-Path $mmPath) {
    $mm = Get-ItemProperty -Path $mmPath -ErrorAction SilentlyContinue
    Write-Host ("  {0} = {1}" -f $fsOverrideName,     ($mm.$fsOverrideName     -as [string]))
    Write-Host ("  {0} = {1}" -f $fsOverrideMaskName, ($mm.$fsOverrideMaskName -as [string]))
} else {
    Write-Host "  $mmPath not found; it will be created."
}

Write-Host ""
Write-Host "Configuring speculative execution mitigation registry values..." 

# Ensure Memory Management key exists
if (-not (Test-Path $mmPath)) {
    New-Item -Path $mmPath -Force | Out-Null
}

# Set FeatureSettingsOverride and FeatureSettingsOverrideMask
New-ItemProperty -Path $mmPath -Name $fsOverrideName     -PropertyType DWord -Value $requiredFsOverride     -Force | Out-Null
New-ItemProperty -Path $mmPath -Name $fsOverrideMaskName -PropertyType DWord -Value $requiredFsOverrideMask -Force | Out-Null

$mmNew = Get-ItemProperty -Path $mmPath
Write-Host "New Memory Management values:"
Write-Host ("  {0} = {1}" -f $fsOverrideName,     $mmNew.$fsOverrideName)
Write-Host ("  {0} = {1}" -f $fsOverrideMaskName, $mmNew.$fsOverrideMaskName)

Write-Host ""
Write-Host "Configuring virtualization key for CPU based mitigations (if applicable)..."

# Ensure Virtualization key exists
if (-not (Test-Path $virtPath)) {
    New-Item -Path $virtPath -Force | Out-Null
}

# MinVmVersionForCpuBasedMitigations is commonly set to "1.0"
$minVmName  = "MinVmVersionForCpuBasedMitigations"
$minVmValue = "1.0"

New-ItemProperty -Path $virtPath -Name $minVmName -PropertyType String -Value $minVmValue -Force | Out-Null

$virtNew = Get-ItemProperty -Path $virtPath
Write-Host "Virtualization key values:"
Write-Host ("  {0} = {1}" -f $minVmName, $virtNew.$minVmName)

Write-Host ""
Write-Host "Speculative execution mitigations have been configured. A system reboot is required for all changes to apply."
