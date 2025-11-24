<#
.SYNOPSIS
    Ensures that the Security event log maximum size is at least 196608 KB (192 MB)
    in accordance with the Windows Server 2019 STIG.

.NOTES
    Author           : Bryan Gilmore
    LinkedIn         : https://www.linkedin.com/in/bryan-gilmore-ii-9b13231b9/
    GitHub           : https://github.com/bryangilmore
    Date Created     : 2025-11-23
    Last Modified    : 2025-11-23
    Version          : 1.0
    Compliance Audit : DISA Microsoft Windows Server 2019 STIG v3r5
    CVEs             : N/A
    Plugin IDs       : N/A
    STIG-ID          : WN19-CC-000280

.TESTED ON
    Date(s) Tested   : 2025-11-23
    Tested By        : Bryan Gilmore
    Systems Tested   : Windows Server 2019 Datacenter - x64 Gen2
    PowerShell Ver.  : 5.1

.USAGE
    Example syntax:
    PS C:\> .\WN19-CC-000280_EventLog_SecuritySize.ps1
#>

# Minimum size required by the STIG in bytes (196608 KB)
$RequiredSizeBytes = 196608KB  # PowerShell understands KB here

function Test-IsAdmin {
    $identity  = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdmin)) {
    Write-Error "Access denied. Please run this script in an elevated PowerShell session."
    exit 1
}

Write-Host "Checking Security event log maximum size..."

# Get current max size using wevtutil
$logConfig   = wevtutil gl Security
$maxSizeLine = $logConfig | Where-Object { $_ -match 'maxSize' }

if (-not $maxSizeLine) {
    Write-Warning "Could not read current maxSize for the Security log."
} else {
    $currentSizeBytes = [int64]($maxSizeLine -split ':' )[-1].Trim()
    Write-Host "Current maxSize (bytes): $currentSizeBytes"
}

if (($currentSizeBytes -lt $RequiredSizeBytes) -or (-not $maxSizeLine)) {
    Write-Host "Noncompliant; setting Security log maxSize to $RequiredSizeBytes bytes (196608 KB) ..."
    wevtutil sl Security /ms:$RequiredSizeBytes

    # Re-read to confirm
    $newConfig   = wevtutil gl Security
    $newSizeLine = $newConfig | Where-Object { $_ -match 'maxSize' }
    $newSize     = [int64]($newSizeLine -split ':' )[-1].Trim()

    Write-Host "New maxSize (bytes): $newSize"
} else {
    Write-Host "Already compliant; no changes made."
}
