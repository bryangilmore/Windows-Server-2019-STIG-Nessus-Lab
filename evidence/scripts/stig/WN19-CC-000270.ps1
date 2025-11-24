<#
.SYNOPSIS
    Ensures that the Application event log maximum size is at least 32768 KB (32 MB)
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
    STIG-ID          : WN19-CC-000270

.TESTED ON
    Date(s) Tested   : 2025-11-23
    Tested By        : Bryan Gilmore
    Systems Tested   : Windows Server 2019 Datacenter - x64 Gen2
    PowerShell Ver.  : 5.1

.USAGE
    Example syntax:
    PS C:\> .\WN19-CC-000270_EventLog_ApplicationSize.ps1
#>

# Minimum size required by the STIG in bytes (32768 KB)
$RequiredSizeBytes = 32768KB  # PowerShell understands KB here

function Test-IsAdmin {
    $identity  = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdmin)) {
    Write-Error "Access denied. Please run this script in an elevated PowerShell session."
    exit 1
}

Write-Host "Checking Application event log maximum size..." 

# Get current max size using wevtutil
$logConfig   = wevtutil gl Application
$maxSizeLine = $logConfig | Where-Object { $_ -match 'maxSize' }

if (-not $maxSizeLine) {
    Write-Warning "Could not read current maxSize for the Application log."
} else {
    $currentSizeBytes = [int64]($maxSizeLine -split ':' )[-1].Trim()
    Write-Host "Current maxSize (bytes): $currentSizeBytes"
}

if (($currentSizeBytes -lt $RequiredSizeBytes) -or (-not $maxSizeLine)) {
    Write-Host "Noncompliant; setting Application log maxSize to $RequiredSizeBytes bytes (32 MB)..." 
    wevtutil sl Application /ms:$RequiredSizeBytes

    # Re-read to confirm
    $newConfig   = wevtutil gl Application
    $newSizeLine = $newConfig | Where-Object { $_ -match 'maxSize' }
    $newSize     = [int64]($newSizeLine -split ':' )[-1].Trim()

    Write-Host "New maxSize (bytes): $newSize" 
} else {
    Write-Host "Already compliant; no changes made." 
}
