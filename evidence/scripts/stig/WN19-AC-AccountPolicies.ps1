<#
.SYNOPSIS
    Configures Windows Server 2019 account lockout and password policy settings
    to meet multiple DISA STIG requirements in one step.

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
    STIG-IDs         : WN19-AC-000010  (Account lockout duration >= 15 minutes)
                       WN19-AC-000020  (Lockout threshold <= 3 bad logon attempts)
                       WN19-AC-000030  (Reset lockout counter after >= 15 minutes)
                       WN19-AC-000040  (Password history 24 remembered)
                       WN19-AC-000060  (Minimum password age >= 1 day)
                       WN19-AC-000070  (Minimum password length >= 14 characters)

.TESTED ON
    Date(s) Tested   : 2025-11-23
    Tested By        : Bryan Gilmore
    Systems Tested   : Windows Server 2019 Datacenter - x64 Gen2
    PowerShell Ver.  : 5.1

.USAGE
    Example syntax:
    PS C:\> .\WN19-AC-AccountPolicies.ps1
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

Write-Host "Current account and password policy (net accounts):"
net accounts

# STIG required values
$lockoutDurationMinutes = 15   # WN19-AC-000010
$lockoutThreshold       = 3    # WN19-AC-000020
$lockoutWindowMinutes   = 15   # WN19-AC-000030
$passwordHistoryCount   = 24   # WN19-AC-000040
$minPasswordAgeDays     = 1    # WN19-AC-000060
$minPasswordLength      = 14   # WN19-AC-000070

Write-Host ""
Write-Host "Applying STIG-compliant account lockout and password policy values..."

# Configure account lockout policy
net accounts /lockoutduration:$lockoutDurationMinutes | Out-Null
net accounts /lockoutthreshold:$lockoutThreshold     | Out-Null
net accounts /lockoutwindow:$lockoutWindowMinutes    | Out-Null

# Configure password policy
net accounts /uniquepw:$passwordHistoryCount | Out-Null
net accounts /minpwage:$minPasswordAgeDays   | Out-Null
net accounts /minpwlen:$minPasswordLength    | Out-Null

Write-Host "Rechecking account and password policy (net accounts) after changes:"
net accounts
Write-Host ""
Write-Host "Account lockout and password policy settings have been updated to meet the STIG requirements listed in STIG-IDs."
