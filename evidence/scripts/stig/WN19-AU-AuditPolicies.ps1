<#
.SYNOPSIS
    Configures advanced audit policy subcategories to satisfy multiple
    Windows Server 2019 DISA STIG audit requirements.

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
    STIG-IDs         : WN19-AU-000080  (Account Logon - Credential Validation failures)
                       WN19-AU-000090  (Account Management - Other Account Management Events successes)
                       WN19-AU-000120  (Account Management - User Account Management failures)
                       WN19-AU-000130  (Detailed Tracking - Plug and Play Events successes)
                       WN19-AU-000140  (Detailed Tracking - Process Creation successes)

.TESTED ON
    Date(s) Tested   : 2025-11-23
    Tested By        : Bryan Gilmore
    Systems Tested   : Windows Server 2019 Datacenter - x64 Gen2
    PowerShell Ver.  : 5.1

.USAGE
    Example syntax:
    PS C:\> .\WN19-AU-AuditPolicies.ps1
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

Write-Host "Current advanced audit policy settings for target subcategories:" 
Write-Host "----------------------------------------------------------------"
auditpol /get /subcategory:"Credential Validation"
auditpol /get /subcategory:"Other Account Management Events"
auditpol /get /subcategory:"User Account Management"
auditpol /get /subcategory:"Plug and Play Events"
auditpol /get /subcategory:"Process Creation"
Write-Host "----------------------------------------------------------------`n"

Write-Host "Applying STIG-compliant advanced audit policy settings..."

# WN19-AU-000080: Credential Validation - failures enabled
auditpol /set /subcategory:"Credential Validation" /failure:enable | Out-Null

# WN19-AU-000090: Other Account Management Events - successes enabled
auditpol /set /subcategory:"Other Account Management Events" /success:enable | Out-Null

# WN19-AU-000120: User Account Management - failures enabled
auditpol /set /subcategory:"User Account Management" /failure:enable | Out-Null

# WN19-AU-000130: Plug and Play Events - successes enabled
auditpol /set /subcategory:"Plug and Play Events" /success:enable | Out-Null

# WN19-AU-000140: Process Creation - successes enabled
auditpol /set /subcategory:"Process Creation" /success:enable | Out-Null

Write-Host "`nRechecking advanced audit policy settings after changes:" 
Write-Host "----------------------------------------------------------------"
auditpol /get /subcategory:"Credential Validation"
auditpol /get /subcategory:"Other Account Management Events"
auditpol /get /subcategory:"User Account Management"
auditpol /get /subcategory:"Plug and Play Events"
auditpol /get /subcategory:"Process Creation"
Write-Host "----------------------------------------------------------------"
Write-Host "Audit policy subcategories updated to meet the listed STIG requirements."
