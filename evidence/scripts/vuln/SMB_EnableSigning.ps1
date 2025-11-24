<#
.SYNOPSIS
    Enables and requires SMB signing on Windows Server 2019
    to remediate the "SMB Signing not required" vulnerability.

.NOTES
    Author           : Bryan Gilmore
    LinkedIn         : https://www.linkedin.com/in/bryan-gilmore-ii-9b13231b9/
    GitHub           : https://github.com/bryangilmore
    Date Created     : 2025-11-24
    Last Modified    : 2025-11-24
    Version          : 1.0
    Compliance Audit : N/A
    CVEs             : CVE-2016-2115 (related)
    Plugin IDs       : 57608
    Reference        : Nessus plugin 57608, Microsoft SMB signing guidance

.TESTED ON
    Date(s) Tested   : 2025-11-24
    Tested By        : Bryan Gilmore
    Systems Tested   : Windows Server 2019 Datacenter - x64 Gen2
    PowerShell Ver.  : 5.1

.USAGE
    Example syntax:
    PS C:\> .\SMB_EnableSigning.ps1
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

Write-Host "Current SMB server configuration:"
Get-SmbServerConfiguration | Select-Object EnableSecuritySignature, RequireSecuritySignature

Write-Host ""
Write-Host "Current SMB client configuration:"
Get-SmbClientConfiguration | Select-Object EnableSecuritySignature, RequireSecuritySignature

Write-Host ""
Write-Host "Enabling and requiring SMB signing on the server, and enabling signing on the client..." 

# Server side: enable and require signing
Set-SmbServerConfiguration -EnableSecuritySignature $true -RequireSecuritySignature $true -Force | Out-Null

# Client side: enable signing (do not strictly require on client to avoid breaking older servers)
Set-SmbClientConfiguration -EnableSecuritySignature $true -Force | Out-Null

Write-Host ""
Write-Host "Rechecking SMB configuration after changes:"

Write-Host "SMB server configuration:"
Get-SmbServerConfiguration | Select-Object EnableSecuritySignature, RequireSecuritySignature

Write-Host ""
Write-Host "SMB client configuration:"
Get-SmbClientConfiguration | Select-Object EnableSecuritySignature, RequireSecuritySignature

Write-Host ""
Write-Host "SMB signing has been enabled and required on the server. Rescan with Nessus plugin 57608 to verify remediation."
