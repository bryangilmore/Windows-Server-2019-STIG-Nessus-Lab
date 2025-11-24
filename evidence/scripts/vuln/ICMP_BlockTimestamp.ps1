<#
.SYNOPSIS
    Creates a Windows Defender Firewall rule to block ICMPv4 timestamp requests
    and replies in order to mitigate the ICMP timestamp remote date disclosure
    vulnerability.

.NOTES
    Author           : Bryan Gilmore
    LinkedIn         : https://www.linkedin.com/in/bryan-gilmore-ii-9b13231b9/
    GitHub           : https://github.com/bryangilmore
    Date Created     : 2025-11-24
    Last Modified    : 2025-11-24
    Version          : 1.0
    Compliance Audit : N/A
    CVEs             : N/A
    Plugin IDs       : 10114 (ICMP timestamp request remote date disclosure)

.TESTED ON
    Date(s) Tested   : 2025-11-24
    Tested By        : Bryan Gilmore
    Systems Tested   : Windows Server 2019 Datacenter - x64 Gen2
    PowerShell Ver.  : 5.1

.USAGE
    Example syntax:
    PS C:\> .\ICMP_BlockTimestamp.ps1

    Note: This rule is only enforced when Windows Defender Firewall is enabled.
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

Write-Host "Checking for existing ICMP timestamp firewall rule..." 

$existingRule = Get-NetFirewallRule -DisplayName "Block ICMPv4 Timestamp Requests" -ErrorAction SilentlyContinue

if ($existingRule) {
    Write-Host "Existing rule found:"
    $existingRule | Select-Object DisplayName, Enabled, Direction, Action, Profile, Description
    Write-Host "No changes made. If you want to recreate it, remove the rule first and rerun this script."
    return
}

Write-Host "No existing rule found; creating a new inbound rule to block ICMPv4 timestamp requests and replies..." 

New-NetFirewallRule `
    -DisplayName "Block ICMPv4 Timestamp Requests" `
    -Description "Blocks ICMPv4 timestamp request (type 13) and reply (type 14) messages to prevent remote time disclosure." `
    -Direction Inbound `
    -Protocol ICMPv4 `
    -IcmpType 13,14 `
    -Action Block `
    -Profile Domain,Private,Public `
    -Enabled True `
    | Out-Null

Write-Host "Firewall rule created. Verifying..." 

Get-NetFirewallRule -DisplayName "Block ICMPv4 Timestamp Requests" |
    Get-NetFirewallPortFilter |
    Select-Object Name, Protocol, IcmpType

Write-Host ""
Write-Host "ICMPv4 timestamp requests and replies will now be blocked when Windows Defender Firewall is enabled."
