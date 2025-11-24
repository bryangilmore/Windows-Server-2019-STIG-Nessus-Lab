<#
.SYNOPSIS
    Hardens SCHANNEL on Windows Server 2019 by disabling TLS 1.0, TLS 1.1,
    and Triple DES (3DES) cipher suites to address TLS legacy protocol and
    SWEET32 related findings.

.NOTES
    Author           : Bryan Gilmore
    LinkedIn         : https://www.linkedin.com/in/bryan-gilmore-ii-9b13231b9/
    GitHub           : https://github.com/bryangilmore
    Date Created     : 2025-11-24
    Last Modified    : 2025-11-24
    Version          : 1.0
    Compliance Audit : DISA Microsoft Windows Server 2019 STIG v3r5 (crypto related items)
    CVEs             : CVE-2016-2183 (SWEET32) and related TLS deprecation issues
    Plugin IDs       : 104743 (TLS 1.0)
                       157288 (TLS 1.1)
                       42873  (SWEET32, 3DES)
    Reference        : SCHANNEL protocol and cipher hardening for Windows Server

.TESTED ON
    Date(s) Tested   : 2025-11-24
    Tested By        : Bryan Gilmore
    Systems Tested   : Windows Server 2019 Datacenter - x64 Gen2
    PowerShell Ver.  : 5.1

.USAGE
    Example syntax:
    PS C:\> .\Crypto_Hardening_DisableLegacyProtocols_And_3DES.ps1

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

Write-Host "Crypto hardening starting on this server..." 

# Helper to set protocol keys
function Set-ProtocolState {
    param(
        [Parameter(Mandatory = $true)]
        [string] $ProtocolName,

        [Parameter(Mandatory = $true)]
        [bool]   $Enable
    )

    $basePath   = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$ProtocolName"
    $serverPath = Join-Path $basePath "Server"
    $clientPath = Join-Path $basePath "Client"

    $enabledValue         = if ($Enable) { 1 } else { 0 }
    $disabledByDefaultVal = if ($Enable) { 0 } else { 1 }

    Write-Host ""
    Write-Host "Configuring protocol '$ProtocolName' (Enable = $Enable) ..." 

    foreach ($path in @($serverPath, $clientPath)) {
        if (-not (Test-Path $path)) {
            Write-Host "Creating key: $path"
            New-Item -Path $path -Force | Out-Null
        }

        Write-Host "Setting values under $path"
        New-ItemProperty -Path $path -Name 'Enabled'          -Value $enabledValue         -PropertyType 'DWord' -Force | Out-Null
        New-ItemProperty -Path $path -Name 'DisabledByDefault' -Value $disabledByDefaultVal -PropertyType 'DWord' -Force | Out-Null

        $result = Get-ItemProperty -Path $path
        Write-Host ("  Enabled          = {0}" -f $result.Enabled)
        Write-Host ("  DisabledByDefault = {0}" -f $result.DisabledByDefault)
    }
}

# 1. Disable TLS 1.0 and TLS 1.1, leave TLS 1.2 alone
Set-ProtocolState -ProtocolName "TLS 1.0" -Enable:$false
Set-ProtocolState -ProtocolName "TLS 1.1" -Enable:$false

# Optional but safe on 2019: explicitly ensure TLS 1.2 is enabled
Set-ProtocolState -ProtocolName "TLS 1.2" -Enable:$true

# 2. Disable 3DES (Triple DES 168) cipher
Write-Host ""
Write-Host "Disabling 3DES cipher (Triple DES 168) to mitigate SWEET32..." 

$cipherPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168"

if (-not (Test-Path $cipherPath)) {
    Write-Host "Creating cipher key: $cipherPath"
    New-Item -Path $cipherPath -Force | Out-Null
}

New-ItemProperty -Path $cipherPath -Name 'Enabled' -Value 0 -PropertyType 'DWord' -Force | Out-Null

$cipherConfig = Get-ItemProperty -Path $cipherPath
Write-Host ("Cipher 'Triple DES 168' Enabled = {0}" -f $cipherConfig.Enabled)

Write-Host ""
Write-Host "Crypto hardening complete. A reboot is required for SCHANNEL to pick up protocol and cipher changes."
