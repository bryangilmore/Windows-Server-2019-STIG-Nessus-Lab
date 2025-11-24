<#
.SYNOPSIS
    Enables the WinVerifyTrust certificate padding check (EnableCertPaddingCheck)
    to mitigate CVE-2013-3900 on Windows Server 2019.

.NOTES
    Author           : Bryan Gilmore
    LinkedIn         : https://www.linkedin.com/in/bryan-gilmore-ii-9b13231b9/
    GitHub           : https://github.com/bryangilmore
    Date Created     : 2025-11-24
    Last Modified    : 2025-11-24
    Version          : 1.0
    Compliance Audit : N/A
    CVEs             : CVE-2013-3900
    Plugin IDs       : 166555
    Reference        : Microsoft guidance for EnableCertPaddingCheck

.TESTED ON
    Date(s) Tested   : 2025-11-24
    Tested By        : Bryan Gilmore
    Systems Tested   : Windows Server 2019 Datacenter - x64 Gen2
    PowerShell Ver.  : 5.1

.USAGE
    Example syntax:
    PS C:\> .\WinVerifyTrust_EnableCertPaddingCheck.ps1
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

$registryPaths = @(
    "HKLM:\Software\Microsoft\Cryptography\Wintrust\Config",
    "HKLM:\Software\Wow6432Node\Microsoft\Cryptography\Wintrust\Config"
)

$propertyName  = "EnableCertPaddingCheck"
$requiredValue = 1

Write-Host "Configuring WinVerifyTrust mitigation (EnableCertPaddingCheck)..." 

foreach ($path in $registryPaths) {

    Write-Host "Processing path: $path"

    # Ensure the key exists
    if (-not (Test-Path $path)) {
        Write-Host "Key not found; creating $path"
        New-Item -Path $path -Force | Out-Null
    }

    # Read current value if it exists
    try {
        $currentValue = (Get-ItemProperty -Path $path -Name $propertyName -ErrorAction Stop).$propertyName
        Write-Host "Current $propertyName value: $currentValue"
    } catch {
        Write-Host "$propertyName not present; treating as noncompliant."
        $currentValue = $null
    }

    if ($currentValue -ne $requiredValue) {
        Write-Host "Setting $propertyName to $requiredValue (REG_DWORD) at $path"
        New-ItemProperty -Path $path -Name $propertyName -PropertyType DWord -Value $requiredValue -Force | Out-Null

        $newValue = (Get-ItemProperty -Path $path -Name $propertyName).$propertyName
        Write-Host ("New {0} value at {1}: {2}" -f $propertyName, $path, $newValue)
    } else {
        Write-Host "$propertyName already set to $requiredValue at $path; no change needed."
    }

    Write-Host ""
}

Write-Host "WinVerifyTrust mitigation configured. A reboot is recommended so changes fully take effect."
