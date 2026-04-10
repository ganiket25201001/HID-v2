# Requires elevation.
# Applies host hardening settings aligned with HID Shield USB isolation mode.

[CmdletBinding()]
param(
    [switch]$EnableNoAutoMount
)

$ErrorActionPreference = "Stop"

function Test-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Admin)) {
    throw "Run this script from an elevated PowerShell session."
}

Write-Host "Applying AutoPlay/AutoRun hardening policies..."

$explorerPolicy = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
if (-not (Test-Path $explorerPolicy)) {
    New-Item -Path $explorerPolicy -Force | Out-Null
}
Set-ItemProperty -Path $explorerPolicy -Name NoDriveTypeAutoRun -Type DWord -Value 255

$windowsExplorerPolicy = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"
if (-not (Test-Path $windowsExplorerPolicy)) {
    New-Item -Path $windowsExplorerPolicy -Force | Out-Null
}
Set-ItemProperty -Path $windowsExplorerPolicy -Name NoAutoplayfornonVolume -Type DWord -Value 1

$storagePolicy = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices"
if (-not (Test-Path $storagePolicy)) {
    New-Item -Path $storagePolicy -Force | Out-Null
}

# Do not deny all removable storage by policy here because HID Shield needs
# controlled, privileged read access for secure staging and sandbox analysis.
Set-ItemProperty -Path $storagePolicy -Name AllowRemoteDASD -Type DWord -Value 0

if ($EnableNoAutoMount) {
    Write-Host "Disabling automatic drive-letter assignment (mountvol /N)..."
    mountvol /N | Out-Null
}

Write-Host "USB host hardening policy applied successfully."
