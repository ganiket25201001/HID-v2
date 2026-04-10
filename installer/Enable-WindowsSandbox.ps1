# Requires elevation.
# Enables Windows Sandbox feature and reports if restart is required.

[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"

function Test-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Admin)) {
    throw "Run this script from an elevated PowerShell session."
}

$featureName = "Containers-DisposableClientVM"
$featureState = Get-WindowsOptionalFeature -Online -FeatureName $featureName

if ($featureState.State -eq "Enabled") {
    Write-Host "Windows Sandbox is already enabled."
    exit 0
}

Write-Host "Enabling Windows Sandbox feature: $featureName"
$enableResult = Enable-WindowsOptionalFeature -Online -FeatureName $featureName -All -NoRestart

if ($enableResult.RestartNeeded) {
    Write-Host "Windows Sandbox feature enabled. Restart required before use."
} else {
    Write-Host "Windows Sandbox feature enabled. No restart required."
}
