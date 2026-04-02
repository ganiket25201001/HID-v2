param(
    [string]$SourceExe = "./HID Shield.exe",
    [string]$InstallDir = "$env:ProgramFiles\HID Shield"
)

$ErrorActionPreference = "Stop"

function Test-Admin {
    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Ensure-Admin {
    if (Test-Admin) {
        return
    }

    $args = "-ExecutionPolicy Bypass -File `"$PSCommandPath`""
    if ($SourceExe) {
        $args += " -SourceExe `"$SourceExe`""
    }
    if ($InstallDir) {
        $args += " -InstallDir `"$InstallDir`""
    }

    Start-Process -FilePath "powershell.exe" -ArgumentList $args -Verb RunAs
    exit 0
}

function New-Shortcut {
    param(
        [string]$Path,
        [string]$Target,
        [string]$WorkingDirectory,
        [string]$Description
    )

    $wsh = New-Object -ComObject WScript.Shell
    $shortcut = $wsh.CreateShortcut($Path)
    $shortcut.TargetPath = $Target
    $shortcut.WorkingDirectory = $WorkingDirectory
    $shortcut.Description = $Description
    $shortcut.IconLocation = "$Target,0"
    $shortcut.Save()
}

Ensure-Admin

$resolvedExe = Resolve-Path $SourceExe
if (-not (Test-Path $resolvedExe)) {
    throw "Source executable not found: $SourceExe"
}

New-Item -Path $InstallDir -ItemType Directory -Force | Out-Null
$targetExe = Join-Path $InstallDir "HID Shield.exe"
Copy-Item -Path $resolvedExe -Destination $targetExe -Force

$uninstallPath = Join-Path $InstallDir "Uninstall-HIDShield.ps1"
$uninstallScript = @"
`$ErrorActionPreference = 'Stop'

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process powershell -Verb RunAs -ArgumentList '-ExecutionPolicy Bypass -File "' + `$PSCommandPath + '"'
    exit 0
}

`$installDir = '$InstallDir'
`$desktopShortcut = Join-Path `$env:Public 'Desktop\\HID Shield.lnk'
`$startMenuShortcut = Join-Path `$env:ProgramData 'Microsoft\\Windows\\Start Menu\\Programs\\HID Shield.lnk'

if (Test-Path `$desktopShortcut) { Remove-Item `$desktopShortcut -Force }
if (Test-Path `$startMenuShortcut) { Remove-Item `$startMenuShortcut -Force }
if (Test-Path `$installDir) { Remove-Item `$installDir -Recurse -Force }

Write-Host 'HID Shield uninstalled successfully.' -ForegroundColor Green
"@
Set-Content -Path $uninstallPath -Value $uninstallScript -Encoding UTF8

$desktopShortcut = Join-Path $env:Public "Desktop\HID Shield.lnk"
$startMenuDir = Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs"
$startMenuShortcut = Join-Path $startMenuDir "HID Shield.lnk"

New-Shortcut -Path $desktopShortcut -Target $targetExe -WorkingDirectory $InstallDir -Description "HID Shield"
New-Shortcut -Path $startMenuShortcut -Target $targetExe -WorkingDirectory $InstallDir -Description "HID Shield"

Write-Host "HID Shield installed successfully to: $InstallDir" -ForegroundColor Green
Write-Host "Desktop and Start Menu shortcuts created." -ForegroundColor Green
Write-Host "Uninstaller: $uninstallPath" -ForegroundColor Yellow
