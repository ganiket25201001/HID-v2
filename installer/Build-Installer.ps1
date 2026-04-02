param(
    [string]$ProjectRoot = ".."
)

$ErrorActionPreference = "Stop"

$root = (Resolve-Path $ProjectRoot).Path
$distExe = Join-Path $root "dist\HID Shield.exe"
$installerDir = Join-Path $root "installer"
$issPath = Join-Path $installerDir "HIDShield.iss"
$legacyInstallScript = Join-Path $installerDir "Install-HIDShield.ps1"

if (-not (Test-Path $distExe)) {
    throw "EXE not found at: $distExe. Build first with: pyinstaller build.spec"
}

$iscc = Get-Command iscc -ErrorAction SilentlyContinue
if ($iscc) {
    Push-Location $installerDir
    try {
        & $iscc.Source "HIDShield.iss"
        Write-Host "Installer created successfully via Inno Setup." -ForegroundColor Green
    }
    finally {
        Pop-Location
    }
    exit 0
}

Write-Warning "Inno Setup compiler (iscc) not found. Creating portable installer package zip fallback."

$packageDir = Join-Path $installerDir "package"
New-Item -ItemType Directory -Path $packageDir -Force | Out-Null
Copy-Item $distExe (Join-Path $packageDir "HID Shield.exe") -Force
Copy-Item $legacyInstallScript (Join-Path $packageDir "Install-HIDShield.ps1") -Force

$zipPath = Join-Path $installerDir "HIDShield-Installer-Package.zip"
if (Test-Path $zipPath) {
    Remove-Item $zipPath -Force
}
Compress-Archive -Path (Join-Path $packageDir "*") -DestinationPath $zipPath

Write-Host "Fallback installer package created: $zipPath" -ForegroundColor Yellow
