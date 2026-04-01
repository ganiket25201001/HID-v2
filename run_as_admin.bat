@echo off
setlocal

set "EXE_NAME=HID Shield.exe"
set "EXE_PATH=%~dp0%EXE_NAME%"

if not exist "%EXE_PATH%" (
    set "EXE_PATH=%~dp0dist\%EXE_NAME%"
)

if not exist "%EXE_PATH%" (
    echo [HID Shield] Could not find "%EXE_NAME%".
    echo Build first with: pyinstaller build.spec
    pause
    exit /b 1
)

powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%EXE_PATH%' -Verb RunAs"
endlocal
