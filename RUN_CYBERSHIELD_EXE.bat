@echo off
setlocal
cd /d "%~dp0"
if exist "%~dp0dist\CyberShield.exe" (
    start "" "%~dp0dist\CyberShield.exe"
) else (
    echo CyberShield EXE not found.
    echo Expected: %~dp0dist\CyberShield.exe
    pause
)
endlocal
