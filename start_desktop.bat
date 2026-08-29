@echo off
setlocal
cd /d "%~dp0"
python launch_cybershield.py desktop
if errorlevel 1 (
  echo.
  echo CyberShield desktop failed to start.
  echo Please check Python installation and dependencies.
  pause
)
endlocal
