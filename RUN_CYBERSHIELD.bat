@echo off
setlocal
cd /d "%~dp0"
python -m app.main
if errorlevel 1 (
  echo.
  echo CyberShield ishga tushmadi.
  echo Python va requirements-desktop.txt ni tekshiring.
  pause
)
endlocal
