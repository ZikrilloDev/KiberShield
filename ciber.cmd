@echo off
setlocal
python "%~dp0main.py" ciber %*
set "RC=%ERRORLEVEL%"
endlocal & exit /b %RC%
