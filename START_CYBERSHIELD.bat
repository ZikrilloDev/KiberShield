@echo off
setlocal
python "%~dp0main.py" %*
set "RC=%ERRORLEVEL%"
endlocal & exit /b %RC%
