$ErrorActionPreference='Stop'
$Project=Split-Path -Parent $MyInvocation.MyCommand.Path
$Python=(Get-Command python.exe -ErrorAction SilentlyContinue).Source
if(-not $Python){throw 'Python not found. Install Python first.'}
$Action=New-ScheduledTaskAction -Execute $Python -Argument "`"$Project\background_service.py`"" -WorkingDirectory $Project
$Trigger=New-ScheduledTaskTrigger -AtLogOn
$Settings=New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName 'CyberShield Background Protection' -Action $Action -Trigger $Trigger -Settings $Settings -Description 'CyberShield local-first background protection and phishing guard.' -Force
Write-Host 'CyberShield background protection installed and will start at Windows logon.'
