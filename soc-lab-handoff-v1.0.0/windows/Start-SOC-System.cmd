@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Start-SOC-System.ps1"
exit /b %ERRORLEVEL%
