@echo off
powershell.exe -NoProfile -STA -ExecutionPolicy Bypass -File "%~dp0Brave-Feature-Control.ps1"
if errorlevel 1 pause
