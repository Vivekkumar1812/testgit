@echo off
cd /d "%~dp0"
powershell.exe -Command "Start-Process PowerShell -ArgumentList '-ExecutionPolicy Bypass -NoProfile -File .\clear_browser_history.ps1 -ForceCloseBrowsers' -Verb RunAs -Wait"
