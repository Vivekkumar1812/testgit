@echo off
cd /d "%~dp0"
REM Launch the PowerShell script elevated and wait for it to finish.
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Start-Process PowerShell -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File \"%~dp0\19156_Win_Update_Repair_Windows_Update_Standalone_Installer_failure.ps1\"' -Verb RunAs -Wait"
