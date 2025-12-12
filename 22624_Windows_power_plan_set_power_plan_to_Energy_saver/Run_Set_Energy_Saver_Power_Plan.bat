@echo off
cd /d "%~dp0"
powershell.exe -Command "Start-Process PowerShell -ArgumentList '-ExecutionPolicy Bypass -NoProfile -File .\22624_Windows_power_plan_set_power_plan_to_Energy_saver.ps1' -Verb RunAs -Wait"
