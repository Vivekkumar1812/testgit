@echo off
cd /d "%~dp0"
powershell.exe -Command "Start-Process PowerShell -ArgumentList '-ExecutionPolicy Bypass -NoProfile -File \".\15127_Remove legacy registry artifacts blocking Autopatch.ps1\"' -Verb RunAs -Wait"



