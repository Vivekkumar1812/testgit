@echo off
PowerShell.exe -ExecutionPolicy Bypass -Command "Start-Process PowerShell -ArgumentList '-ExecutionPolicy Bypass -File \"%~dp018737_Set_Registry_Key_Value.ps1\" \"%~1\" \"%~2\" \"%~3\" \"%~4\"' -Verb RunAs -Wait"
