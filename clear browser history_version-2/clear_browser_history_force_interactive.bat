@echo off
cd /d "%~dp0"

REM Check if username parameter is provided
if "%1"=="" (
    set /p targetUser="Enter username to clear browser history for: "
) else (
    set targetUser=%1
)

REM Validate that we have a username
if "%targetUser%"=="" (
    echo Error: No username provided
    pause
    exit /b 1
)

REM Run PowerShell script with provided username and force close browsers
powershell.exe -Command "Start-Process PowerShell -ArgumentList '-ExecutionPolicy Bypass -NoProfile -File .\clear_browser_history.ps1 -TargetUser \"%targetUser%\" -ForceCloseBrowsers' -Verb RunAs -Wait"
pause
