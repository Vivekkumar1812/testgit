@echo off
REM Launcher batch file to run the PowerShell FireEye removal script as Administrator.
REM Usage examples:
REM   Run_Remove_FireEye_Agent.bat
REM   Run_Remove_FireEye_Agent.bat "-ProductCode {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX} -TimeoutSeconds 600"

:: Build PowerShell command line from any passed arguments
set "ARGS=%~1"
if "%ARGS%"=="" (
  set "PSARGS=-ExecutionPolicy Bypass -File "%~dp0\19148_Remove_FireEye_Agent.ps1""
) else (
  set "PSARGS=-ExecutionPolicy Bypass -File "%~dp0\19148_Remove_FireEye_Agent.ps1" %ARGS%"
)

:: Use PowerShell to start elevated if not already elevated. This attempts to use ShellExecute Verb RunAs to prompt for elevation.
powershell -NoProfile -Command "Start-Process powershell -ArgumentList '%PSARGS%' -Verb RunAs"
exit /b %ERRORLEVEL%