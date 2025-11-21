# Getting current script path and name
$ScriptName = & { $MyInvocation.ScriptName }
$ScriptPath = Split-Path $ScriptName -parent
$ScriptName = Split-Path $ScriptName -Leaf
$scriptName = $ScriptName -replace '.PS1',''

# Log file path
$logFile = "$ScriptPath\$ScriptName" + "Log.txt"

# Log function
function LogMessage {
    param ([string]$message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $logFile -Value "$timestamp - $message"
}

# Stop FireEye services
function Stop-FireEyeServices {
    $services = Get-Service | Where-Object { $_.DisplayName -like "*FireEye*" }
    foreach ($svc in $services) {
        try {
            if ($svc.Status -eq 'Running') {
                Stop-Service -Name $svc.Name -Force
                LogMessage "Stopped service: $($svc.DisplayName)"
            }
        } catch {
            LogMessage "Failed to stop service: $($svc.DisplayName). Tamper protection suspected."
        }
    }
}

# Main logic
param([string]$ProductCode)

if ($ProductCode) {
    LogMessage "Product code provided: $ProductCode"
    try {
        Stop-FireEyeServices
        Start-Process "msiexec.exe" -ArgumentList "/x $ProductCode /quiet /norestart" -Wait
        LogMessage "Uninstall initiated using product code."
    } catch {
        LogMessage "Uninstall failed using product code. Tamper protection suspected."
    }
} else {
    $fireEye = Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -like "*FireEye Agent*" }
    if ($fireEye) {
        LogMessage "FireEye Agent detected on this machine."
        Stop-FireEyeServices
        try {
            $result = $fireEye.Uninstall()
            if ($result.ReturnValue -eq 0) {
                LogMessage "Uninstallation completed successfully."
            } else {
                LogMessage "Uninstallation failed. Likely due to tamper protection or policy restrictions."
            }
        } catch {
            LogMessage "Error occurred during uninstall attempt. Tamper protection suspected."
        }
    } else {
        LogMessage "No FireEye Agent found on this machine."
    }
}

LogMessage "Process completed."