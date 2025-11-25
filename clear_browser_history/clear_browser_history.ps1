<#
SCRIPT NAME             clear_browser_history.ps1
IN REPOSITORY           No
AUTHOR & EMAIL          Vivek: vivek.f.vivek@capgemini.com
COMPANY                 Capgemini
TAGS                    Browser, History, Cleanup, Privacy
STATUS                  draft
DATE OF CHANGES         Nov 25th, 2025  
VERSION                 1.0
RELEASENOTES            NA
APPROVED                No
SUPPORT                 NA
DEX TOOLS               NA
DEPENDENCIES            - PowerShell 5.1 or later (Windows 10/11 default)
                        - Administrator privileges required
CONTEXT                 User
OS                      Windows
SYNOPSIS                Clears browsing history for Chrome and Edge browsers.
DESCRIPTION             This script clears browsing history files from Google Chrome and Microsoft Edge browsers. 
                        It removes only the History file from each browser's default profile directory. All operations 
                        are logged with timestamps, error handling, and validation checks. The script requires 
                        administrator privileges to access and delete browser history files.
INPUTS                  None - Script operates on default browser profile paths:
                            - Chrome: $env:LOCALAPPDATA\Google\Chrome\User Data\Default
                            - Edge: $env:LOCALAPPDATA\Microsoft\Edge\User Data\Default
OUTPUTS                 Log messages indicating:
                            - Admin privilege check status
                            - Browser history processing status
                            - File deletion success or failure
                            - Final execution summary with exit codes
VARIABLE DESCRIPTION    $MyInvocation = Contains information about how the script was invoked, used for log file naming
                        $ScriptName = Stores the name of the script file without extension
                        $ScriptPath = Stores the directory path where the script is located
                        $logFile = Full path to the log file where all activities are recorded
                        $chromeHistryPath = Path to Chrome browser history directory
                        $edgeHistryPath = Path to Edge browser history directory
                        $historyFiles = Array of history files to delete
EXAMPLE                 .\clear_browser_history.ps1
LOGIC DOCUMENT          NA          
#>

# Getting current script path and name
$ScriptName = & { $MyInvocation.ScriptName }
$ScriptPath = Split-Path $ScriptName -parent
$ScriptName = Split-Path $ScriptName -Leaf
$scriptName = $ScriptName -replace '.PS1',''

# Log file path
$logFile = "$ScriptPath\$ScriptName" + "Log.txt"

function Write_LogMessage {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet('INFO', 'WARNING', 'ERROR', 'SUCCESS')]
        [string]$Level = 'INFO'
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "$timestamp - [$Level] - $Message"
    Add-Content -Path $logFile -Value $logEntry
}

# Check if running as administrator
try {
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
    if (-NOT $isAdmin) {
        Write_LogMessage "This script must be run as Administrator. Please run PowerShell as Administrator and try again." -Level 'ERROR'
        exit 1
    }
    Write_LogMessage "Administrator privileges confirmed." -Level 'INFO'
} catch {
    Write_LogMessage "Failed to verify administrator privileges: $_" -Level 'ERROR'
    exit 1
}

# Define paths to browser history directories
$chromeHistryPath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default"
$edgeHistryPath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default"

#Files related only to browsing history
$historyFiles = @(
    "History"
)
# Function to delete history files
function Clear-BrowserHistory {
    param(
        [string]$browserHistoryPath,
        [string]$browserName
    )    
    try {
        if (-not $browserHistoryPath) {
            Write_LogMessage "Browser history path is empty for $browserName" -Level 'ERROR'
            return
        }
        
        if (Test-Path $browserHistoryPath) {
            Write_LogMessage "Processing $browserName browser history at: $browserHistoryPath" -Level 'INFO'
            
            foreach ($file in $historyFiles) {
                $targetFile = Join-Path $browserHistoryPath $file
                if (Test-Path $targetFile) {
                    try {
                        Remove-Item $targetFile -Force -ErrorAction Stop
                        Write_LogMessage "Successfully deleted: $targetFile" -Level 'SUCCESS'
                    } catch {
                        Write_LogMessage "Failed to delete: $targetFile. Error: $_" -Level 'ERROR'
                    }
                } else {
                    Write_LogMessage "File not found: $targetFile" -Level 'WARNING'
                }
            }
        } else {
            Write_LogMessage "$browserName browser profile not found at: $browserHistoryPath" -Level 'WARNING'
        }
    } catch {
        Write_LogMessage "Unexpected error processing $browserName history: $_" -Level 'ERROR'
    }
}

# Main execution block
try {
    Write_LogMessage "Starting browser history cleanup process..." -Level 'INFO'
    
    # Initialize counters
    $successCount = 0
    $failCount = 0
    $totalBrowsers = 0
    
    # Clear Chrome history
    if ($chromeHistryPath) {
        $totalBrowsers++
        Write_LogMessage "Attempting to clear Chrome history..." -Level 'INFO'
        Clear-BrowserHistory -browserHistoryPath $chromeHistryPath -browserName "Chrome"
        if (Test-Path (Join-Path $chromeHistryPath "History")) {
            $failCount++
            Write_LogMessage "Chrome history file still exists after cleanup attempt" -Level 'ERROR'
        } else {
            $successCount++
            Write_LogMessage "Chrome history cleared successfully" -Level 'SUCCESS'
        }
    } else {
        Write_LogMessage "Chrome history path is not defined" -Level 'ERROR'
    }
    
    # Clear Edge history
    if ($edgeHistryPath) {
        $totalBrowsers++
        Write_LogMessage "Attempting to clear Edge history..." -Level 'INFO'
        Clear-BrowserHistory -browserHistoryPath $edgeHistryPath -browserName "Edge"
        if (Test-Path (Join-Path $edgeHistryPath "History")) {
            $failCount++
            Write_LogMessage "Edge history file still exists after cleanup attempt" -Level 'ERROR'
        } else {
            $successCount++
            Write_LogMessage "Edge history cleared successfully" -Level 'SUCCESS'
        }
    } else {
        Write_LogMessage "Edge history path is not defined" -Level 'ERROR'
    }
    
    # Execution Summary
    Write_LogMessage "===== Execution Summary =====" -Level 'INFO'
    Write_LogMessage "Total browsers processed: $totalBrowsers" -Level 'INFO'
    Write_LogMessage "Successfully cleared: $successCount" -Level 'INFO'
    Write_LogMessage "Failed to clear: $failCount" -Level 'INFO'
    
    if ($failCount -eq 0 -and $successCount -gt 0) {
        Write_LogMessage "Browser history cleanup process completed successfully." -Level 'SUCCESS'
        Write_LogMessage "===== Script Execution Completed Successfully =====" -Level 'INFO'
        Write_LogMessage "Exit Code: 0 (Success)" -Level 'INFO'
        exit 0
    } elseif ($failCount -gt 0) {
        Write_LogMessage "Browser history cleanup completed with errors." -Level 'WARNING'
        Write_LogMessage "===== Script Execution Completed with Errors =====" -Level 'WARNING'
        Write_LogMessage "Exit Code: 2 (Partial Failure)" -Level 'WARNING'
        exit 2
    } else {
        Write_LogMessage "No browser history was cleared." -Level 'WARNING'
        Write_LogMessage "===== Script Execution Completed with Warnings =====" -Level 'WARNING'
        Write_LogMessage "Exit Code: 3 (No Action Taken)" -Level 'WARNING'
        exit 3
    }
    
} catch {
    Write_LogMessage "Critical error during script execution: $_" -Level 'ERROR'
    Write_LogMessage "===== Script Execution Failed =====" -Level 'ERROR'
    Write_LogMessage "Exit Code: 1 (Critical Failure)" -Level 'ERROR'
    exit 1
}
