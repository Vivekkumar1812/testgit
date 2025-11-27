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
                        - Browsers: Google Chrome, Microsoft Edge should be closed for complete history deletion

CONTEXT                 User
OS                      Windows
SYNOPSIS                Clears browsing history for Chrome and Edge browsers.
DESCRIPTION             This script clears the main browsing history from Google Chrome and Microsoft Edge browsers. 
                        It removes only the core History database (Ctrl+H history) and its transaction journal, 
                        leaving other browser data like bookmarks, saved passwords, and site preferences intact. 
                        The script can optionally close running browsers to ensure complete main history deletion. 
                        All operations are logged with timestamps, error handling, and validation checks. The script 
                        requires administrator privileges to access and delete browser history files and terminate processes.
INPUTS                  -TargetUser (Required): Specify the username whose browser history should be cleared
                                               Example: "john.doe" or "DOMAIN\john.doe"
                        -ForceCloseBrowsers (Optional): Switch to force close running browsers before deletion
                        
                        Target paths for browser history:
                            - Chrome: C:\Users\[TargetUser]\AppData\Local\Google\Chrome\User Data\Default
                            - Edge: C:\Users\[TargetUser]\AppData\Local\Microsoft\Edge\User Data\Default
OUTPUTS                 Log messages indicating:
                            - Admin privilege check status
                            - Browser history processing status
                            - File deletion success or failure
                            - Final execution summary with exit codes
VARIABLE DESCRIPTION    $TargetUser = Required parameter to specify target username for browser history cleanup
                        $ForceCloseBrowsers = Switch parameter to force close running browsers
                        $MyInvocation = Contains information about how the script was invoked, used for log file naming
                        $ScriptName = Stores the name of the script file without extension
                        $ScriptPath = Stores the directory path where the script is located
                        $logFile = Full path to the log file where all activities are recorded
                        $targetUserName = Processed target username (with domain prefix removed if present)
                        $userProfilePath = Target user profile path based on TargetUser parameter
                        $userLocalAppData = User's AppData\Local directory path
                        $chromeHistryPath = Path to Chrome browser history directory
                        $edgeHistryPath = Path to Edge browser history directory
                        $historyFiles = Array of history files to delete
EXAMPLE                 PowerShell (.ps1) Usage:
                        .\clear_browser_history.ps1 -TargetUser "john.doe"
                        .\clear_browser_history.ps1 -TargetUser "john.doe" -ForceCloseBrowsers
                        .\clear_browser_history.ps1 -TargetUser "DOMAIN\john.doe" -ForceCloseBrowsers
                        
                        Batch File (.bat) Usage:
                        clear_browser_history_force.bat "john.doe"
                        clear_browser_history_force.bat "DOMAIN\john.doe"
LOGIC DOCUMENT          NA          
#>

# Script parameters
param(
    [switch]$ForceCloseBrowsers,
    
    [Parameter(Mandatory=$false, HelpMessage="Specify the username whose browser history should be cleared (e.g., 'john.doe' or 'DOMAIN\john.doe')")]
    [string]$TargetUser
)

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

# Validate TargetUser parameter
if (-not $TargetUser -or $TargetUser.Trim() -eq "") {
    Write_LogMessage "Error: Username not provided. TargetUser parameter is required." -Level 'ERROR'
    
    # List available user profiles to help user
    try {
        $availableProfiles = Get-ChildItem "C:\Users" -Directory | Where-Object { 
            $_.Name -notmatch "^(Public|Default|All Users|Default User)$" 
        }
        if ($availableProfiles) {
            Write_LogMessage "Available user profiles: $($availableProfiles.Name -join ', ')" -Level 'INFO'
        } else {
            Write_LogMessage "No user profiles found in C:\Users directory." -Level 'INFO'
        }
    } catch {
        Write_LogMessage "Failed to enumerate user profiles: $_" -Level 'WARNING'
    }
    
    Write_LogMessage "===== Script Execution Failed =====" -Level 'ERROR'
    Write_LogMessage "Exit Code: 1 (Missing Required Parameter)" -Level 'ERROR'
    exit 1
}

# Log script parameters
Write_LogMessage "Target User Parameter: $TargetUser" -Level 'INFO'
if ($ForceCloseBrowsers) {
    Write_LogMessage "Force Close Browsers: Enabled" -Level 'INFO'
} else {
    Write_LogMessage "Force Close Browsers: Disabled (will skip locked files)" -Level 'INFO'
}

# Define paths to browser history directories
# Handle domain users (remove domain prefix if present)
$targetUserName = $TargetUser
if ($TargetUser.Contains('\')) {
    $targetUserName = $TargetUser.Split('\')[1]
    Write_LogMessage "Detected domain user format. Using username: $targetUserName" -Level 'INFO'
}

$userProfilePath = "C:\Users\$targetUserName"
if (Test-Path $userProfilePath) {
    Write_LogMessage "Using specified target user: $targetUserName at $userProfilePath" -Level 'INFO'
} else {
    Write_LogMessage "Specified target user '$targetUserName' profile not found at $userProfilePath" -Level 'ERROR'
    
    # List available user profiles to help user
    $availableProfiles = Get-ChildItem "C:\Users" -Directory | Where-Object { 
        $_.Name -notmatch "^(Public|Default|All Users|Default User)$" 
    }
    if ($availableProfiles) {
        Write_LogMessage "Available user profiles: $($availableProfiles.Name -join ', ')" -Level 'INFO'
    }
    exit 1
}

$userLocalAppData = Join-Path $userProfilePath "AppData\Local"
$chromeHistryPath = Join-Path $userLocalAppData "Google\Chrome\User Data\Default"
$edgeHistryPath = Join-Path $userLocalAppData "Microsoft\Edge\User Data\Default"

Write_LogMessage "Using user profile: $userProfilePath" -Level 'INFO'
Write_LogMessage "Chrome profile path: $chromeHistryPath" -Level 'INFO'
Write_LogMessage "Edge profile path: $edgeHistryPath" -Level 'INFO'

#Files related to main browsing history only
$historyFiles = @(
    "History",
    "History-journal"
)

# Function to check if browser is running and optionally close it
function Test-BrowserRunning {
    param(
        [string]$browserName,
        [bool]$forceClose = $false
    )
    
    $processNames = @()
    switch ($browserName) {
        "Chrome" { $processNames = @("chrome") }
        "Edge" { $processNames = @("msedge") }
    }
    
    foreach ($processName in $processNames) {
        $processes = Get-Process -Name $processName -ErrorAction SilentlyContinue
        if ($processes) {
            if ($forceClose) {
                Write_LogMessage "$browserName is running with $($processes.Count) process(es). Closing to enable complete history deletion..." -Level 'WARNING'
                try {
                    $processes | Stop-Process -Force -ErrorAction Stop
                    Write_LogMessage "Successfully closed $browserName processes." -Level 'SUCCESS'
                    Start-Sleep -Seconds 3  # Wait for processes to fully terminate and release file locks
                    return $false  # Browser is no longer running
                } catch {
                    Write_LogMessage "Failed to close $browserName processes: $_" -Level 'ERROR'
                    return $true   # Still running
                }
            } else {
                Write_LogMessage "$browserName is currently running with $($processes.Count) process(es). Will attempt to clear unlocked history files only." -Level 'INFO'
                Write_LogMessage "Use -ForceCloseBrowsers parameter to close $browserName and delete Ctrl+H history completely." -Level 'INFO'
                return $true
            }
        }
    }
    return $false
}

# Function to delete history files
function Clear-BrowserHistory {
    param(
        [string]$browserHistoryPath,
        [string]$browserName
    )    
    try {
        if (-not $browserHistoryPath) {
            Write_LogMessage "Browser history path is empty for $browserName" -Level 'ERROR'
            return $false
        }
        
        if (Test-Path $browserHistoryPath) {
            Write_LogMessage "Processing $browserName browser history at: $browserHistoryPath" -Level 'INFO'
            
            # Check if browser is running (and optionally close it)
            $browserRunning = Test-BrowserRunning -browserName $browserName -forceClose $ForceCloseBrowsers
            
            $filesDeleted = 0
            $filesLocked = 0
            $filesSkipped = 0
            
            foreach ($file in $historyFiles) {
                $targetFile = Join-Path $browserHistoryPath $file
                if (Test-Path $targetFile) {
                    try {
                        # Test if file is accessible before attempting deletion
                        $fileStream = $null
                        try {
                            $fileStream = [System.IO.File]::Open($targetFile, 'Open', 'Read', 'None')
                            $fileStream.Close()
                            $canAccess = $true
                        } catch {
                            $canAccess = $false
                        }
                        
                        if ($canAccess) {
                            Remove-Item $targetFile -Force -ErrorAction Stop
                            Write_LogMessage "Successfully deleted: $targetFile" -Level 'SUCCESS'
                            $filesDeleted++
                        } else {
                            if ($browserRunning) {
                                Write_LogMessage "Skipped locked file (browser running): $targetFile" -Level 'WARNING'
                                $filesSkipped++
                            } else {
                                Write_LogMessage "File is locked by another process: $targetFile" -Level 'ERROR'
                                $filesLocked++
                            }
                        }
                    } catch {
                        if ($_.Exception.Message -like "*being used by another process*" -or 
                            $_.Exception.Message -like "*cannot access the file*") {
                            if ($browserRunning) {
                                Write_LogMessage "Skipped locked file (browser running): $targetFile" -Level 'WARNING'
                                $filesSkipped++
                            } else {
                                Write_LogMessage "File is locked by another process: $targetFile" -Level 'ERROR'
                                $filesLocked++
                            }
                        } else {
                            Write_LogMessage "Failed to delete: $targetFile. Error: $_" -Level 'ERROR'
                            $filesLocked++
                        }
                    }
                }
            }
            
            # Summary for this browser
            if ($filesDeleted -gt 0) {
                Write_LogMessage "${browserName}: Successfully deleted $filesDeleted history file(s)" -Level 'SUCCESS'
            }
            if ($filesSkipped -gt 0) {
                Write_LogMessage "${browserName}: Skipped $filesSkipped locked file(s) (browser is running)" -Level 'INFO'
            }
            if ($filesLocked -gt 0) {
                Write_LogMessage "${browserName}: Failed to delete $filesLocked file(s) due to file locks" -Level 'ERROR'
            }
            
            # Return true if we deleted at least some files or if browser is running (partial success)
            return ($filesDeleted -gt 0 -or ($browserRunning -and $filesSkipped -gt 0))
            
        } else {
            Write_LogMessage "$browserName browser profile not found at: $browserHistoryPath" -Level 'WARNING'
            return $false
        }
    } catch {
        Write_LogMessage "Unexpected error processing $browserName history: $_" -Level 'ERROR'
        return $false
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
        $chromeProcessed = Clear-BrowserHistory -browserHistoryPath $chromeHistryPath -browserName "Chrome"
        if ($chromeProcessed) {
            $successCount++
            Write_LogMessage "Chrome history processing completed" -Level 'SUCCESS'
        } else {
            # Browser profile not found or processing failed, don't count as success or failure for cleanup
            $totalBrowsers--
        }
    } else {
        Write_LogMessage "Chrome history path is not defined" -Level 'ERROR'
    }
    
    # Clear Edge history
    if ($edgeHistryPath) {
        $totalBrowsers++
        Write_LogMessage "Attempting to clear Edge history..." -Level 'INFO'
        $edgeProcessed = Clear-BrowserHistory -browserHistoryPath $edgeHistryPath -browserName "Edge"
        if ($edgeProcessed) {
            $successCount++
            Write_LogMessage "Edge history processing completed" -Level 'SUCCESS'
        } else {
            # Browser profile not found or processing failed, don't count as success or failure for cleanup
            $totalBrowsers--
        }
    } else {
        Write_LogMessage "Edge history path is not defined" -Level 'ERROR'
    }
    
    # Execution Summary
    Write_LogMessage "===== Execution Summary =====" -Level 'INFO'
    Write_LogMessage "Total browsers processed: $totalBrowsers" -Level 'INFO'
    Write_LogMessage "Successfully cleared: $successCount" -Level 'INFO'
    Write_LogMessage "Failed to clear: $failCount" -Level 'INFO'
    
    if ($ForceCloseBrowsers) {
        Write_LogMessage "Mode: Force close browsers (Complete history deletion including Ctrl+H)" -Level 'INFO'
    } else {
        Write_LogMessage "Mode: Graceful cleanup (Partial deletion, skips locked files)" -Level 'INFO'
        Write_LogMessage "Note: To delete Ctrl+H browsing history, use -ForceCloseBrowsers parameter" -Level 'INFO'
    }
    
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
