<#
SCRIPT NAME             19156_Win_Update_Repair_Windows_Update_Standalone_Installer_failure.ps1
IN REPOSITORY           Yes
AUTHOR & EMAIL          Vivek: vivek@capgemini.com
COMPANY                 Capgemini
TAGS                    Remediation, DISM, SFC, System Repair, Windows 11, Windows Update DLL
STATUS                  Draft
DATE OF CHANGES         2024-06-10 
VERSION                 1.1
RELEASENOTES            Complete Windows Update DLL repair using DISM + SFC (Microsoft recommended approach)
                        - Added SFC /scannow for System32 file repair
                        - Enhanced logging with detailed comments
                        - Two-tier repair: Component Store (DISM) + System Files (SFC)
                        - Fixed exit code handling (3=Admin Required, 2=Partial, 1=Failure, 0=Success)
                        - Improved network connectivity error handling
                        - Added DISM output capture for diagnostics
APPROVED                No
SUPPORT                 NA
DEX TOOLS               NA
DEPENDENCIES            PowerShell 5.1+, Administrative privileges, Windows 11/10
CONTEXT                 System
OS                      Windows 11/10
SYNOPSIS                Comprehensive Windows Update DLL repair script using DISM and SFC with detailed logging
DESCRIPTION             This script performs comprehensive Windows Update DLL repair with detailed logging:
                        
                        TWO-TIER REPAIR ARCHITECTURE:
                        Tier 1: Component Store (C:\Windows\WinSxS) - Master DLL repository
                        Tier 2: System Files (C:\Windows\System32) - Active DLL files in use
                        
                        REPAIR PHASES:
                        - Phase 1: DISM CheckHealth (Quick corruption check)
                        - Phase 2: DISM ScanHealth (Deep component store scan)
                        - Phase 3: DISM RestoreHealth (Repair component store corruption)
                        - Phase 4: SFC /scannow (Repair System32 DLL files)
                        
                        FEATURES:
                        - Detailed time tracking for each phase
                        - Comprehensive inline comments explaining each step
                        - Microsoft-recommended repair sequence
                        - Exit codes for monitoring systems
                        
                        MICROSOFT OFFICIAL GUIDANCE:
                        Per KB947821: DISM must run first to repair Component Store,
                        then SFC uses the repaired Component Store to fix System32 files.
                        
INPUTS                  None
OUTPUTS                 Detailed logging with timestamps and duration tracking
                        Exit Code 0: Success - All repairs completed successfully
                        Exit Code 1: Failure - Critical error during execution
                        Exit Code 2: Partial Success - Some operations completed with warnings
                        Exit Code 3: Administrator Required - Script must run with elevated privileges
VARIABLE DESCRIPTION    MyInvocation = Contains information about how the script was invoked, used for log file naming
                        $ScriptName = Stores the name of the script file without extension
                        $ScriptPath = Stores the directory path where the script is located
                        $logFile = Full path to the log file where all activities are recorded
                        $Global:RepairResults = Hashtable storing results and timing for each repair phase
                        $Global:RepairResults = @{} # Initializes the hashtable for tracking results
                        
FUNCTIONS               WriteLog = Centralized logging function with timestamps
                        Test-SystemRequirements = Validates system prerequisites (OS version, admin rights, disk space)
                        Get-DISMPath = Locates correct DISM executable considering WOW64 redirection
                        Get-SFCPath = Locates correct SFC executable considering WOW64 redirection
                        Format-Duration = Converts TimeSpan to human-readable format
                        Test-InternetConnectivity = Verifies network access to Windows Update servers
                        Test-PendingReboot = Checks for pending system reboots
                        Test-DiskSpace = Monitors available disk space during operations
                        Export-RepairResultsToJSON = Exports repair results to JSON file for integration
                        Invoke-DISMCheckHealth = Executes DISM CheckHealth phase
                        Invoke-DISMScanHealth = Executes DISM ScanHealth phase
                        Invoke-DISMRestoreHealth = Executes DISM RestoreHealth phase
                        Invoke-SFCScanNow = Executes SFC /scannow phase
NOTES                   Ensure script is run with Administrator privileges for DISM and SFC to function correctly.
                        Recommended to run in an elevated PowerShell session.
                        Monitor log file for detailed progress and results.
                        Review Microsoft KB947821 for official DISM and SFC repair procedures.
LICENSE                 MIT License

#>

#==================================================================================================
# LOGGING INITIALIZATION
# Purpose: Creates log file with same name as script in same directory
# Format: ScriptName + "Log.txt" (e.g., DISM-Repair.ps1 → DISM-RepairLog.txt)
#==================================================================================================

###### Extract script name and path for log file creation ######
$ScriptName = & { $myInvocation.ScriptName }  # Get full path of currently executing script
$ScriptPath = Split-Path -parent $ScriptName   # Extract directory path
$ScriptName = Split-Path $ScriptName -Leaf     # Extract filename only
$scriptNameOnly = $ScriptName -replace '.PS1','' # Remove .PS1 extension
$LogFile = "$ScriptPath\$ScriptNameOnly" + "Log.txt" # Construct log file path

########## Function: Write messages to log file with timestamp ########
# Purpose: Centralized logging function that adds timestamp to every log entry
# Format: yyyy/MM/dd HH:mm:ss <Message>
# Usage: WriteLog "Your message here"
##########################################################################
function WriteLog    
{
    Param (
        [string]$LogString  # Message to be logged
    )
    $Stamp = (Get-Date).toString("yyyy/MM/dd HH:mm:ss")  # Generate timestamp
    $LogMessage = "$Stamp $LogString"                     # Combine timestamp + message
    Add-content $LogFile -value $LogMessage               # Append to log file
}

# Log script initialization
WriteLog "------------------------------------------------------------------------------------"
WriteLog "#####################Starting DISM + SFC System Repair Process#####################"
WriteLog "------------------------------------------------------------------------------------"
WriteLog "Log file created at: $LogFile"
WriteLog "Microsoft Official Procedure: DISM (Component Store) → SFC (System Files)"

#==================================================================================================
# GLOBAL TRACKING VARIABLES
# Purpose: Store repair results and timing information for summary reporting
# These variables are accessed across multiple functions to build the final report
#==================================================================================================
$Global:RepairResults = @{
    # DISM Phase Results
    DISMCheckHealthSuccess = $false      # True if CheckHealth passed
    DISMScanHealthSuccess = $false       # True if ScanHealth found no corruption
    DISMRestoreHealthSuccess = $false    # True if RestoreHealth completed successfully
    RebootRequired = $false              # True if reboot needed to finalize repairs (Exit Code 3010)
    
    # SFC Phase Results
    SFCSuccess = $false                  # True if SFC scan completed successfully
    SFCCorruptionFound = $false          # True if SFC found corruption
    SFCCorruptionFixed = $false          # True if SFC fixed the corruption
    
    # System Pre-Check Results
    PendingRebootDetected = $false       # True if system had pending reboot before repair
    InitialDiskSpaceGB = 0               # Free disk space at start (GB)
    FinalDiskSpaceGB = 0                 # Free disk space at end (GB)
    
    # Timing Information (for performance tracking and reporting)
    CheckHealthDuration = ""             # Time taken for DISM CheckHealth
    ScanHealthDuration = ""              # Time taken for DISM ScanHealth
    RestoreHealthDuration = ""           # Time taken for DISM RestoreHealth
    SFCDuration = ""                     # Time taken for SFC scan
    TotalDuration = ""                   # Total script execution time
}

#==================================================================================================
# REGION: HELPER FUNCTIONS
# Purpose: Utility functions used across the script for validation and formatting
#==================================================================================================
#region Helper Functions

#--------------------------------------------------------------------------------------------------
# Function: Test-SystemRequirements
# Purpose: Validates that the system meets all prerequisites for running DISM/SFC repair
# Checks: Windows version, Administrator rights, PowerShell version, Disk space
# Returns: $true if all requirements met, $false otherwise
#--------------------------------------------------------------------------------------------------
function Test-SystemRequirements {
    WriteLog "=== Validating System Requirements ==="
    
    try {
        #----- Check 1: Windows Version -----
        # Requirement: Windows 10 or later (DISM/SFC behave differently on older versions)
        $OSInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $WindowsVersion = [System.Version]$OSInfo.Version
        
        WriteLog "Operating System: $($OSInfo.Caption) (Build $($OSInfo.BuildNumber))"
        WriteLog "System Architecture: $($OSInfo.OSArchitecture)"
        
        if ($WindowsVersion.Major -lt 10) {
            WriteLog "ERROR: This script requires Windows 10 or later"
            return $false
        }
        
        #----- Check 2: Administrator Rights -----
        # Requirement: DISM and SFC both require elevated privileges
        $Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $Principal = New-Object Security.Principal.WindowsPrincipal($Identity)
        
        if (-not $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            WriteLog "ERROR: Script must be run as Administrator"
            WriteLog "=============================================================="
            WriteLog "Script execution stopped - Administrator privileges required"
            WriteLog "=============================================================="
            WriteLog ""
            WriteLog "Script execution completed with exit code: 3"
            WriteLog "Exit Code Legend: 0=Success, 1=Failure, 2=Partial Success, 3=Administrator Required"
            exit 3
        }
        
        WriteLog "Administrator privileges: Confirmed"
        
        #----- Check 3: PowerShell Version -----
        # Requirement: PowerShell 5.0+ for modern cmdlets (Get-CimInstance, etc.)
        WriteLog "PowerShell Version: $($PSVersionTable.PSVersion.Major).$($PSVersionTable.PSVersion.Minor)"
        
        if ($PSVersionTable.PSVersion.Major -lt 5) {
            WriteLog "ERROR: PowerShell 5.0 or later required"
            return $false
        }
        
        #----- Check 4: Available Disk Space -----
        # Requirement: Minimum 2GB free space for DISM operations
        # Why: DISM downloads files from Windows Update and needs temporary storage
        $SystemDrive = Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object {$_.DeviceID -eq $env:SystemDrive}
        $FreeSpaceGB = [math]::Round($SystemDrive.FreeSpace / 1GB, 2)
        $Global:RepairResults.InitialDiskSpaceGB = $FreeSpaceGB
        
        WriteLog "System Drive: $($env:SystemDrive)"
        WriteLog "Available Disk Space: ${FreeSpaceGB} GB"
        
        if ($FreeSpaceGB -lt 2) {
            WriteLog "ERROR: Insufficient disk space (Minimum 2GB required for safe operation)"
            return $false
        }
        
        if ($FreeSpaceGB -lt 5) {
            WriteLog "WARNING: Disk space is limited (${FreeSpaceGB} GB) - recommend 5GB+ for large repairs"
        }
        
        WriteLog "System requirements validation: PASSED"
        return $true
    }
    catch {
        WriteLog "ERROR: System validation failed - $($_.Exception.Message)"
        return $false
    }
}

#--------------------------------------------------------------------------------------------------
# Function: Get-DISMPath
# Purpose: Locates the correct DISM executable, handling WOW64 redirection
# Why Needed: On 64-bit Windows, 32-bit PowerShell might be redirected to wrong DISM binary
# Returns: Full path to DISM.exe or $null if not found
#--------------------------------------------------------------------------------------------------
function Get-DISMPath {
    # WOW64 Redirection Handling:
    # - If OS is 64-bit but PowerShell is 32-bit, use Sysnative path
    # - This ensures we run the native 64-bit DISM, not the 32-bit version
    $DISMPath = if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
        "$env:SystemRoot\Sysnative\dism.exe"  # Bypass WOW64 redirection
    } else {
        "$env:SystemRoot\System32\dism.exe"   # Standard path
    }
    
    if (-not (Test-Path $DISMPath)) {
        WriteLog "ERROR: DISM executable not found at: $DISMPath"
        return $null
    }
    
    WriteLog "DISM Executable Location: $DISMPath"
    return $DISMPath
}

#--------------------------------------------------------------------------------------------------
# Function: Get-SFCPath
# Purpose: Locates the correct SFC executable, handling WOW64 redirection
# Why Needed: Same WOW64 considerations as DISM
# Returns: Full path to sfc.exe or $null if not found
#--------------------------------------------------------------------------------------------------
function Get-SFCPath {
    # WOW64 Redirection Handling (same logic as Get-DISMPath)
    $SFCPath = if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
        "$env:SystemRoot\Sysnative\sfc.exe"   # Bypass WOW64 redirection
    } else {
        "$env:SystemRoot\System32\sfc.exe"    # Standard path
    }
    
    if (-not (Test-Path $SFCPath)) {
        WriteLog "ERROR: SFC executable not found at: $SFCPath"
        return $null
    }
    
    WriteLog "SFC Executable Location: $SFCPath"
    return $SFCPath
}

#--------------------------------------------------------------------------------------------------
# Function: Format-Duration
# Purpose: Converts TimeSpan object to human-readable duration string
# Input: TimeSpan object (e.g., from measuring operation duration)
# Output: Formatted string like "5 minutes 30 seconds" or "45 seconds"
#--------------------------------------------------------------------------------------------------
function Format-Duration {
    param([TimeSpan]$TimeSpan)
    
    if ($TimeSpan.TotalHours -ge 1) {
        return "{0} hours {1} minutes {2} seconds" -f [int]$TimeSpan.Hours, [int]$TimeSpan.Minutes, [int]$TimeSpan.Seconds
    } elseif ($TimeSpan.TotalMinutes -ge 1) {
        return "{0} minutes {1} seconds" -f [int]$TimeSpan.Minutes, [int]$TimeSpan.Seconds
    } else {
        return "{0} seconds" -f [int]$TimeSpan.TotalSeconds
    }
}

#--------------------------------------------------------------------------------------------------
# Function: Test-InternetConnectivity
# Purpose: Verifies network connectivity to Windows Update servers before RestoreHealth
# Why Needed: RestoreHealth downloads files from Windows Update; fails without internet
# Returns: $true if connectivity verified, $false if unreachable (with warning logged)
#--------------------------------------------------------------------------------------------------
function Test-InternetConnectivity {
    WriteLog ""
    WriteLog "=== Checking Network Connectivity ==="
    
    try {
        # Test connection to Microsoft Windows Update servers
        # Using Test-NetConnection to verify both DNS resolution and port accessibility
        WriteLog "Testing connectivity to windowsupdate.microsoft.com (Port 443)..."
        
        $testConnection = Test-NetConnection -ComputerName "windowsupdate.microsoft.com" -Port 443 -InformationLevel Quiet -WarningAction SilentlyContinue -ErrorAction Stop
        
        if ($testConnection) {
            WriteLog "Network connectivity: VERIFIED"
            WriteLog "Status: Windows Update servers are reachable"
            WriteLog "Details: HTTPS connection to windowsupdate.microsoft.com successful"
            return $true
        } else {
            WriteLog "WARNING: Cannot reach Windows Update servers"
            WriteLog "Status: Network connectivity test FAILED"
            WriteLog "Impact: DISM RestoreHealth may fail without internet access"
            WriteLog "Possible causes:"
            WriteLog "  - No internet connection"
            WriteLog "  - Firewall blocking outbound HTTPS (port 443)"
            WriteLog "  - Proxy configuration required"
            WriteLog "  - DNS resolution issues"
            WriteLog ""
            WriteLog "Recommendation: Verify network connection before proceeding"
            WriteLog "Note: RestoreHealth will still attempt to run but may fail"
            return $false
        }
    }
    catch {
        WriteLog "WARNING: Network connectivity test encountered an error"
        WriteLog "Error: $($_.Exception.Message)"
        WriteLog "Note: Treating as connectivity failure - RestoreHealth may have issues"
        return $false  # Treat test failure as connectivity problem
    }
}

#--------------------------------------------------------------------------------------------------
# Function: Test-PendingReboot
# Purpose: Checks if system has pending reboot from previous updates/installations
# Why Needed: Pending reboots can affect DISM/SFC scan accuracy and component store state
# Returns: $true if reboot pending, $false if system is clean
#--------------------------------------------------------------------------------------------------
function Test-PendingReboot {
    WriteLog ""
    WriteLog "=== Checking for Pending System Reboot ==="
    
    $RebootPending = $false
    $RebootReasons = @()
    
    try {
        # Check 1: Component Based Servicing (CBS) pending reboot
        # Indicates Windows Update or DISM operations require reboot
        if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") {
            $RebootPending = $true
            $RebootReasons += "Component Based Servicing (CBS) operations pending"
            WriteLog "Found: Component Based Servicing reboot flag"
        }
        
        # Check 2: Windows Update pending reboot
        # Indicates Windows Update has installed updates requiring restart
        if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired") {
            $RebootPending = $true
            $RebootReasons += "Windows Update installations pending"
            WriteLog "Found: Windows Update reboot flag"
        }
        
        # Check 3: Pending file rename operations
        # Indicates files need to be replaced/moved on next boot
        if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\PendingFileRenameOperations") {
            $RebootPending = $true
            $RebootReasons += "Pending file rename operations"
            WriteLog "Found: Pending file rename operations"
        }
        
        # Check 4: Computer rename pending
        $computerName = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName" -ErrorAction SilentlyContinue).ComputerName
        $pendingComputerName = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName" -ErrorAction SilentlyContinue).ComputerName
        if ($computerName -and $pendingComputerName -and ($computerName -ne $pendingComputerName)) {
            $RebootPending = $true
            $RebootReasons += "Computer name change pending"
            WriteLog "Found: Computer rename pending ($computerName -> $pendingComputerName)"
        }
        
        # Report results
        if ($RebootPending) {
            WriteLog ""
            WriteLog "========================================="
            WriteLog "WARNING: PENDING REBOOT DETECTED"
            WriteLog "========================================="
            WriteLog ""
            WriteLog "Reason(s):"
            foreach ($reason in $RebootReasons) {
                WriteLog "  - $reason"
            }
            WriteLog ""
            WriteLog "IMPACT ON DISM/SFC REPAIR:"
            WriteLog "  - Component store may be in inconsistent state"
            WriteLog "  - Scan results may be inaccurate"
            WriteLog "  - Some corruption may not be detected"
            WriteLog "  - Repair operations may fail or be incomplete"
            WriteLog ""
            WriteLog "RECOMMENDATION:"
            WriteLog "  1. Reboot the system first"
            WriteLog "  2. Then re-run this DISM/SFC repair script"
            WriteLog "  3. This ensures accurate scan results"
            WriteLog ""
            WriteLog "DECISION: Continuing anyway (results may be less reliable)"
            WriteLog "========================================="
            WriteLog ""
            
            $Global:RepairResults.PendingRebootDetected = $true
            return $true
        } else {
            WriteLog "Result: No pending reboot detected"
            WriteLog "Status: System is in clean state for repair operations"
            $Global:RepairResults.PendingRebootDetected = $false
            return $false
        }
    }
    catch {
        WriteLog "WARNING: Error checking pending reboot status - $($_.Exception.Message)"
        WriteLog "Assuming no pending reboot and continuing..."
        $Global:RepairResults.PendingRebootDetected = $false
        return $false
    }
}

#--------------------------------------------------------------------------------------------------
# Function: Test-DiskSpace
# Purpose: Monitors available disk space on system drive throughout repair operations
# Why Needed: DISM RestoreHealth can download 2-3GB; must prevent mid-operation failures
# Parameters: $MinimumGB - Minimum free space required (default: 2GB)
# Returns: $true if sufficient space, $false if insufficient
#--------------------------------------------------------------------------------------------------
function Test-DiskSpace {
    param(
        [Parameter(Mandatory=$false)]
        [double]$MinimumGB = 2.0,
        [Parameter(Mandatory=$false)]
        [string]$Phase = "Operation"
    )
    
    try {
        $SystemDrive = Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object {$_.DeviceID -eq $env:SystemDrive}
        $FreeSpaceGB = [math]::Round($SystemDrive.FreeSpace / 1GB, 2)
        
        WriteLog "Disk Space Check ($Phase): ${FreeSpaceGB} GB available on $($env:SystemDrive)"
        
        if ($FreeSpaceGB -lt $MinimumGB) {
            WriteLog ""
            WriteLog "========================================="
            WriteLog "CRITICAL: INSUFFICIENT DISK SPACE"
            WriteLog "========================================="
            WriteLog "Available: ${FreeSpaceGB} GB"
            WriteLog "Required: ${MinimumGB} GB"
            WriteLog "Deficit: $([math]::Round($MinimumGB - $FreeSpaceGB, 2)) GB"
            WriteLog ""
            WriteLog "RISKS:"
            WriteLog "  - DISM may fail mid-download"
            WriteLog "  - System instability possible"
            WriteLog "  - Temp files cannot be created"
            WriteLog ""
            WriteLog "ACTION REQUIRED: Free up disk space before continuing"
            WriteLog "========================================="
            WriteLog ""
            return $false
        } elseif ($FreeSpaceGB -lt ($MinimumGB * 1.5)) {
            WriteLog "WARNING: Disk space is tight (${FreeSpaceGB} GB) - monitor closely"
            return $true
        } else {
            WriteLog "Status: Sufficient disk space available"
            return $true
        }
    }
    catch {
        WriteLog "WARNING: Unable to check disk space - $($_.Exception.Message)"
        return $true  # Don't block execution on check failure
    }
}

#--------------------------------------------------------------------------------------------------
# Function: Export-RepairResultsToJSON
# Purpose: Exports repair results to JSON file for automation/integration purposes
# Why Needed: Enables integration with monitoring systems, dashboards, and automation pipelines
# Output: Creates <ScriptName>-Results.json in same directory as script
#--------------------------------------------------------------------------------------------------
function Export-RepairResultsToJSON {
    try {
        WriteLog ""
        WriteLog "=== Exporting Results to JSON ==="
        
        # Prepare structured output with additional metadata
        $JsonOutput = @{
            Metadata = @{
                ScriptName = $ScriptName
                ExecutionDate = Get-Date -Format "yyyy-MM-dd"
                ExecutionTime = Get-Date -Format "HH:mm:ss"
                ComputerName = $env:COMPUTERNAME
                WindowsVersion = (Get-CimInstance -ClassName Win32_OperatingSystem).Version
                WindowsBuild = (Get-CimInstance -ClassName Win32_OperatingSystem).BuildNumber
            }
            RepairResults = $Global:RepairResults
            ExitCode = $null  # Will be set by caller
            LogFilePath = $LogFile
        }
        
        # Generate JSON file path
        $JsonPath = "$ScriptPath\$scriptNameOnly-Results.json"
        
        # Export to JSON with formatting
        $JsonOutput | ConvertTo-Json -Depth 5 | Out-File -FilePath $JsonPath -Encoding UTF8 -Force
        
        WriteLog "JSON export successful: $JsonPath"
        WriteLog "File size: $([math]::Round((Get-Item $JsonPath).Length / 1KB, 2)) KB"
        
        return $JsonPath
    }
    catch {
        WriteLog "WARNING: Failed to export JSON - $($_.Exception.Message)"
        WriteLog "Continuing without JSON export..."
        return $null
    }
}
#endregion

#==================================================================================================
# REGION: DISM REPAIR FUNCTIONS
# Purpose: Three-phase DISM repair process for Windows Component Store
# Sequence: CheckHealth → ScanHealth → RestoreHealth (only if corruption detected)
#==================================================================================================
#region DISM Repair Functions
function Invoke-DISMCheckHealth {
    param([string]$DISMPath)
    
    WriteLog ""
    WriteLog "=========================================="
    WriteLog "PHASE 1: DISM CheckHealth Scan"
    WriteLog "=========================================="
    WriteLog "Description: Quick check to determine if the image has been flagged as corrupted"
    WriteLog "Expected Duration: 5-15 seconds"
    WriteLog "Starting DISM CheckHealth at: $(Get-Date -Format 'yyyy/MM/dd HH:mm:ss')"
    
    $StartTime = Get-Date
    
    try {
        WriteLog "Executing: DISM.exe /Online /Cleanup-Image /CheckHealth"
        $CheckHealthResult = Start-Process $DISMPath `
                                          -ArgumentList "/Online", "/Cleanup-Image", "/CheckHealth" `
                                          -Wait `
                                          -PassThru `
                                          -WindowStyle Hidden `
                                          -RedirectStandardOutput "$env:TEMP\dism_checkhealth_output.txt" `
                                          -RedirectStandardError "$env:TEMP\dism_checkhealth_error.txt"
        
        $EndTime = Get-Date
        $Duration = $EndTime - $StartTime
        $Global:RepairResults.CheckHealthDuration = Format-Duration $Duration
        
        WriteLog "DISM CheckHealth completed at: $(Get-Date -Format 'yyyy/MM/dd HH:mm:ss')"
        WriteLog "Duration: $($Global:RepairResults.CheckHealthDuration)"
        WriteLog "Exit Code: $($CheckHealthResult.ExitCode)"
        
        if ($CheckHealthResult.ExitCode -eq 0) {
            WriteLog "Result: No component store corruption detected"
            $Global:RepairResults.DISMCheckHealthSuccess = $true
            
            # Cleanup temp files
            Remove-Item "$env:TEMP\dism_checkhealth_output.txt" -Force -ErrorAction SilentlyContinue
            Remove-Item "$env:TEMP\dism_checkhealth_error.txt" -Force -ErrorAction SilentlyContinue
            return $true
        } else {
            WriteLog "Result: Potential corruption detected (Exit Code: $($CheckHealthResult.ExitCode))"
            WriteLog "Recommendation: Proceeding to ScanHealth for detailed analysis"
            
            # Cleanup temp files
            Remove-Item "$env:TEMP\dism_checkhealth_output.txt" -Force -ErrorAction SilentlyContinue
            Remove-Item "$env:TEMP\dism_checkhealth_error.txt" -Force -ErrorAction SilentlyContinue
            return $false
        }
    }
    catch {
        WriteLog "ERROR: DISM CheckHealth failed - $($_.Exception.Message)"
        return $false
    }
}

function Invoke-DISMScanHealth {
    param([string]$DISMPath)
    
    WriteLog ""
    WriteLog "=========================================="
    WriteLog "PHASE 2: DISM ScanHealth Deep Scan"
    WriteLog "=========================================="
    WriteLog "Description: Thorough scan to check for component store corruption"
    WriteLog "Expected Duration: 5-15 minutes"
    WriteLog "Starting DISM ScanHealth at: $(Get-Date -Format 'yyyy/MM/dd HH:mm:ss')"
    WriteLog "NOTE: This operation may take several minutes. Please wait..."
    
    $StartTime = Get-Date
    
    try {
        WriteLog "Executing: DISM.exe /Online /Cleanup-Image /ScanHealth"
        $ScanHealthResult = Start-Process $DISMPath `
                                         -ArgumentList "/Online", "/Cleanup-Image", "/ScanHealth" `
                                         -Wait `
                                         -PassThru `
                                         -WindowStyle Hidden `
                                         -RedirectStandardOutput "$env:TEMP\dism_scanhealth_output.txt" `
                                         -RedirectStandardError "$env:TEMP\dism_scanhealth_error.txt"
        
        $EndTime = Get-Date
        $Duration = $EndTime - $StartTime
        $Global:RepairResults.ScanHealthDuration = Format-Duration $Duration
        
        WriteLog "DISM ScanHealth completed at: $(Get-Date -Format 'yyyy/MM/dd HH:mm:ss')"
        WriteLog "Duration: $($Global:RepairResults.ScanHealthDuration)"
        WriteLog "Exit Code: $($ScanHealthResult.ExitCode)"
        
        if ($ScanHealthResult.ExitCode -eq 0) {
            WriteLog "Result: No corruption found in component store"
            $Global:RepairResults.DISMScanHealthSuccess = $true
            
            # Cleanup temp files
            Remove-Item "$env:TEMP\dism_scanhealth_output.txt" -Force -ErrorAction SilentlyContinue
            Remove-Item "$env:TEMP\dism_scanhealth_error.txt" -Force -ErrorAction SilentlyContinue
            return $true
        } else {
            WriteLog "Result: Corruption detected in component store (Exit Code: $($ScanHealthResult.ExitCode))"
            WriteLog "Recommendation: Proceeding to RestoreHealth for repair"
            
            # Cleanup temp files
            Remove-Item "$env:TEMP\dism_scanhealth_output.txt" -Force -ErrorAction SilentlyContinue
            Remove-Item "$env:TEMP\dism_scanhealth_error.txt" -Force -ErrorAction SilentlyContinue
            return $false
        }
    }
    catch {
        WriteLog "ERROR: DISM ScanHealth failed - $($_.Exception.Message)"
        return $false
    }
}

function Invoke-DISMRestoreHealth {
    param(
        [string]$DISMPath,
        [string]$SourcePath = $null,
        [switch]$LimitAccess
    )

    WriteLog ""
    WriteLog "=========================================="
    WriteLog "PHASE 3: DISM RestoreHealth Repair"
    WriteLog "=========================================="
    WriteLog "Description: Repairs component store corruption using Windows Update or supplied source"
    WriteLog "Expected Duration: 5-30 minutes (depends on corruption extent)"
    WriteLog "Starting DISM RestoreHealth at: $(Get-Date -Format 'yyyy/MM/dd HH:mm:ss')"
    WriteLog "NOTE: This operation may download files from Windows Update or use the provided source..."

    $StartTime = Get-Date

    try {
        # Build argument list dynamically to support /Source and /LimitAccess
        $dismArgs = @('/Online','/Cleanup-Image','/RestoreHealth')
        if ($SourcePath) {
            WriteLog "Using DISM Source: $SourcePath"
            $dismArgs += "/Source:$SourcePath"
        }
        if ($LimitAccess) {
            WriteLog "Applying /LimitAccess to prevent contacting Windows Update"
            $dismArgs += '/LimitAccess'
        }

        WriteLog "Executing: DISM.exe $($dismArgs -join ' ')"
        $RestoreHealthResult = Start-Process $DISMPath `
                                            -ArgumentList $dismArgs `
                                            -Wait `
                                            -PassThru `
                                            -WindowStyle Hidden `
                                            -RedirectStandardOutput "$env:TEMP\dism_restorehealth_output.txt" `
                                            -RedirectStandardError "$env:TEMP\dism_restorehealth_error.txt"

        $EndTime = Get-Date
        $Duration = $EndTime - $StartTime
        $Global:RepairResults.RestoreHealthDuration = Format-Duration $Duration

        WriteLog "DISM RestoreHealth completed at: $(Get-Date -Format 'yyyy/MM/dd HH:mm:ss')"
        WriteLog "Duration: $($Global:RepairResults.RestoreHealthDuration)"
        WriteLog "Exit Code: $($RestoreHealthResult.ExitCode)"

        if ($RestoreHealthResult.ExitCode -eq 0) {
            WriteLog ""
            WriteLog "Result: Component store successfully repaired"
            WriteLog "Status: All repairs applied immediately - no reboot required"
            $Global:RepairResults.DISMRestoreHealthSuccess = $true

            # Cleanup temp files
            Remove-Item "$env:TEMP\dism_restorehealth_output.txt" -Force -ErrorAction SilentlyContinue
            Remove-Item "$env:TEMP\dism_restorehealth_error.txt" -Force -ErrorAction SilentlyContinue
            return $true
        }
        elseif ($RestoreHealthResult.ExitCode -eq 3010) {
            WriteLog ""
            WriteLog "=========================================="
            WriteLog "Result: Repair SUCCESSFUL - REBOOT REQUIRED"
            WriteLog "=========================================="
            $Global:RepairResults.DISMRestoreHealthSuccess = $true
            $Global:RepairResults.RebootRequired = $true

            # Cleanup temp files
            Remove-Item "$env:TEMP\dism_restorehealth_output.txt" -Force -ErrorAction SilentlyContinue
            Remove-Item "$env:TEMP\dism_restorehealth_error.txt" -Force -ErrorAction SilentlyContinue
            return $true
        }
        else {
            WriteLog ""
            WriteLog "Result: RestoreHealth encountered issues (Exit Code: $($RestoreHealthResult.ExitCode))"
            WriteLog "Possible causes: Network connectivity, Windows Update service issues, corrupted source files"
            WriteLog "Recommendation: Check network connection, verify Windows Update service status"

            # Cleanup temp files
            Remove-Item "$env:TEMP\dism_restorehealth_output.txt" -Force -ErrorAction SilentlyContinue
            Remove-Item "$env:TEMP\dism_restorehealth_error.txt" -Force -ErrorAction SilentlyContinue
            return $false
        }
    }
    catch {
        WriteLog "ERROR: DISM RestoreHealth failed - $($_.Exception.Message)"
        return $false
    }
}

<# 
.SYNOPSIS
    Executes System File Checker (SFC) to repair corrupted system files in System32
    
.DESCRIPTION
    WHAT: Runs sfc.exe /scannow to scan and repair corrupted files in C:\Windows\System32
    WHY: SFC is the Tier 2 repair that fixes active DLL files in use by Windows components
    HOW: Validates system file integrity against WinSxS component store repaired by DISM
    
    TECHNICAL NOTES:
    - Must run AFTER DISM RestoreHealth to ensure WinSxS master repository is clean
    - SFC copies correct files from WinSxS to System32 when corruption detected
    - Exit codes: 0=No issues, 1=Issues found and fixed, 2=Issues found but not fixed, 3=Scan failed
    - Typical duration: 10-20 minutes on healthy systems, 30-60 minutes with corruption
    
    RETURN VALUES:
    - $true: SFC completed successfully (exit code 0 or 1)
    - $false: SFC failed or found unfixable corruption (exit code 2 or 3)
#>
function Invoke-SFCRepair {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$SFCPath
    )
    
    try {
        WriteLog ""
        WriteLog "=========================================="
        WriteLog "PHASE 4: System File Checker (SFC) Scan"
        WriteLog "=========================================="
        WriteLog ""
        WriteLog "WHAT: Scanning and repairing corrupted system files in System32"
        WriteLog "WHY: SFC fixes Tier 2 active DLL files used by Windows Update components"
        WriteLog "HOW: Validates files against WinSxS component store (repaired by DISM)"
        WriteLog ""
        WriteLog "Starting SFC /scannow at: $(Get-Date -Format 'yyyy/MM/dd HH:mm:ss')"
        WriteLog "Expected Duration: 10-60 minutes depending on system state"
        WriteLog ""
        
        # Record start time for duration tracking
        $SFCStartTime = Get-Date
        
        # Execute SFC with /scannow parameter
        # - /scannow: Scans all protected system files and repairs corrupted files
        # - No online/offline required: SFC always operates on running OS
        WriteLog "Executing: $SFCPath /scannow"
        WriteLog "Please wait - SFC is scanning protected system files..."
        
        $SFCProcess = Start-Process -FilePath $SFCPath `
                                     -ArgumentList "/scannow" `
                                     -Wait `
                                     -PassThru `
                                     -NoNewWindow `
                                     -RedirectStandardOutput "$env:TEMP\sfc_output.txt" `
                                     -RedirectStandardError "$env:TEMP\sfc_error.txt"
        
        # Calculate execution duration
        $SFCEndTime = Get-Date
        $SFCDuration = $SFCEndTime - $SFCStartTime
        $Global:RepairResults.SFCDuration = Format-Duration $SFCDuration
        
        WriteLog ""
        WriteLog "SFC scan completed at: $(Get-Date -Format 'yyyy/MM/dd HH:mm:ss')"
        WriteLog "Duration: $($Global:RepairResults.SFCDuration)"
        WriteLog ""
        
        # Interpret SFC exit code to determine repair status
        # Exit Code 0: No integrity violations found (system files are clean)
        # Exit Code 1: Corruption found and successfully repaired
        # Exit Code 2: Corruption found but could NOT be repaired (requires manual intervention)
        # Exit Code 3: SFC scan failed to complete (access denied, disk errors, etc.)
        
        $SFCExitCode = $SFCProcess.ExitCode
        WriteLog "SFC Exit Code: $SFCExitCode"
        
        switch ($SFCExitCode) {
            0 {
                # System files are clean - no corruption detected
                WriteLog "RESULT: No integrity violations detected"
                WriteLog "STATUS: System files are healthy - no repair needed"
                $Global:RepairResults.SFCSuccess = $true
                $Global:RepairResults.SFCCorruptionFound = $false
                $Global:RepairResults.SFCCorruptionFixed = $false
                return $true
            }
            1 {
                # Corruption found and successfully repaired
                WriteLog "RESULT: Corruption detected and successfully repaired"
                WriteLog "STATUS: SFC fixed corrupted system files from WinSxS component store"
                $Global:RepairResults.SFCSuccess = $true
                $Global:RepairResults.SFCCorruptionFound = $true
                $Global:RepairResults.SFCCorruptionFixed = $true
                return $true
            }
            2 {
                # Corruption found but could not be repaired - critical failure
                WriteLog "WARNING: Corruption detected but SFC could NOT repair files"
                WriteLog "REASON: Files may be locked, WinSxS missing source files, or disk errors present"
                WriteLog "ACTION REQUIRED: Review CBS.log for details, may need in-place upgrade repair"
                $Global:RepairResults.SFCSuccess = $false
                $Global:RepairResults.SFCCorruptionFound = $true
                $Global:RepairResults.SFCCorruptionFixed = $false
                return $false
            }
            3 {
                # SFC scan failed to complete - critical failure
                WriteLog "ERROR: SFC scan failed to complete"
                WriteLog "REASON: Access denied, disk errors, or system instability"
                WriteLog "ACTION REQUIRED: Check disk health, run as admin, review CBS.log"
                $Global:RepairResults.SFCSuccess = $false
                $Global:RepairResults.SFCCorruptionFound = $false
                $Global:RepairResults.SFCCorruptionFixed = $false
                return $false
            }
            default {
                # Unexpected exit code - treat as failure
                WriteLog "WARNING: Unexpected SFC exit code: $SFCExitCode"
                WriteLog "REASON: Unknown SFC result - review CBS.log for details"
                $Global:RepairResults.SFCSuccess = $false
                $Global:RepairResults.SFCCorruptionFound = $false
                $Global:RepairResults.SFCCorruptionFixed = $false
                return $false
            }
        }
        
        # Cleanup temporary SFC output files
        WriteLog ""
        WriteLog "Cleaning up temporary files..."
        try {
            $SFCOutputFile = "$env:TEMP\sfc_output.txt"
            $SFCErrorFile = "$env:TEMP\sfc_error.txt"
            
            if (Test-Path $SFCOutputFile) {
                Remove-Item $SFCOutputFile -Force -ErrorAction Stop
                WriteLog "Removed: $SFCOutputFile"
            }
            
            if (Test-Path $SFCErrorFile) {
                Remove-Item $SFCErrorFile -Force -ErrorAction Stop
                WriteLog "Removed: $SFCErrorFile"
            }
            
            WriteLog "Temporary file cleanup: COMPLETED"
        }
        catch {
            WriteLog "WARNING: Failed to cleanup temporary files - $($_.Exception.Message)"
            # Non-critical error - don't affect return value
        }
    }
    catch {
        WriteLog "ERROR: SFC scan failed - $($_.Exception.Message)"
        $Global:RepairResults.SFCSuccess = $false
        $Global:RepairResults.SFCCorruptionFound = $false
        $Global:RepairResults.SFCCorruptionFixed = $false
        
        # Attempt cleanup even on failure
        try {
            Remove-Item "$env:TEMP\sfc_output.txt" -Force -ErrorAction SilentlyContinue
            Remove-Item "$env:TEMP\sfc_error.txt" -Force -ErrorAction SilentlyContinue
        }
        catch { }
        
        return $false
    }
}
#endregion

#region Main Execution
function Start-DISMRepair {
    param(
        [string]$DISMSourcePath = $null,
        [switch]$LimitAccess
    )

    $ExitCode = 0
    $ScriptStartTime = Get-Date
    
    try {
        WriteLog ""
        WriteLog "=========================================="
        WriteLog "Starting DISM + SFC System Repair Process"
        WriteLog "=========================================="
        WriteLog "Process Start Time: $(Get-Date -Format 'yyyy/MM/dd HH:mm:ss')"
        
        # Validate system requirements
        if (-not (Test-SystemRequirements)) {
            throw "System requirements validation failed"
        }
        
        # Check for pending reboot (warning only, does not block execution)
        Test-PendingReboot | Out-Null
        
        # Get DISM path
        $DISMPath = Get-DISMPath
        if (-not $DISMPath) {
            throw "DISM executable not found"
        }
        
        # Phase 1: CheckHealth
        if (-not (Test-DiskSpace -MinimumGB 2 -Phase "Before CheckHealth")) {
            throw "Insufficient disk space to proceed with DISM operations"
        }
        $CheckHealthSuccess = Invoke-DISMCheckHealth -DISMPath $DISMPath
        
        # Phase 2: ScanHealth (if CheckHealth passed, run for thoroughness; if failed, mandatory)
        if (-not (Test-DiskSpace -MinimumGB 2 -Phase "Before ScanHealth")) {
            throw "Insufficient disk space to proceed with DISM ScanHealth"
        }
        $ScanHealthSuccess = Invoke-DISMScanHealth -DISMPath $DISMPath
        
        # Phase 3: RestoreHealth (only if corruption detected)
        if (-not $CheckHealthSuccess -or -not $ScanHealthSuccess) {
            WriteLog ""
            WriteLog "Corruption detected - RestoreHealth repair is required"
            
            # Check network connectivity before attempting RestoreHealth
            # RestoreHealth downloads component files from Windows Update servers
            $NetworkAvailable = Test-InternetConnectivity
            
            if (-not $NetworkAvailable) {
                WriteLog ""
                WriteLog "NOTICE: Network connectivity issue detected"
                WriteLog "WARNING: RestoreHealth may fail without internet access"
                WriteLog "INFO: Attempting RestoreHealth anyway (may use local sources if available)"
            }
            
            # Critical: Check disk space before downloading components
            if (-not (Test-DiskSpace -MinimumGB 3 -Phase "Before RestoreHealth")) {
                WriteLog "ERROR: Insufficient disk space for RestoreHealth download operations"
                WriteLog "RestoreHealth typically requires 2-3GB for component downloads"
                $ExitCode = 2  # Partial success
            } else {
                Ensure-WindowsUpdateServices | Out-Null
                $RestoreHealthSuccess = Invoke-DISMRestoreHealth -DISMPath $DISMPath -SourcePath $DISMSourcePath -LimitAccess:$LimitAccess
                
                # Check disk space after RestoreHealth to monitor consumption
                Test-DiskSpace -MinimumGB 1 -Phase "After RestoreHealth" | Out-Null
            }
            
            if (-not $RestoreHealthSuccess) {
                WriteLog "WARNING: RestoreHealth completed with issues"
                $ExitCode = 2  # Partial success
            } elseif ($Global:RepairResults.RebootRequired) {
                WriteLog ""
                WriteLog "INFO: RestoreHealth succeeded with pending reboot requirement"
                WriteLog "INFO: Component files are staged but require restart to activate"
                WriteLog "INFO: Continuing with SFC phase using current component store state"
                # Exit code remains 0 - reboot is a post-action, not a failure
            }
        } else {
            WriteLog ""
            WriteLog "No corruption detected - RestoreHealth repair not required"
            $Global:RepairResults.DISMRestoreHealthSuccess = $true
            $Global:RepairResults.RestoreHealthDuration = "Not Required (No Corruption)"
        }
        
        # Phase 4: System File Checker (SFC) - Tier 2 Repair
        # MUST run after DISM to ensure WinSxS component store is clean
        # SFC copies correct files from WinSxS to System32 when corruption detected
        WriteLog ""
        WriteLog "Proceeding to Phase 4: SFC scan (Tier 2 System32 file repair)"
        WriteLog "Microsoft Guidance: Always run SFC after DISM for complete repair coverage"
        
        $SFCPath = Get-SFCPath
        if (-not $SFCPath) {
            WriteLog "ERROR: SFC executable not found - skipping Phase 4"
            $ExitCode = 2  # Partial success
        } else {
            # Check disk space before SFC scan
            if (-not (Test-DiskSpace -MinimumGB 1 -Phase "Before SFC Scan")) {
                WriteLog "WARNING: Low disk space before SFC scan"
            }
            
            $SFCSuccess = Invoke-SFCRepair -SFCPath $SFCPath
            
            if (-not $SFCSuccess) {
                WriteLog "WARNING: SFC completed with issues or unfixable corruption"
                $ExitCode = 2  # Partial success
            }
        }
        
        # Calculate total duration and final disk space
        $ScriptEndTime = Get-Date
        $TotalDuration = $ScriptEndTime - $ScriptStartTime
        $Global:RepairResults.TotalDuration = Format-Duration $TotalDuration
        
        # Record final disk space
        $SystemDrive = Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object {$_.DeviceID -eq $env:SystemDrive}
        $Global:RepairResults.FinalDiskSpaceGB = [math]::Round($SystemDrive.FreeSpace / 1GB, 2)
        
        WriteLog ""
        WriteLog "=========================================="
        WriteLog "DISM + SFC Repair Process Completed"
        WriteLog "=========================================="
        WriteLog "Process End Time: $(Get-Date -Format 'yyyy/MM/dd HH:mm:ss')"
        WriteLog "Total Duration: $($Global:RepairResults.TotalDuration)"
        
        # Generate summary report
        WriteLog ""
        WriteLog "=== DETAILED SUMMARY REPORT ==="
        WriteLog ""
        WriteLog "TIER 1: DISM Component Store Repair (WinSxS)"
        WriteLog "---------------------------------------------"
        WriteLog ""
        WriteLog "PHASE 1 - CheckHealth:"
        WriteLog "  Status: $(if($Global:RepairResults.DISMCheckHealthSuccess){'SUCCESS'}else{'ISSUES DETECTED'})"
        WriteLog "  Duration: $($Global:RepairResults.CheckHealthDuration)"
        WriteLog ""
        WriteLog "PHASE 2 - ScanHealth:"
        WriteLog "  Status: $(if($Global:RepairResults.DISMScanHealthSuccess){'SUCCESS'}else{'CORRUPTION FOUND'})"
        WriteLog "  Duration: $($Global:RepairResults.ScanHealthDuration)"
        WriteLog ""
        WriteLog "PHASE 3 - RestoreHealth:"
        WriteLog "  Status: $(if($Global:RepairResults.DISMRestoreHealthSuccess){'SUCCESS'}else{'COMPLETED WITH ISSUES'})"
        WriteLog "  Duration: $($Global:RepairResults.RestoreHealthDuration)"
        if ($Global:RepairResults.RebootRequired) {
            WriteLog "  ⚠️  REBOOT REQUIRED: Component files staged for replacement on next boot"
        }
        WriteLog ""
        WriteLog "TIER 2: SFC System File Repair (System32)"
        WriteLog "---------------------------------------------"
        WriteLog ""
        WriteLog "PHASE 4 - SFC /scannow:"
        WriteLog "  Status: $(if($Global:RepairResults.SFCSuccess){'SUCCESS'}else{'ISSUES DETECTED'})"
        WriteLog "  Corruption Found: $(if($Global:RepairResults.SFCCorruptionFound){'YES'}else{'NO'})"
        WriteLog "  Corruption Fixed: $(if($Global:RepairResults.SFCCorruptionFixed){'YES'}elseif($Global:RepairResults.SFCCorruptionFound){'NO - MANUAL INTERVENTION REQUIRED'}else{'N/A'})"
        WriteLog "  Duration: $($Global:RepairResults.SFCDuration)"
        WriteLog ""
        WriteLog "TOTAL EXECUTION TIME: $($Global:RepairResults.TotalDuration)"
        WriteLog ""
        WriteLog "DISK SPACE ANALYSIS:"
        WriteLog "---------------------------------------------"
        WriteLog "  Initial Free Space: $($Global:RepairResults.InitialDiskSpaceGB) GB"
        WriteLog "  Final Free Space: $($Global:RepairResults.FinalDiskSpaceGB) GB"
        $DiskChange = $Global:RepairResults.InitialDiskSpaceGB - $Global:RepairResults.FinalDiskSpaceGB
        if ($DiskChange -gt 0) {
            WriteLog "  Space Consumed: $([math]::Round($DiskChange, 2)) GB"
        } elseif ($DiskChange -lt 0) {
            WriteLog "  Space Freed: $([math]::Round([Math]::Abs($DiskChange), 2)) GB"
        } else {
            WriteLog "  Net Change: 0 GB"
        }
        WriteLog ""
        
        # Display reboot requirement warning if applicable
        if ($Global:RepairResults.RebootRequired) {
            WriteLog "=========================================="
            WriteLog "⚠️  REBOOT REQUIRED TO FINALIZE REPAIRS"
            WriteLog "=========================================="
            WriteLog ""
            WriteLog "IMPORTANT: Component files are staged but NOT yet active"
            WriteLog ""
            WriteLog "WHAT TO DO:"
            WriteLog "  1. Schedule system restart during maintenance window"
            WriteLog "  2. Reboot will activate staged component files"
            WriteLog "  3. After reboot, repairs will be fully applied"
            WriteLog ""
            WriteLog "VERIFICATION AFTER REBOOT:"
            WriteLog "  Run: DISM /Online /Cleanup-Image /ScanHealth"
            WriteLog "  Expected: 'No component store corruption detected'"
            WriteLog ""
            WriteLog "AUTOMATION INTEGRATION:"
            WriteLog "  - SCCM/Intune: Can detect RebootRequired flag for scheduling"
            WriteLog "  - PowerShell DSC: Add PendingReboot configuration"
            WriteLog "  - Scripts: Check exit code and schedule restart"
            WriteLog ""
            WriteLog "=========================================="
            WriteLog ""
        }
        
        if ($ExitCode -eq 0) {
            $RebootNote = if ($Global:RepairResults.RebootRequired) { " (Reboot Required to Activate)" } else { "" }
            WriteLog "FINAL RESULT: All repair operations completed successfully$RebootNote"
            WriteLog "SYSTEM STATUS: Component Store and System Files are healthy"
            
            if ($Global:RepairResults.RebootRequired) {
                WriteLog "POST-ACTION: Schedule system restart to finalize component replacement"
            }
        } else {
            WriteLog "FINAL RESULT: Repair operations completed with warnings"
            WriteLog "SYSTEM STATUS: Review phase details above for specific issues"
        }
        
        WriteLog ""
        WriteLog "Log file saved: $LogFile"
        WriteLog "CBS.log location: C:\\Windows\\Logs\\CBS\\CBS.log (for detailed SFC results)"
        WriteLog "DISM.log location: C:\\Windows\\Logs\\DISM\\dism.log (for detailed DISM results)"
        
        # Export results to JSON for automation integration
        $JsonPath = Export-RepairResultsToJSON
        if ($JsonPath) {
            WriteLog "JSON results exported: $JsonPath"
        }
        
        WriteLog "#####################DISM + SFC Repair Process Ended#####################"
    }
    catch {
        WriteLog ""
        WriteLog "CRITICAL ERROR: $($_.Exception.Message)"
        WriteLog "Stack Trace: $($_.ScriptStackTrace)"
        $ExitCode = 1
        
        $ScriptEndTime = Get-Date
        $TotalDuration = $ScriptEndTime - $ScriptStartTime
        WriteLog "Process terminated after: $(Format-Duration $TotalDuration)"
        WriteLog "#####################DISM + SFC Repair Process Failed#####################"
    }
    
    return $ExitCode
}

# Script execution entry point
try {
    $FinalExitCode = Start-DISMRepair
    
    # Update JSON with final exit code
    if ($Global:RepairResults) {
        $JsonPath = "$ScriptPath\\$scriptNameOnly-Results.json"
        if (Test-Path $JsonPath) {
            $JsonData = Get-Content $JsonPath | ConvertFrom-Json
            $JsonData.ExitCode = $FinalExitCode
            $JsonData | ConvertTo-Json -Depth 5 | Out-File -FilePath $JsonPath -Encoding UTF8 -Force
        }
    }
    
    WriteLog ""
    WriteLog "Script execution completed with exit code: $FinalExitCode"
    WriteLog "Exit Code Legend: 0=Success, 1=Failure, 2=Partial Success, 3=Administrator Required"

    # Return proper exit code for monitoring systems
    if ($Host.Name -eq "ConsoleHost") {
        exit $FinalExitCode
    } else {
        WriteLog "Running in $($Host.Name) - Exit code: $FinalExitCode"
    }
}
catch {
    WriteLog ""
    WriteLog "Script execution failed: $($_.Exception.Message)"
    if ($Host.Name -eq "ConsoleHost") {
        exit 1
    }
}
#endregion
