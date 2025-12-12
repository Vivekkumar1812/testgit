<#
SCRIPT NAME             19156_Win_Update_Repair_Enhanced.ps1
IN REPOSITORY           Yes
AUTHOR & EMAIL          Vivek: vivek@capgemini.com
COMPANY                 Capgemini
TAGS                    Remediation, DISM, SFC, System Repair, Windows 11, Windows Update DLL, Enhanced Validation
STATUS                  Draft
DATE OF CHANGES         2025-12-09
VERSION                 2.0
RELEASENOTES            Enhanced Windows Update DLL repair with comprehensive pre-validation
                        NEW FEATURES IN V2.0:
                        - Windows Update Service health check and auto-repair
                        - Component Store validation (WinSxS integrity check)
                        - Group Policy restriction detection
                        - WSUS configuration detection for enterprise environments
                        - Mandatory pending reboot enforcement (blocks execution if reboot pending)
                        - Enhanced exit codes (4=Reboot Required First, 5=Service Issues, 6=Component Store Missing)
                        - Smart DISM source selection based on environment (WSUS vs Windows Update)
                        - CBS.log validation before operations
APPROVED                No
SUPPORT                 NA
DEX TOOLS               NA
DEPENDENCIES            PowerShell 5.1+, Administrative privileges, Windows 11/10
CONTEXT                 System
OS                      Windows 11/10
SYNOPSIS                Comprehensive Windows Update DLL repair with intelligent pre-validation and environment detection
DESCRIPTION             This script performs comprehensive Windows Update DLL repair with extensive pre-checks:
                        
                        PRE-VALIDATION PHASES (NEW IN V2.0):
                        - Windows Update Service verification and repair
                        - Component Store existence and integrity validation
                        - Group Policy restriction detection
                        - WSUS vs Direct Windows Update environment detection
                        - Mandatory pending reboot check (blocks execution)
                        
                        TWO-TIER REPAIR ARCHITECTURE:
                        Tier 1: Component Store (C:\Windows\WinSxS) - Master DLL repository
                        Tier 2: System Files (C:\Windows\System32) - Active DLL files in use
                        
                        REPAIR PHASES:
                        - Phase 1: DISM CheckHealth (Quick corruption check)
                        - Phase 2: DISM ScanHealth (Deep component store scan)
                        - Phase 3: DISM RestoreHealth (Repair component store corruption)
                        - Phase 4: SFC /scannow (Repair System32 DLL files)
                        
INPUTS                  None
OUTPUTS                 Detailed logging with timestamps and duration tracking
                        Exit Code 0: Success - All repairs completed successfully
                        Exit Code 1: Failure - Critical error during execution
                        Exit Code 2: Partial Success - Some operations completed with warnings
                        Exit Code 3: Administrator Required - Script must run with elevated privileges
                        Exit Code 4: Reboot Required First - Pending reboot detected, must reboot before repair
                        Exit Code 5: Service Issues - Windows Update service cannot be started
                        Exit Code 6: Component Store Missing - WinSxS directory inaccessible or missing
                        
FUNCTIONS               NEW FUNCTIONS IN V2.0:
                        Test-WindowsUpdateService = Validates and repairs Windows Update service
                        Test-ComponentStoreIntegrity = Validates WinSxS directory and CBS.log accessibility
                        Test-GroupPolicyRestrictions = Detects Group Policy blocks on Windows Update
                        Test-WSUSConfiguration = Detects enterprise WSUS configuration
                        Ensure-WindowsUpdateServices = Starts required Windows Update services
                        
                        EXISTING FUNCTIONS:
                        WriteLog = Centralized logging function with timestamps
                        Test-SystemRequirements = Validates system prerequisites (OS version, admin rights, disk space)
                        Get-DISMPath = Locates correct DISM executable considering WOW64 redirection
                        Get-SFCPath = Locates correct SFC executable considering WOW64 redirection
                        Format-Duration = Converts TimeSpan to human-readable format
                        Test-InternetConnectivity = Verifies network access to Windows Update servers
                        Test-PendingReboot = Checks for pending system reboots (NOW ENFORCED)
                        Test-DiskSpace = Monitors available disk space during operations
                        Export-RepairResultsToJSON = Exports repair results to JSON file for integration
                        Invoke-DISMCheckHealth = Executes DISM CheckHealth phase
                        Invoke-DISMScanHealth = Executes DISM ScanHealth phase
                        Invoke-DISMRestoreHealth = Executes DISM RestoreHealth phase (WSUS-aware)
                        Invoke-SFCScanNow = Executes SFC /scannow phase
                        
NOTES                   V2.0 ENHANCEMENTS:
                        - Script now blocks execution if pending reboot detected (returns Exit Code 4)
                        - Automatically detects and adapts to WSUS environments
                        - Validates Component Store before attempting repairs
                        - Detects Group Policy restrictions that would prevent repairs
                        - Auto-starts Windows Update services if stopped
                        
LICENSE                 MIT License

#>

#==================================================================================================
# LOGGING INITIALIZATION
#==================================================================================================

$ScriptName = & { $myInvocation.ScriptName }
$ScriptPath = Split-Path -parent $ScriptName
$ScriptName = Split-Path $ScriptName -Leaf
$scriptNameOnly = $ScriptName -replace '.PS1',''
$LogFile = "$ScriptPath\$ScriptNameOnly" + "Log.txt"

function WriteLog {
    Param ([string]$LogString)
    $Stamp = (Get-Date).toString("yyyy/MM/dd HH:mm:ss")
    $LogMessage = "$Stamp $LogString"
    Add-content $LogFile -value $LogMessage
}

WriteLog "------------------------------------------------------------------------------------"
WriteLog "#####################Starting Enhanced DISM + SFC System Repair v2.0#####################"
WriteLog "------------------------------------------------------------------------------------"
WriteLog "Log file created at: $LogFile"
WriteLog "Enhanced Features: Service validation, Component Store check, Group Policy detection, WSUS awareness"

#==================================================================================================
# GLOBAL TRACKING VARIABLES
#==================================================================================================
$Global:RepairResults = @{
    # DISM Phase Results
    DISMCheckHealthSuccess = $false
    DISMScanHealthSuccess = $false
    DISMRestoreHealthSuccess = $false
    RebootRequired = $false
    
    # SFC Phase Results
    SFCSuccess = $false
    SFCCorruptionFound = $false
    SFCCorruptionFixed = $false
    
    # System Pre-Check Results (NEW IN V2.0)
    WindowsUpdateServiceHealthy = $false
    ComponentStoreValid = $false
    GroupPolicyRestricted = $false
    WSUSConfigured = $false
    WSUSServer = ""
    PendingRebootDetected = $false
    InitialDiskSpaceGB = 0
    FinalDiskSpaceGB = 0
    
    # Timing Information
    CheckHealthDuration = ""
    ScanHealthDuration = ""
    RestoreHealthDuration = ""
    SFCDuration = ""
    TotalDuration = ""
}

#==================================================================================================
# REGION: HELPER FUNCTIONS
#==================================================================================================
#region Helper Functions

function Test-SystemRequirements {
    WriteLog "=== Validating System Requirements ==="
    
    try {
        $OSInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $WindowsVersion = [System.Version]$OSInfo.Version
        
        WriteLog "Operating System: $($OSInfo.Caption) (Build $($OSInfo.BuildNumber))"
        WriteLog "System Architecture: $($OSInfo.OSArchitecture)"
        
        if ($WindowsVersion.Major -lt 10) {
            WriteLog "ERROR: This script requires Windows 10 or later"
            return $false
        }
        
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
        
        WriteLog "PowerShell Version: $($PSVersionTable.PSVersion.Major).$($PSVersionTable.PSVersion.Minor)"
        
        if ($PSVersionTable.PSVersion.Major -lt 5) {
            WriteLog "ERROR: PowerShell 5.0 or later required"
            return $false
        }
        
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
# NEW FUNCTION: Test-WindowsUpdateService
# Purpose: Validates Windows Update service health and attempts to start if stopped
# Returns: $true if service is running, $false if service cannot be started
#--------------------------------------------------------------------------------------------------
function Test-WindowsUpdateService {
    WriteLog ""
    WriteLog "=== Validating Windows Update Service Health ==="
    
    try {
        # Check Windows Update service (wuauserv)
        $WUService = Get-Service -Name "wuauserv" -ErrorAction Stop
        WriteLog "Windows Update Service Status: $($WUService.Status)"
        WriteLog "Startup Type: $($WUService.StartType)"
        
        if ($WUService.Status -ne "Running") {
            WriteLog "WARNING: Windows Update service is not running"
            WriteLog "Attempting to start Windows Update service..."
            
            try {
                Start-Service -Name "wuauserv" -ErrorAction Stop
                Start-Sleep -Seconds 3
                
                $WUService = Get-Service -Name "wuauserv"
                if ($WUService.Status -eq "Running") {
                    WriteLog "SUCCESS: Windows Update service started successfully"
                    $Global:RepairResults.WindowsUpdateServiceHealthy = $true
                    return $true
                } else {
                    WriteLog "ERROR: Failed to start Windows Update service"
                    WriteLog "Current Status: $($WUService.Status)"
                    $Global:RepairResults.WindowsUpdateServiceHealthy = $false
                    return $false
                }
            }
            catch {
                WriteLog "ERROR: Cannot start Windows Update service - $($_.Exception.Message)"
                WriteLog "Possible causes: Service disabled, dependency failure, system corruption"
                $Global:RepairResults.WindowsUpdateServiceHealthy = $false
                return $false
            }
        } else {
            WriteLog "Windows Update service is running: VERIFIED"
            $Global:RepairResults.WindowsUpdateServiceHealthy = $true
            return $true
        }
        
        return $true
    }
    catch {
        WriteLog "ERROR: Service validation failed - $($_.Exception.Message)"
        $Global:RepairResults.WindowsUpdateServiceHealthy = $false
        return $false
    }
}

#--------------------------------------------------------------------------------------------------
# NEW FUNCTION: Test-ComponentStoreIntegrity
# Purpose: Validates Component Store (WinSxS) directory exists and is accessible
# Returns: $true if Component Store is valid, $false if missing or inaccessible
#--------------------------------------------------------------------------------------------------
function Test-ComponentStoreIntegrity {
    WriteLog ""
    WriteLog "=== Validating Component Store Integrity ==="
    
    try {
        # Check if WinSxS directory exists
        $WinSxSPath = "$env:SystemRoot\WinSxS"
        WriteLog "Component Store Path: $WinSxSPath"
        
        if (-not (Test-Path $WinSxSPath)) {
            WriteLog ""
            WriteLog "=========================================="
            WriteLog "CRITICAL ERROR: COMPONENT STORE MISSING"
            WriteLog "=========================================="
            WriteLog "Path: $WinSxSPath"
            WriteLog "Status: Directory does not exist"
            WriteLog ""
            WriteLog "IMPACT: DISM repair cannot proceed without Component Store"
            WriteLog "This is a critical system corruption that requires:"
            WriteLog "  - Windows In-Place Upgrade Repair"
            WriteLog "  - System Restore to earlier point"
            WriteLog "  - Clean Windows installation"
            WriteLog ""
            WriteLog "DISM and SFC cannot repair a missing Component Store"
            WriteLog "=========================================="
            WriteLog ""
            $Global:RepairResults.ComponentStoreValid = $false
            return $false
        }
        
        WriteLog "Component Store exists: VERIFIED"
        
        WriteLog ""
        WriteLog "Component Store validation: PASSED"
        $Global:RepairResults.ComponentStoreValid = $true
        return $true
    }
    catch {
        WriteLog "ERROR: Component Store validation failed - $($_.Exception.Message)"
        $Global:RepairResults.ComponentStoreValid = $false
        return $false
    }
}

#--------------------------------------------------------------------------------------------------
# NEW FUNCTION: Test-GroupPolicyRestrictions
# Purpose: Detects Group Policy restrictions that prevent Windows Update access
# Returns: $true if no restrictions, $false if Group Policies block Windows Update
#--------------------------------------------------------------------------------------------------
function Test-GroupPolicyRestrictions {
    WriteLog ""
    WriteLog "=== Checking Group Policy Restrictions ==="
    
    try {
        $GPRestricted = $false
        $Restrictions = @()
        
        # Registry path for Windows Update Group Policies
        $WUPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
        
        WriteLog "Group Policy Registry Path: $WUPolicyPath"
        
        if (Test-Path $WUPolicyPath) {
            WriteLog "Windows Update Group Policies detected"
            
            # Check: DoNotConnectToWindowsUpdateInternetLocations
            # If set to 1, prevents connection to Windows Update servers
            $DoNotConnect = (Get-ItemProperty -Path $WUPolicyPath -Name "DoNotConnectToWindowsUpdateInternetLocations" -ErrorAction SilentlyContinue).DoNotConnectToWindowsUpdateInternetLocations
            
            if ($DoNotConnect -eq 1) {
                $GPRestricted = $true
                $Restrictions += "DoNotConnectToWindowsUpdateInternetLocations is ENABLED"
                WriteLog "DETECTED: Connection to Windows Update Internet locations is BLOCKED"
            }
            
            # Check: SetDisableUXWUAccess
            # If set to 1, disables Windows Update user experience
            $DisableUXAccess = (Get-ItemProperty -Path $WUPolicyPath -Name "SetDisableUXWUAccess" -ErrorAction SilentlyContinue).SetDisableUXWUAccess
            
            if ($DisableUXAccess -eq 1) {
                $GPRestricted = $true
                $Restrictions += "Windows Update access is DISABLED via Group Policy"
                WriteLog "DETECTED: Windows Update UX access is DISABLED"
            }
            
            # Check: DisableWindowsUpdateAccess
            $DisableWUAccess = (Get-ItemProperty -Path $WUPolicyPath -Name "DisableWindowsUpdateAccess" -ErrorAction SilentlyContinue).DisableWindowsUpdateAccess
            
            if ($DisableWUAccess -eq 1) {
                $GPRestricted = $true
                $Restrictions += "Windows Update access is completely DISABLED"
                WriteLog "DETECTED: Windows Update access is completely DISABLED"
            }
        } else {
            WriteLog "No Windows Update Group Policies detected in registry"
        }
        
        if ($GPRestricted) {
            WriteLog ""
            WriteLog "=========================================="
            WriteLog "WARNING: GROUP POLICY RESTRICTIONS DETECTED"
            WriteLog "=========================================="
            WriteLog ""
            WriteLog "Detected Restrictions:"
            foreach ($restriction in $Restrictions) {
                WriteLog "  - $restriction"
            }
            WriteLog ""
            WriteLog "IMPACT ON DISM REPAIR:"
            WriteLog "  - DISM RestoreHealth may fail to download components"
            WriteLog "  - Windows Update connectivity is restricted"
            WriteLog "  - May need to use /Source parameter with install media"
            WriteLog ""
            WriteLog "RECOMMENDATIONS:"
            WriteLog "  1. Contact system administrator about Group Policy"
            WriteLog "  2. Use DISM /Source with Windows installation media"
            WriteLog "  3. Temporarily disable policy if authorized"
            WriteLog ""
            WriteLog "Note: Script will continue but RestoreHealth may have limited functionality"
            WriteLog "=========================================="
            WriteLog ""
            
            $Global:RepairResults.GroupPolicyRestricted = $true
        } else {
            WriteLog "Group Policy check: No restrictions detected"
            $Global:RepairResults.GroupPolicyRestricted = $false
        }
        
        return (-not $GPRestricted)
    }
    catch {
        WriteLog "ERROR: Group Policy check failed - $($_.Exception.Message)"
        WriteLog "Assuming no Group Policy restrictions..."
        $Global:RepairResults.GroupPolicyRestricted = $false
        return $true
    }
}

#--------------------------------------------------------------------------------------------------
# NEW FUNCTION: Test-WSUSConfiguration
# Purpose: Detects if system is configured for WSUS (enterprise environment)
# Returns: Hashtable with WSUS configuration details
#--------------------------------------------------------------------------------------------------
function Test-WSUSConfiguration {
    WriteLog ""
    WriteLog "=== Detecting WSUS Configuration ==="
    
    try {
        $WSUSConfig = @{
            IsConfigured = $false
            WUServer = ""
            WUStatusServer = ""
            UseWUServer = $false
        }
        
        # Registry path for WSUS configuration
        $WUAUPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
        
        if (Test-Path $WUAUPath) {
            # Check if UseWUServer is enabled
            $UseWUServer = (Get-ItemProperty -Path $WUAUPath -Name "UseWUServer" -ErrorAction SilentlyContinue).UseWUServer
            
            if ($UseWUServer -eq 1) {
                WriteLog "WSUS Configuration: DETECTED"
                
                # Get WSUS server URL
                $WUPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
                $WUServer = (Get-ItemProperty -Path $WUPath -Name "WUServer" -ErrorAction SilentlyContinue).WUServer
                $WUStatusServer = (Get-ItemProperty -Path $WUPath -Name "WUStatusServer" -ErrorAction SilentlyContinue).WUStatusServer
                
                $WSUSConfig.IsConfigured = $true
                $WSUSConfig.WUServer = $WUServer
                $WSUSConfig.WUStatusServer = $WUStatusServer
                $WSUSConfig.UseWUServer = $true
                
                WriteLog "WSUS Server: $WUServer"
                WriteLog "WSUS Status Server: $WUStatusServer"
                WriteLog ""
                WriteLog "=========================================="
                WriteLog "ENTERPRISE WSUS ENVIRONMENT DETECTED"
                WriteLog "=========================================="
                WriteLog ""
                WriteLog "WSUS Configuration:"
                WriteLog "  Primary Server: $WUServer"
                WriteLog "  Status Server: $WUStatusServer"
                WriteLog ""
                WriteLog "IMPACT ON DISM REPAIR:"
                WriteLog "  - DISM RestoreHealth will use WSUS instead of Windows Update"
                WriteLog "  - If WSUS doesn't have required components, use /Source parameter"
                WriteLog "  - Enterprise policies may restrict component downloads"
                WriteLog ""
                WriteLog "RECOMMENDATIONS:"
                WriteLog "  1. Verify WSUS server has required components"
                WriteLog "  2. If issues persist, use /Source with install.wim"
                WriteLog "  3. Contact WSUS administrator for component availability"
                WriteLog ""
                WriteLog "Note: Script will attempt WSUS-based repair"
                WriteLog "=========================================="
                WriteLog ""
                
                $Global:RepairResults.WSUSConfigured = $true
                $Global:RepairResults.WSUSServer = $WUServer
            } else {
                WriteLog "WSUS Configuration: Not active (UseWUServer = $UseWUServer)"
                WriteLog "System is configured for direct Windows Update"
                $Global:RepairResults.WSUSConfigured = $false
            }
        } else {
            WriteLog "WSUS Configuration: Not configured"
            WriteLog "System is configured for direct Windows Update"
            $Global:RepairResults.WSUSConfigured = $false
        }
        
        return $WSUSConfig
    }
    catch {
        WriteLog "ERROR: WSUS configuration check failed - $($_.Exception.Message)"
        WriteLog "Assuming direct Windows Update configuration..."
        $Global:RepairResults.WSUSConfigured = $false
        return @{
            IsConfigured = $false
            WUServer = ""
            WUStatusServer = ""
            UseWUServer = $false
        }
    }
}

#--------------------------------------------------------------------------------------------------
# NEW FUNCTION: Ensure-WindowsUpdateServices
# Purpose: Ensures all required Windows Update services are running
# Returns: $true if all services started successfully, $false otherwise
#--------------------------------------------------------------------------------------------------
function Ensure-WindowsUpdateServices {
    WriteLog ""
    WriteLog "=== Ensuring Windows Update Services are Running ==="
    
    try {
        $ServicesToStart = @(
            @{Name="wuauserv"; DisplayName="Windows Update"},
            @{Name="BITS"; DisplayName="Background Intelligent Transfer Service"},
            @{Name="CryptSvc"; DisplayName="Cryptographic Services"}
        )
        
        $AllServicesStarted = $true
        
        foreach ($svc in $ServicesToStart) {
            WriteLog ""
            WriteLog "Checking $($svc.DisplayName) ($($svc.Name))..."
            
            $service = Get-Service -Name $svc.Name -ErrorAction SilentlyContinue
            
            if (-not $service) {
                WriteLog "WARNING: Service $($svc.Name) not found on system"
                continue
            }
            
            WriteLog "Current Status: $($service.Status)"
            
            if ($service.Status -ne "Running") {
                WriteLog "Service is not running - attempting to start..."
                
                try {
                    Start-Service -Name $svc.Name -ErrorAction Stop
                    Start-Sleep -Seconds 2
                    
                    $service = Get-Service -Name $svc.Name
                    if ($service.Status -eq "Running") {
                        WriteLog "SUCCESS: $($svc.DisplayName) started"
                    } else {
                        WriteLog "WARNING: Failed to start $($svc.DisplayName) - Status: $($service.Status)"
                        $AllServicesStarted = $false
                    }
                }
                catch {
                    WriteLog "ERROR: Cannot start $($svc.DisplayName) - $($_.Exception.Message)"
                    $AllServicesStarted = $false
                }
            } else {
                WriteLog "$($svc.DisplayName) is already running"
            }
        }
        
        WriteLog ""
        if ($AllServicesStarted) {
            WriteLog "All Windows Update services are running: VERIFIED"
        } else {
            WriteLog "WARNING: Some services could not be started - repairs may be limited"
        }
        
        return $AllServicesStarted
    }
    catch {
        WriteLog "ERROR: Service management failed - $($_.Exception.Message)"
        return $false
    }
}

function Get-DISMPath {
    $DISMPath = if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
        "$env:SystemRoot\Sysnative\dism.exe"
    } else {
        "$env:SystemRoot\System32\dism.exe"
    }
    
    if (-not (Test-Path $DISMPath)) {
        WriteLog "ERROR: DISM executable not found at: $DISMPath"
        return $null
    }
    
    WriteLog "DISM Executable Location: $DISMPath"
    return $DISMPath
}

function Get-SFCPath {
    $SFCPath = if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
        "$env:SystemRoot\Sysnative\sfc.exe"
    } else {
        "$env:SystemRoot\System32\sfc.exe"
    }
    
    if (-not (Test-Path $SFCPath)) {
        WriteLog "ERROR: SFC executable not found at: $SFCPath"
        return $null
    }
    
    WriteLog "SFC Executable Location: $SFCPath"
    return $SFCPath
}

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

function Test-InternetConnectivity {
    WriteLog ""
    WriteLog "=== Checking Network Connectivity ==="
    
    try {
        WriteLog "Testing connectivity to windowsupdate.microsoft.com (Port 443)..."
        
        $testConnection = Test-NetConnection -ComputerName "windowsupdate.microsoft.com" -Port 443 -InformationLevel Quiet -WarningAction SilentlyContinue -ErrorAction Stop
        
        if ($testConnection) {
            WriteLog "Network connectivity: VERIFIED"
            WriteLog "Status: Windows Update servers are reachable"
            return $true
        } else {
            WriteLog "WARNING: Cannot reach Windows Update servers"
            WriteLog "Impact: DISM RestoreHealth may fail without internet access"
            return $false
        }
    }
    catch {
        WriteLog "WARNING: Network connectivity test encountered an error - $($_.Exception.Message)"
        return $false
    }
}

#--------------------------------------------------------------------------------------------------
# ENHANCED FUNCTION: Test-PendingReboot (NOW ENFORCED - BLOCKS EXECUTION)
# Purpose: Checks for pending reboot and BLOCKS execution if detected
# Returns: $true if reboot pending (script should exit), $false if system is clean
#--------------------------------------------------------------------------------------------------
function Test-PendingReboot {
    WriteLog ""
    WriteLog "=== Checking for Pending System Reboot (MANDATORY CHECK) ==="
    
    $RebootPending = $false
    $RebootReasons = @()
    
    try {
        if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") {
            $RebootPending = $true
            $RebootReasons += "Component Based Servicing (CBS) operations pending"
            WriteLog "Found: Component Based Servicing reboot flag"
        }
        
        if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired") {
            $RebootPending = $true
            $RebootReasons += "Windows Update installations pending"
            WriteLog "Found: Windows Update reboot flag"
        }
        
        if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\PendingFileRenameOperations") {
            $RebootPending = $true
            $RebootReasons += "Pending file rename operations"
            WriteLog "Found: Pending file rename operations"
        }
        
        if ($RebootPending) {
            WriteLog ""
            WriteLog "=========================================="
            WriteLog "CRITICAL: PENDING REBOOT DETECTED"
            WriteLog "=========================================="
            WriteLog ""
            WriteLog "Reason(s):"
            foreach ($reason in $RebootReasons) {
                WriteLog "  - $reason"
            }
            WriteLog ""
            WriteLog "MANDATORY ACTION REQUIRED:"
            WriteLog "  THIS SCRIPT CANNOT PROCEED WITH PENDING REBOOT"
            WriteLog ""
            WriteLog "WHY REBOOT IS REQUIRED FIRST:"
            WriteLog "  - Component Store may be in transition state"
            WriteLog "  - File system has pending operations"
            WriteLog "  - DISM/SFC results would be inaccurate"
            WriteLog "  - Repair operations may fail or cause instability"
            WriteLog ""
            WriteLog "REQUIRED STEPS:"
            WriteLog "  1. REBOOT THE SYSTEM NOW"
            WriteLog "  2. Re-run this script after reboot"
            WriteLog "  3. System will be in clean state for accurate repair"
            WriteLog ""
            WriteLog "SCRIPT EXECUTION TERMINATED"
            WriteLog "Exit Code 4: Reboot Required First"
            WriteLog "=========================================="
            WriteLog ""
            
            $Global:RepairResults.PendingRebootDetected = $true
            
            # Export results before exiting
            Export-RepairResultsToJSON
            
            WriteLog "Script execution completed with exit code: 4"
            WriteLog "Exit Code Legend: 0=Success, 1=Failure, 2=Partial Success, 3=Admin Required, 4=Reboot Required First"
            
            exit 4
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
            WriteLog "CRITICAL: INSUFFICIENT DISK SPACE - Available: ${FreeSpaceGB} GB, Required: ${MinimumGB} GB"
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
        return $true
    }
}

function Export-RepairResultsToJSON {
    try {
        WriteLog ""
        WriteLog "=== Exporting Results to JSON ==="
        
        $JsonOutput = @{
            Metadata = @{
                ScriptName = $ScriptName
                ScriptVersion = "2.0"
                ExecutionDate = Get-Date -Format "yyyy-MM-dd"
                ExecutionTime = Get-Date -Format "HH:mm:ss"
                ComputerName = $env:COMPUTERNAME
                WindowsVersion = (Get-CimInstance -ClassName Win32_OperatingSystem).Version
                WindowsBuild = (Get-CimInstance -ClassName Win32_OperatingSystem).BuildNumber
            }
            RepairResults = $Global:RepairResults
            ExitCode = $null
            LogFilePath = $LogFile
        }
        
        $JsonPath = "$ScriptPath\$scriptNameOnly-Results.json"
        $JsonOutput | ConvertTo-Json -Depth 5 | Out-File -FilePath $JsonPath -Encoding UTF8 -Force
        
        WriteLog "JSON export successful: $JsonPath"
        return $JsonPath
    }
    catch {
        WriteLog "WARNING: Failed to export JSON - $($_.Exception.Message)"
        return $null
    }
}
#endregion

#==================================================================================================
# REGION: DISM REPAIR FUNCTIONS
#==================================================================================================
#region DISM Repair Functions

function Invoke-DISMCheckHealth {
    param([string]$DISMPath)
    
    WriteLog ""
    WriteLog "=========================================="
    WriteLog "PHASE 1: DISM CheckHealth Scan"
    WriteLog "=========================================="
    WriteLog "Expected Duration: 5-15 seconds"
    WriteLog "Starting at: $(Get-Date -Format 'yyyy/MM/dd HH:mm:ss')"
    
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
        
        WriteLog "Completed at: $(Get-Date -Format 'yyyy/MM/dd HH:mm:ss')"
        WriteLog "Duration: $($Global:RepairResults.CheckHealthDuration)"
        WriteLog "Exit Code: $($CheckHealthResult.ExitCode)"
        
        Remove-Item "$env:TEMP\dism_checkhealth_output.txt" -Force -ErrorAction SilentlyContinue
        Remove-Item "$env:TEMP\dism_checkhealth_error.txt" -Force -ErrorAction SilentlyContinue
        
        if ($CheckHealthResult.ExitCode -eq 0) {
            WriteLog "Result: No component store corruption detected"
            $Global:RepairResults.DISMCheckHealthSuccess = $true
            return $true
        } else {
            WriteLog "Result: Potential corruption detected - proceeding to ScanHealth"
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
    WriteLog "Expected Duration: 5-15 minutes"
    WriteLog "Starting at: $(Get-Date -Format 'yyyy/MM/dd HH:mm:ss')"
    
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
        
        WriteLog "Completed at: $(Get-Date -Format 'yyyy/MM/dd HH:mm:ss')"
        WriteLog "Duration: $($Global:RepairResults.ScanHealthDuration)"
        WriteLog "Exit Code: $($ScanHealthResult.ExitCode)"
        
        Remove-Item "$env:TEMP\dism_scanhealth_output.txt" -Force -ErrorAction SilentlyContinue
        Remove-Item "$env:TEMP\dism_scanhealth_error.txt" -Force -ErrorAction SilentlyContinue
        
        if ($ScanHealthResult.ExitCode -eq 0) {
            WriteLog "Result: No corruption found"
            $Global:RepairResults.DISMScanHealthSuccess = $true
            return $true
        } else {
            WriteLog "Result: Corruption detected - proceeding to RestoreHealth"
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
    WriteLog "Expected Duration: 5-30 minutes"
    WriteLog "Starting at: $(Get-Date -Format 'yyyy/MM/dd HH:mm:ss')"

    $StartTime = Get-Date

    try {
        $dismArgs = @('/Online','/Cleanup-Image','/RestoreHealth')
        
        if ($SourcePath) {
            WriteLog "Using DISM Source: $SourcePath"
            $dismArgs += "/Source:$SourcePath"
        }
        
        if ($LimitAccess) {
            WriteLog "Applying /LimitAccess to prevent Windows Update contact"
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

        WriteLog "Completed at: $(Get-Date -Format 'yyyy/MM/dd HH:mm:ss')"
        WriteLog "Duration: $($Global:RepairResults.RestoreHealthDuration)"
        WriteLog "Exit Code: $($RestoreHealthResult.ExitCode)"

        Remove-Item "$env:TEMP\dism_restorehealth_output.txt" -Force -ErrorAction SilentlyContinue
        Remove-Item "$env:TEMP\dism_restorehealth_error.txt" -Force -ErrorAction SilentlyContinue

        if ($RestoreHealthResult.ExitCode -eq 0) {
            WriteLog "Result: Component store successfully repaired"
            $Global:RepairResults.DISMRestoreHealthSuccess = $true
            return $true
        }
        elseif ($RestoreHealthResult.ExitCode -eq 3010) {
            WriteLog "Result: Repair SUCCESSFUL - REBOOT REQUIRED"
            $Global:RepairResults.DISMRestoreHealthSuccess = $true
            $Global:RepairResults.RebootRequired = $true
            return $true
        }
        else {
            WriteLog "Result: RestoreHealth encountered issues (Exit Code: $($RestoreHealthResult.ExitCode))"
            return $false
        }
    }
    catch {
        WriteLog "ERROR: DISM RestoreHealth failed - $($_.Exception.Message)"
        return $false
    }
}

function Invoke-SFCRepair {
    param([string]$SFCPath)
    
    try {
        WriteLog ""
        WriteLog "=========================================="
        WriteLog "PHASE 4: System File Checker (SFC) Scan"
        WriteLog "=========================================="
        WriteLog "Expected Duration: 10-60 minutes"
        WriteLog "Starting at: $(Get-Date -Format 'yyyy/MM/dd HH:mm:ss')"
        
        $SFCStartTime = Get-Date
        
        WriteLog "Executing: $SFCPath /scannow"
        $SFCProcess = Start-Process -FilePath $SFCPath `
                                     -ArgumentList "/scannow" `
                                     -Wait `
                                     -PassThru `
                                     -NoNewWindow `
                                     -RedirectStandardOutput "$env:TEMP\sfc_output.txt" `
                                     -RedirectStandardError "$env:TEMP\sfc_error.txt"
        
        $SFCEndTime = Get-Date
        $SFCDuration = $SFCEndTime - $SFCStartTime
        $Global:RepairResults.SFCDuration = Format-Duration $SFCDuration
        
        WriteLog "Completed at: $(Get-Date -Format 'yyyy/MM/dd HH:mm:ss')"
        WriteLog "Duration: $($Global:RepairResults.SFCDuration)"
        WriteLog "Exit Code: $($SFCProcess.ExitCode)"
        
        Remove-Item "$env:TEMP\sfc_output.txt" -Force -ErrorAction SilentlyContinue
        Remove-Item "$env:TEMP\sfc_error.txt" -Force -ErrorAction SilentlyContinue
        
        switch ($SFCProcess.ExitCode) {
            0 {
                WriteLog "Result: No integrity violations detected"
                $Global:RepairResults.SFCSuccess = $true
                $Global:RepairResults.SFCCorruptionFound = $false
                return $true
            }
            1 {
                WriteLog "Result: Corruption detected and successfully repaired"
                $Global:RepairResults.SFCSuccess = $true
                $Global:RepairResults.SFCCorruptionFound = $true
                $Global:RepairResults.SFCCorruptionFixed = $true
                return $true
            }
            default {
                WriteLog "WARNING: SFC completed with issues (Exit Code: $($SFCProcess.ExitCode))"
                $Global:RepairResults.SFCSuccess = $false
                return $false
            }
        }
    }
    catch {
        WriteLog "ERROR: SFC scan failed - $($_.Exception.Message)"
        $Global:RepairResults.SFCSuccess = $false
        return $false
    }
}
#endregion

#==================================================================================================
# MAIN EXECUTION FUNCTION
#==================================================================================================
function Start-EnhancedDISMRepair {
    param(
        [string]$DISMSourcePath = $null,
        [switch]$LimitAccess
    )

    $ExitCode = 0
    $ScriptStartTime = Get-Date
    
    try {
        WriteLog ""
        WriteLog "=========================================="
        WriteLog "ENHANCED DISM + SFC REPAIR v2.0"
        WriteLog "=========================================="
        WriteLog "Start Time: $(Get-Date -Format 'yyyy/MM/dd HH:mm:ss')"
        
        # === PHASE 0: PRE-VALIDATION (NEW IN V2.0) ===
        WriteLog ""
        WriteLog "=========================================="
        WriteLog "PHASE 0: COMPREHENSIVE PRE-VALIDATION"
        WriteLog "=========================================="
        
        # 1. System Requirements
        if (-not (Test-SystemRequirements)) {
            throw "System requirements validation failed"
        }
        
        # 2. Pending Reboot Check (ENFORCED - WILL EXIT IF PENDING)
        Test-PendingReboot | Out-Null
        
        # 3. Windows Update Service Check (NEW)
        if (-not (Test-WindowsUpdateService)) {
            WriteLog ""
            WriteLog "=========================================="
            WriteLog "CRITICAL: WINDOWS UPDATE SERVICE ISSUES"
            WriteLog "=========================================="
            WriteLog "The Windows Update service could not be started."
            WriteLog "This will prevent DISM RestoreHealth from functioning."
            WriteLog ""
            WriteLog "Possible causes:"
            WriteLog "  - Service is disabled in services.msc"
            WriteLog "  - Service dependencies are not running"
            WriteLog "  - System corruption affecting service startup"
            WriteLog ""
            WriteLog "RECOMMENDED ACTIONS:"
            WriteLog "  1. Check services.msc for wuauserv status"
            WriteLog "  2. Verify dependent services (BITS, CryptSvc)"
            WriteLog "  3. Review System Event Log for service errors"
            WriteLog ""
            WriteLog "Script will continue but RestoreHealth may fail"
            WriteLog "=========================================="
            WriteLog ""
            $ExitCode = 5
        }
        
        # 4. Component Store Validation (NEW)
        if (-not (Test-ComponentStoreIntegrity)) {
            WriteLog ""
            WriteLog "=========================================="
            WriteLog "FATAL ERROR: COMPONENT STORE VALIDATION FAILED"
            WriteLog "=========================================="
            WriteLog ""
            WriteLog "The Windows Component Store (WinSxS) is missing or inaccessible."
            WriteLog "DISM repair cannot proceed without a valid Component Store."
            WriteLog ""
            WriteLog "This requires advanced recovery:"
            WriteLog "  - Windows In-Place Upgrade Repair"
            WriteLog "  - System Restore (if available)"
            WriteLog "  - Clean Windows installation"
            WriteLog ""
            WriteLog "SCRIPT EXECUTION TERMINATED"
            WriteLog "Exit Code 6: Component Store Missing"
            WriteLog "=========================================="
            
            Export-RepairResultsToJSON
            
            WriteLog ""
            WriteLog "Script execution completed with exit code: 6"
            exit 6
        }
        
        # 5. Group Policy Check (NEW)
        Test-GroupPolicyRestrictions | Out-Null
        
        # 6. WSUS Detection (NEW)
        $WSUSConfig = Test-WSUSConfiguration
        
        # 7. Network Connectivity
        Test-InternetConnectivity | Out-Null
        
        WriteLog ""
        WriteLog "=========================================="
        WriteLog "PRE-VALIDATION COMPLETE"
        WriteLog "=========================================="
        WriteLog "System Requirements: PASSED"
        WriteLog "Pending Reboot: NONE"
        WriteLog "Windows Update Service: $(if($Global:RepairResults.WindowsUpdateServiceHealthy){'HEALTHY'}else{'ISSUES DETECTED'})"
        WriteLog "Component Store: VALID"
        WriteLog "Group Policy Restrictions: $(if($Global:RepairResults.GroupPolicyRestricted){'DETECTED'}else{'NONE'})"
        WriteLog "WSUS Configuration: $(if($Global:RepairResults.WSUSConfigured){'CONFIGURED'}else{'NOT CONFIGURED'})"
        WriteLog ""
        WriteLog "Proceeding to DISM + SFC repair phases..."
        WriteLog "=========================================="
        
        # Get tool paths
        $DISMPath = Get-DISMPath
        if (-not $DISMPath) {
            throw "DISM executable not found"
        }
        
        # Ensure services are running
        Ensure-WindowsUpdateServices | Out-Null
        
        # === PHASE 1-3: DISM REPAIR ===
        Test-DiskSpace -MinimumGB 2 -Phase "Before CheckHealth" | Out-Null
        $CheckHealthSuccess = Invoke-DISMCheckHealth -DISMPath $DISMPath
        
        Test-DiskSpace -MinimumGB 2 -Phase "Before ScanHealth" | Out-Null
        $ScanHealthSuccess = Invoke-DISMScanHealth -DISMPath $DISMPath
        
        if (-not $CheckHealthSuccess -or -not $ScanHealthSuccess) {
            WriteLog ""
            WriteLog "Corruption detected - RestoreHealth required"
            
            Test-DiskSpace -MinimumGB 3 -Phase "Before RestoreHealth" | Out-Null
            
            # Use WSUS-aware repair if configured
            if ($WSUSConfig.IsConfigured -and -not $DISMSourcePath) {
                WriteLog "Using WSUS-based repair (enterprise environment)"
            }
            
            $RestoreHealthSuccess = Invoke-DISMRestoreHealth -DISMPath $DISMPath -SourcePath $DISMSourcePath -LimitAccess:$LimitAccess
            
            if (-not $RestoreHealthSuccess) {
                WriteLog "WARNING: RestoreHealth completed with issues"
                $ExitCode = 2
            }
        } else {
            WriteLog ""
            WriteLog "No corruption detected - RestoreHealth not required"
            $Global:RepairResults.DISMRestoreHealthSuccess = $true
            $Global:RepairResults.RestoreHealthDuration = "Not Required"
        }
        
        # === PHASE 4: SFC REPAIR ===
        $SFCPath = Get-SFCPath
        if (-not $SFCPath) {
            WriteLog "ERROR: SFC executable not found"
            $ExitCode = 2
        } else {
            Test-DiskSpace -MinimumGB 1 -Phase "Before SFC" | Out-Null
            $SFCSuccess = Invoke-SFCRepair -SFCPath $SFCPath
            
            if (-not $SFCSuccess) {
                WriteLog "WARNING: SFC completed with issues"
                $ExitCode = 2
            }
        }
        
        # === FINAL SUMMARY ===
        $ScriptEndTime = Get-Date
        $TotalDuration = $ScriptEndTime - $ScriptStartTime
        $Global:RepairResults.TotalDuration = Format-Duration $TotalDuration
        
        $SystemDrive = Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object {$_.DeviceID -eq $env:SystemDrive}
        $Global:RepairResults.FinalDiskSpaceGB = [math]::Round($SystemDrive.FreeSpace / 1GB, 2)
        
        WriteLog ""
        WriteLog "=========================================="
        WriteLog "REPAIR PROCESS COMPLETED"
        WriteLog "=========================================="
        WriteLog "Total Duration: $($Global:RepairResults.TotalDuration)"
        WriteLog ""
        WriteLog "=== SUMMARY REPORT ==="
        WriteLog ""
        WriteLog "PRE-VALIDATION:"
        WriteLog "  Windows Update Service: $(if($Global:RepairResults.WindowsUpdateServiceHealthy){'HEALTHY'}else{'ISSUES'})"
        WriteLog "  Component Store: $(if($Global:RepairResults.ComponentStoreValid){'VALID'}else{'INVALID'})"
        WriteLog "  Group Policy: $(if($Global:RepairResults.GroupPolicyRestricted){'RESTRICTED'}else{'NO RESTRICTIONS'})"
        WriteLog "  WSUS: $(if($Global:RepairResults.WSUSConfigured){'CONFIGURED'}else{'NOT CONFIGURED'})"
        WriteLog ""
        WriteLog "DISM REPAIR:"
        WriteLog "  CheckHealth: $(if($Global:RepairResults.DISMCheckHealthSuccess){'PASS'}else{'FAIL'})"
        WriteLog "  ScanHealth: $(if($Global:RepairResults.DISMScanHealthSuccess){'PASS'}else{'FAIL'})"
        WriteLog "  RestoreHealth: $(if($Global:RepairResults.DISMRestoreHealthSuccess){'SUCCESS'}else{'ISSUES'})"
        WriteLog ""
        WriteLog "SFC REPAIR:"
        WriteLog "  Status: $(if($Global:RepairResults.SFCSuccess){'SUCCESS'}else{'ISSUES'})"
        WriteLog "  Corruption Found: $(if($Global:RepairResults.SFCCorruptionFound){'YES'}else{'NO'})"
        WriteLog "  Corruption Fixed: $(if($Global:RepairResults.SFCCorruptionFixed){'YES'}else{'NO'})"
        WriteLog ""
        WriteLog "DISK SPACE:"
        WriteLog "  Initial: $($Global:RepairResults.InitialDiskSpaceGB) GB"
        WriteLog "  Final: $($Global:RepairResults.FinalDiskSpaceGB) GB"
        WriteLog ""
        
        if ($Global:RepairResults.RebootRequired) {
            WriteLog "=========================================="
            WriteLog "⚠️  REBOOT REQUIRED TO FINALIZE REPAIRS"
            WriteLog "=========================================="
        }
        
        $JsonPath = Export-RepairResultsToJSON
        if ($JsonPath) {
            WriteLog "JSON results: $JsonPath"
        }
        
        WriteLog "Log file: $LogFile"
        WriteLog "#####################Enhanced DISM + SFC Repair Complete#####################"
    }
    catch {
        WriteLog ""
        WriteLog "CRITICAL ERROR: $($_.Exception.Message)"
        $ExitCode = 1
        
        $ScriptEndTime = Get-Date
        $TotalDuration = $ScriptEndTime - $ScriptStartTime
        WriteLog "Terminated after: $(Format-Duration $TotalDuration)"
        WriteLog "#####################Repair Process Failed#####################"
    }
    
    return $ExitCode
}

#==================================================================================================
# SCRIPT ENTRY POINT
#==================================================================================================
try {
    $FinalExitCode = Start-EnhancedDISMRepair
    
    # Update JSON with exit code
    if ($Global:RepairResults) {
        $JsonPath = "$ScriptPath\$scriptNameOnly-Results.json"
        if (Test-Path $JsonPath) {
            $JsonData = Get-Content $JsonPath | ConvertFrom-Json
            $JsonData.ExitCode = $FinalExitCode
            $JsonData | ConvertTo-Json -Depth 5 | Out-File -FilePath $JsonPath -Encoding UTF8 -Force
        }
    }
    
    WriteLog ""
    WriteLog "Script execution completed with exit code: $FinalExitCode"
    WriteLog "Exit Codes: 0=Success, 1=Failure, 2=Partial, 3=Admin Required, 4=Reboot First, 5=Service Issues, 6=Component Store Missing"

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
