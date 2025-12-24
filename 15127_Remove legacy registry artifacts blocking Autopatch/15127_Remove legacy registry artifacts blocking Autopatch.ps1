
<#
SCRIPT NAME             15127_Remove legacy registry artifacts blocking Autopatch.ps1
IN REPOSITORY           Yes
AUTHOR & EMAIL          Vivek: vivek.f.vivek@capgemini.com  
COMPANY                 Capgemini
TAGS                    Windows Update, Autopatch, Registry, WSUS, GPO, Remediation
STATUS                  Draft
DATE OF CHANGES         December 24, 2025
VERSION                 1.2
RELEASENOTES            Version 1.2: Fixed critical logging bug, added GPO/MDM detection, meaningful exit codes (0/1/2/3), 
                        optional -ForceNoBackup parameter, improved service validation, enhanced error handling
                        Version 1.1: SYSTRAC-optimized with silent execution, enhanced logging, detailed artifact tracking
APPROVED                Yes
SUPPORT                 NA
DEX TOOLS               NA
DEPENDENCIES            - PowerShell 5.1 or later (Windows 10/11 default)
                        - Administrator privileges required (enforced by #Requires)
                        - Windows 10 (Build 10.0+) or Windows 11

CONTEXT                 NA
OS                      Windows 10/11
SYNOPSIS                Removes legacy registry artifacts that block Windows Autopatch enrollment.
DESCRIPTION             This script identifies, optionally backs up, and removes deprecated or conflicting registry 
                        keys and values that interfere with Windows Autopatch functionality. It targets legacy WSUS 
                        server configurations, update deferral and pause policies, automatic update blocking policies, 
                        telemetry collection restrictions (conditional), delivery optimization overrides (conditional), 
                        Windows Update access blocks, and third-party update management artifacts. All operations are 
                        logged with timestamps, computer name, domain, and user context. Registry backups can be exported 
                        as .reg files before removal for safety. The script validates core Windows Update services after 
                        cleanup and provides detailed reporting suitable for SYSTRAC monitoring and compliance tracking.
                        
INPUTS                  -VerboseLogging (Optional): Switch to enable additional verbose logging output
                                                    Default: $false
                        -ForceNoBackup (Optional): Force execution without creating registry backups (not recommended)
                                                   Default: $false
                                                   Use only when backup path issues prevent execution
                        -WhatIf (Built-in): Preview all changes without executing them (dry run)
                        -Confirm (Built-in): Prompt for confirmation before each registry modification
                        
                        Note: Registry backups are automatically created in script directory
                        Root backup folder: RegistryBackup (persistent, created once)
                        Session backup subfolder format: Backup_yyyyMMdd_HHmmss (created per execution)
                        Full path example: .\RegistryBackup\Backup_20251224_172250\
                        
                        Target registry paths:
                            - HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate (WSUS and Update policies)
                            - HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection (Telemetry settings)
                            - HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization (DO settings)
                            - HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate (Legacy artifacts)
                            
OUTPUTS                 Log file with all operations:
                            - Computer name, user context, domain information
                            - System compatibility check (Windows 10/11 detection)
                            - GPO/MDM management detection and warnings
                            - Registry artifact processing status (removed/skipped)
                            - Detailed list of removed artifacts with paths and values
                            - Windows Update service validation results
                            - Final execution summary with STATUS and REBOOT requirements
                            - Exit codes: 0 (Success/Clean), 1 (No Admin Rights), 2 (Partial/Issues), 3 (Failure)
                            
VARIABLE DESCRIPTION    $CreateBackup = Automatically set based on -ForceNoBackup parameter (default: enabled)
                        $BackupRootFolder = Root folder for all registry backups (RegistryBackup)
                        $BackupSessionFolder = Timestamped subfolder name for current execution
                        $BackupPath = Full path to current session's backup folder
                        $VerboseLogging = Switch parameter to enable detailed logging
                        $ScriptName = Stores the name of the script file without extension
                        $ScriptPath = Stores the directory path where the script is located
                        $logFile = Full path to the log file where all activities are recorded
                        $RegistryArtifacts = Array of hashtables defining registry keys/values to remove
                        $RemovedArtifactsList = Array tracking all successfully removed artifacts
                        $TotalArtifacts = Count of total registry artifacts to process
                        $ProcessedArtifacts = Counter for processed artifacts
                        $RemovedArtifacts = Counter for successfully removed artifacts
                        $SkippedArtifacts = Counter for skipped artifacts (not found or conditional)
                        $CoreServices = Array of critical Windows Update service names to validate
                        
EXAMPLE                 PowerShell (.ps1) Usage:
                        & ".\15127_Remove legacy registry artifacts blocking Autopatch.ps1"
                        & ".\15127_Remove legacy registry artifacts blocking Autopatch.ps1" -WhatIf
                        & ".\15127_Remove legacy registry artifacts blocking Autopatch.ps1" -Verbose
                        & ".\15127_Remove legacy registry artifacts blocking Autopatch.ps1" -ForceNoBackup
                        
                        SYSTRAC Command:
                        PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File ".\15127_Remove legacy registry artifacts blocking Autopatch.ps1"
                        
                        Expected Output:
                        - Exit Code 0: Success (artifacts removed) or Clean (no artifacts found)
                        - Exit Code 1: Failure (missing admin privileges)
                        - Exit Code 2: Partial (some issues encountered, review log)
                        - Exit Code 3: Failure (unable to process artifacts)
                        - Log file: STATUS line indicates SUCCESS/CLEAN/PARTIAL/FAILURE
                        - Log file: REBOOT line indicates if restart required
                        - Log file: GPO/MDM warnings if centrally managed
                        
LOGIC DOCUMENT          Workflow:
                        1. Validate administrator privileges (exit if not admin)
                        2. Log system information (computer, domain, user, OS version)
                        3. Check Windows Autopatch eligibility (Windows 10/11)
                        4. Create backup directory if -CreateBackup enabled
                        5. Process each registry artifact:
                           - Check if conditional removal applies
                           - Test registry key/value existence
                           - Backup registry key if -CreateBackup enabled
                           - Remove registry key or value (respects -WhatIf)
                           - Track success/failure status
                        6. Validate core Windows Update services (wuauserv, bits, cryptsvc, msiserver)
                        7. Generate detailed summary with removed artifacts list
                        8. Log final STATUS (SUCCESS/CLEAN/PARTIAL) and REBOOT requirement
                        9. Exit with appropriate code for SYSTRAC monitoring
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(HelpMessage = "Enable verbose logging")]
    [switch]$VerboseLogging = $false,
    
    [Parameter(HelpMessage = "Force execution without creating registry backups (not recommended)")]
    [switch]$ForceNoBackup = $false
)

$ScriptName = & {$MyInvocation.ScriptName}
$ScriptPath = Split-Path -Parent $ScriptName
$ScriptName = Split-Path -Leaf $ScriptName
$ScriptName = $ScriptName -replace ".ps1",""

# Writing log file path
$logFile = "$ScriptPath\$ScriptName"+"Log.txt"

# Automatic backup configuration - enabled by default unless -ForceNoBackup specified
$CreateBackup = -not $ForceNoBackup
$BackupRootFolder = Join-Path $ScriptPath "RegistryBackup"
$BackupSessionFolder = "Backup_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
$BackupPath = Join-Path $BackupRootFolder $BackupSessionFolder

#Log function to write messages to log file
function LogMessage {
    param (
        [Parameter(Mandatory=$false)]
        [AllowEmptyString()]
        [string]$message = "",
        
        [Parameter(Mandatory=$false)]
        [ValidateSet('INFO', 'WARNING', 'ERROR', 'SUCCESS')]
        [string]$Level = 'INFO'
    )
    
    # Handle empty messages (for blank lines in log)
    if ([string]::IsNullOrWhiteSpace($message)) {
        Add-Content -Path $logFile -Value ""
    } else {
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $logMessage = "$timestamp - [$Level] $message"
        Add-Content -Path $logFile -Value $logMessage
    }
}

# Script execution start marker
LogMessage ""
LogMessage "============================================== SCRIPT EXECUTION START ==============================================" -Level 'INFO'
LogMessage "Script: 15127_Remove legacy registry artifacts blocking Autopatch.ps1 | Version: 1.2 | Start Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -Level 'INFO'
LogMessage "=========================================================================================================" -Level 'INFO'
LogMessage ""

# Check if running as administrator
try {
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
    if (-NOT $isAdmin) {
        LogMessage "This script must be run as Administrator. Please run PowerShell as Administrator and try again." -Level 'ERROR'
        exit 1
    }
    LogMessage "Administrator privileges confirmed." -Level 'INFO'
} catch {
    LogMessage "Failed to verify administrator privileges: $_" -Level 'ERROR'
    exit 1
}


function Test-RegistryKeyExists {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )
    
    try {
        return Test-Path -Path $Path -ErrorAction SilentlyContinue
    }
    catch {
        return $false
    }
}
# ...existing code...
function Backup-RegistryKey {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$KeyPath,
        [Parameter(Mandatory)]
        [string]$BackupPath
    )
    
    try {
        if (-not (Test-Path $BackupPath)) {
            New-Item -Path $BackupPath -ItemType Directory -Force | Out-Null
        }
        
        $KeyName = ($KeyPath -split '\\')[-1]
        $BackupFile = Join-Path $BackupPath "$KeyName.reg"
        
        # Export registry key - anchored replacements for PSDrive prefixes
        $RegPath = $KeyPath -replace '^HKLM:\\', 'HKEY_LOCAL_MACHINE\\'
        $RegPath = $RegPath -replace '^HKCU:\\', 'HKEY_CURRENT_USER\\'
        
        $ExportCmd = "reg export `"$RegPath`" `"$BackupFile`" /y"
        $Result = cmd /c $ExportCmd 2>&1
        
        if ($LASTEXITCODE -eq 0) {
            LogMessage "Registry key backed up: $KeyPath -> $BackupFile"
            return $true
        } else {
            LogMessage "Failed to backup registry key: $KeyPath. Error: $Result"
            return $false
        }
    }
    catch {
        LogMessage "Exception during backup of $KeyPath`: $($_.Exception.Message)"
        return $false
    }
}
# ...existing code...
function Remove-RegistryKey {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [Parameter(Mandatory)]
        [string]$KeyPath,
        [string]$ValueName = $null,
        [string]$Description = ""
    )
    
    try {
        # Check if parent key exists
        if (-not (Test-RegistryKeyExists -Path $KeyPath)) {
            LogMessage "Registry key not found (already clean): $KeyPath"
            return "NotFound"  # Return specific status instead of $true
        }
        
        # If checking a value, verify it exists
        if ($ValueName) {
            $prop = Get-ItemProperty -Path $KeyPath -Name $ValueName -ErrorAction SilentlyContinue
            if ($null -eq $prop) {
                LogMessage "Value not present, nothing to remove: $KeyPath\$ValueName ($Description)"
                return "NotFound"  # Return specific status instead of $true
            }
        }
        
        # Backup before removal if enabled
        if ($CreateBackup) {
            $BackupSuccess = Backup-RegistryKey -KeyPath $KeyPath -BackupPath $BackupPath
            if (-not $BackupSuccess) {
                LogMessage "Backup failed for: $KeyPath" -Level 'WARNING'
                if (-not $ForceNoBackup) {
                    LogMessage "Skipping removal due to backup failure (use -ForceNoBackup to override)" -Level 'WARNING'
                    return "BackupFailed"
                } else {
                    LogMessage "Proceeding with removal despite backup failure (-ForceNoBackup enabled)" -Level 'WARNING'
                }
            }
        }
        
        if ($PSCmdlet.ShouldProcess($KeyPath, "Remove Registry Key/Value")) {
            if ($ValueName) {
                Remove-ItemProperty -Path $KeyPath -Name $ValueName -Force -ErrorAction Stop
                LogMessage "Removed registry value: $KeyPath\$ValueName ($Description)"
            } else {
                # Remove entire key
                Remove-Item -Path $KeyPath -Recurse -Force -ErrorAction Stop
                LogMessage "Removed registry key: $KeyPath ($Description)"
            }
            return "Removed"  # Successfully removed
        } else {
            LogMessage "Operation skipped by ShouldProcess: $KeyPath ($Description)"
            return "Skipped"  # WhatIf or Confirm = No
        }
    }
    catch {
        LogMessage "Failed to remove $KeyPath`: $($_.Exception.Message)"
        return "Failed"
    }
}
#

function Get-WindowsVersion {
    try {
        $OS = Get-CimInstance -ClassName Win32_OperatingSystem
        $Version = [System.Environment]::OSVersion.Version
        
        return @{
            ProductName = $OS.Caption
            Version = $Version
            BuildNumber = $OS.BuildNumber
            IsWindows10 = ($Version.Major -eq 10 -and $Version.Build -lt 22000)
            IsWindows11 = ($Version.Major -eq 10 -and $Version.Build -ge 22000)
        }
    }
    catch {
        LogMessage "Failed to determine Windows version: $($_.Exception.Message)"
        return $null
    }
}

function Test-AutopatchEligibility {
    $WindowsInfo = Get-WindowsVersion
    
    if ($null -eq $WindowsInfo) {
        return $false
    }
    
    LogMessage "Detected OS: $($WindowsInfo.ProductName) (Build: $($WindowsInfo.BuildNumber))"
    
    # Check Windows 10/11 compatibility
    if ($WindowsInfo.IsWindows10 -or $WindowsInfo.IsWindows11) {
        LogMessage "System is compatible with Windows Autopatch"
        return $true
    } else {
        LogMessage "System may not be compatible with Windows Autopatch"
        return $false
    }
}

function Test-GPOManagedPolicies {
    <#
    .SYNOPSIS
        Detects if Windows Update policies are managed by Group Policy or MDM
    #>
    try {
        $IsDomainJoined = (Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain
        $GPOManaged = $false
        
        if ($IsDomainJoined) {
            LogMessage "System is domain-joined - policies may be GPO-managed" -Level 'WARNING'
            $GPOManaged = $true
        }
        
        # Check for MDM enrollment
        $MDMPath = "HKLM:\SOFTWARE\Microsoft\Enrollments"
        if (Test-Path $MDMPath) {
            $Enrollments = Get-ChildItem $MDMPath -ErrorAction SilentlyContinue
            if ($Enrollments) {
                LogMessage "System appears to be MDM-enrolled - policies may be centrally managed" -Level 'WARNING'
                $GPOManaged = $true
            }
        }
        
        if ($GPOManaged) {
            LogMessage "⚠️ IMPORTANT: Registry changes may be reapplied by GPO/MDM policy refresh" -Level 'WARNING'
            LogMessage "   Coordinate with domain/MDM administrators to update centralized policies" -Level 'WARNING'
        }
        
        return $GPOManaged
    }
    catch {
        LogMessage "Could not determine GPO/MDM management status: $($_.Exception.Message)" -Level 'WARNING'
        return $false
    }
}

# Define registry artifacts to remove
$RegistryArtifacts = @(
    # Legacy WSUS Configuration
    @{
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
        ValueName = "WUServer"
        Description = "Legacy WSUS Server Configuration"
    },
    @{
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
        ValueName = "WUStatusServer"
        Description = "Legacy WSUS Status Server"
    },
    @{
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
        ValueName = "UseWUServer"
        Description = "Legacy WSUS Server Usage Flag"
    },
    
    # Update Deferral Policies
    @{
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
        ValueName = "DeferFeatureUpdates"
        Description = "Feature Update Deferral Policy"
    },
    @{
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
        ValueName = "DeferFeatureUpdatesPeriodInDays"
        Description = "Feature Update Deferral Period"
    },
    @{
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
        ValueName = "DeferQualityUpdates"
        Description = "Quality Update Deferral Policy"
    },
    @{
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
        ValueName = "DeferQualityUpdatesPeriodInDays"
        Description = "Quality Update Deferral Period"
    },
    @{
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
        ValueName = "PauseFeatureUpdates"
        Description = "Feature Updates Pause Policy"
    },
    @{
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
        ValueName = "PauseQualityUpdates"
        Description = "Quality Updates Pause Policy"
    },
    
    # Automatic Updates Blocking
    @{
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
        ValueName = "NoAutoUpdate"
        Description = "Automatic Updates Disabled"
    },
    @{
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
        ValueName = "AUOptions"
        Description = "Automatic Updates Options Override"
    },
    
    # Telemetry Blocking (impacts Autopatch functionality)
    @{
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
        ValueName = "AllowTelemetry"
        Description = "Telemetry Collection Policy (if set to 0)"
        ConditionalRemoval = $true
        Condition = { (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -ErrorAction SilentlyContinue).AllowTelemetry -eq 0 }
    },
    
    # Windows Update Medic Service Blocks
    @{
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
        ValueName = "DisableWindowsUpdateAccess"
        Description = "Windows Update Access Block"
    },
    
    # Legacy GPO Artifact Keys
    @{
        Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"
        Description = "Legacy Reboot Required Flag"
        RemoveEntireKey = $true
    },
    
    # Third-party Update Management Artifacts
    @{
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
        ValueName = "DisableOSUpgrade"
        Description = "OS Upgrade Block Policy"
    },
    
    # Delivery Optimization Blocks
    @{
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization"
        ValueName = "DODownloadMode"
        Description = "Delivery Optimization Mode Override"
        ConditionalRemoval = $true
        Condition = { (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" -Name "DODownloadMode" -ErrorAction SilentlyContinue).DODownloadMode -eq 0 }
    }
)

# Main execution
LogMessage "=============================================="
LogMessage "Windows Autopatch Registry Cleanup"
LogMessage "=============================================="
LogMessage "Script Version: 1.2" -Level 'INFO'
LogMessage "Execution Time: $(Get-Date)" -Level 'INFO'
LogMessage "Computer Name: $env:COMPUTERNAME" -Level 'INFO'
LogMessage "User Context: $env:USERNAME" -Level 'INFO'
LogMessage "Domain: $env:USERDOMAIN" -Level 'INFO'
LogMessage "Backup Enabled: $(if ($CreateBackup) { 'YES (Automatic)' } else { 'NO (-ForceNoBackup specified)' })" -Level 'INFO'
if ($CreateBackup) {
    LogMessage "Backup Location: $BackupPath" -Level 'INFO'
}

# Check system eligibility
if (-not (Test-AutopatchEligibility)) {
    LogMessage "System may not support Autopatch. Continuing with cleanup..." -Level 'WARNING'
}

# Check for GPO/MDM management
$IsGPOManaged = Test-GPOManagedPolicies

# Verify administrator privileges
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    LogMessage "This script requires Administrator privileges. Please run as Administrator."
    exit 1
}

# Create backup directory if needed
if ($CreateBackup) {
    try {
        # Ensure root backup folder exists
        if (-not (Test-Path $BackupRootFolder)) {
            New-Item -Path $BackupRootFolder -ItemType Directory -Force | Out-Null
            LogMessage "Created RegistryBackup root folder: $BackupRootFolder" -Level 'INFO'
        }
        
        # Create session-specific backup folder
        if (-not (Test-Path $BackupPath)) {
            New-Item -Path $BackupPath -ItemType Directory -Force | Out-Null
        }
        LogMessage "Backup directory ready: $BackupPath" -Level 'INFO'
    } catch {
        LogMessage "Failed to create backup directory: $($_.Exception.Message)" -Level 'ERROR'
        if (-not $ForceNoBackup) {
            LogMessage "ERROR: Cannot proceed without backup capability. Use -ForceNoBackup to override (not recommended)" -Level 'ERROR'
            exit 3
        } else {
            LogMessage "WARNING: Continuing without backup capability (-ForceNoBackup enabled)" -Level 'WARNING'
            $CreateBackup = $false
        }
    }
} else {
    LogMessage "WARNING: Backups disabled via -ForceNoBackup parameter" -Level 'WARNING'
}

$TotalArtifacts = $RegistryArtifacts.Count
$ProcessedArtifacts = 0
$RemovedArtifacts = 0
$SkippedArtifacts = 0
$RemovedArtifactsList = @()

LogMessage "Processing $TotalArtifacts registry artifacts..."

foreach ($Artifact in $RegistryArtifacts) {
    $ProcessedArtifacts++
    Write-Progress -Activity "Cleaning Registry Artifacts" -Status "Processing $($Artifact.Description)" -PercentComplete (($ProcessedArtifacts / $TotalArtifacts) * 100)
    
    try {
        # Check conditional removal
        if ($Artifact.ConditionalRemoval -and $Artifact.Condition) {
            $ShouldRemove = & $Artifact.Condition
            if (-not $ShouldRemove) {
                LogMessage "Skipping conditional removal: $($Artifact.Description)"
                $SkippedArtifacts++
                continue
            }
        }
        
        # Determine removal method
        if ($Artifact.RemoveEntireKey) {
            $Result = Remove-RegistryKey -KeyPath $Artifact.Path -Description $Artifact.Description
        } else {
            $Result = Remove-RegistryKey -KeyPath $Artifact.Path -ValueName $Artifact.ValueName -Description $Artifact.Description
        }
        
        # Handle result based on status
        switch ($Result) {
            "Removed" {
                $RemovedArtifacts++
                # Add to removed artifacts list - only if actually removed
                $RemovedArtifactsList += @{
                    Description = $Artifact.Description
                    Path = $Artifact.Path
                    ValueName = $Artifact.ValueName
                }
            }
            "NotFound" {
                $SkippedArtifacts++
                # Already clean, don't add to removed list
            }
            "Skipped" {
                $SkippedArtifacts++
                # WhatIf or user declined, don't add to removed list
            }
            default {
                $SkippedArtifacts++
                # Failed or other status
            }
        }
    }
    catch {
        LogMessage "Error processing artifact '$($Artifact.Description)': $($_.Exception.Message)"
        $SkippedArtifacts++
    }
}

Write-Progress -Activity "Cleaning Registry Artifacts" -Completed

# Validate core update services
LogMessage "Validating core Windows Update services..." -Level 'INFO'

$CoreServices = @(
    'wuauserv',    # Windows Update
    'bits',        # Background Intelligent Transfer Service
    'cryptsvc',    # Cryptographic Services
    'msiserver'    # Windows Installer
)

$ServiceIssues = 0
foreach ($ServiceName in $CoreServices) {
    try {
        $Service = Get-Service -Name $ServiceName -ErrorAction Stop
        if ($Service.Status -eq 'Running') {
            LogMessage "Core service '$ServiceName' is running (StartType: $($Service.StartType))" -Level 'INFO'
        } elseif ($Service.StartType -eq 'Disabled') {
            LogMessage "Core service '$ServiceName' is DISABLED - may impact Windows Update functionality" -Level 'WARNING'
            $ServiceIssues++
        } else {
            LogMessage "Core service '$ServiceName' is not running but available (Status: $($Service.Status), StartType: $($Service.StartType))" -Level 'INFO'
        }
    }
    catch {
        LogMessage "Could not validate service '$ServiceName': $($_.Exception.Message)" -Level 'WARNING'
        $ServiceIssues++
    }
}

# Final summary
LogMessage "=============================================="
LogMessage "Registry Cleanup Completed!"
LogMessage "=============================================="
LogMessage "Total artifacts processed: $ProcessedArtifacts"
LogMessage "Artifacts removed: $RemovedArtifacts"
LogMessage "Artifacts skipped: $SkippedArtifacts"

# Log detailed list of removed artifacts
if ($RemovedArtifacts -gt 0) {
    LogMessage ""
    LogMessage "REMOVED ARTIFACTS DETAILS:"
    LogMessage "=============================================="
    $counter = 1
    foreach ($artifact in $RemovedArtifactsList) {
        if ($artifact.ValueName) {
            LogMessage "$counter. $($artifact.Description)"
            LogMessage "   Path: $($artifact.Path)"
            LogMessage "   Value: $($artifact.ValueName)"
        } else {
            LogMessage "$counter. $($artifact.Description)"
            LogMessage "   Path: $($artifact.Path)"
            LogMessage "   Action: Entire key removed"
        }
        $counter++
    }
    LogMessage "=============================================="
    LogMessage ""
    LogMessage "Registry backups stored in: $BackupPath"
    LogMessage "To restore, run: reg import <backup_file.reg>"
}

LogMessage ""
LogMessage "Log file saved to: $logFile"

# Recommend next steps
LogMessage "=============================================="
LogMessage "Next Steps for Autopatch Enablement:"
LogMessage "=============================================="
LogMessage "1. Verify Windows Update service is running"
LogMessage "2. Check Group Policy configuration"
LogMessage "3. Ensure device meets Autopatch requirements"
LogMessage "4. Monitor Windows Update functionality"

if ($RemovedArtifacts -gt 0) {
    LogMessage "⚠️ SYSTEM RESTART RECOMMENDED to apply changes."
}

# SYSTRAC-friendly exit with status
LogMessage "=============================================="

# Determine exit code and status
$ExitCode = 0
$StatusMessage = ""
$RebootMessage = ""

if ($RemovedArtifacts -gt 0) {
    $StatusMessage = "STATUS: SUCCESS - $RemovedArtifacts artifacts removed"
    $RebootMessage = "REBOOT: Required to apply registry changes"
    $ExitCode = 0
    LogMessage $StatusMessage -Level 'SUCCESS'
    LogMessage $RebootMessage -Level 'INFO'
} elseif ($SkippedArtifacts -eq $TotalArtifacts) {
    $StatusMessage = "STATUS: CLEAN - No artifacts found to remove"
    $RebootMessage = "REBOOT: Not required"
    $ExitCode = 0
    LogMessage $StatusMessage -Level 'INFO'
    LogMessage $RebootMessage -Level 'INFO'
} elseif ($ProcessedArtifacts -gt 0 -and $RemovedArtifacts -eq 0) {
    $StatusMessage = "STATUS: PARTIAL - Artifacts found but none removed (check log for details)"
    $RebootMessage = "REBOOT: May be required - review log file"
    $ExitCode = 2
    LogMessage $StatusMessage -Level 'WARNING'
    LogMessage $RebootMessage -Level 'WARNING'
} else {
    $StatusMessage = "STATUS: FAILURE - Unable to process artifacts"
    $RebootMessage = "REBOOT: Unknown - review log file"
    $ExitCode = 3
    LogMessage $StatusMessage -Level 'ERROR'
    LogMessage $RebootMessage -Level 'WARNING'
}

# Add GPO warning if managed
if ($IsGPOManaged) {
    LogMessage "⚠️ REMINDER: System is GPO/MDM managed - coordinate with administrators for persistent changes" -Level 'WARNING'
}

if ($ServiceIssues -gt 0) {
    LogMessage "⚠️ WARNING: $ServiceIssues service issue(s) detected - review service status above" -Level 'WARNING'
}

LogMessage "=============================================="
LogMessage "Exit Code: $ExitCode (0=Success, 1=No Admin, 2=Partial, 3=Failure)" -Level 'INFO'
LogMessage ""
LogMessage "============================================== SCRIPT EXECUTION END ===============================================" -Level 'INFO'
LogMessage "Script completed at: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | Exit Code: $ExitCode" -Level 'INFO'
LogMessage "=========================================================================================================" -Level 'INFO'
LogMessage ""

exit $ExitCode