<#
SCRIPT NAME             22624_Windows_power_plan_set_power_plan_to_Energy_saver.ps1
IN REPOSITORY           Yes
AUTHOR & EMAIL          Vivek: vivek.f.vivek@capgemini.com
COMPANY                 Capgemini
TAGS                    Remediation, Power Plan, Energy Saver, Windows Configuration
STATUS                  Draft
DATE OF CHANGES         2025-12-12
VERSION                 1.0
RELEASENOTES            Initial release - Set Windows Power Plan to Energy Saver mode
                        - Validates prerequisites (PowerShell 5.1+, Administrator privileges)
                        - Checks current power plan before making changes
                        - Creates backup of power plan settings in timestamped directory
                        - Detects Energy Saver plan or alternative power saver plans
                        - Silent execution with comprehensive logging
                        - Exit codes: 0=Success, 1=Failure
APPROVED                No
SUPPORT                 NA
DEX TOOLS               NA
DEPENDENCIES            PowerShell 5.1+, Administrative privileges, Windows PowerCfg utility
CONTEXT                 System
OS                      Windows 11/10
SYNOPSIS                Sets Windows Power Plan to Energy Saver mode with validation and backup
DESCRIPTION             This script changes the active Windows power plan to Energy Saver (Power Saver) mode
                        with comprehensive validation, error handling, backup, and detailed logging.
                        
                        EXECUTION PHASES:
                        Phase 1: Prerequisites validation (PowerShell version, admin rights, powercfg availability)
                        Phase 2: Current power plan detection (skip if already on Energy Saver)
                        Phase 3: Available power plans enumeration
                        Phase 4: Energy Saver plan availability verification
                        Phase 5: Backup creation (timestamped JSON backup in PowerPlanBackup directory)
                        Phase 6: Power plan activation
                        Phase 7: Post-change validation
                        
                        FEATURES:
                        - Silent execution (no console output)
                        - Comprehensive logging to file
                        - Automatic backup before changes
                        - Reuses existing backup directory
                        - Validates change after execution
                        - Detects alternative power saver plans if standard Energy Saver not found
                        - Includes restore function for rollback capability
#>

# Script Configuration
$script:ScriptName = "22624_Windows_power_plan_set_power_plan_to_Energy_saver"
$script:ScriptVersion = "1.0"
$script:LogFile = Join-Path $PSScriptRoot "$($script:ScriptName)Log.txt"
$script:BackupDir = $null  # Will be set during backup creation
$script:BackupFile = $null  # Will be set during backup creation

# Energy Saver (Power Saver) GUID - Standard Windows GUID
$script:EnergySaverGUID = "a1841308-3541-4fab-bc81-f71556f20b4a"

#region Logging Functions

function Write-Log {
    <#
    .SYNOPSIS
        Writes a message to the log file only (silent execution)
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet('INFO', 'WARNING', 'ERROR', 'SUCCESS')]
        [string]$Level = 'INFO'
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    # Write to log file only (silent execution)
    Add-Content -Path $script:LogFile -Value $logMessage -ErrorAction SilentlyContinue
}

function Write-LogSeparator {
    $separator = "=" * 80
    Add-Content -Path $script:LogFile -Value $separator -ErrorAction SilentlyContinue
}

#endregion

#region Pre-Execution Checks

function Test-Prerequisites {
    <#
    .SYNOPSIS
        Validates prerequisites before execution
    #>
    Write-Log "Checking prerequisites..." -Level INFO
    
    $checksPass = $true
    
    # Check PowerShell Version
    if ($PSVersionTable.PSVersion.Major -lt 5) {
        Write-Log "PowerShell version 5.1 or higher is required. Current version: $($PSVersionTable.PSVersion)" -Level ERROR
        $checksPass = $false
    } else {
        Write-Log "PowerShell version: $($PSVersionTable.PSVersion) - OK" -Level INFO
    }
    
    # Check Administrator Privileges
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    if (-not $isAdmin) {
        Write-Log "Administrator privileges are required to change power plans" -Level ERROR
        $checksPass = $false
    } else {
        Write-Log "Administrator privileges confirmed - OK" -Level SUCCESS
    }
    
    # Check if powercfg is available
    try {
        $null = powercfg /list 2>&1
        Write-Log "PowerCfg utility is available - OK" -Level INFO
    }
    catch {
        Write-Log "PowerCfg utility is not available or accessible" -Level ERROR
        $checksPass = $false
    }
    
    return $checksPass
}

#endregion

#region Power Plan Functions

function Get-CurrentPowerPlan {
    <#
    .SYNOPSIS
        Gets the currently active power plan
    #>
    try {
        Write-Log "Retrieving current power plan..." -Level INFO
        
        $currentPlan = powercfg /getactivescheme
        
        if ($currentPlan -match "Power Scheme GUID: ([a-f0-9-]+)\s+\(([^)]+)\)") {
            $planGUID = $Matches[1]
            $planName = $Matches[2]
            
            Write-Log "Current active power plan: $planName (GUID: $planGUID)" -Level INFO
            
            return @{
                Name = $planName
                GUID = $planGUID
            }
        }
        else {
            Write-Log "Unable to parse current power plan information" -Level WARNING
            return $null
        }
    }
    catch {
        Write-Log "Error retrieving current power plan: $($_.Exception.Message)" -Level ERROR
        return $null
    }
}

function Get-AvailablePowerPlans {
    <#
    .SYNOPSIS
        Lists all available power plans
    #>
    try {
        Write-Log "Retrieving available power plans..." -Level INFO
        
        $plans = @()
        $output = powercfg /list
        
        foreach ($line in $output) {
            if ($line -match "Power Scheme GUID: ([a-f0-9-]+)\s+\(([^)]+)\)(\s+\*)?") {
                $plans += @{
                    GUID = $Matches[1]
                    Name = $Matches[2]
                    IsActive = $Matches[3] -eq " *"
                }
                
                $activeStatus = if ($Matches[3] -eq " *") { "(Active)" } else { "" }
                Write-Log "  - $($Matches[2]) (GUID: $($Matches[1])) $activeStatus" -Level INFO
            }
        }
        
        return $plans
    }
    catch {
        Write-Log "Error retrieving available power plans: $($_.Exception.Message)" -Level ERROR
        return @()
    }
}

function Test-EnergySaverPlanExists {
    <#
    .SYNOPSIS
        Checks if Energy Saver plan exists on the system
    #>
    param(
        [Parameter(Mandatory=$true)]
        [array]$AvailablePlans
    )
    
    try {
        Write-Log "Checking if Energy Saver power plan exists..." -Level INFO
        
        $energySaverPlan = $AvailablePlans | Where-Object { $_.GUID -eq $script:EnergySaverGUID }
        
        if ($energySaverPlan) {
            Write-Log "Energy Saver power plan found: $($energySaverPlan.Name)" -Level SUCCESS
            return $true
        }
        else {
            Write-Log "Energy Saver power plan not found on this system" -Level WARNING
            
            # Check for alternative power saver plans
            $powerSaverPlan = $AvailablePlans | Where-Object { $_.Name -like "*Power Saver*" -or $_.Name -like "*Energy*" }
            
            if ($powerSaverPlan) {
                Write-Log "Alternative power saver plan found: $($powerSaverPlan.Name) (GUID: $($powerSaverPlan.GUID))" -Level INFO
                $script:EnergySaverGUID = $powerSaverPlan.GUID
                return $true
            }
            
            return $false
        }
    }
    catch {
        Write-Log "Error checking for Energy Saver plan: $($_.Exception.Message)" -Level ERROR
        return $false
    }
}

function Enable-EnergySaverPlan {
    <#
    .SYNOPSIS
        Activates the Energy Saver power plan
    #>
    try {
        Write-Log "Attempting to set power plan to Energy Saver..." -Level INFO
        
        $output = powercfg /setactive $script:EnergySaverGUID 2>&1
        
        if ($LASTEXITCODE -eq 0) {
            Write-Log "Successfully set power plan to Energy Saver" -Level SUCCESS
            return $true
        }
        else {
            Write-Log "Failed to set power plan. Exit code: $LASTEXITCODE. Output: $output" -Level ERROR
            return $false
        }
    }
    catch {
        Write-Log "Error setting power plan: $($_.Exception.Message)" -Level ERROR
        return $false
    }
}

function Backup-PowerPlanSettings {
    <#
    .SYNOPSIS
        Creates a backup of current power plan settings in a backup directory
    #>
    param(
        [Parameter(Mandatory=$true)]
        $CurrentPlan,
        
        [Parameter(Mandatory=$true)]
        [array]$AvailablePlans
    )
    
    try {
        Write-Log "Creating backup of current power plan settings..." -Level INFO
        
        if ($CurrentPlan) {
            # Check if backup directory exists, create if not
            $script:BackupDir = Join-Path $PSScriptRoot "PowerPlanBackup"
            
            if (-not (Test-Path $script:BackupDir)) {
                New-Item -Path $script:BackupDir -ItemType Directory -Force | Out-Null
                Write-Log "Backup directory created: $script:BackupDir" -Level INFO
            }
            
            # Create timestamped backup file inside the backup directory
            $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
            $script:BackupFile = Join-Path $script:BackupDir "PowerPlan_Backup_$timestamp.json"
            
            # Create backup data
            $backupData = @{
                BackupDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                ComputerName = $env:COMPUTERNAME
                OriginalPowerPlan = $CurrentPlan
                AllAvailablePlans = $AvailablePlans
            }
            
            # Save backup to file
            $backupData | ConvertTo-Json -Depth 10 | Out-File -FilePath $script:BackupFile -Force
            Write-Log "Backup created at: $script:BackupDir" -Level SUCCESS
            return $true
        }
        else {
            Write-Log "Unable to create backup - could not retrieve current power plan" -Level WARNING
            return $false
        }
    }
    catch {
        Write-Log "Error creating backup: $($_.Exception.Message)" -Level ERROR
        return $false
    }
}

function Test-PowerPlanChange {
    <#
    .SYNOPSIS
        Validates that the power plan was successfully changed
    #>
    try {
        Write-Log "Validating power plan change..." -Level INFO
        
        Start-Sleep -Seconds 2  # Brief delay to ensure change is applied
        
        $currentPlan = Get-CurrentPowerPlan
        
        if ($currentPlan -and $currentPlan.GUID -eq $script:EnergySaverGUID) {
            Write-Log "Validation successful - Energy Saver plan is now active" -Level SUCCESS
            Write-Log "Final Power Plan: $($currentPlan.Name)" -Level INFO
            return $true
        }
        else {
            Write-Log "Validation failed - Energy Saver plan is not active" -Level ERROR
            if ($currentPlan) {
                Write-Log "Current Power Plan: $($currentPlan.Name)" -Level ERROR
            }
            return $false
        }
    }
    catch {
        Write-Log "Error validating power plan change: $($_.Exception.Message)" -Level ERROR
        return $false
    }
}

#endregion

#region Restore Function

function Restore-PreviousPowerPlan {
    <#
    .SYNOPSIS
        Restores the previous power plan from backup
    #>
    param(
        [string]$BackupFilePath = $script:BackupFile
    )
    
    try {
        if (-not (Test-Path $BackupFilePath)) {
            Write-Log "Backup file not found: $BackupFilePath" -Level ERROR
            return $false
        }
        
        Write-Log "Restoring previous power plan from backup..." -Level INFO
        
        $backup = Get-Content $BackupFilePath -Raw | ConvertFrom-Json
        $previousGUID = $backup.OriginalPowerPlan.GUID
        $previousName = $backup.OriginalPowerPlan.Name
        
        Write-Log "Restoring power plan: $previousName (GUID: $previousGUID)" -Level INFO
        
        $output = powercfg /setactive $previousGUID 2>&1
        
        if ($LASTEXITCODE -eq 0) {
            Write-Log "Successfully restored previous power plan: $previousName" -Level SUCCESS
            return $true
        }
        else {
            Write-Log "Failed to restore power plan. Exit code: $LASTEXITCODE" -Level ERROR
            return $false
        }
    }
    catch {
        Write-Log "Error restoring power plan: $($_.Exception.Message)" -Level ERROR
        return $false
    }
}

#endregion

#region Main Execution

function Invoke-PowerPlanChange {
    <#
    .SYNOPSIS
        Main function to orchestrate the power plan change
    #>
    
    Write-LogSeparator
    Write-Log "Starting $script:ScriptName v$script:ScriptVersion" -Level INFO
    Write-Log "Execution Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -Level INFO
    Write-Log "Computer: $env:COMPUTERNAME" -Level INFO
    Write-Log "User: $env:USERNAME" -Level INFO
    Write-LogSeparator
    
    try {
        # Step 1: Prerequisites Check
        Write-Log "STEP 1: Checking Prerequisites" -Level INFO
        if (-not (Test-Prerequisites)) {
            throw "Prerequisites check failed. Cannot proceed."
        }
        Write-LogSeparator
        
        # Step 2: Get Current Power Plan
        Write-Log "STEP 2: Getting Current Power Plan Information" -Level INFO
        $currentPlan = Get-CurrentPowerPlan
        if ($currentPlan) {
            # Check if already on Energy Saver
            if ($currentPlan.GUID -eq $script:EnergySaverGUID) {
                Write-Log "System is already using Energy Saver power plan - no change needed" -Level SUCCESS
                return $true
            }
        }
        Write-LogSeparator
        
        # Step 3: List Available Power Plans
        Write-Log "STEP 3: Listing Available Power Plans" -Level INFO
        $availablePlans = Get-AvailablePowerPlans
        Write-LogSeparator
        
        # Step 4: Check if Energy Saver Plan Exists
        Write-Log "STEP 4: Verifying Energy Saver Plan Availability" -Level INFO
        if (-not (Test-EnergySaverPlanExists -AvailablePlans $availablePlans)) {
            throw "Energy Saver power plan is not available on this system"
        }
        Write-LogSeparator
        
        # Step 5: Create Backup
        Write-Log "STEP 5: Creating Backup of Current Settings" -Level INFO
        Backup-PowerPlanSettings -CurrentPlan $currentPlan -AvailablePlans $availablePlans
        Write-LogSeparator
        
        # Step 6: Apply Energy Saver Plan
        Write-Log "STEP 6: Applying Energy Saver Power Plan" -Level INFO
        if (-not (Enable-EnergySaverPlan)) {
            throw "Failed to set Energy Saver power plan"
        }
        Write-LogSeparator
        
        # Step 7: Validate Change
        Write-Log "STEP 7: Validating Power Plan Change" -Level INFO
        if (-not (Test-PowerPlanChange)) {
            throw "Power plan change validation failed"
        }
        Write-LogSeparator
        
        # Success
        Write-Log "Power plan successfully changed to Energy Saver" -Level SUCCESS
        
        return $true
    }
    catch {
        Write-Log "Script execution failed: $($_.Exception.Message)" -Level ERROR
        return $false
    }
    finally {
        Write-LogSeparator
        Write-Log "Script execution completed" -Level INFO
        Write-Log "Log file: $script:LogFile" -Level INFO
        if ($script:BackupDir) {
            Write-Log "Backup location: $script:BackupDir" -Level INFO
        }
        Write-LogSeparator
    }
}

#endregion

# Execute Main Function
try {
    $exitCode = if (Invoke-PowerPlanChange) { 0 } else { 1 }
    exit $exitCode
}
catch {
    Write-Log "Unexpected error: $($_.Exception.Message)" -Level ERROR
    exit 1
}
