<#
SCRIPT NAME             19148_Remove_FireEye_Agent.ps1
IN REPOSITORY           No
AUTHOR & EMAIL          Vivek: vivek.f.vivek@capgemini.com
COMPANY                 Capgemini
TAGS                    Remediation, Security, Uninstall
STATUS                  draft
DATE OF CHANGES         Dec 26th, 2025  
VERSION                 2.0
RELEASENOTES            - Replaced Win32_Product with registry-based detection (faster, no MSI repairs)
                        - Added support for Mandiant and rebranded products
                        - Implemented service management (stop services before uninstall)
                        - Added retry logic for MSI error 1618 (installer busy)
                        - Enhanced residual cleanup for failed verifications
                        - Added registry fallback when CIM/WMI fails
                        - Improved detection with multiple methods
                        - Added uninstall passphrase parameter support
APPROVED                No
SUPPORT                 NA
DEX TOOLS               NA
DEPENDENCIES            - PowerShell 5.1 or later (Windows 10/11 default)
                        - Administrator privileges required
                        - Sufficient permissions to uninstall software and stop services
                        - Optional: Product code and/or uninstall passphrase parameters
CONTEXT                 User
OS                      Windows
SYNOPSIS                Removes FireEye/Mandiant Agent from Windows systems with comprehensive validation and cleanup.
DESCRIPTION             This script removes FireEye/Mandiant Agent from the system using registry-based detection 
                        (avoiding slow Win32_Product), service management, and multiple uninstall methods including
                        MSI, vendor tools (xagt.exe), and manual cleanup. All operations are logged with timestamps,
                        error handling, retry logic, and comprehensive pre/post-removal validation with residual cleanup.
INPUTS                  Optional parameters:
                            - $ProductCode: MSI product code for silent uninstall (e.g., "{GUID}")
                            - $UninstallPassphrase: Passphrase for vendor uninstall tool (xagt.exe)
                            - $TimeoutSeconds: Custom timeout for uninstall operations (default: 300)
                            - $MaxRetries: Maximum retries for MSI busy errors (default: 3)
                        If no parameters provided, the script will auto-detect using registry scan.
OUTPUTS                 Log messages indicating:
                            - Admin privilege check status
                            - Pre-removal validation (detecting installed products)
                            - Uninstall attempts and results from multiple methods
                            - Post-removal verification results
                            - Final execution summary with exit codes

VARIABLE DESCRIPTION    $MyInvocation = Contains information about how the script was invoked, used for log file naming
                        $ScriptName = Stores the name of the script file without extension
                        $ScriptPath = Stores the directory path where the script is located
                        $logFile = Full path to the log file where all activities are recorded
                        $ProductCode = Optional MSI product code for uninstalling FireEye Agent
                        $UninstallPassphrase = Optional passphrase for vendor uninstall tool
                        $TimeoutSeconds = Maximum time allowed for uninstall operation (default: 300 seconds)
                        $MaxRetries = Maximum retry attempts for MSI busy errors (default: 3)
                        $UninstallSuccessful = Boolean flag indicating overall uninstall success
                        $ErrorsEncountered = Array collecting all error messages during execution
                        $fireEyeProducts = Registry-based objects representing detected FireEye/Mandiant installations
                        $successCount = Number of successfully removed products
                        $failCount = Number of failed removal attempts
                        $RebootRequired = Flag indicating if system reboot is needed
EXAMPLE                 .\19148_Remove_FireEye_Agent.ps1 (or run batch file instead of .ps1)
                        Or with product code:
                        .\19148_Remove_FireEye_Agent.ps1 -ProductCode "{12345678-1234-1234-1234-123456789012}"
                        Or with custom timeout:
                        .\19148_Remove_FireEye_Agent.ps1 -TimeoutSeconds 600
                        Or with uninstall passphrase:
                        .\19148_Remove_FireEye_Agent.ps1 -UninstallPassphrase "YourPassphraseHere"
                        Or combined:
                        .\19148_Remove_FireEye_Agent.ps1 -ProductCode "{11111111-2222-3333-4444-555555555555}" -TimeoutSeconds 600 -MaxRetries 5
LOGIC DOCUMENT          NA          
#>


# Parameter validation
param(
    [Parameter(Mandatory=$false,
               HelpMessage="MSI Product Code GUID for FireEye Agent")]
    [ValidatePattern('^\{[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}\}$')]
    [string]$ProductCode,
    
    [Parameter(Mandatory=$false,
               HelpMessage="Timeout in seconds for uninstall operation")]
    [ValidateRange(60, 3600)]
    [int]$TimeoutSeconds = 300,
    
    [Parameter(Mandatory=$false,
               HelpMessage="Uninstall passphrase for FireEye/Mandiant agent")]
    [SecureString]$UninstallPassphrase,
    
    [Parameter(Mandatory=$false,
               HelpMessage="Maximum retry attempts for MSI busy errors")]
    [ValidateRange(1, 10)]
    [int]$MaxRetries = 3
)

# Getting current script path and name
$ScriptName = & { $MyInvocation.ScriptName }
$ScriptPath = Split-Path $ScriptName -parent
$ScriptName = Split-Path $ScriptName -Leaf
$scriptName = $ScriptName -replace '.PS1',''

# Log file path
$logFile = "$ScriptPath\$ScriptName" + "Log.txt"

# Initialize tracking variables
$script:UninstallSuccessful = $false
$script:ErrorsEncountered = @()
$script:RebootRequired = $false

# Log function
function Write-LogMessage {
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
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-LogMessage "This script must be run as Administrator. Please run PowerShell as Administrator and try again." -Level 'ERROR'
    exit 1
}

Write-LogMessage "=== FireEye Agent Removal Script Started ===" -Level 'INFO'
Write-LogMessage "Script Version: 2.0" -Level 'INFO'
Write-LogMessage "Timeout configured: $TimeoutSeconds seconds" -Level 'INFO'
Write-LogMessage "Max retries configured: $MaxRetries" -Level 'INFO'
if ($ProductCode) {
    Write-LogMessage "User-provided Product Code: $ProductCode" -Level 'INFO'
}
if ($UninstallPassphrase) {
    Write-LogMessage "Uninstall passphrase provided: Yes" -Level 'INFO'
}

# Pre-removal validation function using registry (faster, no MSI repairs)
function Test-FireEyePresence {
    Write-LogMessage "Performing pre-removal validation using registry scan..." -Level 'INFO'
    
    $detectedProducts = @()
    
    try {
        # Method 1: Registry-based detection (preferred - fast and reliable)
        $registryPaths = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
        )
        
        $patterns = @("*FireEye*", "*Mandiant*", "*xagt*", "*HX*")
        
        foreach ($regPath in $registryPaths) {
            try {
                $apps = Get-ItemProperty $regPath -ErrorAction SilentlyContinue | Where-Object {
                    $displayName = $_.DisplayName
                    $publisher = $_.Publisher
                    $displayName -or $publisher
                }
                
                foreach ($app in $apps) {
                    foreach ($pattern in $patterns) {
                        if (($app.DisplayName -like $pattern) -or ($app.Publisher -like $pattern)) {
                            $productInfo = [PSCustomObject]@{
                                Name = $app.DisplayName
                                Version = $app.DisplayVersion
                                Publisher = $app.Publisher
                                IdentifyingNumber = $app.PSChildName
                                UninstallString = $app.UninstallString
                                QuietUninstallString = $app.QuietUninstallString
                                Source = "Registry"
                            }
                            
                            # Avoid duplicates
                            if ($detectedProducts.IdentifyingNumber -notcontains $productInfo.IdentifyingNumber) {
                                $detectedProducts += $productInfo
                            }
                            break
                        }
                    }
                }
            } catch {
                Write-LogMessage "Error scanning registry path ${regPath}: $($_.Exception.Message)" -Level 'WARNING'
            }
        }
        
        # Method 2: Service-based detection as supplement
        try {
            $fireEyeServices = Get-Service -ErrorAction SilentlyContinue | Where-Object {
                $_.DisplayName -like "*FireEye*" -or 
                $_.Name -like "*FireEye*" -or 
                $_.Name -like "*xagt*" -or
                $_.DisplayName -like "*Mandiant*"
            }
            
            if ($fireEyeServices -and $detectedProducts.Count -eq 0) {
                Write-LogMessage "No products in registry, but found FireEye/Mandiant services" -Level 'INFO'
                foreach ($svc in $fireEyeServices) {
                    Write-LogMessage "Service detected: $($svc.Name) - $($svc.DisplayName) (Status: $($svc.Status))" -Level 'INFO'
                }
            }
        } catch {
            Write-LogMessage "Error checking services: $($_.Exception.Message)" -Level 'WARNING'
        }
        
        if ($detectedProducts.Count -gt 0) {
            Write-LogMessage "Pre-validation: Found $($detectedProducts.Count) FireEye/Mandiant product(s) installed" -Level 'INFO'
            
            foreach ($product in $detectedProducts) {
                Write-LogMessage "Product: $($product.Name) | Version: $($product.Version) | Publisher: $($product.Publisher) | ID: $($product.IdentifyingNumber)" -Level 'INFO'
            }
            return $detectedProducts
        } else {
            Write-LogMessage "Pre-validation: No FireEye/Mandiant products detected in registry" -Level 'INFO'
            return $null
        }
    } catch {
        Write-LogMessage "Error during pre-validation: $($_.Exception.Message)" -Level 'ERROR'
        $script:ErrorsEncountered += "Pre-validation error: $($_.Exception.Message)"
        return $null
    }
}

# Post-removal verification function
function Test-FireEyeRemoval {
    Write-LogMessage "Performing post-removal verification..." -Level 'INFO'
    
    $verificationPassed = $true
    $issuesFound = @()
    
    # Check 1: Verify no FireEye/Mandiant products in registry
    try {
        $registryPaths = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
        )
        
        $patterns = @("*FireEye*", "*Mandiant*", "*xagt*", "*HX*")
        $remainingProducts = @()
        
        foreach ($regPath in $registryPaths) {
            $apps = Get-ItemProperty $regPath -ErrorAction SilentlyContinue | Where-Object {
                $displayName = $_.DisplayName
                $publisher = $_.Publisher
                
                foreach ($pattern in $patterns) {
                    if (($displayName -like $pattern) -or ($publisher -like $pattern)) {
                        return $true
                    }
                }
                return $false
            }
            
            if ($apps) {
                $remainingProducts += $apps
            }
        }
        
        if ($remainingProducts.Count -gt 0) {
            $productNames = ($remainingProducts | ForEach-Object { $_.DisplayName }) -join ', '
            Write-LogMessage "Verification FAILED: $($remainingProducts.Count) FireEye/Mandiant product(s) still in registry: $productNames" -Level 'WARNING'
            $issuesFound += "Products still in registry: $productNames"
            $verificationPassed = $false
        } else {
            Write-LogMessage "Verification CHECK 1: No FireEye/Mandiant products in registry" -Level 'SUCCESS'
        }
    } catch {
        Write-LogMessage "Error checking registry: $($_.Exception.Message)" -Level 'WARNING'
    }
    
    # Check 2: Verify no FireEye/Mandiant services
    try {
        $remainingServices = Get-Service -ErrorAction SilentlyContinue | Where-Object { 
            $_.DisplayName -like "*FireEye*" -or 
            $_.Name -like "*FireEye*" -or 
            $_.Name -like "*xagt*" -or
            $_.DisplayName -like "*Mandiant*" -or
            $_.Name -like "*Mandiant*"
        }
        
        if ($remainingServices) {
            $serviceNames = $remainingServices.Name -join ', '
            Write-LogMessage "Verification FAILED: FireEye/Mandiant service(s) still present: $serviceNames" -Level 'WARNING'
            $issuesFound += "Services still present: $serviceNames"
            $verificationPassed = $false
        } else {
            Write-LogMessage "Verification CHECK 2: No FireEye/Mandiant services found" -Level 'SUCCESS'
        }
    } catch {
        Write-LogMessage "Error checking services: $($_.Exception.Message)" -Level 'WARNING'
    }
    
    # Check 3: Verify no FireEye/Mandiant directories
    $commonPaths = @(
        "$env:ProgramFiles\FireEye",
        "${env:ProgramFiles(x86)}\FireEye",
        "$env:ProgramData\FireEye",
        "$env:ProgramFiles\Mandiant",
        "${env:ProgramFiles(x86)}\Mandiant",
        "$env:ProgramData\Mandiant"
    )
    
    foreach ($path in $commonPaths) {
        if (Test-Path $path) {
            Write-LogMessage "Verification FAILED: FireEye/Mandiant directory still exists: $path" -Level 'WARNING'
            $issuesFound += "Directory exists: $path"
            $verificationPassed = $false
        }
    }
    
    if ($verificationPassed) {
        Write-LogMessage "Verification CHECK 3: No FireEye/Mandiant directories found" -Level 'SUCCESS'
        Write-LogMessage "=== POST-REMOVAL VERIFICATION PASSED ===" -Level 'SUCCESS'
    } else {
        Write-LogMessage "=== POST-REMOVAL VERIFICATION FAILED ===" -Level 'WARNING'
        Write-LogMessage "Issues detected: $($issuesFound.Count)" -Level 'WARNING'
        foreach ($issue in $issuesFound) {
            Write-LogMessage "  - $issue" -Level 'WARNING'
        }
    }
    
    return $verificationPassed
}

# Stop FireEye/Mandiant services before uninstall
function Stop-FireEyeServices {
    Write-LogMessage "Attempting to stop FireEye/Mandiant services..." -Level 'INFO'
    
    try {
        $fireEyeServices = Get-Service -ErrorAction SilentlyContinue | Where-Object {
            $_.DisplayName -like "*FireEye*" -or 
            $_.Name -like "*FireEye*" -or 
            $_.Name -like "*xagt*" -or
            $_.DisplayName -like "*Mandiant*" -or
            $_.Name -like "*Mandiant*"
        }
        
        if (-not $fireEyeServices) {
            Write-LogMessage "No FireEye/Mandiant services found to stop" -Level 'INFO'
            return $true
        }
        
        $stoppedCount = 0
        $failedCount = 0
        
        foreach ($service in $fireEyeServices) {
            try {
                if ($service.Status -eq 'Running') {
                    Write-LogMessage "Stopping service: $($service.Name) ($($service.DisplayName))" -Level 'INFO'
                    Stop-Service -Name $service.Name -Force -ErrorAction Stop
                    
                    # Set to disabled to prevent restart
                    Set-Service -Name $service.Name -StartupType Disabled -ErrorAction SilentlyContinue
                    
                    Write-LogMessage "Service stopped and disabled: $($service.Name)" -Level 'SUCCESS'
                    $stoppedCount++
                } else {
                    Write-LogMessage "Service already stopped: $($service.Name) (Status: $($service.Status))" -Level 'INFO'
                    # Still try to disable it
                    Set-Service -Name $service.Name -StartupType Disabled -ErrorAction SilentlyContinue
                }
            } catch {
                Write-LogMessage "Failed to stop service $($service.Name): $($_.Exception.Message)" -Level 'WARNING'
                $failedCount++
            }
        }
        
        Write-LogMessage "Service management complete: $stoppedCount stopped, $failedCount failed" -Level 'INFO'
        return ($failedCount -eq 0)
        
    } catch {
        Write-LogMessage "Error managing services: $($_.Exception.Message)" -Level 'WARNING'
        return $false
    }
}

# Cleanup residual files and services
function Remove-FireEyeResiduals {
    Write-LogMessage "Performing residual cleanup..." -Level 'INFO'
    
    $cleanupSuccess = $true
    
    # Remove leftover services
    try {
        $services = Get-Service -ErrorAction SilentlyContinue | Where-Object {
            $_.DisplayName -like "*FireEye*" -or 
            $_.Name -like "*FireEye*" -or 
            $_.Name -like "*xagt*" -or
            $_.DisplayName -like "*Mandiant*" -or
            $_.Name -like "*Mandiant*"
        }
        
        foreach ($service in $services) {
            try {
                Write-LogMessage "Removing residual service: $($service.Name)" -Level 'INFO'
                Stop-Service -Name $service.Name -Force -ErrorAction SilentlyContinue
                sc.exe delete $service.Name | Out-Null
                Write-LogMessage "Service removed: $($service.Name)" -Level 'SUCCESS'
            } catch {
                Write-LogMessage "Failed to remove service $($service.Name): $($_.Exception.Message)" -Level 'WARNING'
                $cleanupSuccess = $false
            }
        }
    } catch {
        Write-LogMessage "Error during service cleanup: $($_.Exception.Message)" -Level 'WARNING'
    }
    
    # Remove leftover directories
    $dirsToRemove = @(
        "$env:ProgramFiles\FireEye",
        "${env:ProgramFiles(x86)}\FireEye",
        "$env:ProgramData\FireEye",
        "$env:ProgramFiles\Mandiant",
        "${env:ProgramFiles(x86)}\Mandiant",
        "$env:ProgramData\Mandiant"
    )
    
    foreach ($dir in $dirsToRemove) {
        if (Test-Path $dir) {
            try {
                Write-LogMessage "Removing residual directory: $dir" -Level 'INFO'
                Remove-Item -Path $dir -Recurse -Force -ErrorAction Stop
                Write-LogMessage "Directory removed: $dir" -Level 'SUCCESS'
            } catch {
                Write-LogMessage "Failed to remove directory ${dir}: $($_.Exception.Message)" -Level 'WARNING'
                $cleanupSuccess = $false
            }
        }
    }
    
    return $cleanupSuccess
}

# Uninstall using MSI product code with retry logic
function Remove-FireEyeByProductCode {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Code,
        
        [Parameter(Mandatory=$false)]
        [int]$RetryAttempt = 1
    )
    
    Write-LogMessage "Method: MSI uninstall using Product Code: $Code (Attempt $RetryAttempt of $MaxRetries)" -Level 'INFO'
    
    try {
        # Validate product code format
        if ($Code -notmatch '^\{[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}\}$') {
            Write-LogMessage "Invalid product code format: $Code" -Level 'ERROR'
            return $false
        }
        
        $msiLogPath = "$ScriptPath\FireEye_Uninstall_$((Get-Date).ToString('yyyyMMdd_HHmmss')).log"
        $arguments = "/x $Code /quiet /norestart /l*v `"$msiLogPath`""
        
        Write-LogMessage "MSI Arguments: $arguments" -Level 'INFO'
        Write-LogMessage "MSI Log file: $msiLogPath" -Level 'INFO'
        
        $processInfo = New-Object System.Diagnostics.ProcessStartInfo
        $processInfo.FileName = "msiexec.exe"
        $processInfo.Arguments = $arguments
        $processInfo.RedirectStandardOutput = $true
        $processInfo.RedirectStandardError = $true
        $processInfo.UseShellExecute = $false
        $processInfo.CreateNoWindow = $true
        
        $process = New-Object System.Diagnostics.Process
        $process.StartInfo = $processInfo
        
        Write-LogMessage "Starting MSI uninstall process..." -Level 'INFO'
        $startTime = Get-Date
        $process.Start() | Out-Null
        
        # Wait with timeout
        $completed = $process.WaitForExit($TimeoutSeconds * 1000)
        $endTime = Get-Date
        $duration = ($endTime - $startTime).TotalSeconds
        
        if (-not $completed) {
            Write-LogMessage "Uninstall exceeded timeout of $TimeoutSeconds seconds (elapsed: $([math]::Round($duration, 2))s)" -Level 'ERROR'
            try {
                $process.Kill()
                Write-LogMessage "Process terminated due to timeout" -Level 'ERROR'
            } catch {
                Write-LogMessage "Failed to terminate process: $($_.Exception.Message)" -Level 'ERROR'
            }
            $script:ErrorsEncountered += "MSI uninstall timeout (Product Code: $Code)"
            return $false
        }
        
        $exitCode = $process.ExitCode
        Write-LogMessage "MSI uninstall completed in $([math]::Round($duration, 2)) seconds with exit code: $exitCode" -Level 'INFO'
        
        # Interpret MSI exit codes
        switch ($exitCode) {
            0 { 
                Write-LogMessage "Uninstall SUCCESS - Exit Code: 0 (Success)" -Level 'SUCCESS'
                return $true
            }
            3010 { 
                Write-LogMessage "Uninstall SUCCESS - Exit Code: 3010 (Success, reboot required)" -Level 'SUCCESS'
                Write-LogMessage "NOTE: A system reboot is required to complete the uninstallation" -Level 'WARNING'
                $script:RebootRequired = $true
                return $true
            }
            1605 { 
                Write-LogMessage "Product code not found or already uninstalled - Exit Code: 1605" -Level 'WARNING'
                return $false
            }
            1618 { 
                Write-LogMessage "Another installation is already in progress - Exit Code: 1618" -Level 'WARNING'
                
                # Retry logic for error 1618
                if ($RetryAttempt -lt $MaxRetries) {
                    $waitTime = 30 * $RetryAttempt
                    Write-LogMessage "Waiting $waitTime seconds before retry (Attempt $RetryAttempt of $MaxRetries)..." -Level 'INFO'
                    Start-Sleep -Seconds $waitTime
                    return Remove-FireEyeByProductCode -Code $Code -RetryAttempt ($RetryAttempt + 1)
                } else {
                    Write-LogMessage "Max retries reached for MSI error 1618" -Level 'ERROR'
                    $script:ErrorsEncountered += "MSI Error 1618: Another installation in progress (max retries exceeded)"
                    return $false
                }
            }
            1603 { 
                Write-LogMessage "Fatal error during installation - Exit Code: 1603 (Possible tamper protection)" -Level 'ERROR'
                $script:ErrorsEncountered += "MSI Error 1603: Fatal error - may require vendor uninstall tool or passphrase"
                return $false
            }
            default { 
                Write-LogMessage "Uninstall FAILED - Exit Code: $exitCode" -Level 'ERROR'
                $script:ErrorsEncountered += "MSI uninstall failed with exit code: $exitCode"
                return $false
            }
        }
    } catch {
        $errorMsg = $_.Exception.Message
        Write-LogMessage "Exception during MSI uninstall: $errorMsg" -Level 'ERROR'
        $script:ErrorsEncountered += "MSI uninstall exception: $errorMsg"
        return $false
    }
}

# Uninstall using vendor tool (xagt.exe) with passphrase
function Remove-FireEyeByVendorTool {
    Write-LogMessage "Method: Vendor uninstall tool (xagt.exe)" -Level 'INFO'
    
    try {
        # Common locations for xagt.exe
        $xagtPaths = @(
            "$env:ProgramFiles\FireEye\xagt.exe",
            "${env:ProgramFiles(x86)}\FireEye\xagt.exe",
            "$env:ProgramData\FireEye\xagt.exe",
            "$env:ProgramFiles\Mandiant\xagt.exe",
            "${env:ProgramFiles(x86)}\Mandiant\xagt.exe"
        )
        
        $xagtPath = $null
        foreach ($path in $xagtPaths) {
            if (Test-Path $path) {
                $xagtPath = $path
                Write-LogMessage "Found vendor tool at: $xagtPath" -Level 'INFO'
                break
            }
        }
        
        if (-not $xagtPath) {
            Write-LogMessage "Vendor tool (xagt.exe) not found in common locations" -Level 'WARNING'
            return $false
        }
        
        # Convert SecureString to plain text for command execution
        $plainPassphrase = ""
        if ($UninstallPassphrase) {
            $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($UninstallPassphrase)
            $plainPassphrase = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
        }
        
        # Build command arguments
        $arguments = if ($plainPassphrase) {
            "-uninstall $plainPassphrase"
        } else {
            "-uninstall"
        }
        
        Write-LogMessage "Executing vendor uninstall tool..." -Level 'INFO'
        
        $processInfo = New-Object System.Diagnostics.ProcessStartInfo
        $processInfo.FileName = $xagtPath
        $processInfo.Arguments = $arguments
        $processInfo.RedirectStandardOutput = $true
        $processInfo.RedirectStandardError = $true
        $processInfo.UseShellExecute = $false
        $processInfo.CreateNoWindow = $true
        
        $process = New-Object System.Diagnostics.Process
        $process.StartInfo = $processInfo
        
        $startTime = Get-Date
        $process.Start() | Out-Null
        
        # Wait with timeout
        $completed = $process.WaitForExit($TimeoutSeconds * 1000)
        $endTime = Get-Date
        $duration = ($endTime - $startTime).TotalSeconds
        
        if (-not $completed) {
            Write-LogMessage "Vendor uninstall exceeded timeout of $TimeoutSeconds seconds" -Level 'ERROR'
            try {
                $process.Kill()
                Write-LogMessage "Process terminated due to timeout" -Level 'ERROR'
            } catch {
                Write-LogMessage "Failed to terminate process: $($_.Exception.Message)" -Level 'ERROR'
            }
            return $false
        }
        
        $exitCode = $process.ExitCode
        $stdout = $process.StandardOutput.ReadToEnd()
        $stderr = $process.StandardError.ReadToEnd()
        
        Write-LogMessage "Vendor tool completed in $([math]::Round($duration, 2)) seconds with exit code: $exitCode" -Level 'INFO'
        
        if ($stdout) {
            Write-LogMessage "Vendor tool output: $stdout" -Level 'INFO'
        }
        if ($stderr) {
            Write-LogMessage "Vendor tool errors: $stderr" -Level 'WARNING'
        }
        
        if ($exitCode -eq 0) {
            Write-LogMessage "Vendor uninstall SUCCESS" -Level 'SUCCESS'
            return $true
        } else {
            Write-LogMessage "Vendor uninstall FAILED with exit code: $exitCode" -Level 'ERROR'
            $script:ErrorsEncountered += "Vendor uninstall failed with exit code: $exitCode"
            return $false
        }
        
    } catch {
        $errorMsg = $_.Exception.Message
        Write-LogMessage "Exception during vendor uninstall: $errorMsg" -Level 'ERROR'
        $script:ErrorsEncountered += "Vendor uninstall exception: $errorMsg"
        return $false
    }
}

# Uninstall using UninstallString from registry
function Remove-FireEyeByUninstallString {
    param(
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$Product
    )
    
    Write-LogMessage "Method: UninstallString from registry for product: $($Product.Name)" -Level 'INFO'
    
    try {
        $uninstallString = $Product.QuietUninstallString
        if (-not $uninstallString) {
            $uninstallString = $Product.UninstallString
        }
        
        if (-not $uninstallString) {
            Write-LogMessage "No uninstall string found for product: $($Product.Name)" -Level 'WARNING'
            return $false
        }
        
        Write-LogMessage "Using uninstall string: $uninstallString" -Level 'INFO'
        
        # Parse the uninstall string
        if ($uninstallString -match '^"?([^"]+)"?\s*(.*)$') {
            $executable = $matches[1]
            $arguments = $matches[2]
            
            # Add quiet switches if not present
            if ($arguments -notmatch '/quiet' -and $arguments -notmatch '/silent') {
                $arguments += " /quiet /norestart"
            }
            
            Write-LogMessage "Executable: $executable" -Level 'INFO'
            Write-LogMessage "Arguments: $arguments" -Level 'INFO'
            
            $processInfo = New-Object System.Diagnostics.ProcessStartInfo
            $processInfo.FileName = $executable
            $processInfo.Arguments = $arguments
            $processInfo.RedirectStandardOutput = $true
            $processInfo.RedirectStandardError = $true
            $processInfo.UseShellExecute = $false
            $processInfo.CreateNoWindow = $true
            
            $process = New-Object System.Diagnostics.Process
            $process.StartInfo = $processInfo
            
            Write-LogMessage "Starting uninstall via UninstallString..." -Level 'INFO'
            $startTime = Get-Date
            $process.Start() | Out-Null
            
            $completed = $process.WaitForExit($TimeoutSeconds * 1000)
            $endTime = Get-Date
            $duration = ($endTime - $startTime).TotalSeconds
            
            if (-not $completed) {
                Write-LogMessage "UninstallString execution exceeded timeout" -Level 'ERROR'
                try { $process.Kill() } catch {}
                return $false
            }
            
            $exitCode = $process.ExitCode
            Write-LogMessage "UninstallString completed in $([math]::Round($duration, 2))s with exit code: $exitCode" -Level 'INFO'
            
            if ($exitCode -eq 0 -or $exitCode -eq 3010) {
                Write-LogMessage "Uninstall via UninstallString SUCCESS" -Level 'SUCCESS'
                if ($exitCode -eq 3010) {
                    $script:RebootRequired = $true
                }
                return $true
            } else {
                Write-LogMessage "Uninstall via UninstallString FAILED" -Level 'ERROR'
                return $false
            }
        } else {
            Write-LogMessage "Could not parse uninstall string: $uninstallString" -Level 'ERROR'
            return $false
        }
    } catch {
        Write-LogMessage "Exception during UninstallString execution: $($_.Exception.Message)" -Level 'ERROR'
        return $false
    }
}

# Uninstall using CIM method (fallback, kept for compatibility)
function Remove-FireEyeByCIM {
    param(
        [Parameter(Mandatory=$true)]
        [string]$ProductCode
    )
    
    Write-LogMessage "Method: CIM Invoke uninstall for product code: $ProductCode" -Level 'INFO'
    
    try {
        # Try to get the product via CIM
        $product = Get-CimInstance -ClassName Win32_Product -Filter "IdentifyingNumber='$ProductCode'" -ErrorAction SilentlyContinue
        
        if (-not $product) {
            Write-LogMessage "Product not found via CIM: $ProductCode" -Level 'WARNING'
            return $false
        }
        
        Write-LogMessage "Found product via CIM: $($product.Name)" -Level 'INFO'
        
        # Run Invoke-CimMethod inside a job to allow timeout
        $job = Start-Job -ArgumentList $product -ScriptBlock {
            param($p)
            try {
                $res = Invoke-CimMethod -InputObject $p -MethodName Uninstall -ErrorAction Stop
                return @{ Success = $true; ReturnValue = $res.ReturnValue }
            } catch {
                return @{ Success = $false; Error = $_.Exception.Message }
            }
        }

        $completed = Wait-Job -Job $job -Timeout $TimeoutSeconds
        if (-not $completed) {
            Write-LogMessage "CIM uninstall job timed out after $TimeoutSeconds seconds" -Level 'ERROR'
            try { Stop-Job -Job $job -Force -ErrorAction SilentlyContinue; Remove-Job -Job $job -ErrorAction SilentlyContinue } catch {}
            $script:ErrorsEncountered += "CIM uninstall timeout for $ProductCode"
            return $false
        }

        $result = Receive-Job -Job $job -ErrorAction SilentlyContinue
        Remove-Job -Job $job -ErrorAction SilentlyContinue

        if ($null -eq $result) {
            Write-LogMessage "CIM uninstall returned no result" -Level 'ERROR'
            $script:ErrorsEncountered += "CIM uninstall no result for $ProductCode"
            return $false
        }

        if ($result.Success) {
            if ($result.ReturnValue -eq 0) {
                Write-LogMessage "CIM uninstall SUCCESS - Return Value: 0" -Level 'SUCCESS'
                return $true
            } else {
                Write-LogMessage "CIM uninstall FAILED - Return Value: $($result.ReturnValue)" -Level 'ERROR'
                $script:ErrorsEncountered += "CIM uninstall failed with return value: $($result.ReturnValue)"
                return $false
            }
        } else {
            Write-LogMessage "CIM uninstall exception: $($result.Error)" -Level 'ERROR'
            $script:ErrorsEncountered += "CIM uninstall exception: $($result.Error)"
            return $false
        }
    } catch {
        $errorMsg = $_.Exception.Message
        Write-LogMessage "CIM uninstall exception (outer): $errorMsg" -Level 'ERROR'
        $script:ErrorsEncountered += "CIM uninstall exception: $errorMsg"
        return $false
    }
}


# ========== MAIN EXECUTION ==========

try {
    # Step 1: Pre-removal validation
    Write-LogMessage "========== STEP 1: PRE-REMOVAL VALIDATION ==========" -Level 'INFO'
    $fireEyeProducts = Test-FireEyePresence
    
    if (-not $fireEyeProducts) {
        Write-LogMessage "No FireEye/Mandiant Agent found on this machine. Nothing to remove." -Level 'INFO'
        $script:UninstallSuccessful = $true
        
        # Still perform verification to confirm
        Write-LogMessage "========== STEP 2: VERIFICATION ==========" -Level 'INFO'
        $verificationPassed = Test-FireEyeRemoval
        
        Write-LogMessage "=== EXECUTION SUMMARY ===" -Level 'INFO'
        Write-LogMessage "Uninstall required: No" -Level 'INFO'
        Write-LogMessage "Verification passed: $verificationPassed" -Level 'INFO'
        Write-LogMessage "=== FireEye Agent Not Present - Script Completed ===" -Level 'SUCCESS'
        exit 0
    }
    
    # Step 1.5: Stop services before uninstall
    Write-LogMessage "========== STEP 1.5: SERVICE MANAGEMENT ==========" -Level 'INFO'
    $servicesManaged = Stop-FireEyeServices
    if ($servicesManaged) {
        Write-LogMessage "Services stopped successfully" -Level 'SUCCESS'
    } else {
        Write-LogMessage "Some services could not be stopped - proceeding with uninstall" -Level 'WARNING'
    }
    
    # Wait a moment for services to fully stop
    Start-Sleep -Seconds 3
    
    # Step 2: Attempt removal using multiple methods
    Write-LogMessage "========== STEP 2: REMOVAL PROCESS ==========" -Level 'INFO'
    
    # Convert to array for uniform processing
    $productsToRemove = @($fireEyeProducts)
    $successCount = 0
    $failCount = 0
    $totalProducts = $productsToRemove.Count
    
    Write-LogMessage "Total products to remove: $totalProducts" -Level 'INFO'
    
    foreach ($fireEyeProduct in $productsToRemove) {
        $productRemoved = $false
        $productName = $fireEyeProduct.Name
        
        Write-LogMessage "--- Processing product: $productName ---" -Level 'INFO'
        
        # Method 1: Try vendor uninstall tool (if passphrase provided or tool found)
        if (-not $productRemoved) {
            Write-LogMessage "Attempting Method 1: Vendor Uninstall Tool (xagt.exe)" -Level 'INFO'
            $productRemoved = Remove-FireEyeByVendorTool
            
            if ($productRemoved) {
                Write-LogMessage "Method 1 SUCCESS: Removed using vendor tool" -Level 'SUCCESS'
                $successCount++
                continue
            } else {
                Write-LogMessage "Method 1 FAILED or not available: Trying next method..." -Level 'WARNING'
            }
        }
        
        # Method 2: Try with user-provided product code
        if ($ProductCode -and -not $productRemoved) {
            Write-LogMessage "Attempting Method 2: User-provided Product Code" -Level 'INFO'
            $productRemoved = Remove-FireEyeByProductCode -Code $ProductCode
            
            if ($productRemoved) {
                Write-LogMessage "Method 2 SUCCESS: Removed using user-provided product code" -Level 'SUCCESS'
                $successCount++
                continue
            } else {
                Write-LogMessage "Method 2 FAILED: Trying next method..." -Level 'WARNING'
            }
        }
        
        # Method 3: Try with detected product code from IdentifyingNumber
        if (-not $productRemoved -and $fireEyeProduct.IdentifyingNumber) {
            Write-LogMessage "Attempting Method 3: Auto-detected Product Code" -Level 'INFO'
            $productRemoved = Remove-FireEyeByProductCode -Code $fireEyeProduct.IdentifyingNumber
            
            if ($productRemoved) {
                Write-LogMessage "Method 3 SUCCESS: Removed using auto-detected product code" -Level 'SUCCESS'
                $successCount++
                continue
            } else {
                Write-LogMessage "Method 3 FAILED: Trying next method..." -Level 'WARNING'
            }
        }
        
        # Method 4: Try UninstallString from registry
        if (-not $productRemoved -and $fireEyeProduct.UninstallString) {
            Write-LogMessage "Attempting Method 4: UninstallString from registry" -Level 'INFO'
            $productRemoved = Remove-FireEyeByUninstallString -Product $fireEyeProduct
            
            if ($productRemoved) {
                Write-LogMessage "Method 4 SUCCESS: Removed using UninstallString" -Level 'SUCCESS'
                $successCount++
                continue
            } else {
                Write-LogMessage "Method 4 FAILED: Trying next method..." -Level 'WARNING'
            }
        }
        
        # Method 5: Fallback to CIM Invoke-CimMethod
        if (-not $productRemoved -and $fireEyeProduct.IdentifyingNumber) {
            Write-LogMessage "Attempting Method 5: CIM Invoke-CimMethod (fallback)" -Level 'INFO'
            $productRemoved = Remove-FireEyeByCIM -ProductCode $fireEyeProduct.IdentifyingNumber
            
            if ($productRemoved) {
                Write-LogMessage "Method 5 SUCCESS: Removed using CIM method" -Level 'SUCCESS'
                $successCount++
            } else {
                Write-LogMessage "Method 5 FAILED: All removal methods exhausted" -Level 'ERROR'
                $failCount++
            }
        }
        
        # Log final status for this product
        if ($productRemoved) {
            Write-LogMessage "Product '$productName' removed successfully" -Level 'SUCCESS'
        } else {
            Write-LogMessage "Product '$productName' removal FAILED after all attempts" -Level 'ERROR'
        }
    }
    
    # Evaluate removal results
    Write-LogMessage "--- Removal Summary ---" -Level 'INFO'
    Write-LogMessage "Total products: $totalProducts" -Level 'INFO'
    Write-LogMessage "Successfully removed: $successCount" -Level 'INFO'
    Write-LogMessage "Failed to remove: $failCount" -Level 'INFO'
    
    $script:UninstallSuccessful = ($successCount -gt 0 -and $failCount -eq 0)
    
    # Step 3: Post-removal verification
    if ($script:UninstallSuccessful) {
        Write-LogMessage "Waiting 5 seconds for system cleanup..." -Level 'INFO'
        Start-Sleep -Seconds 5
    }
    
    Write-LogMessage "========== STEP 3: POST-REMOVAL VERIFICATION ==========" -Level 'INFO'
    $verificationPassed = Test-FireEyeRemoval
    
    # Step 4: Residual cleanup if verification failed
    if (-not $verificationPassed) {
        Write-LogMessage "========== STEP 4: RESIDUAL CLEANUP ==========" -Level 'INFO'
        $cleanupSuccess = Remove-FireEyeResiduals
        
        if ($cleanupSuccess) {
            Write-LogMessage "Residual cleanup completed successfully" -Level 'SUCCESS'
            # Re-verify after cleanup
            Start-Sleep -Seconds 3
            Write-LogMessage "Re-verifying after cleanup..." -Level 'INFO'
            $verificationPassed = Test-FireEyeRemoval
        } else {
            Write-LogMessage "Residual cleanup completed with some issues" -Level 'WARNING'
        }
    }
    
} catch {
    $errorMsg = $_.Exception.Message
    Write-LogMessage "CRITICAL ERROR in main execution: $errorMsg" -Level 'ERROR'
    Write-LogMessage "Stack Trace: $($_.ScriptStackTrace)" -Level 'ERROR'
    $script:ErrorsEncountered += "Critical error: $errorMsg"
    $script:UninstallSuccessful = $false
    $verificationPassed = $false
}

# ========== FINAL SUMMARY ==========

Write-LogMessage "========================================" -Level 'INFO'
Write-LogMessage "===   FINAL EXECUTION SUMMARY       ===" -Level 'INFO'
Write-LogMessage "========================================" -Level 'INFO'
Write-LogMessage "Uninstall successful: $script:UninstallSuccessful" -Level 'INFO'
Write-LogMessage "Verification passed: $verificationPassed" -Level 'INFO'
Write-LogMessage "Reboot required: $script:RebootRequired" -Level 'INFO'
Write-LogMessage "Total errors encountered: $($script:ErrorsEncountered.Count)" -Level 'INFO'

if ($script:ErrorsEncountered.Count -gt 0) {
    Write-LogMessage "--- Error Details ---" -Level 'ERROR'
    for ($i = 0; $i -lt $script:ErrorsEncountered.Count; $i++) {
        Write-LogMessage "  Error $($i + 1): $($script:ErrorsEncountered[$i])" -Level 'ERROR'
    }
}

if ($script:RebootRequired) {
    Write-LogMessage "========================================" -Level 'WARNING'
    Write-LogMessage "!!! SYSTEM REBOOT REQUIRED !!!" -Level 'WARNING'
    Write-LogMessage "!!! Please restart the computer to complete the uninstallation !!!" -Level 'WARNING'
    Write-LogMessage "========================================" -Level 'WARNING'
}

# Determine final exit code and status
if ($script:UninstallSuccessful -and $verificationPassed -and $script:ErrorsEncountered.Count -eq 0) {
    Write-LogMessage "========================================" -Level 'SUCCESS'
    Write-LogMessage "=== FireEye Agent Removal: SUCCESS  ===" -Level 'SUCCESS'
    Write-LogMessage "=== All components removed & verified ==" -Level 'SUCCESS'
    Write-LogMessage "========================================" -Level 'SUCCESS'
    Write-LogMessage "Script completed at: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -Level 'INFO'
    exit 0
} elseif ($script:UninstallSuccessful -and -not $verificationPassed) {
    Write-LogMessage "========================================" -Level 'WARNING'
    Write-LogMessage "=== FireEye Agent Removal: WARNING  ===" -Level 'WARNING'
    Write-LogMessage "=== Uninstalled but residuals remain ==" -Level 'WARNING'
    Write-LogMessage "========================================" -Level 'WARNING'
    Write-LogMessage "Script completed at: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -Level 'INFO'
    exit 2
} else {
    Write-LogMessage "========================================" -Level 'ERROR'
    Write-LogMessage "=== FireEye Agent Removal: FAILED   ===" -Level 'ERROR'
    Write-LogMessage "=== Review errors above for details ===" -Level 'ERROR'
    Write-LogMessage "========================================" -Level 'ERROR'
    Write-LogMessage "Script completed at: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -Level 'INFO'
    exit 1
}
