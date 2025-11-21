<#
SCRIPT NAME             19148_Remove_FireEye_Agent.ps1
IN REPOSITORY           No
AUTHOR & EMAIL          Vivek: vivek.f.vivek@capgemini.com
COMPANY                 Capgemini
TAGS                    Remediation, Security, Uninstall
STATUS                  draft
DATE OF CHANGES         Nov 21st, 2025  
VERSION                 1.1
RELEASENOTES            NA
APPROVED                No
SUPPORT                 NA
DEX TOOLS               NA
DEPENDENCIES            - PowerShell 5.1 or later (Windows 10/11 default)
                        - Administrator privileges required
                        - Sufficient permissions to uninstall software
                        - Optional: Product code can be passed as parameter for silent uninstall
CONTEXT                 User
OS                      Windows
SYNOPSIS                Removes FireEye Agent from Windows systems with comprehensive validation.
DESCRIPTION             This script removes FireEye Agent from the system using either a provided product code (MSI uninstall) 
                        or by auto-detecting and uninstalling via CIM (modern WMI replacement). All operations are logged with 
                        timestamps, error handling, and comprehensive pre/post-removal validation. The script uses multiple 
                        removal methods with automatic fallback and verifies complete removal after uninstallation.
INPUTS                  Optional parameter:
                            - $ProductCode: MSI product code for silent uninstall (e.g., "{GUID}")
                        If no product code is provided, the script will auto-detect FireEye Agent via CIM.
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
                        $TimeoutSeconds = Maximum time allowed for uninstall operation (default: 300 seconds)
                        $UninstallSuccessful = Boolean flag indicating overall uninstall success
                        $ErrorsEncountered = Array collecting all error messages during execution
                        $fireEyeProducts = CIM objects representing detected FireEye installations
                        $successCount = Number of successfully removed products
                        $failCount = Number of failed removal attempts
EXAMPLE                 .\19148_Remove_FireEye_Agent.ps1 (or run batch file instead of .ps1)
                        Or with product code:
                        .\19148_Remove_FireEye_Agent.ps1 -ProductCode "{12345678-1234-1234-1234-123456789012}"
                        Or with custom timeout:
                        .\19148_Remove_FireEye_Agent.ps1 -TimeoutSeconds 600
                        or
                        .\19148_Remove_FireEye_Agent.ps1 -ProductCode "{11111111-2222-3333-4444-555555555555}"
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
    [int]$TimeoutSeconds = 300
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
Write-LogMessage "Script Version: 1.1" -Level 'INFO'
Write-LogMessage "Timeout configured: $TimeoutSeconds seconds" -Level 'INFO'
if ($ProductCode) {
    Write-LogMessage "User-provided Product Code: $ProductCode" -Level 'INFO'
}

# Pre-removal validation function
function Test-FireEyePresence {
    Write-LogMessage "Performing pre-removal validation..." -Level 'INFO'
    
    try {
        # Scan for FireEye products (run in job to enforce timeout)
        $job = Start-Job -ScriptBlock {
            try {
                Get-CimInstance -ClassName Win32_Product -ErrorAction Stop | Where-Object { $_.Name -like "*FireEye*" }
            } catch {
                throw $_
            }
        }
        $completed = Wait-Job -Job $job -Timeout $TimeoutSeconds
        if (-not $completed) {
            Write-LogMessage "Pre-validation CIM scan timed out after $TimeoutSeconds seconds" -Level 'ERROR'
            try { Stop-Job -Job $job -Force -ErrorAction SilentlyContinue; Remove-Job -Job $job -ErrorAction SilentlyContinue } catch {}
            $script:ErrorsEncountered += "CIM scan timeout"
            return $null
        }
        $products = Receive-Job -Job $job -ErrorAction Stop
        Remove-Job -Job $job -ErrorAction SilentlyContinue
        
        if ($products) {
            $count = if ($products -is [array]) { $products.Count } else { 1 }
            Write-LogMessage "Pre-validation: Found $count FireEye product(s) installed" -Level 'INFO'
            
            foreach ($product in $products) {
                Write-LogMessage "Product: $($product.Name) | Version: $($product.Version) | Vendor: $($product.Vendor) | IdentifyingNumber: $($product.IdentifyingNumber)" -Level 'INFO'
            }
            return $products
        } else {
            Write-LogMessage "Pre-validation: No FireEye products detected" -Level 'INFO'
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
    
    # Check 1: Verify no FireEye products in installed programs
    try {
        $remainingProducts = Get-CimInstance -ClassName Win32_Product -ErrorAction Stop | 
            Where-Object { $_.Name -like "*FireEye*" }
        
        if ($remainingProducts) {
            $count = if ($remainingProducts -is [array]) { $remainingProducts.Count } else { 1 }
            $productNames = $remainingProducts.Name -join ', '
            Write-LogMessage "Verification FAILED: $count FireEye product(s) still installed: $productNames" -Level 'WARNING'
            $issuesFound += "Products still installed: $productNames"
            $verificationPassed = $false
        } else {
            Write-LogMessage "Verification CHECK 1: No FireEye products in installed programs" -Level 'SUCCESS'
        }
    } catch {
        Write-LogMessage "Error checking installed products: $($_.Exception.Message)" -Level 'WARNING'
    }
    
    # Check 2: Verify no FireEye services
    try {
        $remainingServices = Get-Service -ErrorAction SilentlyContinue | Where-Object { 
            $_.DisplayName -like "*FireEye*" -or $_.Name -like "*FireEye*" -or $_.Name -like "*xagt*"
        }
        
        if ($remainingServices) {
            $serviceNames = $remainingServices.Name -join ', '
            Write-LogMessage "Verification FAILED: FireEye service(s) still present: $serviceNames" -Level 'WARNING'
            $issuesFound += "Services still present: $serviceNames"
            $verificationPassed = $false
        } else {
            Write-LogMessage "Verification CHECK 2: No FireEye services found" -Level 'SUCCESS'
        }
    } catch {
        Write-LogMessage "Error checking services: $($_.Exception.Message)" -Level 'WARNING'
    }
    
    # Check 3: Verify no FireEye directories
    $commonPaths = @(
        "$env:ProgramFiles\FireEye",
        "${env:ProgramFiles(x86)}\FireEye",
        "$env:ProgramData\FireEye"
    )
    
    foreach ($path in $commonPaths) {
        if (Test-Path $path) {
            Write-LogMessage "Verification FAILED: FireEye directory still exists: $path" -Level 'WARNING'
            $issuesFound += "Directory exists: $path"
            $verificationPassed = $false
        }
    }
    
    if ($verificationPassed) {
        Write-LogMessage "Verification CHECK 3: No FireEye directories found" -Level 'SUCCESS'
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

# Uninstall using MSI product code
function Remove-FireEyeByProductCode {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Code
    )
    
    Write-LogMessage "Method: MSI uninstall using Product Code: $Code" -Level 'INFO'
    
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
                return $true
            }
            1605 { 
                Write-LogMessage "Product code not found or already uninstalled - Exit Code: 1605" -Level 'WARNING'
                return $false
            }
            1618 { 
                Write-LogMessage "Another installation is already in progress - Exit Code: 1618" -Level 'ERROR'
                $script:ErrorsEncountered += "MSI Error 1618: Another installation in progress"
                return $false
            }
            1603 { 
                Write-LogMessage "Fatal error during installation - Exit Code: 1603" -Level 'ERROR'
                $script:ErrorsEncountered += "MSI Error 1603: Fatal error"
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

# Uninstall using CIM method
function Remove-FireEyeByCIM {
    param(
        [Parameter(Mandatory=$true)]
        [CimInstance]$Product
    )
    
    Write-LogMessage "Method: CIM Invoke uninstall for product: $($Product.Name)" -Level 'INFO'
    
    try {
        # Run Invoke-CimMethod inside a job to allow timeout
        $job = Start-Job -ArgumentList $Product -ScriptBlock {
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
            Write-LogMessage "CIM uninstall job timed out after $TimeoutSeconds seconds for $($Product.Name)" -Level 'ERROR'
            try { Stop-Job -Job $job -Force -ErrorAction SilentlyContinue; Remove-Job -Job $job -ErrorAction SilentlyContinue } catch {}
            $script:ErrorsEncountered += "CIM uninstall timeout for $($Product.Name)"
            return $false
        }

        $result = Receive-Job -Job $job -ErrorAction SilentlyContinue
        Remove-Job -Job $job -ErrorAction SilentlyContinue

        if ($null -eq $result) {
            Write-LogMessage "CIM uninstall returned no result for $($Product.Name)" -Level 'ERROR'
            $script:ErrorsEncountered += "CIM uninstall no result for $($Product.Name)"
            return $false
        }

        if ($result.Success) {
            if ($result.ReturnValue -eq 0) {
                Write-LogMessage "CIM uninstall SUCCESS - Return Value: 0" -Level 'SUCCESS'
                return $true
            } else {
                Write-LogMessage "CIM uninstall FAILED - Return Value: $($result.ReturnValue)" -Level 'ERROR'
                $script:ErrorsEncountered += "CIM uninstall failed for $($Product.Name) with return value: $($result.ReturnValue)"
                return $false
            }
        } else {
            Write-LogMessage "CIM uninstall exception for $($Product.Name): $($result.Error)" -Level 'ERROR'
            $script:ErrorsEncountered += "CIM uninstall exception for $($Product.Name): $($result.Error)"
            return $false
        }
    } catch {
        $errorMsg = $_.Exception.Message
        Write-LogMessage "CIM uninstall exception (outer): $errorMsg" -Level 'ERROR'
        $script:ErrorsEncountered += "CIM uninstall exception for $($Product.Name): $errorMsg"
        return $false
    }
}


# ========== MAIN EXECUTION ==========

try {
    # Step 1: Pre-removal validation
    Write-LogMessage "========== STEP 1: PRE-REMOVAL VALIDATION ==========" -Level 'INFO'
    $fireEyeProducts = Test-FireEyePresence
    
    if (-not $fireEyeProducts) {
        Write-LogMessage "No FireEye Agent found on this machine. Nothing to remove." -Level 'INFO'
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
        
        # Method 1: Try with user-provided product code (highest priority)
        if ($ProductCode -and -not $productRemoved) {
            Write-LogMessage "Attempting Method 1: User-provided Product Code" -Level 'INFO'
            $productRemoved = Remove-FireEyeByProductCode -Code $ProductCode
            
            if ($productRemoved) {
                Write-LogMessage "Method 1 SUCCESS: Removed using user-provided product code" -Level 'SUCCESS'
                $successCount++
                continue
            } else {
                Write-LogMessage "Method 1 FAILED: Trying next method..." -Level 'WARNING'
            }
        }
        
        # Method 2: Try with detected product code from IdentifyingNumber
        if (-not $productRemoved -and $fireEyeProduct.IdentifyingNumber) {
            Write-LogMessage "Attempting Method 2: Auto-detected Product Code" -Level 'INFO'
            $productRemoved = Remove-FireEyeByProductCode -Code $fireEyeProduct.IdentifyingNumber
            
            if ($productRemoved) {
                Write-LogMessage "Method 2 SUCCESS: Removed using auto-detected product code" -Level 'SUCCESS'
                $successCount++
                continue
            } else {
                Write-LogMessage "Method 2 FAILED: Trying next method..." -Level 'WARNING'
            }
        }
        
        # Method 3: Fallback to CIM Invoke-CimMethod (normal uninstall)
        if (-not $productRemoved) {
            Write-LogMessage "Attempting Method 3: CIM Invoke-CimMethod" -Level 'INFO'
            $productRemoved = Remove-FireEyeByCIM -Product $fireEyeProduct
            
            if ($productRemoved) {
                Write-LogMessage "Method 3 SUCCESS: Removed using CIM method" -Level 'SUCCESS'
                $successCount++
            } else {
                Write-LogMessage "Method 3 FAILED: All removal methods exhausted" -Level 'ERROR'
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
Write-LogMessage "Total errors encountered: $($script:ErrorsEncountered.Count)" -Level 'INFO'

if ($script:ErrorsEncountered.Count -gt 0) {
    Write-LogMessage "--- Error Details ---" -Level 'ERROR'
    for ($i = 0; $i -lt $script:ErrorsEncountered.Count; $i++) {
        Write-LogMessage "  Error $($i + 1): $($script:ErrorsEncountered[$i])" -Level 'ERROR'
    }
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
