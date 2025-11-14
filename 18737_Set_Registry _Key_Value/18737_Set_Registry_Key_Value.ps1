<#
SCRIPT NAME             18737_Set_Registry_Key_Value.ps1
IN REPOSITORY           No
AUTHOR & EMAIL          Vivek: vivek.f.vivek@capgemini.com
COMPANY                 Capgemini
TAGS                    Remediation
STATUS                  draft
DATE OF CHANGES         Nov 14th, 2025  
VERSION                 1.0
RELEASENOTES            NA
APPROVED                No
SUPPORT                 NA
DEX TOOLS               NA
DEPENDENCIES            - PowerShell 5.1 or later (Windows 10/11 default)
                        - Administrator privileges to run the script
                        - Registry path must exist prior to running the script
                        - Ensure the script has write permissions to that directory.
                        - The script expects 4 arguments:<RegistryPath> <ValueName> <ValueType> <NewValue>
                        - Valid ValueTypes: DWord, QWord, String, ExpandString, MultiString, Binary
CONTEXT                 User
OS                      Windows
SYNOPSIS                Sets a registry key value using arguments passed by the user without prompting.
DESCRIPTION             This script sets a specified registry key value using arguments passed from batch file. It logs all operations, backs up existing values, and includes error handling using try-catch.
INPUTS                  Arguments passed from batch file:
                            - $args[0]: The full registry path where the key is located.
                            - $args[1]: The name of the registry value to set.
                            - $args[2]: The type of the registry value (e.g., DWord, String).
                            - $args[3]: The new value to set for the registry key.
OUTPUTS                 Log messages indicating:
                            - Whether the registry path exists.
                            - Backup of current value before change.
                            - Whether the value was set successfully.
                            - Any errors encountered during execution.

VARIABLE DESCRIPTION    $MyInvocation = It contains information about how script, function, or command was invoked. For creating log file name
                        $ScriptName = Stores the full path of the script file (from $MyInvocation.ScriptName).
                        $ScriptPath = Stores only the folder(directory)path where the script is located.
                        $Logfile = Path to the log file where script activity messages will be written.
                        $RegistryPath = The full registry path where the key is located, passed as first argument.
                        $ValueName = The name of the registry value to set, passed as second argument.
                        $NewValue = The new value to set for the registry key, passed as third argument.
                        $CurrentValue = Stores the current value of the registry key before modification.
EXAMPLE                 .\18737_Set_Registry _Key_Value.bat "HKLM:\SOFTWARE\YourPath" "YourValueName" "DWord" "1"
                        Or
                        .\18737_Set_Registry_Key_Value.ps1 "registry path" "YourValueName" "ValueType" "value"
LOGIC DOCUMENT          NA          
#>

# Get registry settings from arguments
$RegistryPath = $args[0]
$ValueName    = $args[1]
$ValueType    = $args[2]
$NewValue     = $args[3]

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

# Check if running as administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    LogMessage "This script must be run as Administrator. Please run PowerShell as Administrator and try again."
    exit 1
}

# Validate arguments
if ($args.Count -lt 4) {
    LogMessage "ERROR: Missing required arguments. Usage: script.ps1 <RegistryPath> <ValueName> <ValueType> <NewValue>"
    LogMessage "Script execution failed"
    exit 1
}

# Validate ValueType
$validTypes = @("DWord","QWord","String","ExpandString","MultiString","Binary")
if ($ValueType -notin $validTypes) {
    LogMessage "ERROR: Invalid ValueType '$ValueType'. Valid types: $($validTypes -join ', ')"
    exit 1
}

# Validate NewValue based on ValueType
switch ($ValueType) {
    "DWord" { 
        if ($NewValue -notmatch '^\d+$') { 
            LogMessage "ERROR: NewValue must be numeric for DWord"; exit 1 
        } 
        $NewValue = [int]$NewValue 
    }
    "QWord" { 
        if ($NewValue -notmatch '^\d+$') { 
            LogMessage "ERROR: NewValue must be numeric for QWord"; exit 1 
        } 
        $NewValue = [long]$NewValue 
    }
    "MultiString" { 
        $NewValue = $NewValue -split ',' 
    }
    "Binary" { 
        try {
            # Only accept binary values (containing only 0 and 1)
            if ($NewValue -match '^[01]+$') {
                # Valid binary string (e.g., "10101")
                # Convert binary to decimal first
                $decimalValue = [Convert]::ToInt64($NewValue, 2)
                
                # Convert decimal to byte array
                if ($decimalValue -le 255) {
                    # Single byte
                    $NewValue = [byte[]]@([byte]$decimalValue)
                } else {
                    # Multiple bytes - convert to hex then split into bytes
                    $hexString = $decimalValue.ToString("X")
                    if ($hexString.Length % 2 -ne 0) { $hexString = "0" + $hexString }
                    $hexPairs = @()
                    for ($i = 0; $i -lt $hexString.Length; $i += 2) {
                        $hexPairs += $hexString.Substring($i, 2)
                    }
                    $NewValue = $hexPairs | ForEach-Object { [Convert]::ToByte($_, 16) }
                }
            }
            else {
                throw "Invalid binary format. Binary values must contain only 0 and 1 digits (e.g., '10101', '11110000')"
            }
        }
        catch {
            LogMessage "ERROR: Invalid Binary value '$NewValue'. $_"
            LogMessage "Binary values must contain only 0 and 1 digits (e.g., '10101', '11110000')"
            exit 1
        }
    }
}

# Start logging
LogMessage "Script execution started"
LogMessage "Registry Path: $RegistryPath"

# Display binary values with both decimal and hex for clarity
if ($ValueType -eq "Binary") {
    $hexDisplay = ($NewValue | ForEach-Object { $_.ToString("X2") }) -join " "
    $decDisplay = ($NewValue | ForEach-Object { $_.ToString() }) -join " "
    LogMessage "Value Name: $ValueName / Value Type: $ValueType"
    LogMessage "Binary Value - Decimal: [$decDisplay] | Hex (as shown in Registry Editor): [$hexDisplay]"
} else {
    LogMessage "Value Name/ Value Type/ New Value: $ValueName / $ValueType / $NewValue"
}

try {
    # Check if registry path exists
    if (!(Test-Path $RegistryPath)) {
        LogMessage "ERROR: Registry path not found: $RegistryPath"
        LogMessage "Script execution failed"
        exit 1
    }

    LogMessage "Registry path exists: $RegistryPath"

    # Get current value if exists
    $CurrentValue = $null
    try {
        $item = Get-ItemProperty -Path $RegistryPath -Name $ValueName -ErrorAction Stop
        $CurrentValue = $item.$ValueName

        # Get the registry value type
        $regKey = Get-Item -Path $RegistryPath
        $valueType = ($regKey.GetValueKind($ValueName)).ToString()

        if ([string]::IsNullOrEmpty($CurrentValue)) {
            LogMessage "Value '$ValueName' exists but is empty. Type: $valueType"
        } 
        else {
        LogMessage "Current value of '$ValueName': $CurrentValue (Type: $valueType)"
        }
    }
    catch {
    LogMessage "Value '$ValueName' does not exist. It will be created."
    }

    # Set new value
    if ($null -eq $CurrentValue) {
        New-ItemProperty -Path $RegistryPath -Name $ValueName -Value $NewValue -PropertyType $ValueType -Force | Out-Null
        if ($ValueType -eq "Binary") {
            $hexDisplay = ($NewValue | ForEach-Object { $_.ToString("X2") }) -join " "
            LogMessage "Created new registry value '$ValueName' - Decimal: [$($NewValue -join ' ')] | Hex: [$hexDisplay] (Type: $ValueType)"
        } else {
            LogMessage "Created new registry value '$ValueName' with value '$NewValue' (Type: $ValueType)"
        }
    } elseif ($CurrentValue -ne $NewValue) {
        LogMessage "Backup: $ValueName was $CurrentValue at $RegistryPath"
        Set-ItemProperty -Path $RegistryPath -Name $ValueName -Value $NewValue -Force
        if ($ValueType -eq "Binary") {
            $hexDisplay = ($NewValue | ForEach-Object { $_.ToString("X2") }) -join " "
            LogMessage "Updated registry value '$ValueName' - Decimal: [$($NewValue -join ' ')] | Hex: [$hexDisplay] (Type: $ValueType)"
        } else {
            LogMessage "Updated registry value '$ValueName' from '$CurrentValue' to '$NewValue' (Type: $ValueType)"
        }
    } else {
        LogMessage "Registry value '$ValueName' already has the desired value: $CurrentValue"
        LogMessage "No changes required."
    }

    if ($ValueType -eq "Binary") {
        $hexDisplay = ($NewValue | ForEach-Object { $_.ToString("X2") }) -join " "
        LogMessage "SUCCESS: Registry key '$ValueName' set - Decimal: [$($NewValue -join ' ')] | Hex (Registry Editor shows): [$hexDisplay] at '$RegistryPath'"
        LogMessage "NOTE: Registry Editor will display the hex values: $hexDisplay"
    } else {
        LogMessage "SUCCESS: Registry key '$ValueName' set to '$NewValue' at '$RegistryPath'"
    }
    LogMessage "Script execution completed successfully"

} catch {
    LogMessage "ERROR: $($_.Exception.Message)"
    LogMessage "Script execution failed"
    exit 1
}