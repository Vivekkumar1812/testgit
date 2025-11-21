# 19148_Remove_FireEye_Agent.ps1

Purpose
-------
This repository contains `19148_Remove_FireEye_Agent.ps1`, a PowerShell script that detects and removes FireEye Agent installations from Windows systems. The script runs multiple uninstall methods (MSI product code via msiexec, and CIM uninstall) and performs pre/post validation with logging and timeouts.

Prerequisites
-------------
- Windows 10/11 or compatible Windows Server.
- PowerShell 5.1 or later.
- Administrator privileges (required). The included batch launcher will prompt for elevation.

Files
-----
- `19148_Remove_FireEye_Agent.ps1` — Main PowerShell script to detect and remove FireEye Agent.
- `Run_Remove_FireEye_Agent.bat` — Simple launcher that runs the PowerShell script elevated and forwards arguments.
- `README.md` — This file.

How to run
----------
1. Open an elevated Command Prompt or double-click `Run_Remove_FireEye_Agent.bat` (it will prompt for elevation).
2. From PowerShell (elevated), run:

```powershell
# Default run (uses default 300s timeout)
.\19148_Remove_FireEye_Agent.ps1

# Run with product code and custom timeout (example)
.\19148_Remove_FireEye_Agent.ps1 -ProductCode "{12345678-1234-1234-1234-123456789012}" -TimeoutSeconds 600
```

Or from the launcher batch (forward args in quotes):

```bat
Run_Remove_FireEye_Agent.bat "-ProductCode {12345678-1234-1234-1234-123456789012} -TimeoutSeconds 600"
```

Log file
--------
The script writes a log file in the same directory where the script is located. The file name pattern is:

`<script-folder>\19148_Remove_FireEye_AgentLog.txt`

The log contains timestamped entries with severity: INFO, WARNING, ERROR, SUCCESS. Inspect this file after execution for details and troubleshooting.

Timeouts and tuning
-------------------
- Default `-TimeoutSeconds` is 300 (seconds). It controls discovery and uninstall waits.
- Increase for slow or production systems (e.g., 600–1200) if uninstalls commonly run longer than the default.

Exit codes
----------
- 0: Success — uninstalled and verified with no errors.
- 2: Warning — uninstalled but verification found residuals.
- 1: Failure — uninstall failed or critical errors occurred.

Notes & recommendations
-----------------------
- The script currently uses CIM (`Win32_Product`) for discovery and uninstall fallback. Running `Win32_Product` can cause MSI repair/configuration actions. Consider updating discovery to registry-based enumeration to avoid side effects.
- If you want different timeouts for discovery versus uninstall operations, request an update to add `-DiscoveryTimeoutSeconds` and `-UninstallTimeoutSeconds` parameters.
- For automation (SCCM, Intune, Orchestrator), capture and inspect logs and set a higher timeout if needed.

Troubleshooting
---------------
- If the script reports `MSI Error 1618`, another installation is in progress. Retry after the other install completes or add retry/backoff logic.
- If the script times out during discovery, increase `-TimeoutSeconds` or run discovery manually to inspect installed MSIs.

Contact
-------
Author: Vivek — vivek.f.vivek@capgemini.com
Company: Capgemini

---

If you want, I can:
- Add `-DiscoveryTimeoutSeconds` and `-UninstallTimeoutSeconds` and update the launcher and README; or
- Replace the CIM discovery with registry-based detection for safety and speed; or
- Add a `-WhatIf`/`-DryRun` mode to show planned actions without performing them.
Tell me which and I’ll implement it and run a syntax check.