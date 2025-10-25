<#
.SYNOPSIS
    Web Integrity Monitor for Windows - Defacement Detection System

.DESCRIPTION
    Monitors critical web server files for unauthorized changes using SHA-256 hashing.
    Logs alerts to Windows Event Log for SIEM integration.

.NOTES
    Author: Blue Team - CCDC Competition
    Requires: PowerShell 5.1+, Administrator privileges
    Platform: Windows Server 2016+, IIS
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [switch]$Baseline,

    [Parameter(Mandatory=$false)]
    [switch]$Monitor,

    [Parameter(Mandatory=$false)]
    [switch]$Verbose,

    [Parameter(Mandatory=$false)]
    [string]$BaselineFile = "$env:ProgramData\WebIntegrityMonitor\baseline.json"
)

# Ensure running as Administrator
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "This script must be run as Administrator"
    exit 1
}

# Event Log configuration
$EventLogName = "Application"
$EventSource = "WebIntegrityMonitor"

# Create event source if it doesn't exist
if (-not [System.Diagnostics.EventLog]::SourceExists($EventSource)) {
    try {
        New-EventLog -LogName $EventLogName -Source $EventSource -ErrorAction Stop
        Write-Host "Created Event Log source: $EventSource" -ForegroundColor Green
    } catch {
        Write-Warning "Could not create Event Log source: $_"
    }
}

# Default paths to monitor (IIS and common web locations)
$Script:MonitoredPaths = @(
    "C:\inetpub\wwwroot",
    "C:\inetpub\wwwroot\*\web.config",
    "C:\Windows\System32\inetsrv\config\applicationHost.config",
    "C:\Windows\System32\inetsrv\config\*.config",
    "C:\inetpub\*\web.config"
)

#region Helper Functions

function Write-LogInfo {
    param([string]$Message)

    Write-EventLog -LogName $EventLogName -Source $EventSource -EntryType Information -EventId 1000 -Message $Message -ErrorAction SilentlyContinue
}

function Write-LogWarning {
    param([string]$Message)

    Write-EventLog -LogName $EventLogName -Source $EventSource -EntryType Warning -EventId 2000 -Message $Message -ErrorAction SilentlyContinue
}

function Write-LogError {
    param([string]$Message)

    Write-EventLog -LogName $EventLogName -Source $EventSource -EntryType Error -EventId 3000 -Message $Message -ErrorAction SilentlyContinue
}

function Write-LogAlert {
    param([string]$Message)

    # Use Error level for alerts to ensure visibility
    Write-EventLog -LogName $EventLogName -Source $EventSource -EntryType Error -EventId 4000 -Message "ALERT: $Message" -ErrorAction SilentlyContinue
}

function Get-FileHashSHA256 {
    param([string]$FilePath)

    try {
        $hash = Get-FileHash -Path $FilePath -Algorithm SHA256 -ErrorAction Stop
        return $hash.Hash
    } catch {
        Write-LogError "Error hashing file ${FilePath}: $_"
        return $null
    }
}

function Get-MonitoredFiles {
    $files = @()

    foreach ($pathPattern in $Script:MonitoredPaths) {
        # Check if it's a directory
        if (Test-Path -Path $pathPattern -PathType Container) {
            # Recursively get all files
            $files += Get-ChildItem -Path $pathPattern -File -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName
        }
        # Check if it's a file
        elseif (Test-Path -Path $pathPattern -PathType Leaf) {
            $files += $pathPattern
        }
        # Try wildcard expansion
        else {
            $files += Get-ChildItem -Path $pathPattern -File -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName
        }
    }

    # Return unique absolute paths
    return $files | Select-Object -Unique | ForEach-Object { [System.IO.Path]::GetFullPath($_) }
}

function Initialize-BaselineDirectory {
    $baselineDir = Split-Path -Path $BaselineFile -Parent

    if (-not (Test-Path -Path $baselineDir)) {
        try {
            New-Item -Path $baselineDir -ItemType Directory -Force | Out-Null

            # Set NTFS permissions - Administrators only
            $acl = Get-Acl -Path $baselineDir
            $acl.SetAccessRuleProtection($true, $false)  # Disable inheritance

            # Add Administrators with Full Control
            $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                "BUILTIN\Administrators",
                "FullControl",
                "ContainerInherit,ObjectInherit",
                "None",
                "Allow"
            )
            $acl.AddAccessRule($adminRule)

            # Add SYSTEM with Full Control
            $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                "NT AUTHORITY\SYSTEM",
                "FullControl",
                "ContainerInherit,ObjectInherit",
                "None",
                "Allow"
            )
            $acl.AddAccessRule($systemRule)

            Set-Acl -Path $baselineDir -AclObject $acl

            Write-Host "Created baseline directory: $baselineDir" -ForegroundColor Green
        } catch {
            Write-LogError "Failed to create baseline directory: $_"
            Write-Error "Failed to create baseline directory: $_"
            exit 1
        }
    }
}

#endregion

#region Main Functions

function New-Baseline {
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "WEB INTEGRITY MONITOR - BASELINE CREATION" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host ""

    Initialize-BaselineDirectory

    Write-Host "Monitored paths:" -ForegroundColor Yellow
    $Script:MonitoredPaths | ForEach-Object { Write-Host "  - $_" }
    Write-Host ""

    $files = Get-MonitoredFiles

    if ($files.Count -eq 0) {
        Write-Warning "No files found to monitor. Check your paths."
        Write-LogWarning "No files found during baseline creation"
        return
    }

    Write-Host "Found $($files.Count) files to monitor" -ForegroundColor Green
    Write-Host ""

    $baseline = @{}
    $count = 0

    foreach ($file in $files) {
        $hash = Get-FileHashSHA256 -FilePath $file
        if ($hash) {
            $fileInfo = Get-Item -Path $file -ErrorAction SilentlyContinue
            $baseline[$file] = @{
                hash = $hash
                size = $fileInfo.Length
                lastWriteTime = $fileInfo.LastWriteTime.ToString("o")
            }
            $count++
            Write-Host "  [OK] $file" -ForegroundColor Gray
        }
    }

    # Create baseline object
    $baselineData = @{
        created = (Get-Date).ToString("o")
        computerName = $env:COMPUTERNAME
        files = $baseline
    }

    # Save to JSON
    try {
        $baselineData | ConvertTo-Json -Depth 10 | Out-File -FilePath $BaselineFile -Encoding UTF8 -Force

        # Secure the baseline file - Administrators only
        $acl = Get-Acl -Path $BaselineFile
        $acl.SetAccessRuleProtection($true, $false)

        $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            "BUILTIN\Administrators",
            "FullControl",
            "Allow"
        )
        $acl.AddAccessRule($adminRule)

        $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            "NT AUTHORITY\SYSTEM",
            "FullControl",
            "Allow"
        )
        $acl.AddAccessRule($systemRule)

        Set-Acl -Path $BaselineFile -AclObject $acl

        Write-Host ""
        Write-Host "============================================================" -ForegroundColor Cyan
        Write-Host "Baseline created successfully: $BaselineFile" -ForegroundColor Green
        Write-Host "Total files in baseline: $count" -ForegroundColor Green
        Write-Host "============================================================" -ForegroundColor Cyan

        Write-LogInfo "Baseline created with $count files"

    } catch {
        Write-LogError "Failed to save baseline: $_"
        Write-Error "Failed to save baseline: $_"
        exit 1
    }
}

function Start-Monitoring {
    param([bool]$VerboseOutput = $false)

    if ($VerboseOutput) {
        Write-Host "============================================================" -ForegroundColor Cyan
        Write-Host "WEB INTEGRITY MONITOR - MONITORING CHECK" -ForegroundColor Cyan
        Write-Host "============================================================" -ForegroundColor Cyan
        Write-Host ""
    }

    # Load baseline
    if (-not (Test-Path -Path $BaselineFile)) {
        $msg = "Baseline file not found: $BaselineFile. Run with -Baseline first."
        Write-LogError $msg
        Write-Error $msg
        exit 1
    }

    try {
        $baselineData = Get-Content -Path $BaselineFile -Raw | ConvertFrom-Json
    } catch {
        Write-LogError "Failed to load baseline: $_"
        Write-Error "Failed to load baseline: $_"
        exit 1
    }

    if ($VerboseOutput) {
        Write-Host "Baseline created: $($baselineData.created)" -ForegroundColor Gray
        Write-Host "Baseline contains: $($baselineData.files.PSObject.Properties.Count) files" -ForegroundColor Gray
        Write-Host ""
        Write-Host "Checking files..." -ForegroundColor Yellow
        Write-Host ""
    }

    $currentFiles = Get-MonitoredFiles
    $baselineFiles = $baselineData.files.PSObject.Properties.Name

    $changedFiles = @()
    $newFiles = @()
    $deletedFiles = @()
    $unchangedCount = 0

    # Check current files
    foreach ($file in $currentFiles) {
        if ($file -in $baselineFiles) {
            $currentHash = Get-FileHashSHA256 -FilePath $file
            if ($currentHash -and $currentHash -ne $baselineData.files.$file.hash) {
                $changedFiles += $file
                Write-LogAlert "FILE MODIFIED: $file"
                if ($VerboseOutput) {
                    Write-Host "  [MODIFIED] $file" -ForegroundColor Red
                }
            } else {
                $unchangedCount++
            }
        } else {
            $newFiles += $file
            Write-LogAlert "NEW FILE DETECTED: $file"
            if ($VerboseOutput) {
                Write-Host "  [NEW] $file" -ForegroundColor Yellow
            }
        }
    }

    # Check for deleted files
    foreach ($file in $baselineFiles) {
        if ($file -notin $currentFiles) {
            $deletedFiles += $file
            Write-LogAlert "FILE DELETED: $file"
            if ($VerboseOutput) {
                Write-Host "  [DELETED] $file" -ForegroundColor Magenta
            }
        }
    }

    # Summary
    if ($VerboseOutput) {
        Write-Host ""
        Write-Host "============================================================" -ForegroundColor Cyan
        Write-Host "INTEGRITY CHECK SUMMARY" -ForegroundColor Cyan
        Write-Host "============================================================" -ForegroundColor Cyan
        Write-Host "Changed files:   $($changedFiles.Count)" -ForegroundColor $(if ($changedFiles.Count -gt 0) { "Red" } else { "Green" })
        Write-Host "New files:       $($newFiles.Count)" -ForegroundColor $(if ($newFiles.Count -gt 0) { "Yellow" } else { "Green" })
        Write-Host "Deleted files:   $($deletedFiles.Count)" -ForegroundColor $(if ($deletedFiles.Count -gt 0) { "Magenta" } else { "Green" })
        Write-Host "Unchanged files: $unchangedCount" -ForegroundColor Green
        Write-Host "============================================================" -ForegroundColor Cyan
        Write-Host ""

        if ($changedFiles.Count -gt 0 -or $newFiles.Count -gt 0 -or $deletedFiles.Count -gt 0) {
            Write-Host "WARNING: Changes detected! Review Event Log for details." -ForegroundColor Red
            Write-Host "Event Viewer -> Windows Logs -> Application -> Source: WebIntegrityMonitor" -ForegroundColor Yellow
        } else {
            Write-Host "All files match baseline - No changes detected" -ForegroundColor Green
        }
    }

    # Log summary
    $summaryMsg = "Integrity check completed: $($changedFiles.Count) modified, $($newFiles.Count) new, $($deletedFiles.Count) deleted"
    if ($changedFiles.Count -gt 0 -or $newFiles.Count -gt 0 -or $deletedFiles.Count -gt 0) {
        Write-LogWarning $summaryMsg
        exit 1  # Exit with error code for Task Scheduler
    } else {
        Write-LogInfo $summaryMsg
        exit 0
    }
}

#endregion

#region Main Execution

if ($Baseline) {
    New-Baseline
}
elseif ($Monitor) {
    Start-Monitoring -VerboseOutput:$Verbose
}
else {
    # Show usage
    Write-Host @"
Web Integrity Monitor for Windows - Defacement Detection

Usage:
  .\Web-IntegrityMonitor.ps1 -Baseline          Create baseline hash database
  .\Web-IntegrityMonitor.ps1 -Monitor           Run monitoring check (silent)
  .\Web-IntegrityMonitor.ps1 -Monitor -Verbose  Run monitoring check (detailed output)

Examples:
  # Create initial baseline
  .\Web-IntegrityMonitor.ps1 -Baseline

  # Run monitoring check with verbose output
  .\Web-IntegrityMonitor.ps1 -Monitor -Verbose

  # Silent monitoring (for Task Scheduler)
  .\Web-IntegrityMonitor.ps1 -Monitor

Alerts are logged to:
  Event Viewer -> Windows Logs -> Application -> Source: WebIntegrityMonitor

"@ -ForegroundColor Cyan
}

#endregion
