<#
.SYNOPSIS
    Installation script for Web Integrity Monitor on Windows

.DESCRIPTION
    Installs and configures the Web Integrity Monitor with security hardening
    and automated Task Scheduler configuration.

.NOTES
    Requires: Administrator privileges, PowerShell 5.1+
    Platform: Windows Server 2016+
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param()

# Colors for output
function Write-Step {
    param([string]$Message)
    Write-Host $Message -ForegroundColor Yellow
}

function Write-Success {
    param([string]$Message)
    Write-Host "  $([char]0x2713) $Message" -ForegroundColor Green
}

function Write-Failure {
    param([string]$Message)
    Write-Host "  [X] $Message" -ForegroundColor Red
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Web Integrity Monitor - Windows Installation" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# Define paths
$ScriptName = "Web-IntegrityMonitor.ps1"
$InstallDir = "C:\Program Files\WebIntegrityMonitor"
$InstallPath = Join-Path $InstallDir $ScriptName
$BaselineDir = "$env:ProgramData\WebIntegrityMonitor"

# Step 1: Check if source script exists
Write-Step "[1/7] Checking source script..."
if (-not (Test-Path -Path $ScriptName)) {
    Write-Failure "Source script '$ScriptName' not found in current directory"
    Write-Host ""
    Write-Host "Please run this installation script from the directory containing:" -ForegroundColor Red
    Write-Host "  - Web-IntegrityMonitor.ps1" -ForegroundColor Red
    Write-Host ""
    exit 1
}
Write-Success "Source script found"

# Step 2: Create installation directory
Write-Step "[2/7] Creating installation directory..."
try {
    if (-not (Test-Path -Path $InstallDir)) {
        New-Item -Path $InstallDir -ItemType Directory -Force | Out-Null
    }

    # Set NTFS permissions - Administrators and SYSTEM only
    $acl = Get-Acl -Path $InstallDir
    $acl.SetAccessRuleProtection($true, $false)  # Disable inheritance

    # Administrators - Full Control
    $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        "BUILTIN\Administrators",
        "FullControl",
        "ContainerInherit,ObjectInherit",
        "None",
        "Allow"
    )
    $acl.AddAccessRule($adminRule)

    # SYSTEM - Full Control
    $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        "NT AUTHORITY\SYSTEM",
        "FullControl",
        "ContainerInherit,ObjectInherit",
        "None",
        "Allow"
    )
    $acl.AddAccessRule($systemRule)

    Set-Acl -Path $InstallDir -AclObject $acl

    Write-Success "Created directory: $InstallDir"
} catch {
    Write-Failure "Failed to create installation directory: $_"
    exit 1
}

# Step 3: Copy script to installation directory
Write-Step "[3/7] Installing script..."
try {
    Copy-Item -Path $ScriptName -Destination $InstallPath -Force
    Write-Success "Installed to: $InstallPath"
} catch {
    Write-Failure "Failed to copy script: $_"
    exit 1
}

# Step 4: Secure the script file
Write-Step "[4/7] Setting secure permissions..."
try {
    $acl = Get-Acl -Path $InstallPath
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

    Set-Acl -Path $InstallPath -AclObject $acl

    Write-Success "Script secured (Administrators and SYSTEM only)"
} catch {
    Write-Failure "Failed to set permissions: $_"
    exit 1
}

# Step 5: Create baseline directory
Write-Step "[5/7] Creating baseline directory..."
try {
    if (-not (Test-Path -Path $BaselineDir)) {
        New-Item -Path $BaselineDir -ItemType Directory -Force | Out-Null
    }

    $acl = Get-Acl -Path $BaselineDir
    $acl.SetAccessRuleProtection($true, $false)

    $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        "BUILTIN\Administrators",
        "FullControl",
        "ContainerInherit,ObjectInherit",
        "None",
        "Allow"
    )
    $acl.AddAccessRule($adminRule)

    $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        "NT AUTHORITY\SYSTEM",
        "FullControl",
        "ContainerInherit,ObjectInherit",
        "None",
        "Allow"
    )
    $acl.AddAccessRule($systemRule)

    Set-Acl -Path $BaselineDir -AclObject $acl

    Write-Success "Created baseline directory: $BaselineDir"
} catch {
    Write-Failure "Failed to create baseline directory: $_"
    exit 1
}

# Step 6: Create initial baseline
Write-Step "[6/7] Creating initial baseline..."
Write-Host ""
try {
    & $InstallPath -Baseline
    if ($LASTEXITCODE -eq 0 -or $null -eq $LASTEXITCODE) {
        Write-Host ""
        Write-Success "Baseline created successfully"
    }
} catch {
    Write-Failure "Failed to create baseline: $_"
    exit 1
}

# Step 7: Set up scheduled task
Write-Step "[7/7] Creating scheduled task (runs every 5 minutes)..."
try {
    $taskName = "Web Integrity Monitor"
    $taskDescription = "Monitors web files for defacement - CCDC Defense"

    # Remove existing task if present
    if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
    }

    # Create task action
    $action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$InstallPath`" -Monitor"

    # Create task trigger (every 5 minutes)
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 5) -RepetitionDuration ([TimeSpan]::MaxValue)

    # Additional trigger - at startup (delayed)
    $triggerStartup = New-ScheduledTaskTrigger -AtStartup
    $triggerStartup.Delay = "PT2M"  # 2 minutes after startup

    # Create task principal (run as SYSTEM)
    $principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest

    # Task settings
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RunOnlyIfNetworkAvailable:$false

    # Register the task
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger,$triggerStartup -Principal $principal -Settings $settings -Description $taskDescription -Force | Out-Null

    Write-Success "Scheduled task created: $taskName"
    Write-Host "    - Runs every 5 minutes" -ForegroundColor Gray
    Write-Host "    - Runs as SYSTEM" -ForegroundColor Gray
    Write-Host "    - Logs to Event Viewer -> Application -> WebIntegrityMonitor" -ForegroundColor Gray
} catch {
    Write-Failure "Failed to create scheduled task: $_"
    Write-Warning "You can create the task manually using Setup-ScheduledTask.ps1"
}

# Installation complete
Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Installation Complete!" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "Next Steps:" -ForegroundColor Yellow
Write-Host ""
Write-Host "1. Verify scheduled task:" -ForegroundColor White
Write-Host "   Get-ScheduledTask -TaskName 'Web Integrity Monitor'" -ForegroundColor Gray
Write-Host ""
Write-Host "2. View task history:" -ForegroundColor White
Write-Host "   Task Scheduler -> Task Scheduler Library -> Web Integrity Monitor" -ForegroundColor Gray
Write-Host ""
Write-Host "3. View alerts in Event Viewer:" -ForegroundColor White
Write-Host "   Event Viewer -> Windows Logs -> Application" -ForegroundColor Gray
Write-Host "   Filter by Source: WebIntegrityMonitor" -ForegroundColor Gray
Write-Host ""
Write-Host "4. Run manual check:" -ForegroundColor White
Write-Host "   & '$InstallPath' -Monitor -Verbose" -ForegroundColor Gray
Write-Host ""
Write-Host "5. Update baseline after legitimate changes:" -ForegroundColor White
Write-Host "   & '$InstallPath' -Baseline" -ForegroundColor Gray
Write-Host ""

Write-Host "Security Notes:" -ForegroundColor Yellow
Write-Host "  - Script location: $InstallPath" -ForegroundColor Gray
Write-Host "  - Permissions: Administrators and SYSTEM only" -ForegroundColor Gray
Write-Host "  - Baseline: $BaselineDir\baseline.json" -ForegroundColor Gray
Write-Host "  - Monitoring: Every 5 minutes via Task Scheduler" -ForegroundColor Gray
Write-Host "  - Alerts: Windows Event Log (Event ID 4000)" -ForegroundColor Gray
Write-Host ""
