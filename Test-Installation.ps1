<#
.SYNOPSIS
    Test Web Integrity Monitor installation on Windows

.DESCRIPTION
    Verifies that the Web Integrity Monitor is properly installed and configured.

.NOTES
    Should be run as Administrator for complete testing
#>

[CmdletBinding()]
param()

$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Web Integrity Monitor - Installation Test" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

$Errors = 0
$Warnings = 0

# Test 1: Administrator privileges
Write-Host -NoNewline "Checking administrator privileges... "
if ($IsAdmin) {
    Write-Host "OK" -ForegroundColor Green
} else {
    Write-Host "WARNING" -ForegroundColor Yellow
    Write-Host "  Not running as Administrator. Some tests may fail." -ForegroundColor Yellow
    $Warnings++
}

# Test 2: Script installation
$ScriptPath = "C:\Program Files\WebIntegrityMonitor\Web-IntegrityMonitor.ps1"
Write-Host -NoNewline "Checking script installation... "
if (Test-Path -Path $ScriptPath) {
    Write-Host "OK" -ForegroundColor Green
} else {
    Write-Host "FAILED" -ForegroundColor Red
    Write-Host "  Script not found at $ScriptPath" -ForegroundColor Red
    $Errors++
}

# Test 3: Script permissions
Write-Host -NoNewline "Checking script permissions... "
if (Test-Path -Path $ScriptPath) {
    try {
        $acl = Get-Acl -Path $ScriptPath
        $adminAccess = $acl.Access | Where-Object { $_.IdentityReference -like "*Administrators*" }
        if ($adminAccess) {
            Write-Host "OK" -ForegroundColor Green
        } else {
            Write-Host "WARNING" -ForegroundColor Yellow
            Write-Host "  Administrators may not have full access" -ForegroundColor Yellow
            $Warnings++
        }
    } catch {
        Write-Host "WARNING" -ForegroundColor Yellow
        Write-Host "  Could not check permissions: $_" -ForegroundColor Yellow
        $Warnings++
    }
} else {
    Write-Host "SKIPPED" -ForegroundColor Gray
}

# Test 4: Baseline directory
$BaselineDir = "$env:ProgramData\WebIntegrityMonitor"
Write-Host -NoNewline "Checking baseline directory... "
if (Test-Path -Path $BaselineDir -PathType Container) {
    Write-Host "OK" -ForegroundColor Green
} else {
    Write-Host "FAILED" -ForegroundColor Red
    Write-Host "  Directory not found: $BaselineDir" -ForegroundColor Red
    $Errors++
}

# Test 5: Baseline file
$BaselineFile = Join-Path $BaselineDir "baseline.json"
Write-Host -NoNewline "Checking baseline file... "
if (Test-Path -Path $BaselineFile) {
    Write-Host "OK" -ForegroundColor Green
} else {
    Write-Host "WARNING" -ForegroundColor Yellow
    Write-Host "  Baseline not created yet" -ForegroundColor Yellow
    Write-Host "  Run: & '$ScriptPath' -Baseline" -ForegroundColor Yellow
    $Warnings++
}

# Test 6: Event Log source
Write-Host -NoNewline "Checking Event Log source... "
if ([System.Diagnostics.EventLog]::SourceExists("WebIntegrityMonitor")) {
    Write-Host "OK" -ForegroundColor Green
} else {
    Write-Host "WARNING" -ForegroundColor Yellow
    Write-Host "  Event Log source not created yet" -ForegroundColor Yellow
    Write-Host "  Will be created automatically on first run" -ForegroundColor Yellow
    $Warnings++
}

# Test 7: Scheduled task exists
$TaskName = "Web Integrity Monitor"
Write-Host -NoNewline "Checking scheduled task... "
$task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($task) {
    Write-Host "OK" -ForegroundColor Green
} else {
    Write-Host "WARNING" -ForegroundColor Yellow
    Write-Host "  Scheduled task not installed" -ForegroundColor Yellow
    Write-Host "  Run: .\Setup-ScheduledTask.ps1 -Action Create" -ForegroundColor Yellow
    $Warnings++
}

# Test 8: Scheduled task status
Write-Host -NoNewline "Checking task activation... "
if ($task) {
    if ($task.State -eq 'Ready') {
        Write-Host "READY" -ForegroundColor Green
    } elseif ($task.State -eq 'Disabled') {
        Write-Host "DISABLED" -ForegroundColor Yellow
        Write-Host "  Run: .\Setup-ScheduledTask.ps1 -Action Enable" -ForegroundColor Yellow
        $Warnings++
    } else {
        Write-Host $task.State -ForegroundColor Yellow
        $Warnings++
    }
} else {
    Write-Host "NOT INSTALLED" -ForegroundColor Yellow
    $Warnings++
}

# Test 9: PowerShell version
Write-Host -NoNewline "Checking PowerShell version... "
$psVersion = $PSVersionTable.PSVersion
if ($psVersion.Major -ge 5) {
    Write-Host "OK (v$psVersion)" -ForegroundColor Green
} else {
    Write-Host "WARNING" -ForegroundColor Yellow
    Write-Host "  PowerShell $psVersion found, 5.1+ recommended" -ForegroundColor Yellow
    $Warnings++
}

# Test 10: IIS installation
Write-Host -NoNewline "Checking IIS installation... "
$iisFeature = Get-WindowsFeature -Name Web-Server -ErrorAction SilentlyContinue
if ($iisFeature -and $iisFeature.Installed) {
    Write-Host "OK" -ForegroundColor Green
} else {
    Write-Host "WARNING" -ForegroundColor Yellow
    Write-Host "  IIS may not be installed" -ForegroundColor Yellow
    $Warnings++
}

# Test 11: Test script execution
Write-Host -NoNewline "Testing script execution... "
if (Test-Path -Path $ScriptPath) {
    try {
        $result = & $ScriptPath 2>&1
        if ($LASTEXITCODE -eq 0 -or $null -eq $LASTEXITCODE -or $result -like "*Usage:*") {
            Write-Host "OK" -ForegroundColor Green
        } else {
            Write-Host "WARNING" -ForegroundColor Yellow
            Write-Host "  Script executed but returned error code: $LASTEXITCODE" -ForegroundColor Yellow
            $Warnings++
        }
    } catch {
        Write-Host "FAILED" -ForegroundColor Red
        Write-Host "  Error executing script: $_" -ForegroundColor Red
        $Errors++
    }
} else {
    Write-Host "SKIPPED" -ForegroundColor Gray
}

# Summary
Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Test Summary" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

if ($Errors -eq 0 -and $Warnings -eq 0) {
    Write-Host "All tests passed!" -ForegroundColor Green
    Write-Host ""
    Write-Host "Installation is complete and properly configured." -ForegroundColor Green
}
elseif ($Errors -eq 0) {
    Write-Host "Tests passed with $Warnings warning(s)" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Installation is functional but has minor issues." -ForegroundColor Yellow
}
else {
    Write-Host "Tests failed with $Errors error(s) and $Warnings warning(s)" -ForegroundColor Red
    Write-Host ""
    Write-Host "Please review the errors above and fix the issues." -ForegroundColor Red
}

Write-Host ""
Write-Host "Next Steps:" -ForegroundColor Yellow
Write-Host ""

if (-not (Test-Path -Path $BaselineFile)) {
    Write-Host "1. Create baseline:" -ForegroundColor White
    Write-Host "   & '$ScriptPath' -Baseline" -ForegroundColor Gray
    Write-Host ""
}

if (-not $task) {
    Write-Host "2. Create scheduled task:" -ForegroundColor White
    Write-Host "   .\Setup-ScheduledTask.ps1 -Action Create" -ForegroundColor Gray
    Write-Host ""
}

Write-Host "3. Test monitoring:" -ForegroundColor White
Write-Host "   & '$ScriptPath' -Monitor -Verbose" -ForegroundColor Gray
Write-Host ""

Write-Host "4. View Event Log:" -ForegroundColor White
Write-Host "   Get-EventLog -LogName Application -Source WebIntegrityMonitor -Newest 10" -ForegroundColor Gray
Write-Host ""

Write-Host "5. Check task status:" -ForegroundColor White
Write-Host "   .\Setup-ScheduledTask.ps1 -Action Status" -ForegroundColor Gray
Write-Host ""

exit $Errors
