<#
.SYNOPSIS
    Configure Task Scheduler for Web Integrity Monitor

.DESCRIPTION
    Creates or updates the scheduled task to run monitoring every 5 minutes.
    Can also be used to enable/disable/remove the task.

.PARAMETER Action
    Action to perform: Create, Enable, Disable, Remove, Status

.EXAMPLE
    .\Setup-ScheduledTask.ps1 -Action Create
    .\Setup-ScheduledTask.ps1 -Action Status
    .\Setup-ScheduledTask.ps1 -Action Disable

.NOTES
    Requires: Administrator privileges
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [ValidateSet('Create', 'Enable', 'Disable', 'Remove', 'Status')]
    [string]$Action = 'Create'
)

$TaskName = "Web Integrity Monitor"
$ScriptPath = "C:\Program Files\WebIntegrityMonitor\Web-IntegrityMonitor.ps1"

function Show-TaskStatus {
    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue

    if ($null -eq $task) {
        Write-Host "Task Status: NOT INSTALLED" -ForegroundColor Red
        Write-Host ""
        Write-Host "Run with -Action Create to install the task" -ForegroundColor Yellow
        return
    }

    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "Scheduled Task Status" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Task Name:    $($task.TaskName)" -ForegroundColor White
    Write-Host "State:        $($task.State)" -ForegroundColor $(if ($task.State -eq 'Ready') { 'Green' } else { 'Yellow' })
    Write-Host "Enabled:      $(-not $task.Settings.Enabled)" -ForegroundColor $(if ($task.Settings.Enabled) { 'Green' } else { 'Red' })
    Write-Host "Last Run:     $($task.LastTaskResult)" -ForegroundColor Gray

    # Get last run time
    $taskInfo = Get-ScheduledTaskInfo -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($taskInfo) {
        Write-Host "Last Runtime: $($taskInfo.LastRunTime)" -ForegroundColor Gray
        Write-Host "Next Runtime: $($taskInfo.NextRunTime)" -ForegroundColor Gray
    }

    Write-Host ""
    Write-Host "Triggers:" -ForegroundColor Yellow
    foreach ($trigger in $task.Triggers) {
        Write-Host "  - $($trigger.GetType().Name): Every $($trigger.Repetition.Interval)" -ForegroundColor Gray
    }

    Write-Host ""
    Write-Host "Actions:" -ForegroundColor Yellow
    foreach ($action in $task.Actions) {
        Write-Host "  - Execute: $($action.Execute)" -ForegroundColor Gray
        Write-Host "    Arguments: $($action.Arguments)" -ForegroundColor Gray
    }
    Write-Host ""
}

switch ($Action) {
    'Create' {
        Write-Host "Creating scheduled task..." -ForegroundColor Yellow
        Write-Host ""

        # Check if script exists
        if (-not (Test-Path -Path $ScriptPath)) {
            Write-Host "ERROR: Script not found at $ScriptPath" -ForegroundColor Red
            Write-Host "Please run Install-WebIntegrityMonitor.ps1 first" -ForegroundColor Yellow
            exit 1
        }

        # Remove existing task if present
        if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
            Write-Host "Removing existing task..." -ForegroundColor Gray
            Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        }

        try {
            # Create task action
            $action = New-ScheduledTaskAction -Execute "PowerShell.exe" `
                -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$ScriptPath`" -Monitor"

            # Create task trigger (every 5 minutes, indefinitely)
            $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) `
                -RepetitionInterval (New-TimeSpan -Minutes 5) `
                -RepetitionDuration ([TimeSpan]::MaxValue)

            # Additional trigger - at startup (delayed 2 minutes)
            $triggerStartup = New-ScheduledTaskTrigger -AtStartup
            $triggerStartup.Delay = "PT2M"

            # Create task principal (run as SYSTEM with highest privileges)
            $principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" `
                -LogonType ServiceAccount `
                -RunLevel Highest

            # Task settings
            $settings = New-ScheduledTaskSettingsSet `
                -AllowStartIfOnBatteries `
                -DontStopIfGoingOnBatteries `
                -StartWhenAvailable `
                -RunOnlyIfNetworkAvailable:$false `
                -MultipleInstances IgnoreNew

            # Register the task
            Register-ScheduledTask `
                -TaskName $TaskName `
                -Action $action `
                -Trigger $trigger,$triggerStartup `
                -Principal $principal `
                -Settings $settings `
                -Description "Monitors web files for defacement - CCDC Defense" `
                -Force | Out-Null

            Write-Host "Scheduled task created successfully!" -ForegroundColor Green
            Write-Host ""
            Show-TaskStatus

        } catch {
            Write-Host "ERROR: Failed to create task: $_" -ForegroundColor Red
            exit 1
        }
    }

    'Enable' {
        $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        if ($null -eq $task) {
            Write-Host "ERROR: Task not found. Run with -Action Create first." -ForegroundColor Red
            exit 1
        }

        Enable-ScheduledTask -TaskName $TaskName | Out-Null
        Write-Host "Task enabled successfully" -ForegroundColor Green
        Show-TaskStatus
    }

    'Disable' {
        $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        if ($null -eq $task) {
            Write-Host "ERROR: Task not found." -ForegroundColor Red
            exit 1
        }

        Disable-ScheduledTask -TaskName $TaskName | Out-Null
        Write-Host "Task disabled successfully" -ForegroundColor Yellow
    }

    'Remove' {
        $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        if ($null -eq $task) {
            Write-Host "Task is not installed" -ForegroundColor Yellow
            exit 0
        }

        Write-Host "Removing scheduled task..." -ForegroundColor Yellow
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-Host "Task removed successfully" -ForegroundColor Green
    }

    'Status' {
        Show-TaskStatus
    }
}
