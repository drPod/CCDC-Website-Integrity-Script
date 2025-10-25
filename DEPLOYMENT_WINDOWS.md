# Windows Deployment Guide

## Quick Reference for Web Server 2019

**Target System:**
- ✅ **Web Server 2019** - IIS Web Server - **DEPLOY HERE**

---

## Deployment Methods

### Method 1: PowerShell Remote (From your workstation)

```powershell
# From your local machine or Wkst
# Replace with actual Web Server 2019 IP/hostname
$webServer = "web-server-ip"

# Copy files
$session = New-PSSession -ComputerName $webServer
Copy-Item -Path ".\*" -Destination "C:\Temp\web-integrity\" -ToSession $session -Recurse -Force
Remove-PSSession $session

# Run installation
Invoke-Command -ComputerName $webServer -ScriptBlock {
    cd C:\Temp\web-integrity
    .\Install-WebIntegrityMonitor.ps1
}
```

---

### Method 2: Direct Transfer (Recommended for CCDC)

**Transfer files to Web Server 2019:**
- Use RDP file share
- USB drive
- Network share
- Git clone (if available)

**On Web Server 2019:**

1. **Open PowerShell as Administrator**
   ```
   Right-click PowerShell -> Run as Administrator
   ```

2. **Navigate to the files**
   ```powershell
   cd C:\Path\To\web-integrity-monitor
   ```

3. **Enable script execution (if needed)**
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process -Force
   ```

4. **Run installation**
   ```powershell
   .\Install-WebIntegrityMonitor.ps1
   ```

---

## Installation Process

The installation script will:

1. ✅ Create `C:\Program Files\WebIntegrityMonitor\`
2. ✅ Copy script with Administrators-only permissions
3. ✅ Create `C:\ProgramData\WebIntegrityMonitor\` for baseline
4. ✅ Generate initial baseline of IIS files
5. ✅ Create scheduled task (runs every 5 minutes)
6. ✅ Configure Windows Event Log source

**Expected Output:**
```
============================================================
Web Integrity Monitor - Windows Installation
============================================================

[1/7] Checking source script...
  ✓ Source script found
[2/7] Creating installation directory...
  ✓ Created directory: C:\Program Files\WebIntegrityMonitor
[3/7] Installing script...
  ✓ Installed to: C:\Program Files\WebIntegrityMonitor\Web-IntegrityMonitor.ps1
[4/7] Setting secure permissions...
  ✓ Script secured (Administrators and SYSTEM only)
[5/7] Creating baseline directory...
  ✓ Created baseline directory: C:\ProgramData\WebIntegrityMonitor
[6/7] Creating initial baseline...
  [... lists files being hashed ...]
  ✓ Baseline created successfully
[7/7] Creating scheduled task (runs every 5 minutes)...
  ✓ Scheduled task created: Web Integrity Monitor

Installation Complete!
```

---

## Verification

### Check Installation

```powershell
# Run test script
.\Test-Installation.ps1

# Check scheduled task
Get-ScheduledTask -TaskName "Web Integrity Monitor"

# Verify baseline exists
Test-Path "C:\ProgramData\WebIntegrityMonitor\baseline.json"

# Manual test run
& "C:\Program Files\WebIntegrityMonitor\Web-IntegrityMonitor.ps1" -Monitor -Verbose
```

---

## Monitored Files (Default)

The Windows version monitors:

| Path | Description |
|------|-------------|
| `C:\inetpub\wwwroot` | IIS web content (recursive) |
| `C:\inetpub\*\web.config` | Web.config files |
| `C:\Windows\System32\inetsrv\config\applicationHost.config` | IIS main configuration |
| `C:\Windows\System32\inetsrv\config\*.config` | Other IIS configs |

---

## Monitoring and Alerts

### View Alerts in Event Viewer

**Method 1: Event Viewer GUI**
1. Open Event Viewer (`eventvwr.msc`)
2. Navigate to: **Windows Logs → Application**
3. Filter by Source: **WebIntegrityMonitor**

**Method 2: PowerShell**
```powershell
# View recent events
Get-EventLog -LogName Application -Source WebIntegrityMonitor -Newest 10

# Watch for new events (real-time)
Get-EventLog -LogName Application -Source WebIntegrityMonitor -After (Get-Date).AddMinutes(-5)

# Filter for alerts only (Event ID 4000)
Get-EventLog -LogName Application -Source WebIntegrityMonitor -InstanceId 4000 -Newest 20
```

### Alert Event IDs

| Event ID | Type | Description |
|----------|------|-------------|
| 1000 | Information | Normal operations, baseline created |
| 2000 | Warning | Summary of detected changes |
| 3000 | Error | Script errors, file access issues |
| 4000 | Error/Alert | **FILE MODIFIED/ADDED/DELETED** |

---

## Operational Commands

### Manual Monitoring Check

```powershell
# Verbose output (for manual checks)
& "C:\Program Files\WebIntegrityMonitor\Web-IntegrityMonitor.ps1" -Monitor -Verbose

# Silent mode (for automation)
& "C:\Program Files\WebIntegrityMonitor\Web-IntegrityMonitor.ps1" -Monitor
```

### Update Baseline (After Legitimate Changes)

```powershell
# Recreate baseline after authorized updates
& "C:\Program Files\WebIntegrityMonitor\Web-IntegrityMonitor.ps1" -Baseline
```

### Manage Scheduled Task

```powershell
# Check task status
.\Setup-ScheduledTask.ps1 -Action Status

# Disable temporarily
.\Setup-ScheduledTask.ps1 -Action Disable

# Re-enable
.\Setup-ScheduledTask.ps1 -Action Enable

# View task in Task Scheduler GUI
taskschd.msc
# Navigate to: Task Scheduler Library → Web Integrity Monitor
```

---

## Troubleshooting

### Issue: "Execution Policy" Error

**Error:**
```
File cannot be loaded because running scripts is disabled on this system
```

**Solution:**
```powershell
# Temporarily allow script execution
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force

# Then run the installation
.\Install-WebIntegrityMonitor.ps1
```

---

### Issue: "No files found to monitor"

**Cause:** IIS not installed or custom paths

**Solution:**
1. Check if IIS is installed:
   ```powershell
   Get-WindowsFeature -Name Web-Server
   ```

2. If using custom web paths, edit the script:
   ```powershell
   notepad "C:\Program Files\WebIntegrityMonitor\Web-IntegrityMonitor.ps1"
   # Edit the $MonitoredPaths array at the top
   ```

3. Recreate baseline:
   ```powershell
   & "C:\Program Files\WebIntegrityMonitor\Web-IntegrityMonitor.ps1" -Baseline
   ```

---

### Issue: Task Not Running

**Check task status:**
```powershell
Get-ScheduledTask -TaskName "Web Integrity Monitor" | Format-List *
```

**Check task history:**
1. Open Task Scheduler (`taskschd.msc`)
2. Find "Web Integrity Monitor"
3. Click "History" tab
4. Review recent runs

**Manually trigger task:**
```powershell
Start-ScheduledTask -TaskName "Web Integrity Monitor"
```

---

### Issue: Permission Denied

**Ensure you're running as Administrator:**
```powershell
# Check if running as admin
([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
# Should return: True
```

If False, close PowerShell and re-open with "Run as Administrator"

---

## CCDC Competition Tips

### 1. Deploy Immediately (First 15 minutes)

```powershell
# Quick deployment (copy-paste this entire block)
cd C:\Temp\web-integrity
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force
.\Install-WebIntegrityMonitor.ps1
```

### 2. Keep Event Viewer Open

- Filter: Source = WebIntegrityMonitor
- Refresh regularly or enable auto-refresh
- Watch for Event ID 4000 (alerts)

### 3. Baseline Updates

After deploying website updates:
```powershell
& "C:\Program Files\WebIntegrityMonitor\Web-IntegrityMonitor.ps1" -Baseline
```

### 4. Incident Response

If defacement detected:

1. **Review Event Log** - See exactly which files changed
2. **Check IIS Logs** - `C:\inetpub\logs\LogFiles\`
3. **Look for backdoors** - Common webshells: `*.aspx`, `cmd.aspx`, `shell.aspx`
4. **Restore from backup** - Or manually fix defaced files
5. **Update baseline** - After restoration
6. **Investigate entry point** - Review firewall, IIS logs, auth logs

---

## Example Alert Output

### Clean Check (No Changes)
```
============================================================
WEB INTEGRITY MONITOR - MONITORING CHECK
============================================================

Baseline created: 2025-10-25T15:30:00
Baseline contains: 47 files

Checking files...

============================================================
INTEGRITY CHECK SUMMARY
============================================================
Changed files:   0
New files:       0
Deleted files:   0
Unchanged files: 47
============================================================

All files match baseline - No changes detected
```

### Defacement Detected
```
Checking files...

  [MODIFIED] C:\inetpub\wwwroot\index.html
  [NEW] C:\inetpub\wwwroot\shell.aspx

============================================================
INTEGRITY CHECK SUMMARY
============================================================
Changed files:   1
New files:       1
Deleted files:   0
Unchanged files: 46
============================================================

WARNING: Changes detected! Review Event Log for details.
Event Viewer -> Windows Logs -> Application -> Source: WebIntegrityMonitor
```

**Corresponding Event Log:**
```
Event ID: 4000
Source: WebIntegrityMonitor
Type: Error
Message: ALERT: FILE MODIFIED: C:\inetpub\wwwroot\index.html

Event ID: 4000
Source: WebIntegrityMonitor
Type: Error
Message: ALERT: NEW FILE DETECTED: C:\inetpub\wwwroot\shell.aspx
```

---

## Quick Command Reference

```powershell
# Installation
.\Install-WebIntegrityMonitor.ps1

# Manual check (verbose)
& "C:\Program Files\WebIntegrityMonitor\Web-IntegrityMonitor.ps1" -Monitor -Verbose

# Update baseline
& "C:\Program Files\WebIntegrityMonitor\Web-IntegrityMonitor.ps1" -Baseline

# View recent alerts
Get-EventLog -LogName Application -Source WebIntegrityMonitor -InstanceId 4000 -Newest 10

# Check task status
.\Setup-ScheduledTask.ps1 -Action Status

# Test installation
.\Test-Installation.ps1

# View task in GUI
taskschd.msc

# View Event Viewer
eventvwr.msc
```

---

## Files Included (Windows)

- `Web-IntegrityMonitor.ps1` - Main monitoring script
- `Install-WebIntegrityMonitor.ps1` - Automated installation
- `Setup-ScheduledTask.ps1` - Task Scheduler configuration
- `Test-Installation.ps1` - Installation verification
- `DEPLOYMENT_WINDOWS.md` - This file

---

## Security Notes

- **Script Location:** `C:\Program Files\WebIntegrityMonitor\`
- **Permissions:** Administrators and SYSTEM only (NTFS ACLs)
- **Baseline:** `C:\ProgramData\WebIntegrityMonitor\baseline.json` (protected)
- **Execution:** Task Scheduler running as SYSTEM
- **Logging:** Windows Event Log (Application → WebIntegrityMonitor)
- **Interval:** Every 5 minutes + at system startup (2min delay)

---

Good luck with CCDC! 🏆
