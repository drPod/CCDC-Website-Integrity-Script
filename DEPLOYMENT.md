# CCDC Deployment Instructions

## Quick Reference

**Target Systems:**
- ✅ **Ubuntu Ecom** (Ubuntu 24) - E-commerce web server - **DEPLOY HERE**
- ⚠️ **Ubuntu Wkst** (Ubuntu 24) - Workstation - Optional, only if hosting web services
- ❌ **Web Server 2019** - Windows server - Not compatible (use Windows-specific solution)

---

## Ubuntu Ecom Deployment (Primary Target)

### Step 1: Transfer Files to Ubuntu Ecom

From your local machine (where you have git access):

```bash
# Clone or copy the repository
git clone <repository-url> web-integrity-monitor
cd web-integrity-monitor

# Transfer to Ubuntu Ecom (replace with actual IP/hostname)
scp -r * user@ubuntu-ecom:/tmp/web-integrity-monitor/
```

OR if you have direct access to Ubuntu Ecom:

```bash
# On Ubuntu Ecom
cd /tmp
git clone <repository-url> web-integrity-monitor
cd web-integrity-monitor
```

---

### Step 2: Install on Ubuntu Ecom

```bash
# SSH into Ubuntu Ecom
ssh user@ubuntu-ecom

# Navigate to the directory
cd /tmp/web-integrity-monitor

# Make scripts executable
chmod +x *.sh

# Run the installation script
sudo ./install.sh
```

**Expected Output:**
```
================================================
Web Integrity Monitor - Installation
================================================

[1/7] Installing Python script...
  ✓ Copied to /usr/local/bin/web-integrity-monitor
[2/7] Setting ownership to root...
  ✓ Owner set to root:root
[3/7] Setting secure permissions...
  ✓ Permissions set to 700 (rwx------)
[4/7] Creating baseline directory...
  ✓ Created /var/lib/web-integrity
[5/7] Setting immutable bit on script...
  ✓ Immutable bit set
[6/7] Installing systemd service and timer...
  ✓ Systemd service and timer created
[7/7] Creating initial baseline...

Creating baseline for web integrity monitoring...
[... list of files ...]

Installation Complete!
```

---

### Step 3: Enable Automated Monitoring

```bash
# Enable the systemd timer to run every 5 minutes
sudo systemctl enable web-integrity-monitor.timer

# Start the timer
sudo systemctl start web-integrity-monitor.timer

# Verify timer is running
sudo systemctl status web-integrity-monitor.timer
```

**Expected Output:**
```
● web-integrity-monitor.timer - Web Integrity Monitor Timer
     Loaded: loaded (/etc/systemd/system/web-integrity-monitor.timer; enabled)
     Active: active (waiting)
    Trigger: [next run time]
```

---

### Step 4: Verify Installation

```bash
# Run the test script
sudo ./test-installation.sh
```

All tests should pass or show only minor warnings.

---

### Step 5: Test Detection

Run a manual check to ensure everything works:

```bash
# Manual monitoring check with verbose output
sudo web-integrity-monitor --monitor --verbose
```

**Expected Output:**
```
Monitoring web integrity...
Baseline: /var/lib/web-integrity/baseline.json
Baseline contains: [number] files

Checking files...

============================================================
INTEGRITY CHECK SUMMARY
============================================================
Changed files:   0
New files:       0
Deleted files:   0
Unchanged files: [number]
============================================================

All files match baseline - No changes detected.
```

---

## Monitoring and Logs

### View Real-Time Alerts

```bash
# Watch syslog for alerts
sudo tail -f /var/log/syslog | grep web-integrity

# View systemd journal
sudo journalctl -u web-integrity-monitor -f
```

### Check Timer Status

```bash
# See when the next check will run
sudo systemctl list-timers web-integrity-monitor.timer

# View recent execution history
sudo journalctl -u web-integrity-monitor -n 20
```

---

## Ubuntu Wkst Deployment (Optional)

**Only deploy to Ubuntu Wkst if:**
- It's hosting web services
- You have development/staging sites running there
- Competition requirements specify it

If deploying to Wkst, follow the same steps as Ubuntu Ecom above.

---

## Operational Commands

### After Legitimate Changes (Updates/Deployments)

When you make authorized changes to the website:

```bash
# Temporarily remove immutable protection
sudo chattr -i /usr/local/bin/web-integrity-monitor

# Recreate baseline with new legitimate state
sudo web-integrity-monitor --baseline

# Restore immutable protection
sudo chattr +i /usr/local/bin/web-integrity-monitor
```

### Manual Integrity Check

```bash
# Run one-time check with detailed output
sudo web-integrity-monitor --monitor --verbose

# Silent check (returns exit code 1 if changes detected)
sudo web-integrity-monitor --monitor
```

### Stop Monitoring Temporarily

```bash
# Stop the timer
sudo systemctl stop web-integrity-monitor.timer

# Restart when ready
sudo systemctl start web-integrity-monitor.timer
```

---

## Troubleshooting

### Issue: "Permission denied" errors

**Solution:** Ensure you're running with sudo:
```bash
sudo web-integrity-monitor --monitor --verbose
```

### Issue: "No files found to monitor"

**Cause:** Default paths don't exist on your system.

**Solution:** Check what web server is running:
```bash
# Check for Apache
ls -la /etc/apache2/ /var/www/html/

# Check for Nginx
ls -la /etc/nginx/ /var/www/html/

# Check for custom app locations
ls -la /opt/ /srv/
```

Then edit the script to monitor the correct paths:
```bash
sudo chattr -i /usr/local/bin/web-integrity-monitor
sudo nano /usr/local/bin/web-integrity-monitor
# Edit the monitored_paths list
sudo chattr +i /usr/local/bin/web-integrity-monitor
sudo web-integrity-monitor --baseline
```

### Issue: Timer not running

**Solution:**
```bash
# Reload systemd
sudo systemctl daemon-reload

# Enable and start timer
sudo systemctl enable --now web-integrity-monitor.timer

# Check status
sudo systemctl status web-integrity-monitor.timer
```

### Issue: "Baseline file not found"

**Solution:** Create the baseline:
```bash
sudo web-integrity-monitor --baseline
```

---

## CCDC Competition Tips

1. **Deploy Early**: Install this in the first 15 minutes of competition
2. **Document Baseline**: Take note of when you created the baseline
3. **Monitor Logs**: Keep syslog visible in a terminal window
4. **Update After Changes**: Always update baseline after legitimate deployments
5. **Response Plan**: If defacement detected:
   - Investigate the change immediately
   - Check other security logs (auth.log, apache logs)
   - Restore from backup if defaced
   - Update baseline after restoration
   - Look for the entry point (check for backdoors)

---

## Alert Examples

### Normal Operation (Syslog)
```
Oct 25 10:30:01 ecom web-integrity-monitor[1234]: Integrity check completed: No changes detected
```

### Defacement Detected (Syslog)
```
Oct 25 10:35:42 ecom web-integrity-monitor[5678]: FILE MODIFIED: /var/www/html/index.html
Oct 25 10:35:42 ecom web-integrity-monitor[5678]: NEW FILE DETECTED: /var/www/html/shell.php
Oct 25 10:35:42 ecom web-integrity-monitor[5678]: Integrity check completed: 1 modified, 1 new, 0 deleted
```

---

## Files Included

- `web_integrity_monitor.py` - Main monitoring script
- `install.sh` - Automated installation and hardening
- `setup-cron.sh` - Alternative cron setup (if systemd unavailable)
- `test-installation.sh` - Verify installation
- `web-integrity-monitor.service` - Systemd service file
- `web-integrity-monitor.timer` - Systemd timer (5-minute interval)
- `README.md` - Complete documentation
- `CCDC_DELIVERABLE.md` - Competition deliverable with annotations
- `DEPLOYMENT.md` - This file

---

## Quick Command Reference

```bash
# Installation
sudo ./install.sh

# Enable monitoring
sudo systemctl enable --now web-integrity-monitor.timer

# Manual check
sudo web-integrity-monitor --monitor --verbose

# View logs
sudo tail -f /var/log/syslog | grep web-integrity

# Update baseline
sudo chattr -i /usr/local/bin/web-integrity-monitor
sudo web-integrity-monitor --baseline
sudo chattr +i /usr/local/bin/web-integrity-monitor

# Test installation
sudo ./test-installation.sh

# Check timer status
sudo systemctl list-timers web-integrity-monitor.timer
```

---

## Support During Competition

If issues arise during competition:

1. Check logs: `sudo journalctl -u web-integrity-monitor -n 50`
2. Verify timer: `sudo systemctl status web-integrity-monitor.timer`
3. Manual run: `sudo web-integrity-monitor --monitor --verbose`
4. Check permissions: `ls -la /usr/local/bin/web-integrity-monitor`
5. Check baseline: `ls -la /var/lib/web-integrity/`

Good luck with CCDC!
