# Quick Start Guide

## For CCDC Competition - Get Scripts onto Your VMs Fast

### Method 1: GitHub (Recommended if you have internet access)

**On your local machine:**
```bash
cd /Users/darshpoddar/Coding/ccdc_script
git add .
git commit -m "CCDC web integrity monitor"
git remote add origin https://github.com/YOUR_USERNAME/web-integrity-monitor.git
git push -u origin master
```

**On Ubuntu Ecom VM:**
```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/web-integrity-monitor.git
cd web-integrity-monitor

# Install
chmod +x *.sh
sudo ./install.sh

# Enable monitoring
sudo systemctl enable --now web-integrity-monitor.timer

# Done!
```

---

### Method 2: Direct SCP (No GitHub needed)

**From your local machine to Ubuntu Ecom:**
```bash
# Replace 'user' and 'ecom-ip' with actual credentials
scp -r /Users/darshpoddar/Coding/ccdc_script/* user@ecom-ip:/tmp/web-integrity/

# SSH into Ubuntu Ecom
ssh user@ecom-ip

# On Ubuntu Ecom:
cd /tmp/web-integrity
chmod +x *.sh
sudo ./install.sh
sudo systemctl enable --now web-integrity-monitor.timer
```

---

### Method 3: Create Tarball (For offline transfer)

**On your local machine:**
```bash
cd /Users/darshpoddar/Coding
tar -czf web-integrity-monitor.tar.gz ccdc_script/
```

Transfer `web-integrity-monitor.tar.gz` via USB or competition file sharing.

**On Ubuntu Ecom:**
```bash
tar -xzf web-integrity-monitor.tar.gz
cd ccdc_script/
chmod +x *.sh
sudo ./install.sh
sudo systemctl enable --now web-integrity-monitor.timer
```

---

## After Installation

**Verify it's working:**
```bash
# Check status
sudo systemctl status web-integrity-monitor.timer

# View next run time
sudo systemctl list-timers web-integrity-monitor.timer

# Manual test
sudo web-integrity-monitor --monitor --verbose

# Watch for alerts
sudo tail -f /var/log/syslog | grep web-integrity
```

**That's it! The system will now check for defacement every 5 minutes.**

---

## One-Line Installation (if files are already on the VM)

```bash
cd /path/to/web-integrity-monitor && chmod +x *.sh && sudo ./install.sh && sudo systemctl enable --now web-integrity-monitor.timer
```

---

See `DEPLOYMENT.md` for detailed instructions and troubleshooting.
