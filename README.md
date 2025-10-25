# Web Integrity Monitor

A robust Python-based file integrity monitoring system designed to protect web servers from defacement attacks. This tool uses SHA-256 hashing to detect unauthorized changes to critical web server files and alerts administrators via syslog.

## Features

- **SHA-256 Hash-Based Detection**: Cryptographically secure file integrity verification
- **Comprehensive Monitoring**: Monitors web content, Apache/Nginx configs, and .htaccess files
- **Syslog Integration**: Real-time alerts logged to system syslog
- **Automated Scanning**: Runs every 5 minutes via systemd timer or cron
- **Security Hardened**: Root-owned with immutable bit set to prevent tampering
- **Baseline Management**: Easy baseline creation and updates
- **Detailed Reporting**: Detects modified, new, and deleted files

## Monitored Paths (Default)

- `/var/www/html` - Web content directory
- `/etc/apache2/*.conf` - Apache configuration files
- `/etc/apache2/sites-available/*` - Apache virtual host configs
- `/etc/apache2/sites-enabled/*` - Active Apache virtual hosts
- `/var/www/**/.htaccess` - htaccess files
- `/etc/nginx/*.conf` - Nginx configuration files
- `/etc/nginx/sites-available/*` - Nginx virtual host configs
- `/etc/nginx/sites-enabled/*` - Active Nginx virtual hosts

## Requirements

- **Operating System**: Ubuntu 20.04 LTS or later
- **Python**: Python 3.6+
- **Privileges**: Root access required
- **Dependencies**: Standard Python libraries only (no external packages)

## Installation

### Quick Install (Recommended)

1. Clone or download the repository:
```bash
cd /opt
sudo git clone <repository-url> web-integrity-monitor
cd web-integrity-monitor
```

2. Run the installation script:
```bash
sudo chmod +x install.sh
sudo ./install.sh
```

The installation script will:
- Copy the script to `/usr/local/bin/web-integrity-monitor`
- Set ownership to root:root
- Set permissions to 700 (rwx------)
- Set the immutable bit using `chattr +i`
- Create baseline directory at `/var/lib/web-integrity`
- Install systemd service and timer
- Create initial baseline of monitored files

### Manual Installation

If you prefer manual installation:

1. Copy the script:
```bash
sudo cp web_integrity_monitor.py /usr/local/bin/web-integrity-monitor
```

2. Set ownership and permissions:
```bash
sudo chown root:root /usr/local/bin/web-integrity-monitor
sudo chmod 700 /usr/local/bin/web-integrity-monitor
```

3. Set immutable bit:
```bash
sudo chattr +i /usr/local/bin/web-integrity-monitor
```

4. Create baseline directory:
```bash
sudo mkdir -p /var/lib/web-integrity
sudo chown root:root /var/lib/web-integrity
sudo chmod 700 /var/lib/web-integrity
```

5. Create initial baseline:
```bash
sudo /usr/local/bin/web-integrity-monitor --baseline
```

## Usage

### Create Baseline

After installation or after making legitimate changes to your website:

```bash
sudo web-integrity-monitor --baseline
```

This scans all monitored files and creates a baseline hash database.

### Manual Monitoring Check

Run a one-time integrity check with detailed output:

```bash
sudo web-integrity-monitor --monitor --verbose
```

Silent mode (for automation):

```bash
sudo web-integrity-monitor --monitor
```

### Add Custom Paths

To monitor additional directories:

```bash
sudo chattr -i /usr/local/bin/web-integrity-monitor
sudo web-integrity-monitor --add-path /opt/custom-webapp --baseline
sudo chattr +i /usr/local/bin/web-integrity-monitor
```

## Automation

### Option 1: Systemd Timer (Recommended)

Enable and start the monitoring timer:

```bash
sudo systemctl enable web-integrity-monitor.timer
sudo systemctl start web-integrity-monitor.timer
```

Check timer status:

```bash
sudo systemctl status web-integrity-monitor.timer
sudo systemctl list-timers web-integrity-monitor.timer
```

View service logs:

```bash
sudo journalctl -u web-integrity-monitor -f
```

### Option 2: Cron

If you prefer cron over systemd:

```bash
sudo chmod +x setup-cron.sh
sudo ./setup-cron.sh
```

This creates a cron job at `/etc/cron.d/web-integrity-monitor` that runs every 5 minutes.

## Monitoring and Alerts

### View Syslog Alerts

Real-time monitoring:

```bash
sudo tail -f /var/log/syslog | grep web-integrity
```

Search for alerts:

```bash
sudo grep "web-integrity-monitor" /var/log/syslog
```

### View Systemd Journal

```bash
sudo journalctl -t web-integrity-monitor -f
```

Recent entries:

```bash
sudo journalctl -t web-integrity-monitor -n 50
```

### Alert Types

The system logs different severity levels:

- **LOG_INFO**: Baseline created, normal operations
- **LOG_WARNING**: Summary of detected changes
- **LOG_ALERT**: Specific file modifications, additions, or deletions
- **LOG_ERR**: Errors during operation

## Security Features

### 1. Root Ownership
```bash
-rwx------ 1 root root /usr/local/bin/web-integrity-monitor
```
Only root can read, write, or execute the script.

### 2. Immutable Bit

The immutable bit prevents modification or deletion:

```bash
sudo lsattr /usr/local/bin/web-integrity-monitor
----i--------e------- /usr/local/bin/web-integrity-monitor
```

To modify the script (e.g., for updates):

```bash
# Remove immutable bit
sudo chattr -i /usr/local/bin/web-integrity-monitor

# Make changes or updates
# ...

# Restore immutable bit
sudo chattr +i /usr/local/bin/web-integrity-monitor
```

### 3. Protected Baseline

The baseline database is stored in `/var/lib/web-integrity/` with:
- Root ownership
- 700 permissions
- Protected from unauthorized access

### 4. Systemd Security Hardening

The systemd service includes:
- `PrivateTmp=yes` - Isolated /tmp directory
- `NoNewPrivileges=yes` - Prevents privilege escalation
- `ProtectSystem=strict` - Read-only /usr, /boot, /efi
- `ProtectHome=yes` - Home directories inaccessible

## Maintenance

### Update Baseline After Legitimate Changes

When you make authorized changes to your website:

```bash
# Remove immutable bit temporarily
sudo chattr -i /usr/local/bin/web-integrity-monitor

# Recreate baseline
sudo web-integrity-monitor --baseline

# Restore immutable bit
sudo chattr +i /usr/local/bin/web-integrity-monitor
```

### Check Current Status

```bash
# Run manual check
sudo web-integrity-monitor --monitor --verbose

# Check if timer is active
sudo systemctl is-active web-integrity-monitor.timer

# View next run time
sudo systemctl list-timers web-integrity-monitor.timer
```

### Disable Monitoring

Temporarily disable:

```bash
sudo systemctl stop web-integrity-monitor.timer
```

Permanently disable:

```bash
sudo systemctl disable web-integrity-monitor.timer
sudo systemctl stop web-integrity-monitor.timer
```

For cron:

```bash
sudo rm /etc/cron.d/web-integrity-monitor
```

## Troubleshooting

### Permission Denied Errors

Ensure you're running as root:

```bash
sudo web-integrity-monitor --monitor --verbose
```

### No Files Found to Monitor

Check if the default paths exist on your system:

```bash
ls -la /var/www/html
ls -la /etc/apache2
ls -la /etc/nginx
```

If using custom paths, add them to the monitoring list.

### Baseline File Not Found

Create a baseline first:

```bash
sudo web-integrity-monitor --baseline
```

### Timer Not Running

Check timer status:

```bash
sudo systemctl status web-integrity-monitor.timer
```

Reload systemd and restart:

```bash
sudo systemctl daemon-reload
sudo systemctl restart web-integrity-monitor.timer
```

### False Positives

Some files may change legitimately (e.g., log files, cache files). Consider:

1. Excluding specific directories
2. Recreating baseline after legitimate changes
3. Reviewing monitored paths in the script

## Integration with Security Tools

### SIEM Integration

Forward syslog to your SIEM:

```bash
# Configure rsyslog to forward web-integrity-monitor logs
sudo vim /etc/rsyslog.d/50-web-integrity.conf
```

Add:

```
:syslogtag, isequal, "web-integrity-monitor:" @@your-siem-server:514
```

### Email Alerts

Create a wrapper script that emails on changes:

```bash
#!/bin/bash
OUTPUT=$(/usr/local/bin/web-integrity-monitor --monitor --verbose)
if [ $? -ne 0 ]; then
    echo "$OUTPUT" | mail -s "Web Integrity Alert" admin@example.com
fi
```

### Slack/Teams Integration

Use a webhook to send alerts to Slack or Teams when changes are detected.

## File Structure

```
.
├── web_integrity_monitor.py          # Main Python script
├── install.sh                         # Automated installation script
├── setup-cron.sh                      # Cron setup script (alternative)
├── web-integrity-monitor.service      # Systemd service file
├── web-integrity-monitor.timer        # Systemd timer file
└── README.md                          # This file
```

## How It Works

1. **Baseline Creation**:
   - Scans all files in monitored paths
   - Calculates SHA-256 hash for each file
   - Stores hashes in `/var/lib/web-integrity/baseline.json`

2. **Monitoring**:
   - Runs every 5 minutes (via timer/cron)
   - Scans current files and calculates hashes
   - Compares against baseline
   - Detects:
     - Modified files (hash changed)
     - New files (not in baseline)
     - Deleted files (in baseline but missing)

3. **Alerting**:
   - Logs all changes to syslog with LOG_ALERT priority
   - Logs summary with LOG_WARNING priority
   - Sends to systemd journal
   - Can be forwarded to SIEM, email, or other tools

## Best Practices

1. **Regular Baseline Updates**: Update baseline after deploying legitimate changes
2. **Monitor the Monitors**: Ensure the timer/cron is running regularly
3. **Review Alerts Promptly**: Investigate all alerts immediately
4. **Test Recovery**: Practice responding to alerts
5. **Backup Baseline**: Keep a backup of your baseline file
6. **Secure Logs**: Ensure syslog is protected and backed up
7. **Document Changes**: Keep a change log for your website

## Security Considerations

- Script runs as root - ensure it's properly secured
- Baseline file contains file paths - protect it appropriately
- Logs may contain sensitive path information
- Immutable bit prevents tampering but can be removed by root
- Consider running on a separate monitoring server for critical environments

## License

This script is provided for defensive security purposes only.

## Support

For issues, questions, or contributions:
- Review the troubleshooting section
- Check systemd/syslog for detailed error messages
- Ensure all prerequisites are met

## Changelog

### Version 1.0
- Initial release
- SHA-256 hash-based integrity checking
- Syslog integration
- Systemd timer and cron support
- Immutable bit security
- Comprehensive monitoring of web server files
