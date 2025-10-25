#!/bin/bash
#
# Installation and Security Hardening Script
# Web Integrity Monitor for Ubuntu
#

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}ERROR: This script must be run as root${NC}"
    echo "Usage: sudo ./install.sh"
    exit 1
fi

echo -e "${GREEN}================================================${NC}"
echo -e "${GREEN}Web Integrity Monitor - Installation${NC}"
echo -e "${GREEN}================================================${NC}"
echo ""

# Define paths
SCRIPT_NAME="web_integrity_monitor.py"
INSTALL_DIR="/usr/local/bin"
INSTALL_PATH="$INSTALL_DIR/web-integrity-monitor"
BASELINE_DIR="/var/lib/web-integrity"
SYSTEMD_DIR="/etc/systemd/system"

# Check if source script exists
if [ ! -f "$SCRIPT_NAME" ]; then
    echo -e "${RED}ERROR: $SCRIPT_NAME not found in current directory${NC}"
    exit 1
fi

echo -e "${YELLOW}[1/7]${NC} Installing Python script..."
# Copy script to /usr/local/bin
cp "$SCRIPT_NAME" "$INSTALL_PATH"
echo -e "  ${GREEN}✓${NC} Copied to $INSTALL_PATH"

echo -e "${YELLOW}[2/7]${NC} Setting ownership to root..."
# Set ownership to root
chown root:root "$INSTALL_PATH"
echo -e "  ${GREEN}✓${NC} Owner set to root:root"

echo -e "${YELLOW}[3/7]${NC} Setting secure permissions..."
# Set permissions (read/execute for owner only)
chmod 700 "$INSTALL_PATH"
echo -e "  ${GREEN}✓${NC} Permissions set to 700 (rwx------)"

echo -e "${YELLOW}[4/7]${NC} Creating baseline directory..."
# Create baseline directory
mkdir -p "$BASELINE_DIR"
chown root:root "$BASELINE_DIR"
chmod 700 "$BASELINE_DIR"
echo -e "  ${GREEN}✓${NC} Created $BASELINE_DIR"

echo -e "${YELLOW}[5/7]${NC} Setting immutable bit on script..."
# Remove immutable bit if already set (for reinstallation)
chattr -i "$INSTALL_PATH" 2>/dev/null || true
# Set immutable bit
chattr +i "$INSTALL_PATH"
echo -e "  ${GREEN}✓${NC} Immutable bit set (use 'chattr -i' to modify)"

echo -e "${YELLOW}[6/7]${NC} Installing systemd service and timer..."

# Create systemd service file
cat > "$SYSTEMD_DIR/web-integrity-monitor.service" << 'EOF'
[Unit]
Description=Web Integrity Monitor - Defacement Detection
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/web-integrity-monitor --monitor
StandardOutput=journal
StandardError=journal
SyslogIdentifier=web-integrity-monitor

[Install]
WantedBy=multi-user.target
EOF

# Create systemd timer file (runs every 5 minutes)
cat > "$SYSTEMD_DIR/web-integrity-monitor.timer" << 'EOF'
[Unit]
Description=Web Integrity Monitor Timer (Every 5 minutes)
Requires=web-integrity-monitor.service

[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
AccuracySec=1s

[Install]
WantedBy=timers.target
EOF

# Set permissions on systemd files
chmod 644 "$SYSTEMD_DIR/web-integrity-monitor.service"
chmod 644 "$SYSTEMD_DIR/web-integrity-monitor.timer"

# Reload systemd
systemctl daemon-reload
echo -e "  ${GREEN}✓${NC} Systemd service and timer created"

echo -e "${YELLOW}[7/7]${NC} Creating initial baseline..."
echo ""
echo -e "${YELLOW}This will scan and hash all monitored files...${NC}"
echo ""

# Create baseline
"$INSTALL_PATH" --baseline

echo ""
echo -e "${GREEN}================================================${NC}"
echo -e "${GREEN}Installation Complete!${NC}"
echo -e "${GREEN}================================================${NC}"
echo ""
echo -e "${YELLOW}Next Steps:${NC}"
echo ""
echo "1. Enable and start the monitoring timer:"
echo -e "   ${GREEN}sudo systemctl enable web-integrity-monitor.timer${NC}"
echo -e "   ${GREEN}sudo systemctl start web-integrity-monitor.timer${NC}"
echo ""
echo "2. Check timer status:"
echo -e "   ${GREEN}sudo systemctl status web-integrity-monitor.timer${NC}"
echo ""
echo "3. View logs:"
echo -e "   ${GREEN}sudo journalctl -u web-integrity-monitor -f${NC}"
echo -e "   ${GREEN}sudo tail -f /var/log/syslog | grep web-integrity${NC}"
echo ""
echo "4. Manual check:"
echo -e "   ${GREEN}sudo web-integrity-monitor --monitor --verbose${NC}"
echo ""
echo "5. Recreate baseline after legitimate changes:"
echo -e "   ${GREEN}sudo chattr -i $INSTALL_PATH${NC}"
echo -e "   ${GREEN}sudo web-integrity-monitor --baseline${NC}"
echo -e "   ${GREEN}sudo chattr +i $INSTALL_PATH${NC}"
echo ""
echo -e "${YELLOW}Security Notes:${NC}"
echo "- Script is owned by root with 700 permissions"
echo "- Immutable bit is set (prevents modification/deletion)"
echo "- Baseline stored in $BASELINE_DIR (protected)"
echo "- Monitoring runs every 5 minutes via systemd timer"
echo "- Alerts logged to syslog and systemd journal"
echo ""
