#!/bin/bash
#
# Setup Cron Job for Web Integrity Monitor
# Alternative to systemd timer
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}ERROR: This script must be run as root${NC}"
    echo "Usage: sudo ./setup-cron.sh"
    exit 1
fi

echo -e "${GREEN}================================================${NC}"
echo -e "${GREEN}Setting up Cron Job for Web Integrity Monitor${NC}"
echo -e "${GREEN}================================================${NC}"
echo ""

CRON_FILE="/etc/cron.d/web-integrity-monitor"

# Create cron job file
cat > "$CRON_FILE" << 'EOF'
# Web Integrity Monitor - Run every 5 minutes
# Alerts are logged to syslog

SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Run every 5 minutes
*/5 * * * * root /usr/local/bin/web-integrity-monitor --monitor 2>&1 | logger -t web-integrity-monitor

EOF

# Set proper permissions
chmod 644 "$CRON_FILE"
chown root:root "$CRON_FILE"

echo -e "${GREEN}✓${NC} Cron job created: $CRON_FILE"
echo ""
echo -e "${YELLOW}Cron Configuration:${NC}"
echo "  - Runs every 5 minutes"
echo "  - Runs as root user"
echo "  - Output logged to syslog"
echo ""
echo -e "${YELLOW}Verify cron job:${NC}"
echo -e "  ${GREEN}cat $CRON_FILE${NC}"
echo ""
echo -e "${YELLOW}View logs:${NC}"
echo -e "  ${GREEN}sudo tail -f /var/log/syslog | grep web-integrity${NC}"
echo ""
echo -e "${YELLOW}Test manually:${NC}"
echo -e "  ${GREEN}sudo /usr/local/bin/web-integrity-monitor --monitor --verbose${NC}"
echo ""
echo -e "${GREEN}Setup complete!${NC}"
echo ""
