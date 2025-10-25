#!/bin/bash
#
# Test Web Integrity Monitor Installation
# Verifies that the system is properly installed and configured
#

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}================================================${NC}"
echo -e "${GREEN}Web Integrity Monitor - Installation Test${NC}"
echo -e "${GREEN}================================================${NC}"
echo ""

ERRORS=0
WARNINGS=0

# Test 1: Check if running as root
echo -n "Checking root privileges... "
if [ "$EUID" -ne 0 ]; then
    echo -e "${YELLOW}WARNING${NC}"
    echo "  Not running as root. Some tests may fail."
    ((WARNINGS++))
else
    echo -e "${GREEN}OK${NC}"
fi

# Test 2: Check if script exists
echo -n "Checking script installation... "
if [ -f "/usr/local/bin/web-integrity-monitor" ]; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${RED}FAILED${NC}"
    echo "  Script not found at /usr/local/bin/web-integrity-monitor"
    ((ERRORS++))
fi

# Test 3: Check ownership
echo -n "Checking script ownership... "
if [ -f "/usr/local/bin/web-integrity-monitor" ]; then
    OWNER=$(stat -c '%U:%G' /usr/local/bin/web-integrity-monitor 2>/dev/null || stat -f '%Su:%Sg' /usr/local/bin/web-integrity-monitor 2>/dev/null)
    if [ "$OWNER" = "root:root" ]; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${RED}FAILED${NC}"
        echo "  Owner is $OWNER, should be root:root"
        ((ERRORS++))
    fi
fi

# Test 4: Check permissions
echo -n "Checking script permissions... "
if [ -f "/usr/local/bin/web-integrity-monitor" ]; then
    PERMS=$(stat -c '%a' /usr/local/bin/web-integrity-monitor 2>/dev/null || stat -f '%A' /usr/local/bin/web-integrity-monitor 2>/dev/null)
    if [ "$PERMS" = "700" ]; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${YELLOW}WARNING${NC}"
        echo "  Permissions are $PERMS, should be 700"
        ((WARNINGS++))
    fi
fi

# Test 5: Check immutable bit
echo -n "Checking immutable bit... "
if [ -f "/usr/local/bin/web-integrity-monitor" ]; then
    if lsattr /usr/local/bin/web-integrity-monitor 2>/dev/null | grep -q '^....i'; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${YELLOW}WARNING${NC}"
        echo "  Immutable bit not set"
        ((WARNINGS++))
    fi
else
    echo -e "${YELLOW}SKIPPED${NC}"
fi

# Test 6: Check baseline directory
echo -n "Checking baseline directory... "
if [ -d "/var/lib/web-integrity" ]; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${RED}FAILED${NC}"
    echo "  Directory /var/lib/web-integrity not found"
    ((ERRORS++))
fi

# Test 7: Check baseline file
echo -n "Checking baseline file... "
if [ -f "/var/lib/web-integrity/baseline.json" ]; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${YELLOW}WARNING${NC}"
    echo "  Baseline not created yet. Run: sudo web-integrity-monitor --baseline"
    ((WARNINGS++))
fi

# Test 8: Check systemd service
echo -n "Checking systemd service... "
if [ -f "/etc/systemd/system/web-integrity-monitor.service" ]; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${YELLOW}WARNING${NC}"
    echo "  Systemd service not installed"
    ((WARNINGS++))
fi

# Test 9: Check systemd timer
echo -n "Checking systemd timer... "
if [ -f "/etc/systemd/system/web-integrity-monitor.timer" ]; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${YELLOW}WARNING${NC}"
    echo "  Systemd timer not installed"
    ((WARNINGS++))
fi

# Test 10: Check timer status
echo -n "Checking timer activation... "
if systemctl is-active --quiet web-integrity-monitor.timer 2>/dev/null; then
    echo -e "${GREEN}ACTIVE${NC}"
elif systemctl is-enabled --quiet web-integrity-monitor.timer 2>/dev/null; then
    echo -e "${YELLOW}ENABLED (not started)${NC}"
    echo "  Run: sudo systemctl start web-integrity-monitor.timer"
    ((WARNINGS++))
else
    echo -e "${YELLOW}NOT ENABLED${NC}"
    echo "  Run: sudo systemctl enable --now web-integrity-monitor.timer"
    ((WARNINGS++))
fi

# Test 11: Check Python version
echo -n "Checking Python version... "
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
    echo -e "${GREEN}OK${NC} (Python $PYTHON_VERSION)"
else
    echo -e "${RED}FAILED${NC}"
    echo "  Python 3 not found"
    ((ERRORS++))
fi

# Test 12: Test script execution
echo -n "Testing script execution... "
if [ -f "/usr/local/bin/web-integrity-monitor" ]; then
    if /usr/local/bin/web-integrity-monitor --help &> /dev/null; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${RED}FAILED${NC}"
        echo "  Script cannot be executed"
        ((ERRORS++))
    fi
fi

# Summary
echo ""
echo -e "${GREEN}================================================${NC}"
echo -e "${GREEN}Test Summary${NC}"
echo -e "${GREEN}================================================${NC}"

if [ $ERRORS -eq 0 ] && [ $WARNINGS -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
    echo ""
    echo "Installation is complete and properly configured."
elif [ $ERRORS -eq 0 ]; then
    echo -e "${YELLOW}Tests passed with $WARNINGS warning(s)${NC}"
    echo ""
    echo "Installation is functional but has minor issues."
else
    echo -e "${RED}Tests failed with $ERRORS error(s) and $WARNINGS warning(s)${NC}"
    echo ""
    echo "Please review the errors above and fix the issues."
fi

echo ""
echo -e "${YELLOW}Next Steps:${NC}"

if [ ! -f "/var/lib/web-integrity/baseline.json" ]; then
    echo "1. Create baseline: ${GREEN}sudo web-integrity-monitor --baseline${NC}"
fi

if ! systemctl is-enabled --quiet web-integrity-monitor.timer 2>/dev/null; then
    echo "2. Enable timer: ${GREEN}sudo systemctl enable --now web-integrity-monitor.timer${NC}"
fi

echo "3. Test monitoring: ${GREEN}sudo web-integrity-monitor --monitor --verbose${NC}"
echo "4. View logs: ${GREEN}sudo journalctl -u web-integrity-monitor -f${NC}"
echo ""

exit $ERRORS
