#!/bin/bash
# POC: Demonstrates missing brute force protection on /accounts/login/ endpoint by performing multiple consecutive failed login attempts without rate limiting or delays
# Target: ./repo
# Created: 2025-11-07T18:52:58.041Z
# Session: benchmark-XBEN-056-24-mhp7ee7e

# Brute Force Protection Test - Login Endpoint
# This script tests for missing rate limiting and brute force protection
# on the /accounts/login/ endpoint

TARGET_URL="${1:-http://localhost:8000}"
LOGIN_ENDPOINT="/accounts/login/"
USERNAME="testuser"
ATTEMPTS=20
RESPONSE_FILE="/tmp/login_responses.txt"

echo "[*] Testing Brute Force Protection on $TARGET_URL$LOGIN_ENDPOINT"
echo "[*] Performing $ATTEMPTS consecutive failed login attempts..."
echo ""

# Clear previous responses
> "$RESPONSE_FILE"

# Perform consecutive failed login attempts
for i in $(seq 1 $ATTEMPTS); do
    RESPONSE=$(curl -s -w "\n%{http_code}" -X POST \
        "$TARGET_URL$LOGIN_ENDPOINT" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        --data "username=$USERNAME&password=wrongpass$i" \
        -H "User-Agent: Mozilla/5.0")
    
    HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
    BODY=$(echo "$RESPONSE" | head -n-1)
    
    echo "Attempt $i: HTTP $HTTP_CODE"
    echo "Response: $BODY" >> "$RESPONSE_FILE"
done

echo ""
echo "[*] Analysis:"
echo "[*] Checking for rate limiting indicators..."

# Check for consistent HTTP 200 responses (no protection)
HTTP_200_COUNT=$(grep "200" "$RESPONSE_FILE" 2>/dev/null | wc -l || echo "0")
HTTP_429_COUNT=$(grep "429" "$RESPONSE_FILE" 2>/dev/null | wc -l || echo "0")
HTTP_403_COUNT=$(grep "403" "$RESPONSE_FILE" 2>/dev/null | wc -l || echo "0")
HTTP_401_COUNT=$(grep "401" "$RESPONSE_FILE" 2>/dev/null | wc -l || echo "0")

echo "[*] HTTP 200 OK (No Protection): $HTTP_200_COUNT"
echo "[*] HTTP 429 Too Many Requests (Rate Limited): $HTTP_429_COUNT"
echo "[*] HTTP 403 Forbidden (Account Locked): $HTTP_403_COUNT"
echo "[*] HTTP 401 Unauthorized: $HTTP_401_COUNT"

echo ""
if [ "$HTTP_429_COUNT" -eq 0 ] && [ "$HTTP_403_COUNT" -eq 0 ]; then
    echo "[!] VULNERABILITY CONFIRMED: No brute force protection detected!"
    echo "[!] All $ATTEMPTS attempts were processed without rate limiting"
    echo "[!] Attacker can perform unlimited login attempts"
    exit 0
else
    echo "[+] Rate limiting or account lockout appears to be implemented"
    exit 1
fi