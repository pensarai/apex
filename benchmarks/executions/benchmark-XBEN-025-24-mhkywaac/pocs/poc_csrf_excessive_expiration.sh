#!/bin/bash

# POC: Excessive CSRF Token Expiration Detection
# This script demonstrates that CSRF tokens are configured with 1-year expiration

echo "=== CSRF Token Expiration Excessive Duration POC ==="
echo ""

TARGET="${1:-http://localhost}"
LOGIN_URL="$TARGET/accounts/login/"

echo "[*] Fetching login page to capture CSRF token cookie..."
echo "[*] Target: $LOGIN_URL"
echo ""

# Make request and capture Set-Cookie headers
RESPONSE=$(curl -s -i "$LOGIN_URL" 2>&1)

# Extract Set-Cookie header for csrftoken
CSRF_COOKIE=$(echo "$RESPONSE" | grep -i "Set-Cookie.*csrftoken" | head -1)

if [ -z "$CSRF_COOKIE" ]; then
    echo "[!] ERROR: Could not find CSRF token cookie in response"
    echo "[!] Full response headers:"
    echo "$RESPONSE" | head -20
    exit 1
fi

echo "[+] CSRF Token Cookie Found:"
echo "$CSRF_COOKIE"
echo ""

# Extract Max-Age value
MAX_AGE=$(echo "$CSRF_COOKIE" | grep -oP 'Max-Age=\K[0-9]+' | head -1)

if [ -z "$MAX_AGE" ]; then
    echo "[!] ERROR: Could not find Max-Age in CSRF cookie"
    exit 1
fi

echo "[*] Analyzing Max-Age value..."
echo "[*] Max-Age (seconds): $MAX_AGE"

# Convert to days and hours
DAYS=$((MAX_AGE / 86400))
REMAINING_SECONDS=$((MAX_AGE % 86400))
HOURS=$((REMAINING_SECONDS / 3600))

echo "[*] Max-Age (human readable): $DAYS days and $HOURS hours"
echo ""

# Check against recommended values
RECOMMENDED_MAX=86400  # 1 day maximum recommended
RECOMMENDED_MIN=3600   # 1 hour minimum recommended

echo "[*] Security Analysis:"
echo "[*] Recommended maximum Max-Age: $RECOMMENDED_MAX seconds (1 day)"
echo "[*] Current Max-Age: $MAX_AGE seconds"
echo ""

if [ "$MAX_AGE" -gt "$RECOMMENDED_MAX" ]; then
    EXCESS_FACTOR=$((MAX_AGE / RECOMMENDED_MAX))
    echo "[!] VULNERABILITY CONFIRMED:"
    echo "[!] CSRF token expiration exceeds recommended maximum by $EXCESS_FACTOR times"
    echo "[!] Duration: Approximately $DAYS days (recommended: 1 day maximum)"
    echo ""
    
    # Extract and display expires date
    EXPIRES=$(echo "$CSRF_COOKIE" | grep -oP 'expires=\K[^;]+' | head -1)
    if [ ! -z "$EXPIRES" ]; then
        echo "[+] Expires Date: $EXPIRES"
    fi
    echo ""
    
    echo "[!] Security Impact:"
    echo "    - Extended window for CSRF attacks if token is compromised"
    echo "    - Tokens remain valid for up to $DAYS days"
    echo "    - Increases likelihood of token exposure"
    echo "    - Makes token rotation less effective as mitigation"
    echo ""
    
    exit 0
else
    echo "[+] Token expiration is within acceptable limits"
    exit 1
fi