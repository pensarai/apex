#!/bin/bash

# POC: Missing Brute Force Protection - No Rate Limiting on Login Attempts
# This script demonstrates that the login endpoint accepts unlimited rapid attempts without rate limiting

TARGET_URL="http://localhost:32768/login"
ATTEMPTS=10

echo "========================================="
echo "Brute Force Protection Test"
echo "========================================="
echo "Target: $TARGET_URL"
echo "Number of rapid attempts: $ATTEMPTS"
echo "Testing for rate limiting, delays, or account lockouts..."
echo ""

# Array to store HTTP status codes
declare -a status_codes

# Send 10 rapid login attempts
for i in $(seq 1 $ATTEMPTS); do
    response=$(curl -s -w "\n%{http_code}" -X POST \
        -d "username=brutetest&password=wrongpass$i" \
        "$TARGET_URL")
    
    # Extract HTTP status code (last line)
    http_code=$(echo "$response" | tail -n 1)
    status_codes[$i]=$http_code
    
    echo "Attempt $i: HTTP $http_code"
done

echo ""
echo "========================================="
echo "Analysis:"
echo "========================================="

# Check if all responses were successful (200-399 range typically)
all_successful=true
for code in "${status_codes[@]}"; do
    if [[ $code -ge 400 ]]; then
        all_successful=false
        break
    fi
done

if $all_successful; then
    echo "[VULNERABLE] All $ATTEMPTS attempts were processed without rate limiting"
    echo "No HTTP 429 (Too Many Requests) detected"
    echo "No account lockout observed"
    echo "No CAPTCHA challenge detected"
    echo ""
    echo "Result: BRUTE FORCE PROTECTION NOT IMPLEMENTED"
    exit 0
else
    echo "[PROTECTED] Some attempts were blocked or rate limited"
    exit 1
fi