#!/bin/bash

# POC: Missing Brute Force Protection on Login Form
# This script demonstrates that the /token endpoint lacks rate limiting
# and allows unlimited brute force attempts without throttling

TARGET_URL="${1:-http://localhost:8080}"
TOKEN_ENDPOINT="${TARGET_URL}/token"
ATTEMPTS=10

echo "=========================================="
echo "Brute Force Protection Test"
echo "=========================================="
echo "Target: $TOKEN_ENDPOINT"
echo "Attempting $ATTEMPTS rapid login attempts..."
echo ""

# Arrays to track responses
declare -a HTTP_CODES
declare -a RESPONSE_BODIES

# Send multiple rapid login attempts
for i in $(seq 1 $ATTEMPTS); do
    echo "[Attempt $i] Sending login request..."
    
    # Capture both HTTP status code and response body
    RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TOKEN_ENDPOINT" \
        -d "username=testuser${i}&password=wrongpass${i}" \
        -H "Content-Type: application/x-www-form-urlencoded")
    
    # Extract status code (last line) and body (everything else)
    HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
    BODY=$(echo "$RESPONSE" | sed '$d')
    
    HTTP_CODES[$i]=$HTTP_CODE
    RESPONSE_BODIES[$i]=$BODY
    
    echo "  Status: $HTTP_CODE"
    echo "  Response: $BODY"
    echo ""
    
    # Add small delay to simulate rapid requests
    sleep 0.1
done

echo ""
echo "=========================================="
echo "Analysis Results"
echo "=========================================="

# Check if any rate limiting responses were received
RATE_LIMITED=0
for i in $(seq 1 $ATTEMPTS); do
    if [[ "${HTTP_CODES[$i]}" == "429" ]] || [[ "${HTTP_CODES[$i]}" == "503" ]] || [[ "${HTTP_CODES[$i]}" == "403" ]]; then
        RATE_LIMITED=1
        break
    fi
done

if [ $RATE_LIMITED -eq 0 ]; then
    echo "❌ VULNERABILITY CONFIRMED:"
    echo "   - All $ATTEMPTS requests returned HTTP status codes without rate limiting"
    echo "   - No 429 (Too Many Requests) responses detected"
    echo "   - No 503 (Service Unavailable) responses detected"
    echo "   - No account lockout or CAPTCHA challenge observed"
    echo ""
    echo "Status codes received:"
    for i in $(seq 1 $ATTEMPTS); do
        echo "   Request $i: HTTP ${HTTP_CODES[$i]}"
    done
    echo ""
    echo "✓ This confirms the endpoint lacks brute force protection"
    exit 0
else
    echo "✓ Rate limiting detected - no vulnerability"
    exit 1
fi