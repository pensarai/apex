#!/bin/bash

# POC: No Brute Force Protection on Login Endpoint
# This script demonstrates the absence of rate limiting and account lockout mechanisms
# by performing multiple consecutive failed login attempts

TARGET_URL="http://localhost:5003/login"
USERNAME="testuser"
ATTEMPT_COUNT=15

echo "=========================================="
echo "Brute Force Protection Test"
echo "=========================================="
echo "Target: $TARGET_URL"
echo "Username: $USERNAME"
echo "Attempts: $ATTEMPT_COUNT"
echo ""

# Arrays to store results
declare -a HTTP_CODES
declare -a RESPONSE_TIMES
declare -a RESPONSES

echo "Executing $ATTEMPT_COUNT consecutive login attempts..."
echo ""

for i in $(seq 1 $ATTEMPT_COUNT); do
    START_TIME=$(date +%s%N)
    
    # Perform login attempt with unique password
    RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL" \
        -d "username=$USERNAME&password=attempt$i" \
        -H "Content-Type: application/x-www-form-urlencoded")
    
    END_TIME=$(date +%s%N)
    
    # Extract HTTP code (last line) and response body (everything else)
    HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
    BODY=$(echo "$RESPONSE" | head -n-1)
    
    # Calculate response time in milliseconds
    RESPONSE_TIME=$(( (END_TIME - START_TIME) / 1000000 ))
    
    HTTP_CODES[$i]=$HTTP_CODE
    RESPONSE_TIMES[$i]=$RESPONSE_TIME
    RESPONSES[$i]="$BODY"
    
    echo "Attempt $i: HTTP $HTTP_CODE | Response Time: ${RESPONSE_TIME}ms"
    
    # Check for rate limiting indicators
    if [[ "$HTTP_CODE" == "429" ]]; then
        echo "  [PROTECTED] Rate limiting detected (HTTP 429)"
    fi
    
    # Check for account lockout message
    if [[ "$BODY" =~ "locked" ]] || [[ "$BODY" =~ "Locked" ]] || [[ "$BODY" =~ "too many" ]]; then
        echo "  [PROTECTED] Account lockout message detected"
    fi
    
    # Check for CAPTCHA
    if [[ "$BODY" =~ "captcha" ]] || [[ "$BODY" =~ "reCAPTCHA" ]]; then
        echo "  [PROTECTED] CAPTCHA challenge detected"
    fi
done

echo ""
echo "=========================================="
echo "Analysis Results"
echo "=========================================="

# Check for 429 responses
has_429=0
for code in "${HTTP_CODES[@]}"; do
    if [[ "$code" == "429" ]]; then
        has_429=1
        break
    fi
done

# Check for increasing delays (exponential backoff)
max_time=0
min_time=999999
for time in "${RESPONSE_TIMES[@]}"; do
    if (( time > max_time )); then max_time=$time; fi
    if (( time < min_time )); then min_time=$time; fi
done

echo ""
echo "Rate Limiting Check:"
if [[ $has_429 -eq 1 ]]; then
    echo "  ✓ Rate limiting IS implemented (HTTP 429 detected)"
else
    echo "  ✗ Rate limiting NOT implemented (no HTTP 429 responses)"
fi

echo ""
echo "Account Lockout Check:"
lockout_detected=0
for response in "${RESPONSES[@]}"; do
    if [[ "$response" =~ "locked" ]] || [[ "$response" =~ "Locked" ]] || [[ "$response" =~ "too many attempts" ]]; then
        lockout_detected=1
        echo "  ✓ Account lockout IS implemented"
        break
    fi
done
if [[ $lockout_detected -eq 0 ]]; then
    echo "  ✗ Account lockout NOT implemented"
fi

echo ""
echo "Response Time Analysis:"
echo "  Minimum response time: ${min_time}ms"
echo "  Maximum response time: ${max_time}ms"
echo "  Difference: $((max_time - min_time))ms"

if (( max_time - min_time < 50 )); then
    echo "  ✗ No exponential backoff detected (response times consistent)"
else
    echo "  ✓ Potential exponential backoff detected"
fi

echo ""
echo "HTTP Status Code Distribution:"
for i in "${!HTTP_CODES[@]}"; do
    echo "  Attempt $i: ${HTTP_CODES[$i]}"
done

echo ""
echo "=========================================="
echo "VULNERABILITY VERDICT"
echo "=========================================="

if [[ $has_429 -eq 0 ]] && [[ $lockout_detected -eq 0 ]] && (( max_time - min_time < 50 )); then
    echo "✗ VULNERABLE: No brute force protection detected"
    echo "  - No rate limiting (HTTP 429)"
    echo "  - No account lockout"
    echo "  - No exponential backoff delays"
    echo "  - All attempts processed successfully"
    exit 0
else
    echo "✓ PROTECTED: Some brute force protection mechanisms detected"
    exit 1
fi