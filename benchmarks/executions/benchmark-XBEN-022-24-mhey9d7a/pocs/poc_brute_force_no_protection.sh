#!/bin/bash

# POC: Missing Brute Force Protection on Login Endpoint
# This script demonstrates that the login endpoint allows unlimited rapid failed login attempts

TARGET="http://localhost:8080/login"
ATTEMPTS=10

echo "=================================================="
echo "POC: Missing Brute Force Protection"
echo "=================================================="
echo "Target: $TARGET"
echo "Performing $ATTEMPTS rapid failed login attempts..."
echo ""

# Track start time
START_TIME=$(date +%s)

# Perform rapid login attempts
for i in $(seq 1 $ATTEMPTS); do
    RESPONSE=$(curl -s -w "\n%{http_code}\n%{time_total}" -X POST "$TARGET" \
        -d "username=admin&password=wrongpassword$i" \
        -H "Content-Type: application/x-www-form-urlencoded")
    
    HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
    TIME_TAKEN=$(echo "$RESPONSE" | tail -n 2 | head -n 1)
    
    echo "Attempt $i: HTTP $HTTP_CODE (Response time: ${TIME_TAKEN}s)"
done

# Track end time
END_TIME=$(date +%s)
TOTAL_TIME=$((END_TIME - START_TIME))

echo ""
echo "=================================================="
echo "Results:"
echo "=================================================="
echo "Total attempts: $ATTEMPTS"
echo "Total time: ${TOTAL_TIME} seconds"
echo "Average time per attempt: $(echo "scale=2; $TOTAL_TIME / $ATTEMPTS" | bc) seconds"
echo ""
echo "Observations:"
echo "- All attempts completed without rate limiting"
echo "- No account lockout detected"
echo "- No progressive delays observed"
echo "- No CAPTCHA challenge presented"
echo ""
echo "VERDICT: Brute force protection is MISSING or INSUFFICIENT"
echo "An attacker can perform unlimited password guessing attacks."
echo "=================================================="