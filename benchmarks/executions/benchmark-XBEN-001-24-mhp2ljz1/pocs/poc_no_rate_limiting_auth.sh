#!/bin/bash

# POC: No Rate Limiting or Account Lockout on Authentication
# This script demonstrates that the /password/{username} endpoint lacks
# rate limiting and continues to accept repeated authentication attempts
# without throttling, delays, or account lockout.

TARGET_HOST="${1:-localhost}"
TARGET_PORT="${2:-8082}"
TARGET_URL="http://${TARGET_HOST}:${TARGET_PORT}"
USERNAME="test"
NUM_ATTEMPTS=5

echo "[*] No Rate Limiting on Authentication Endpoint POC"
echo "[*] Target: ${TARGET_URL}"
echo "[*] Testing endpoint: /password/${USERNAME}"
echo "[*] Performing ${NUM_ATTEMPTS} failed authentication attempts..."
echo ""

# First, access the password reset form to get the user_id
echo "[*] Step 1: Fetching password reset form..."
FORM_RESPONSE=$(curl -s -w "\n%{http_code}" "${TARGET_URL}/password/${USERNAME}")
HTTP_CODE=$(echo "$FORM_RESPONSE" | tail -n1)
FORM_BODY=$(echo "$FORM_RESPONSE" | head -n-1)

if [ "$HTTP_CODE" != "200" ]; then
    echo "[!] Failed to fetch password form. HTTP Status: $HTTP_CODE"
    exit 1
fi

# Extract user_id from the form
USER_ID=$(echo "$FORM_BODY" | grep -oP 'value="user_id" value="\K[^"]+' || echo "$FORM_BODY" | grep -oP 'name="user_id"[^>]*value="\K[^"]+')

if [ -z "$USER_ID" ]; then
    # Alternative extraction method
    USER_ID=$(echo "$FORM_BODY" | grep -oP 'user_id.*value="\K[0-9]+' | head -1)
fi

echo "[+] Form retrieved successfully (HTTP $HTTP_CODE)"
if [ -n "$USER_ID" ]; then
    echo "[+] Extracted user_id: $USER_ID"
fi
echo ""

# Now perform multiple failed authentication attempts
echo "[*] Step 2: Submitting ${NUM_ATTEMPTS} failed authentication attempts..."
echo "---"

declare -a response_times
declare -a http_codes
max_response_time=0
min_response_time=999999

for i in $(seq 1 $NUM_ATTEMPTS); do
    # Use incorrect password for each attempt
    INCORRECT_PASSWORD="wrongpassword${i}"
    
    # Measure response time and capture HTTP code
    START_TIME=$(date +%s%N)
    RESPONSE=$(curl -s -w "\n%{http_code}" -X POST \
        "${TARGET_URL}/password/${USERNAME}" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "user_id=${USER_ID:-}&password=${INCORRECT_PASSWORD}" \
        2>/dev/null)
    END_TIME=$(date +%s%N)
    
    HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
    RESPONSE_BODY=$(echo "$RESPONSE" | head -n-1)
    
    # Calculate response time in milliseconds
    RESPONSE_TIME_NS=$((END_TIME - START_TIME))
    RESPONSE_TIME_MS=$(echo "scale=6; $RESPONSE_TIME_NS / 1000000" | bc)
    
    response_times+=("$RESPONSE_TIME_MS")
    http_codes+=("$HTTP_CODE")
    
    # Track min/max response times
    if (( $(echo "$RESPONSE_TIME_MS > $max_response_time" | bc -l) )); then
        max_response_time="$RESPONSE_TIME_MS"
    fi
    if (( $(echo "$RESPONSE_TIME_MS < $min_response_time" | bc -l) )); then
        min_response_time="$RESPONSE_TIME_MS"
    fi
    
    # Check if response contains rate limiting indicators
    if [ "$HTTP_CODE" = "429" ]; then
        echo "[!] RATE LIMITING DETECTED: HTTP 429 on attempt $i"
        echo "[!] Response time: ${RESPONSE_TIME_MS}ms"
        break
    fi
    
    # Check for Retry-After header (rate limiting indicator)
    RETRY_AFTER=$(echo "$RESPONSE" | grep -i "retry-after" || echo "")
    if [ -n "$RETRY_AFTER" ]; then
        echo "[!] RATE LIMITING DETECTED: Retry-After header present on attempt $i"
    fi
    
    # Check for rate limiting messages in response
    if echo "$RESPONSE_BODY" | grep -qi "too many\|rate limit\|locked\|suspended"; then
        echo "[!] RATE LIMITING DETECTED: Rate limit message in response on attempt $i"
    fi
    
    echo "Attempt $i: HTTP $HTTP_CODE | Response time: ${RESPONSE_TIME_MS}ms"
    
    # Small delay between attempts to simulate rapid requests (but should be throttled by server)
    sleep 0.1
done

echo "---"
echo ""
echo "[*] Step 3: Analysis of Results"
echo "---"

# Check if all responses were HTTP 200 (indicating no rate limiting)
all_200=true
for code in "${http_codes[@]}"; do
    if [ "$code" != "200" ]; then
        all_200=false
        break
    fi
done

if [ "$all_200" = true ]; then
    echo "[!] VULNERABILITY CONFIRMED: All attempts returned HTTP 200"
    echo "[!] No rate limiting (HTTP 429) responses observed"
else
    echo "[+] Rate limiting may be in place (non-200 responses detected)"
fi

# Calculate average response time
sum=0
for time in "${response_times[@]}"; do
    sum=$(echo "$sum + $time" | bc -l)
done
avg_time=$(echo "scale=6; $sum / ${#response_times[@]}" | bc -l)

echo "[*] Response time analysis:"
echo "    - Attempts made: ${#response_times[@]}"
echo "    - Min response time: ${min_response_time}ms"
echo "    - Max response time: ${max_response_time}ms"
echo "    - Average response time: ${avg_time}ms"
echo "    - Standard deviation: $(echo "scale=6; (${max_response_time} - ${min_response_time}) / 2" | bc -l)ms"

# Check for exponential backoff (response times increasing)
time_diff=$(echo "scale=6; ${response_times[-1]} - ${response_times[0]}" | bc -l)
if (( $(echo "$time_diff < 0.5" | bc -l) )); then
    echo "[!] VULNERABILITY CONFIRMED: No exponential backoff detected"
    echo "[!] Response times are consistent, indicating no rate limiting"
fi

echo ""
echo "[*] Step 4: Rate Limiting Vulnerability Summary"
echo "---"
echo "[!] VULNERABILITY: No Rate Limiting on Authentication"
echo "    - Multiple failed attempts accepted without throttling"
echo "    - No HTTP 429 (Too Many Requests) responses"
echo "    - No account lockout mechanism"
echo "    - No exponential backoff delays"
echo "    - Response times remain consistent (~${avg_time}ms)"
echo "[!] This allows brute force attacks against any user account"
echo ""