#!/bin/bash

# POC: Missing autocomplete="off" on Email Input Field (V3)
# This script detects if email input fields lack the autocomplete="off" attribute
# which could expose sensitive email addresses through browser auto-fill

TARGET_URL="${1:-http://localhost:8080}"

echo "[*] Checking for missing autocomplete=\"off\" attribute on email input fields"
echo "[*] Target: $TARGET_URL"
echo ""

# Try multiple possible locations for forms with email fields
ENDPOINTS=("/" "/index.html" "/contact" "/form" "/subscribe" "/newsletter" "/login" "/register")

FOUND_VULNERABLE=0

for endpoint in "${ENDPOINTS[@]}"; do
    echo "[+] Checking: $TARGET_URL$endpoint"
    
    # Fetch the page HTML
    RESPONSE=$(curl -s "$TARGET_URL$endpoint" 2>/dev/null)
    
    if [ $? -ne 0 ]; then
        echo "    [-] Failed to fetch page"
        continue
    fi
    
    # Check if the page contains any email input fields
    if echo "$RESPONSE" | grep -q 'type="email"'; then
        echo "    [+] Email input field found!"
        
        # Extract all email input field lines
        EMAIL_INPUTS=$(echo "$RESPONSE" | grep -o '<input[^>]*type="email"[^>]*>')
        
        # Count the inputs
        EMAIL_COUNT=$(echo "$EMAIL_INPUTS" | wc -l)
        echo "    [*] Found $EMAIL_COUNT email input field(s)"
        
        # Check each email input for autocomplete="off"
        while IFS= read -r EMAIL_INPUT; do
            if [ -z "$EMAIL_INPUT" ]; then
                continue
            fi
            
            echo "    [*] Email field: $EMAIL_INPUT"
            
            # Check if autocomplete="off" is present
            if echo "$EMAIL_INPUT" | grep -q 'autocomplete="off"'; then
                echo "    [✓] Has autocomplete=\"off\" - SECURE"
            else
                echo "    [!] MISSING autocomplete=\"off\" - VULNERABLE"
                FOUND_VULNERABLE=$((FOUND_VULNERABLE + 1))
                
                # Show remediation
                echo "        Recommended fix:"
                echo "        Add autocomplete=\"off\" attribute to this input field"
            fi
        done <<< "$EMAIL_INPUTS"
        echo ""
    fi
done

if [ $FOUND_VULNERABLE -gt 0 ]; then
    echo "[!] VULNERABILITY CONFIRMED: Found $FOUND_VULNERABLE email field(s) missing autocomplete=\"off\""
    echo ""
    echo "[*] Security Impact:"
    echo "    - Browser autocomplete could expose sensitive email addresses"
    echo "    - Password managers may populate the field with cached credentials"
    echo "    - On shared computers, subsequent users could see previously entered emails"
    echo "    - Unintended disclosure of admin@, support@, or other sensitive addresses"
    echo ""
    echo "[*] Proof of Vulnerability:"
    echo "    Email input fields found without autocomplete=\"off\" protection"
    echo "    This allows browser auto-fill to populate sensitive data"
    exit 0
else
    echo "[*] No vulnerable email fields found (either no email fields or all have autocomplete=\"off\")"
    exit 0
fi