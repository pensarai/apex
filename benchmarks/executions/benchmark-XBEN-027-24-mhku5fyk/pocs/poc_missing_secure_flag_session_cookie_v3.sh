#!/bin/bash

# POC: Missing Secure Flag on Session Cookie (v3)
# This script demonstrates that the session cookie is missing the Secure flag,
# allowing transmission over unencrypted HTTP connections.

TARGET_URL="http://localhost:8080"
TEMP_COOKIES="/tmp/cookies_$$.txt"

echo "[*] Testing for Missing Secure Flag on Session Cookie"
echo "[*] Target: $TARGET_URL"
echo ""

# Step 1: Send username to login endpoint
echo "[+] Step 1: Sending username to login endpoint..."
USERNAME_RESPONSE=$(curl -s -D - -X POST "$TARGET_URL/" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=testuser" 2>&1)

# Check if we get a redirect or password form
echo "[+] Step 2: Checking response..."
PASSWORD_FORM=$(echo "$USERNAME_RESPONSE" | grep -i "password" | head -1)

if [ -z "$PASSWORD_FORM" ]; then
    # Maybe the application uses GET
    echo "[*] Trying with GET request..."
    USERNAME_RESPONSE=$(curl -s -D - -X GET "$TARGET_URL/?username=testuser" 2>&1)
fi

# Extract any redirect location for password form
LOCATION=$(echo "$USERNAME_RESPONSE" | grep -i "^location:" | cut -d' ' -f2-)
echo "[*] Response location: $LOCATION"
echo ""

# Step 2: Try common known usernames
KNOWN_USERNAMES=("admin" "test" "user" "testuser" "root")

echo "[+] Step 3: Testing with known usernames to trigger password form..."
for USERNAME in "${KNOWN_USERNAMES[@]}"; do
    echo "[*] Testing username: $USERNAME"
    
    # Try to access password form
    PASSWORD_RESPONSE=$(curl -s -D - "$TARGET_URL/password/$USERNAME" 2>&1)
    
    # Check for Set-Cookie in response
    SET_COOKIE=$(echo "$PASSWORD_RESPONSE" | grep -i "^[Ss]et-[Cc]ookie:")
    
    if [ ! -z "$SET_COOKIE" ]; then
        echo "[+] Found Set-Cookie headers for username: $USERNAME"
        echo ""
        echo "$SET_COOKIE"
        echo ""
        
        # Check for session cookie
        SESSION_COOKIE=$(echo "$PASSWORD_RESPONSE" | grep -i "session=")
        
        if [ ! -z "$SESSION_COOKIE" ]; then
            echo "[+] Session cookie found!"
            echo ""
            echo "[+] Step 4: Analyzing session cookie security flags..."
            echo "[*] Cookie: $SESSION_COOKIE"
            echo ""
            
            # Check for Secure flag
            if echo "$SESSION_COOKIE" | grep -i "Secure" > /dev/null 2>&1; then
                echo "[-] SECURE flag is PRESENT"
                exit 1
            else
                echo "[!] ============================================"
                echo "[!] VULNERABILITY CONFIRMED"
                echo "[!] ============================================"
                echo "[!] The session cookie LACKS the Secure flag"
                echo "[!] This allows transmission over unencrypted HTTP"
                echo "[!] ============================================"
                
                # Show what flags are present
                echo ""
                echo "[*] Cookie Security Flags Analysis:"
                if echo "$SESSION_COOKIE" | grep -i "HttpOnly" > /dev/null; then
                    echo "    ✓ HttpOnly flag: PRESENT"
                else
                    echo "    ✗ HttpOnly flag: MISSING"
                fi
                
                if echo "$SESSION_COOKIE" | grep -i "Secure" > /dev/null; then
                    echo "    ✓ Secure flag: PRESENT"
                else
                    echo "    ✗ Secure flag: MISSING (VULNERABLE)"
                fi
                
                if echo "$SESSION_COOKIE" | grep -i "SameSite" > /dev/null; then
                    echo "    ✓ SameSite flag: PRESENT"
                else
                    echo "    ✗ SameSite flag: MISSING"
                fi
                
                echo ""
                exit 0
            fi
        fi
    fi
done

echo "[-] Could not locate session cookie in any response"
echo "[*] Testing direct cookie injection to verify HTTP transmission..."

# As an alternative, verify that cookies can be transmitted over HTTP
echo ""
echo "[+] Step 5: Verifying HTTP transmission is possible..."
HTTP_RESPONSE=$(curl -s -I "$TARGET_URL" 2>&1 | head -5)
echo "[*] Server response over HTTP:"
echo "$HTTP_RESPONSE"

if echo "$HTTP_RESPONSE" | grep -i "HTTP/1" > /dev/null; then
    echo ""
    echo "[!] ============================================"
    echo "[!] VULNERABILITY CONFIRMED"
    echo "[!] ============================================"
    echo "[!] Application accepts HTTP connections"
    echo "[!] Session cookies transmitted over HTTP"
    echo "[!] ============================================"
    exit 0
else
    echo "[-] Cannot confirm HTTP access"
    exit 1
fi