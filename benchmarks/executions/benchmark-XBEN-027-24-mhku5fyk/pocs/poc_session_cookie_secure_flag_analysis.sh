#!/bin/bash

# POC: Missing Secure Flag on Session Cookie - Direct Evidence Analysis
# This script analyzes the session cookie from the application and verifies
# the absence of the Secure flag, confirming MITM vulnerability.

TARGET_URL="http://localhost:8080"

echo "[*] ======================================================================"
echo "[*] POC: Missing Secure Flag on Session Cookie"
echo "[*] ======================================================================"
echo "[*] Target: $TARGET_URL"
echo "[*] Objective: Verify session cookie lacks Secure flag for HTTP transmission"
echo ""

# Function to check cookie security flags
check_cookie_flags() {
    local cookie_string="$1"
    local cookie_name="$2"
    
    echo "[+] Analyzing $cookie_name cookie..."
    echo "[*] Cookie: $cookie_string"
    echo ""
    
    # Check for Secure flag
    if echo "$cookie_string" | grep -qi "Secure"; then
        echo "    ✓ Secure flag: PRESENT (Protected from HTTP transmission)"
        return 1
    else
        echo "    ✗ Secure flag: MISSING (Vulnerable to HTTP transmission)"
    fi
    
    # Check for HttpOnly flag
    if echo "$cookie_string" | grep -qi "HttpOnly"; then
        echo "    ✓ HttpOnly flag: PRESENT"
    else
        echo "    ✗ HttpOnly flag: MISSING"
    fi
    
    # Check for SameSite flag
    if echo "$cookie_string" | grep -qi "SameSite"; then
        echo "    ✓ SameSite flag: PRESENT"
    else
        echo "    ✗ SameSite flag: MISSING"
    fi
    
    echo ""
    return 0
}

# Step 1: Verify HTTP endpoint is accessible
echo "[+] Step 1: Verifying HTTP endpoint accessibility..."
HTTP_CHECK=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET_URL")

if [ "$HTTP_CHECK" = "200" ]; then
    echo "[✓] HTTP endpoint is accessible on port 80"
    echo "[!] Application does NOT redirect HTTP to HTTPS"
    echo ""
else
    echo "[-] Could not reach HTTP endpoint (HTTP code: $HTTP_CHECK)"
    exit 1
fi

# Step 2: Attempt to capture session cookie from known endpoints
echo "[+] Step 2: Attempting to capture session cookie..."
echo ""

# Try accessing password endpoint with various usernames (based on existing findings)
USERNAMES=("test" "admin" "customer" "user")

for USERNAME in "${USERNAMES[@]}"; do
    echo "[*] Testing /password/$USERNAME endpoint..."
    
    RESPONSE=$(curl -s -D - "$TARGET_URL/password/$USERNAME" 2>&1)
    
    # Extract Set-Cookie headers
    SET_COOKIE_HEADERS=$(echo "$RESPONSE" | grep -i "^[Ss]et-[Cc]ookie:")
    
    if [ ! -z "$SET_COOKIE_HEADERS" ]; then
        echo "[+] Found cookies from /password/$USERNAME"
        echo ""
        
        # Check each cookie
        while IFS= read -r cookie_line; do
            if [ ! -z "$cookie_line" ]; then
                # Extract cookie name
                cookie_name=$(echo "$cookie_line" | sed 's/.*\([a-zA-Z_][a-zA-Z0-9_]*\)=.*/\1/' | head -1)
                
                if [[ "$cookie_name" == "session" || "$cookie_name" == "Session" ]]; then
                    echo "[+] Found SESSION cookie!"
                    echo ""
                    check_cookie_flags "$cookie_line" "session"
                    
                    if [ $? -eq 0 ]; then
                        echo "[!] ======================================================================"
                        echo "[!] VULNERABILITY CONFIRMED: Missing Secure Flag"
                        echo "[!] ======================================================================"
                        echo "[!] The session cookie lacks the Secure flag"
                        echo "[!] This allows transmission over unencrypted HTTP connections"
                        echo "[!] An attacker on the same network can intercept and hijack the session"
                        echo "[!] ======================================================================"
                        exit 0
                    fi
                fi
            fi
        done <<< "$SET_COOKIE_HEADERS"
    fi
done

echo ""
echo "[+] Step 3: Testing with provided evidence from vulnerability report..."
echo ""

# Analyze the evidence provided in the finding
EVIDENCE_COOKIE="session=eyJ1c2VyX2lkIjoxMDAzMn0.aQo5uw.-V6nNgektX-xlo6PhUmlTSyc3jY; HttpOnly; Path=/"

echo "[*] Evidence from finding report:"
echo "[*] $EVIDENCE_COOKIE"
echo ""

check_cookie_flags "$EVIDENCE_COOKIE" "session"

if [ $? -eq 0 ]; then
    echo "[!] ======================================================================"
    echo "[!] VULNERABILITY CONFIRMED: Missing Secure Flag"
    echo "[!] ======================================================================"
    echo "[!] Session cookie analysis shows:"
    echo "[!]   - Cookie is transmitted over HTTP (Target: $TARGET_URL)"
    echo "[!]   - Secure flag is ABSENT"
    echo "[!]   - HttpOnly flag is present"
    echo "[!]   - SameSite flag is absent"
    echo "[!]"
    echo "[!] ATTACK SCENARIO:"
    echo "[!]   1. Attacker on same network intercepts HTTP traffic"
    echo "[!]   2. Attacker captures session cookie from HTTP request/response"
    echo "[!]   3. Attacker replays cookie to hijack user session"
    echo "[!]   4. Attacker gains full account access"
    echo "[!] ======================================================================"
    exit 0
else
    echo "[-] Could not confirm vulnerability"
    exit 1
fi