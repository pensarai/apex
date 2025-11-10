#!/bin/bash

# POC: Session Cookie Missing Security Flags (HTTPOnly, Secure, SameSite)
# Version 3: Tests multiple endpoints to find session cookies

TARGET_HOST="${1:-localhost:8080}"
BASE_URL="http://$TARGET_HOST"

echo "[*] Session Cookie Security Flags POC"
echo "[*] Target Host: $TARGET_HOST"
echo ""

# Common endpoints that typically set session cookies
ENDPOINTS=(
    "/"
    "/index.php"
    "/login.php"
    "/search.php"
    "/admin/"
)

FOUND_COOKIE=0

# Try each endpoint
for endpoint in "${ENDPOINTS[@]}"; do
    echo "[*] Testing endpoint: $BASE_URL$endpoint"
    
    HTTP_RESPONSE=$(curl -s -v "$BASE_URL$endpoint" 2>&1)
    
    # Extract Set-Cookie headers from verbose output (format: "< Set-Cookie: ...")
    SET_COOKIE_HEADERS=$(echo "$HTTP_RESPONSE" | grep "^< Set-Cookie:" 2>/dev/null)
    
    if [ -n "$SET_COOKIE_HEADERS" ]; then
        echo "[+] Set-Cookie header found!"
        echo "$SET_COOKIE_HEADERS" | while read line; do
            echo "    $line"
        done
        
        # Filter for PHPSESSID specifically
        PHPSESSID_COOKIE=$(echo "$SET_COOKIE_HEADERS" | grep -i "PHPSESSID" | head -1)
        
        if [ -n "$PHPSESSID_COOKIE" ]; then
            echo ""
            echo "[+] PHPSESSID Cookie Found:"
            # Clean up the "< Set-Cookie: " prefix for analysis
            COOKIE_VALUE=$(echo "$PHPSESSID_COOKIE" | sed 's/^< Set-Cookie: //')
            echo "    $COOKIE_VALUE"
            echo ""
            
            # Check for security flags
            echo "[*] Analyzing cookie security flags..."
            echo ""
            
            MISSING_FLAGS=()
            FOUND_FLAGS=()
            
            # Check for HTTPOnly flag (case-insensitive)
            if echo "$COOKIE_VALUE" | grep -qi "HttpOnly"; then
                echo "[+] HTTPOnly flag: PRESENT"
                FOUND_FLAGS+=("HTTPOnly")
            else
                echo "[-] HTTPOnly flag: MISSING"
                MISSING_FLAGS+=("HTTPOnly")
            fi
            
            # Check for Secure flag (case-insensitive)
            if echo "$COOKIE_VALUE" | grep -qi "Secure"; then
                echo "[+] Secure flag: PRESENT"
                FOUND_FLAGS+=("Secure")
            else
                echo "[-] Secure flag: MISSING"
                MISSING_FLAGS+=("Secure")
            fi
            
            # Check for SameSite flag (case-insensitive)
            if echo "$COOKIE_VALUE" | grep -qi "SameSite"; then
                echo "[+] SameSite flag: PRESENT"
                FOUND_FLAGS+=("SameSite")
            else
                echo "[-] SameSite flag: MISSING"
                MISSING_FLAGS+=("SameSite")
            fi
            
            echo ""
            echo "[*] Summary:"
            echo "    Security Flags Present: ${#FOUND_FLAGS[@]}/3"
            echo "    Security Flags Missing: ${#MISSING_FLAGS[@]}/3"
            
            # Report vulnerability if flags are missing
            if [ ${#MISSING_FLAGS[@]} -gt 0 ]; then
                echo ""
                echo "[!] VULNERABILITY CONFIRMED"
                echo "[!] Missing security flags: $(IFS=, ; echo "${MISSING_FLAGS[*]}")"
                echo ""
                echo "[*] Risk: Session cookies are vulnerable to XSS theft and CSRF attacks"
                echo "[*] Recommended secure configuration:"
                echo "    Set-Cookie: PHPSESSID=<value>; Path=/; HttpOnly; Secure; SameSite=Strict"
                echo ""
            else
                echo ""
                echo "[+] All security flags are properly configured"
                echo ""
            fi
            
            FOUND_COOKIE=1
            break
        fi
    fi
    
    echo "[-] No PHPSESSID cookie found at this endpoint"
    echo ""
done

if [ $FOUND_COOKIE -eq 0 ]; then
    echo "[-] No PHPSESSID cookie found at any tested endpoint"
    echo "[*] Tested endpoints:"
    for endpoint in "${ENDPOINTS[@]}"; do
        echo "    - $BASE_URL$endpoint"
    done
    exit 1
fi

exit 0