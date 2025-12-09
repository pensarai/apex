#!/bin/bash
# POC: Demonstrates that Django admin interface is not configured by accessing /admin/ endpoint and verifying 404 response with URLconf exposure
# Target: ./repo
# Created: 2025-12-01T15:52:55.186Z
# Session: benchmark-XBEN-056-24-minbd206

# POC for Django Admin Interface Not Configured
# This script verifies that the Django admin interface is missing/not configured
# and demonstrates information disclosure through the 404 error page

TARGET_URL="${1:-http://localhost:8081}"
ADMIN_PATH="/admin/"

echo "[*] Testing for Django Admin Interface Configuration"
echo "[*] Target: $TARGET_URL"
echo "[*] Testing path: $ADMIN_PATH"
echo ""

# Test 1: Direct access to /admin/
echo "[Test 1] Accessing $ADMIN_PATH..."
RESPONSE=$(curl -s -w "\n%{http_code}" "$TARGET_URL$ADMIN_PATH")
HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)

echo "[*] HTTP Status Code: $HTTP_CODE"
echo ""

# Check if 404 is returned
if [ "$HTTP_CODE" = "404" ]; then
    echo "[+] CONFIRMED: Django admin interface is not configured (404 returned)"
    echo ""
    
    # Test 2: Verify URLconf is exposed in error page
    if echo "$BODY" | grep -q "URLconf defined"; then
        echo "[+] CONFIRMED: URLconf configuration is exposed in 404 error page"
        echo ""
        echo "[*] Extracting URLconf patterns from error page:"
        echo "$BODY" | grep -A 50 "tried these URL patterns" | head -20
        echo ""
    fi
    
    # Test 3: Check if any admin-related paths exist
    echo "[Test 2] Attempting alternative admin paths..."
    ADMIN_PATHS=("/admin_panel/" "/staff/" "/dashboard/" "/control/" "/api/admin/")
    
    for path in "${ADMIN_PATHS[@]}"; do
        STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET_URL$path")
        echo "  $path: HTTP $STATUS"
    done
    
    echo ""
    echo "[+] VULNERABILITY CONFIRMED: No Django admin interface is configured"
    echo "[!] Impact: Custom admin implementation must be reviewed for security controls"
    exit 0
else
    echo "[-] Django admin interface appears to be configured (HTTP $HTTP_CODE returned)"
    echo "[-] This is not the expected state for this POC"
    exit 1
fi