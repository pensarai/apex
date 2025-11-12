#!/bin/bash

# POC: DEBUG Mode Information Disclosure
# Tests for DEBUG=True in Django application by accessing non-existent URLs
# and verifying if sensitive information is exposed in error pages

TARGET_URL="${1:-http://localhost}"
INVALID_ENDPOINT="/invalid_page_xyz_$(date +%s)/"

echo "[*] Testing for DEBUG Mode Information Disclosure"
echo "[*] Target: $TARGET_URL"
echo "[*] Testing endpoint: $INVALID_ENDPOINT"
echo ""

# Make request to non-existent endpoint
RESPONSE=$(curl -s -w "\n%{http_code}" "$TARGET_URL$INVALID_ENDPOINT")

# Extract HTTP status code (last line)
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)

# Extract response body (everything except last line)
BODY=$(echo "$RESPONSE" | head -n-1)

echo "[*] HTTP Status Code: $HTTP_CODE"
echo ""

# Check for DEBUG mode indicators
echo "[*] Checking for DEBUG mode information disclosure indicators:"
echo ""

# Check 1: URLconf exposed
if echo "$BODY" | grep -q "URLconf defined in"; then
    echo "✓ FOUND: URLconf module name exposed"
    echo "$BODY" | grep -o "URLconf defined in [^']*" | head -1
    FOUND_URLCONF=1
fi

# Check 2: DEBUG = True message
if echo "$BODY" | grep -q "DEBUG = True"; then
    echo "✓ FOUND: Explicit DEBUG = True statement"
    echo "$BODY" | grep -o "DEBUG = True[^<]*" | head -1
    FOUND_DEBUG=1
fi

# Check 3: URL patterns exposed
if echo "$BODY" | grep -q "url patterns"; then
    echo "✓ FOUND: URL patterns list exposed"
    FOUND_PATTERNS=1
fi

# Check 4: File paths exposed
if echo "$BODY" | grep -q "File \""; then
    echo "✓ FOUND: File paths exposed in traceback"
    FOUND_PATHS=1
fi

# Check 5: Django error page indicator
if echo "$BODY" | grep -q "Django tried matching"; then
    echo "✓ FOUND: Django 404 error page with pattern matching info"
    FOUND_DJANGO_ERROR=1
fi

# Check 6: Settings file reference
if echo "$BODY" | grep -q "settings file"; then
    echo "✓ FOUND: Settings file reference"
    FOUND_SETTINGS=1
fi

echo ""
echo "[*] Summary:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

VULNERABILITY_FOUND=0

if [ "$HTTP_CODE" = "404" ] && ([ "$FOUND_DEBUG" = "1" ] || [ "$FOUND_URLCONF" = "1" ] || [ "$FOUND_DJANGO_ERROR" = "1" ]); then
    echo "✓ VULNERABILITY CONFIRMED: DEBUG mode is enabled"
    echo "  Sensitive information is being exposed in error pages"
    VULNERABILITY_FOUND=1
else
    echo "✗ DEBUG mode indicators not found"
    echo "  DEBUG mode may be disabled (expected in production)"
fi

echo ""
echo "[*] Response Preview (first 2000 chars):"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "$BODY" | head -c 2000
echo ""
echo "[...output truncated...]"
echo ""

# Exit with appropriate code
if [ "$VULNERABILITY_FOUND" = "1" ]; then
    exit 0
else
    exit 1
fi