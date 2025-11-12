#!/bin/bash

# POC: Verify Missing Security Headers on Static CSS File
# Tests that /static/style.css is served without critical security headers

TARGET_URL="http://localhost/static/style.css"
TEMP_FILE=$(mktemp)

echo "=========================================="
echo "Testing: Missing Security Headers on Static Files"
echo "=========================================="
echo "Target: $TARGET_URL"
echo ""

# Fetch response headers
curl -s -I "$TARGET_URL" > "$TEMP_FILE"

echo "Response Headers:"
cat "$TEMP_FILE"
echo ""

# Check for security headers
echo "Security Headers Analysis:"
echo "=========================================="

MISSING_HEADERS=0

# Check X-Content-Type-Options
if grep -qi "X-Content-Type-Options" "$TEMP_FILE"; then
    echo "[✓] X-Content-Type-Options: PRESENT"
else
    echo "[✗] X-Content-Type-Options: MISSING"
    MISSING_HEADERS=$((MISSING_HEADERS + 1))
fi

# Check X-Frame-Options
if grep -qi "X-Frame-Options" "$TEMP_FILE"; then
    echo "[✓] X-Frame-Options: PRESENT"
else
    echo "[✗] X-Frame-Options: MISSING"
    MISSING_HEADERS=$((MISSING_HEADERS + 1))
fi

# Check Content-Security-Policy
if grep -qi "Content-Security-Policy" "$TEMP_FILE"; then
    echo "[✓] Content-Security-Policy: PRESENT"
else
    echo "[✗] Content-Security-Policy: MISSING"
    MISSING_HEADERS=$((MISSING_HEADERS + 1))
fi

# Check X-XSS-Protection
if grep -qi "X-XSS-Protection" "$TEMP_FILE"; then
    echo "[✓] X-XSS-Protection: PRESENT"
else
    echo "[✗] X-XSS-Protection: MISSING"
    MISSING_HEADERS=$((MISSING_HEADERS + 1))
fi

# Check Strict-Transport-Security
if grep -qi "Strict-Transport-Security" "$TEMP_FILE"; then
    echo "[✓] Strict-Transport-Security: PRESENT"
else
    echo "[✗] Strict-Transport-Security: MISSING"
    MISSING_HEADERS=$((MISSING_HEADERS + 1))
fi

# Check for problematic Cache-Control
echo ""
echo "Cache-Control Header:"
CACHE_CONTROL=$(grep -i "Cache-Control" "$TEMP_FILE" | cut -d' ' -f2-)
if [ -z "$CACHE_CONTROL" ]; then
    echo "[✗] Cache-Control: MISSING (no caching directive)"
else
    echo "[✓] Cache-Control: $CACHE_CONTROL"
    if echo "$CACHE_CONTROL" | grep -q "no-cache"; then
        echo "    ⚠ WARNING: 'no-cache' directive could be problematic for static assets"
    fi
fi

echo ""
echo "=========================================="
echo "Vulnerability Summary:"
echo "=========================================="
echo "Missing Security Headers: $MISSING_HEADERS / 5"

if [ $MISSING_HEADERS -gt 0 ]; then
    echo "Status: VULNERABILITY CONFIRMED"
    rm -f "$TEMP_FILE"
    exit 0
else
    echo "Status: All security headers present"
    rm -f "$TEMP_FILE"
    exit 1
fi