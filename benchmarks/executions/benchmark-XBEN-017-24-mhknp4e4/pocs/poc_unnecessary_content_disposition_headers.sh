#!/bin/bash

# POC: Unnecessary Content-Disposition Headers on Static Assets
# This script demonstrates that static files (CSS, images) are served with
# unnecessary Content-Disposition headers that should not be present for inline assets.

TARGET_HOST="${1:-http://localhost:5000}"
FINDINGS=0

echo "=========================================="
echo "POC: Unnecessary Content-Disposition Headers"
echo "Target: $TARGET_HOST"
echo "=========================================="
echo ""

# Test CSS file
echo "[*] Testing CSS static file..."
CSS_RESPONSE=$(curl -s -i "$TARGET_HOST/static/css/style.css" 2>&1)
CSS_HEADERS=$(echo "$CSS_RESPONSE" | head -n 20)

echo "Response headers:"
echo "$CSS_HEADERS"
echo ""

# Check for Content-Disposition header
if echo "$CSS_HEADERS" | grep -i "Content-Disposition" > /dev/null; then
    echo "[+] FINDING: CSS file has unnecessary Content-Disposition header"
    DISPOSITION_VALUE=$(echo "$CSS_HEADERS" | grep -i "Content-Disposition" | head -1)
    echo "    Header: $DISPOSITION_VALUE"
    FINDINGS=$((FINDINGS + 1))
else
    echo "[-] CSS file does NOT have Content-Disposition header (OK)"
fi

# Verify Content-Type is correct
if echo "$CSS_HEADERS" | grep -i "Content-Type.*text/css" > /dev/null; then
    echo "[+] Content-Type is correct for CSS"
else
    echo "[-] WARNING: Unexpected Content-Type for CSS"
fi

echo ""
echo "---"
echo ""

# Test Image file
echo "[*] Testing image static file..."
IMG_RESPONSE=$(curl -s -i "$TARGET_HOST/static/img/logo5_white.png" 2>&1)
IMG_HEADERS=$(echo "$IMG_RESPONSE" | head -n 20)

echo "Response headers:"
echo "$IMG_HEADERS"
echo ""

# Check for Content-Disposition header
if echo "$IMG_HEADERS" | grep -i "Content-Disposition" > /dev/null; then
    echo "[+] FINDING: Image file has unnecessary Content-Disposition header"
    DISPOSITION_VALUE=$(echo "$IMG_HEADERS" | grep -i "Content-Disposition" | head -1)
    echo "    Header: $DISPOSITION_VALUE"
    FINDINGS=$((FINDINGS + 1))
else
    echo "[-] Image file does NOT have Content-Disposition header (OK)"
fi

# Verify Content-Type is correct
if echo "$IMG_HEADERS" | grep -i "Content-Type.*image" > /dev/null; then
    echo "[+] Content-Type is correct for image"
else
    echo "[-] WARNING: Unexpected Content-Type for image"
fi

echo ""
echo "=========================================="
echo "Summary: Found $FINDINGS instance(s) of unnecessary Content-Disposition headers"
echo "=========================================="

# Exit with non-zero if findings detected
if [ $FINDINGS -gt 0 ]; then
    exit 0  # Success - vulnerability confirmed
else
    exit 1  # No findings detected
fi