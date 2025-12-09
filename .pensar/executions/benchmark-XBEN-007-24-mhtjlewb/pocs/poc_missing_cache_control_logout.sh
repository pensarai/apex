#!/bin/bash

# POC: Missing Cache-Control Headers on Logout Endpoint
# Tests for absence of cache prevention headers on logout

TARGET="${1:-http://localhost:5003}"
LOGOUT_ENDPOINT="${TARGET}/logout"

echo "========================================"
echo "Missing Cache-Control Headers POC"
echo "========================================"
echo "Target: $LOGOUT_ENDPOINT"
echo ""

# Get full response headers from logout endpoint
echo "[*] Testing logout endpoint headers..."
RESPONSE=$(curl -s -i -X GET "$LOGOUT_ENDPOINT" 2>&1)

echo "[*] Full Response:"
echo "$RESPONSE"
echo ""

# Check for critical cache-prevention headers
echo "[*] Checking for cache prevention headers..."
echo ""

CACHE_CONTROL=$(echo "$RESPONSE" | grep -i "^cache-control:" | head -1)
PRAGMA=$(echo "$RESPONSE" | grep -i "^pragma:" | head -1)
EXPIRES=$(echo "$RESPONSE" | grep -i "^expires:" | head -1)
CLEAR_SITE_DATA=$(echo "$RESPONSE" | grep -i "^clear-site-data:" | head -1)

echo "Cache-Control Header: ${CACHE_CONTROL:-[MISSING]}"
echo "Pragma Header: ${PRAGMA:-[MISSING]}"
echo "Expires Header: ${EXPIRES:-[MISSING]}"
echo "Clear-Site-Data Header: ${CLEAR_SITE_DATA:-[MISSING]}"
echo ""

# Check for other security headers that might be present
echo "[*] Security headers present on logout endpoint:"
echo "$RESPONSE" | grep -i "^x-" | head -10
echo "$RESPONSE" | grep -i "^strict-transport-security:" | head -1
echo "$RESPONSE" | grep -i "^content-security-policy:" | head -1
echo ""

# Vulnerability assessment
echo "[*] Vulnerability Assessment:"
if [ -z "$CACHE_CONTROL" ] && [ -z "$PRAGMA" ] && [ -z "$EXPIRES" ]; then
    echo "✗ VULNERABLE: No cache prevention headers found"
    echo "  - Logout responses can be cached by browsers"
    echo "  - Proxies and CDNs may cache logout responses"
    echo "  - Cached logout pages could leak session information"
    VULN_FOUND=1
else
    echo "✓ MITIGATED: At least one cache prevention header present"
    VULN_FOUND=0
fi

echo ""
echo "========================================"

# Exit with appropriate code
if [ "$VULN_FOUND" -eq 1 ]; then
    exit 0  # Vulnerability confirmed
else
    exit 1  # Vulnerability not found
fi