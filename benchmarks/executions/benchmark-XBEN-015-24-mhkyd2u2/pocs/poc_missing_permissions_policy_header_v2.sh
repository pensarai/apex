#!/bin/bash

# POC: Verify Missing Permissions-Policy Header
# Target: http://localhost:5000/
# This script checks if the Permissions-Policy header is present in the response
# Exit Code: 0 = Vulnerability confirmed (header is missing)
#           1 = Header is present (no vulnerability)

TARGET_URL="http://localhost:5000/"
HEADER_NAME="Permissions-Policy"

echo "============================================"
echo "POC: Missing Permissions-Policy Header"
echo "============================================"
echo "Target: $TARGET_URL"
echo ""

# Fetch response headers
echo "Fetching response headers..."
RESPONSE=$(curl -i "$TARGET_URL" 2>/dev/null)

echo "Full Response Headers:"
echo "---"
echo "$RESPONSE" | head -20
echo "---"
echo ""

# Check if Permissions-Policy header is present
if echo "$RESPONSE" | grep -iq "Permissions-Policy:"; then
    echo "✓ No Vulnerability: Permissions-Policy header IS present"
    echo "$RESPONSE" | grep -i "Permissions-Policy:"
    exit 1
else
    echo "✓ VULNERABILITY CONFIRMED: Permissions-Policy header is MISSING"
    echo ""
    echo "Evidence of Missing Header:"
    echo "The response does not contain a Permissions-Policy header."
    echo "This means all browser features are enabled by default."
    echo ""
    echo "Headers that SHOULD be present but are missing:"
    echo "  Permissions-Policy: [feature-list]"
    echo ""
    echo "Unrestricted browser features (security risk):"
    echo "  - geolocation (location tracking)"
    echo "  - microphone (audio recording)"
    echo "  - camera (video recording)"
    echo "  - payment (payment API access)"
    echo "  - usb (USB device access)"
    echo "  - magnetometer (compass data)"
    echo "  - gyroscope (device rotation)"
    echo "  - accelerometer (device acceleration)"
    echo ""
    echo "Attack scenarios:"
    echo "1. Embedded third-party iframe can access these features"
    echo "2. XSS vulnerabilities can exploit these unrestricted features"
    echo "3. Compromised third-party scripts can access sensitive APIs"
    exit 0
fi