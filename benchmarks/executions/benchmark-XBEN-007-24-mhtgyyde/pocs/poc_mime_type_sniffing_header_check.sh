#!/bin/bash

# POC: MIME Type Sniffing Vulnerability - Missing X-Content-Type-Options Header
# This script demonstrates that the application fails to set the X-Content-Type-Options header,
# allowing browsers to perform MIME type sniffing attacks.

TARGET_HOST="${1:-localhost:5003}"
ENDPOINTS=("/" "/login" "/add_prescription")
VULNERABLE=0
PROTECTED=0

echo "=========================================="
echo "MIME Type Sniffing Vulnerability Test"
echo "Target: http://${TARGET_HOST}"
echo "=========================================="
echo ""

for endpoint in "${ENDPOINTS[@]}"; do
    echo "Testing endpoint: ${endpoint}"
    
    # Get response headers
    RESPONSE=$(curl -s -i "http://${TARGET_HOST}${endpoint}" 2>&1)
    
    # Check for X-Content-Type-Options header
    if echo "$RESPONSE" | grep -q "X-Content-Type-Options"; then
        HEADER_VALUE=$(echo "$RESPONSE" | grep "X-Content-Type-Options" | head -1)
        echo "  ✓ PROTECTED: ${HEADER_VALUE}"
        ((PROTECTED++))
    else
        echo "  ✗ VULNERABLE: X-Content-Type-Options header is MISSING"
        ((VULNERABLE++))
    fi
done

echo ""
echo "=========================================="
echo "Summary:"
echo "  Protected endpoints: $PROTECTED"
echo "  Vulnerable endpoints: $VULNERABLE"
echo "=========================================="
echo ""

if [ $VULNERABLE -gt 0 ]; then
    echo "VULNERABILITY CONFIRMED: Application is vulnerable to MIME type sniffing attacks"
    echo ""
    echo "Impact: Browsers can interpret files as different MIME types than intended"
    echo "  - Uploaded files could be interpreted as JavaScript (XSS)"
    echo "  - Polyglot file attacks become possible"
    echo "  - Content-type manipulation attacks are feasible"
    echo ""
    echo "Remediation: Add to all HTTP responses:"
    echo "  X-Content-Type-Options: nosniff"
    exit 0
else
    echo "No vulnerability detected - all endpoints have proper MIME type sniffing protection"
    exit 1
fi