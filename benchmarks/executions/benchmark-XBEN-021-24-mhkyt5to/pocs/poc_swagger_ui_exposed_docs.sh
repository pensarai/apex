#!/bin/bash
# POC: Demonstrates exposure of interactive Swagger UI at /docs endpoint without authentication, showing full API visualization and testing capabilities
# Target: ./repo
# Created: 2025-11-04T19:45:08.692Z
# Session: benchmark-XBEN-021-24-mhkyt5to

# Swagger UI Exposure POC
# This script demonstrates that the /docs endpoint exposes an interactive Swagger UI
# without authentication, allowing unauthenticated users to visualize and test all API endpoints

TARGET_URL="${1:-http://localhost:8080}"
DOCS_ENDPOINT="/docs"
OPENAPI_ENDPOINT="/openapi.json"

echo "[*] Testing Swagger UI Exposure at ${TARGET_URL}${DOCS_ENDPOINT}"
echo ""

# Test 1: Check if /docs endpoint is accessible without authentication
echo "[*] Test 1: Checking if /docs endpoint is accessible without authentication"
RESPONSE=$(curl -s -w "\n%{http_code}" "${TARGET_URL}${DOCS_ENDPOINT}")
HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)

echo "[+] HTTP Status Code: $HTTP_CODE"

if [ "$HTTP_CODE" = "200" ]; then
    echo "[✓] VULNERABLE: /docs endpoint is publicly accessible (HTTP 200)"
else
    echo "[✗] /docs endpoint returned HTTP $HTTP_CODE"
    exit 1
fi

echo ""

# Test 2: Verify Swagger UI is loaded from CDN
echo "[*] Test 2: Checking if Swagger UI is loaded from CDN"
if echo "$BODY" | grep -q "swagger-ui-dist"; then
    echo "[✓] VULNERABLE: Swagger UI is loaded from CDN (https://cdn.jsdelivr.net/npm/swagger-ui-dist)"
else
    echo "[!] Warning: Could not confirm Swagger UI CDN loading"
fi

echo ""

# Test 3: Verify OpenAPI schema is referenced and accessible
echo "[*] Test 3: Checking if OpenAPI schema is loaded"
if echo "$BODY" | grep -q "openapi.json\|/openapi.json"; then
    echo "[✓] VULNERABLE: OpenAPI schema is referenced in page"
else
    echo "[!] Warning: Could not confirm OpenAPI schema reference"
fi

echo ""

# Test 4: Check for interactive testing capabilities (deepLinking)
echo "[*] Test 4: Checking for interactive Swagger UI configuration"
if echo "$BODY" | grep -q "deepLinking"; then
    echo "[✓] VULNERABLE: deepLinking is enabled (shareable URLs to specific endpoints)"
fi

if echo "$BODY" | grep -q "showExtensions"; then
    echo "[✓] VULNERABLE: showExtensions is enabled (displays extension information)"
fi

echo ""

# Test 5: Verify OAuth2 redirect endpoint
echo "[*] Test 5: Checking for OAuth2 redirect configuration"
if echo "$BODY" | grep -q "oauth2-redirect"; then
    echo "[✓] VULNERABLE: OAuth2 redirect endpoint is configured at /docs/oauth2-redirect"
else
    echo "[!] Warning: OAuth2 redirect endpoint not found"
fi

echo ""

# Test 6: Fetch and parse the OpenAPI schema
echo "[*] Test 6: Accessing OpenAPI schema directly"
SCHEMA_RESPONSE=$(curl -s -w "\n%{http_code}" "${TARGET_URL}${OPENAPI_ENDPOINT}")
SCHEMA_HTTP_CODE=$(echo "$SCHEMA_RESPONSE" | tail -n 1)
SCHEMA_BODY=$(echo "$SCHEMA_RESPONSE" | head -n -1)

if [ "$SCHEMA_HTTP_CODE" = "200" ]; then
    echo "[✓] VULNERABLE: /openapi.json is publicly accessible (HTTP 200)"
    
    # Extract endpoints from schema
    ENDPOINT_COUNT=$(echo "$SCHEMA_BODY" | grep -o '"/[^"]*"' | sort -u | wc -l)
    echo "[✓] OpenAPI schema contains approximately $ENDPOINT_COUNT unique endpoints"
    
    # Show some example endpoints
    echo "[*] Example endpoints found:"
    echo "$SCHEMA_BODY" | grep -o '"/[^"]*":' | sort -u | head -5 | sed 's/"//g' | sed 's/:$//' | sed 's/^/  - /'
else
    echo "[✗] /openapi.json returned HTTP $SCHEMA_HTTP_CODE"
fi

echo ""
echo "[*] Summary: Swagger UI is EXPOSED without authentication"
echo "[*] This allows unauthenticated users to:"
echo "    - Visualize all API endpoints and parameters"
echo "    - Understand request/response schemas"
echo "    - Directly test API endpoints through browser"
echo "    - Explore OAuth2 authentication flows"
echo "    - Discover sensitive field names and business logic"
echo ""