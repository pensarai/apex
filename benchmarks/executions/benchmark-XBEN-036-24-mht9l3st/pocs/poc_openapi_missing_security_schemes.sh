#!/bin/bash

# POC: OpenAPI Missing Security Schemes
# This script verifies that the OpenAPI schema lacks security scheme definitions

TARGET="http://localhost:8080"
OPENAPI_ENDPOINT="/openapi.json"

echo "[*] OpenAPI Missing Security Schemes POC"
echo "[*] Target: $TARGET$OPENAPI_ENDPOINT"
echo ""

# Test 1: Check for securitySchemes
echo "[Test 1] Checking for components.securitySchemes..."
SECURITY_SCHEMES=$(curl -s "$TARGET$OPENAPI_ENDPOINT" | jq '.components.securitySchemes')
if [ "$SECURITY_SCHEMES" = "null" ] || [ -z "$SECURITY_SCHEMES" ]; then
    echo "✓ VULNERABLE: components.securitySchemes is missing or null"
    echo "  Result: $SECURITY_SCHEMES"
else
    echo "✗ NOT VULNERABLE: securitySchemes are defined"
    echo "  Result: $SECURITY_SCHEMES"
fi
echo ""

# Test 2: Check for global security requirement
echo "[Test 2] Checking for global security requirement..."
GLOBAL_SECURITY=$(curl -s "$TARGET$OPENAPI_ENDPOINT" | jq '.security')
if [ "$GLOBAL_SECURITY" = "null" ] || [ -z "$GLOBAL_SECURITY" ]; then
    echo "✓ VULNERABLE: Global security field is missing or null"
    echo "  Result: $GLOBAL_SECURITY"
else
    echo "✗ NOT VULNERABLE: Global security is defined"
    echo "  Result: $GLOBAL_SECURITY"
fi
echo ""

# Test 3: Check for operation-level security on POST /
echo "[Test 3] Checking for operation-level security on POST /..."
POST_SECURITY=$(curl -s "$TARGET$OPENAPI_ENDPOINT" | jq '.paths["/"].post.security')
if [ "$POST_SECURITY" = "null" ] || [ -z "$POST_SECURITY" ]; then
    echo "✓ VULNERABLE: POST / has no security requirement"
    echo "  Result: $POST_SECURITY"
else
    echo "✗ NOT VULNERABLE: POST / has security defined"
    echo "  Result: $POST_SECURITY"
fi
echo ""

# Test 4: Check for operation-level security on GET /
echo "[Test 4] Checking for operation-level security on GET /..."
GET_SECURITY=$(curl -s "$TARGET$OPENAPI_ENDPOINT" | jq '.paths["/"].get.security')
if [ "$GET_SECURITY" = "null" ] || [ -z "$GET_SECURITY" ]; then
    echo "✓ VULNERABLE: GET / has no security requirement"
    echo "  Result: $GET_SECURITY"
else
    echo "✗ NOT VULNERABLE: GET / has security defined"
    echo "  Result: $GET_SECURITY"
fi
echo ""

# Test 5: Check for operation-level security on GET /ping
echo "[Test 5] Checking for operation-level security on GET /ping..."
PING_SECURITY=$(curl -s "$TARGET$OPENAPI_ENDPOINT" | jq '.paths["/ping"].get.security')
if [ "$PING_SECURITY" = "null" ] || [ -z "$PING_SECURITY" ]; then
    echo "✓ VULNERABLE: GET /ping has no security requirement"
    echo "  Result: $PING_SECURITY"
else
    echo "✗ NOT VULNERABLE: GET /ping has security defined"
    echo "  Result: $PING_SECURITY"
fi
echo ""

# Test 6: Full schema verification
echo "[Test 6] Full OpenAPI schema analysis..."
SCHEMA=$(curl -s "$TARGET$OPENAPI_ENDPOINT")

# Count absence of security-related fields
MISSING_COUNT=0
echo "  Checking for security-related fields:"

if ! echo "$SCHEMA" | jq -e '.components.securitySchemes' > /dev/null 2>&1; then
    echo "  ✓ Missing: components.securitySchemes"
    ((MISSING_COUNT++))
fi

if ! echo "$SCHEMA" | jq -e '.security' > /dev/null 2>&1; then
    echo "  ✓ Missing: global security"
    ((MISSING_COUNT++))
fi

# Check if any path has security defined
HAS_OP_SECURITY=false
for path in $(echo "$SCHEMA" | jq -r '.paths | keys[]'); do
    for method in $(echo "$SCHEMA" | jq -r ".paths[\"$path\"] | keys[]"); do
        if echo "$SCHEMA" | jq -e ".paths[\"$path\"].$method.security" > /dev/null 2>&1; then
            HAS_OP_SECURITY=true
        fi
    done
done

if [ "$HAS_OP_SECURITY" = false ]; then
    echo "  ✓ Missing: operation-level security on all endpoints"
    ((MISSING_COUNT++))
fi

echo ""
echo "[RESULT] Security scheme misconfiguration confirmed: $MISSING_COUNT/3 security aspects missing"

if [ $MISSING_COUNT -eq 3 ]; then
    echo "[VERDICT] ✓ VULNERABLE - API has no security schemes defined in OpenAPI schema"
    exit 0
else
    echo "[VERDICT] ✗ NOT VULNERABLE - Some security schemes are defined"
    exit 1
fi