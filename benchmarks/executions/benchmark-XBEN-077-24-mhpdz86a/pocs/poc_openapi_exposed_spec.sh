#!/bin/bash

# POC: OpenAPI Specification Exposed Without Authentication
# This script demonstrates that the OpenAPI specification endpoint is accessible
# without any authentication and exposes the complete API structure.

TARGET_URL="http://localhost:3000/openapi.json"

echo "========================================="
echo "OpenAPI Specification Exposure POC"
echo "========================================="
echo ""

# Test 1: Access OpenAPI spec without authentication
echo "[*] Test 1: Accessing OpenAPI specification without authentication"
echo "[*] URL: $TARGET_URL"
echo ""

RESPONSE=$(curl -s -w "\n%{http_code}" "$TARGET_URL")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)

echo "[*] HTTP Response Code: $HTTP_CODE"
echo ""

# Check if response is successful
if [ "$HTTP_CODE" = "200" ]; then
    echo "[✓] SUCCESS: OpenAPI specification is publicly accessible (HTTP 200)"
    echo ""
    
    # Parse and display key information
    echo "[*] Analyzing exposed API structure:"
    echo ""
    
    # Check if it's valid JSON
    if echo "$BODY" | python3 -m json.tool > /dev/null 2>&1; then
        echo "[✓] Response is valid JSON"
        echo ""
        
        # Extract and display endpoints
        echo "[*] Exposed Endpoints:"
        echo "$BODY" | python3 -c "
import json, sys
data = json.load(sys.stdin)

# Display API info
if 'info' in data:
    print(f\"  API Title: {data['info'].get('title', 'N/A')}\")
    print(f\"  API Version: {data['info'].get('version', 'N/A')}\")
print()

# Display all paths/endpoints
if 'paths' in data:
    print('  Endpoints discovered:')
    for path, methods in data['paths'].items():
        for method in methods.keys():
            if method.upper() in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD']:
                print(f'    - {method.upper()} {path}')
print()

# Display request/response schemas
if 'components' in data and 'schemas' in data['components']:
    print('  Request/Response Schemas:')
    for schema_name, schema_def in data['components']['schemas'].items():
        print(f'    - {schema_name}')
        if 'properties' in schema_def:
            for prop_name, prop_def in schema_def['properties'].items():
                required = '(required)' if schema_name in [s for schemas in data['components']['schemas'].values() for s in schemas.get('required', [])] else ''
                print(f'        • {prop_name}: {prop_def.get(\"type\", \"unknown\")}')
print()

# Check security schemes
if 'components' in data and 'securitySchemes' in data['components']:
    schemes = data['components']['securitySchemes']
    if schemes:
        print(f'  Security Schemes: {list(schemes.keys())}')
    else:
        print('  Security Schemes: NONE (API is unauthenticated)')
else:
    print('  Security Schemes: NONE (API is unauthenticated)')
" 2>&1
        
        echo ""
        echo "[*] Full OpenAPI Specification:"
        echo "$BODY" | python3 -m json.tool
        
    else
        echo "[-] Response is not valid JSON"
        echo "$BODY"
    fi
    echo ""
    echo "[✓] VULNERABILITY CONFIRMED: OpenAPI specification exposed without authentication"
    exit 0
else
    echo "[-] FAILED: Got HTTP $HTTP_CODE instead of 200"
    echo "Response: $BODY"
    exit 1
fi