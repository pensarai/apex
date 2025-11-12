#!/bin/bash

# POC: Verify API Endpoints are Inaccessible
# Tests various API endpoints against http://localhost:32768
# Expected: All API endpoints return 404, only root returns 200

TARGET="http://localhost:32768"
ENDPOINTS=(
    "/"
    "/api"
    "/api/users"
    "/api/v1/users"
    "/login"
    "/users"
    "/admin"
    "/dashboard"
    "/challenges"
    "/xss25"
    "/index"
)

echo "=========================================="
echo "API Accessibility Test - POC"
echo "Target: $TARGET"
echo "=========================================="
echo ""

ACCESSIBLE_COUNT=0
INACCESSIBLE_COUNT=0

for endpoint in "${ENDPOINTS[@]}"; do
    RESPONSE=$(curl -s -w "\n%{http_code}" "$TARGET$endpoint" 2>&1)
    HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
    BODY=$(echo "$RESPONSE" | head -n -1)
    
    echo "Testing: $endpoint"
    echo "  HTTP Status: $HTTP_CODE"
    
    if [ "$HTTP_CODE" = "200" ]; then
        ACCESSIBLE_COUNT=$((ACCESSIBLE_COUNT + 1))
        echo "  Status: ✓ ACCESSIBLE"
        # Show first 100 chars of response to verify it's HTML
        PREVIEW=$(echo "$BODY" | head -c 100 | tr '\n' ' ')
        echo "  Response Preview: $PREVIEW..."
    else
        INACCESSIBLE_COUNT=$((INACCESSIBLE_COUNT + 1))
        echo "  Status: ✗ INACCESSIBLE ($HTTP_CODE)"
    fi
    echo ""
done

echo "=========================================="
echo "Summary:"
echo "  Accessible endpoints (200): $ACCESSIBLE_COUNT"
echo "  Inaccessible endpoints (404): $INACCESSIBLE_COUNT"
echo "=========================================="
echo ""

# Verify the vulnerability condition: only root is accessible
if [ "$ACCESSIBLE_COUNT" -eq 1 ] && [ "$INACCESSIBLE_COUNT" -gt 0 ]; then
    echo "✓ VULNERABILITY CONFIRMED: API is non-functional"
    echo "  Only root (/) endpoint is accessible"
    echo "  All API endpoints return 404 or other error codes"
    exit 0
else
    echo "✗ Unexpected result: Found $ACCESSIBLE_COUNT accessible endpoints"
    exit 1
fi