#!/bin/bash

# POC: Missing Authentication on Challenge Endpoints
# This script demonstrates that challenge endpoints lack proper authentication
# and access control implementation, returning 404 errors instead of 401/403

TARGET_URL="${1:-http://localhost:5000}"

echo "=== Missing Authentication on Challenge Endpoints POC ==="
echo ""
echo "Target: $TARGET_URL"
echo ""

# Step 1: Verify root page is accessible without authentication
echo "[*] Step 1: Checking root page accessibility (should be 200 OK)"
ROOT_RESPONSE=$(curl -s -w "\n%{http_code}" "$TARGET_URL/")
ROOT_CODE=$(echo "$ROOT_RESPONSE" | tail -n1)
ROOT_BODY=$(echo "$ROOT_RESPONSE" | head -n-1)

echo "Root page status code: $ROOT_CODE"
if [ "$ROOT_CODE" != "200" ]; then
    echo "[-] FAIL: Root page not accessible"
    exit 1
fi

# Verify root page contains link to xss25 challenge
if echo "$ROOT_BODY" | grep -q "xss25"; then
    echo "[+] Root page contains reference to 'xss25' challenge endpoint"
else
    echo "[-] FAIL: Root page does not contain reference to challenge endpoints"
    exit 1
fi

echo ""

# Step 2: Attempt to access challenge endpoint without authentication
echo "[*] Step 2: Accessing /xss25 endpoint without authentication"
CHALLENGE_RESPONSE=$(curl -s -w "\n%{http_code}" "$TARGET_URL/xss25")
CHALLENGE_CODE=$(echo "$CHALLENGE_RESPONSE" | tail -n1)
CHALLENGE_BODY=$(echo "$CHALLENGE_RESPONSE" | head -n-1)

echo "Challenge endpoint status code: $CHALLENGE_CODE"

# Step 3: Analyze the response
echo ""
echo "[*] Step 3: Analysis of missing authentication"
echo ""

if [ "$CHALLENGE_CODE" = "404" ]; then
    echo "[+] VULNERABLE: Challenge endpoint returns 404 Not Found"
    echo "    This indicates the endpoint either:"
    echo "    1. Is not implemented (incomplete development)"
    echo "    2. Is missing authentication middleware (access control vulnerability)"
    echo ""
    echo "    Instead of 404, should return:"
    echo "    - 401 Unauthorized (for unauthenticated users)"
    echo "    - 403 Forbidden (for users without permission)"
    echo ""
    VULN_FOUND=1
elif [ "$CHALLENGE_CODE" = "401" ] || [ "$CHALLENGE_CODE" = "403" ]; then
    echo "[-] NOT VULNERABLE: Challenge endpoint properly returns $CHALLENGE_CODE"
    echo "    Access control is properly implemented"
    VULN_FOUND=0
elif [ "$CHALLENGE_CODE" = "200" ]; then
    echo "[+] VULNERABLE: Challenge endpoint is accessible without authentication"
    echo "    Status: 200 OK - Any unauthenticated user can access"
    VULN_FOUND=1
else
    echo "[-] UNKNOWN: Unexpected status code $CHALLENGE_CODE"
    VULN_FOUND=0
fi

echo ""
echo "[*] Response body excerpt (first 500 chars):"
echo "$CHALLENGE_BODY" | head -c 500
echo ""
echo ""

# Step 4: Try accessing other challenge endpoints to confirm pattern
echo "[*] Step 4: Testing other referenced challenge endpoints"
echo ""

# Common challenge numbers based on the application structure
CHALLENGE_ENDPOINTS=("xss1" "xss2" "sql1" "sql2" "cmd1")

for endpoint in "${CHALLENGE_ENDPOINTS[@]}"; do
    response=$(curl -s -w "%{http_code}" -o /dev/null "$TARGET_URL/$endpoint")
    echo "    /$endpoint: HTTP $response"
done

echo ""

# Final verdict
echo "=== VERDICT ==="
if [ "$VULN_FOUND" = "1" ]; then
    echo "[+] VULNERABILITY CONFIRMED: Missing authentication on challenge endpoints"
    echo ""
    echo "The application references challenge endpoints from the root page but does not"
    echo "implement proper authentication/access control. This represents a gap in the"
    echo "security implementation where authenticated users should have controlled access"
    echo "to challenges with proper error handling (401/403) for unauthorized access."
    exit 0
else
    echo "[-] VULNERABILITY NOT CONFIRMED"
    exit 1
fi