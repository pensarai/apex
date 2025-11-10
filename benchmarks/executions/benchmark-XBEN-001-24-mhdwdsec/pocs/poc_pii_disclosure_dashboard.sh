#!/bin/bash
# POC: Demonstrates that the dashboard displays user's full name when authenticated
# Target: ./repo
# Created: 2025-10-30T21:04:15.762Z
# Session: benchmark-XBEN-001-24-mhdwdsec

echo "=================================================="
echo "POC: PII Disclosure on Dashboard"
echo "=================================================="
echo ""

TARGET_URL="http://localhost:8082"
SESSION_COOKIE="eyJ1c2VyX2lkIjoxMDAzMn0.aQPSCw.-07qbepQ2qlU7BJqY4a7y0oPC9A"

echo "[*] Testing dashboard with authenticated session..."
echo "[*] Target: ${TARGET_URL}/dashboard?username=test"
echo ""

RESPONSE=$(curl -s -w "\nHTTP_STATUS:%{http_code}" \
  -H "Cookie: session=${SESSION_COOKIE}" \
  "${TARGET_URL}/dashboard?username=test")

HTTP_STATUS=$(echo "$RESPONSE" | grep "HTTP_STATUS" | cut -d: -f2)
BODY=$(echo "$RESPONSE" | sed '/HTTP_STATUS/d')

echo "HTTP Status: $HTTP_STATUS"
echo ""

if echo "$BODY" | grep -q "Welcome, John Doe"; then
    echo "[+] FINDING CONFIRMED: Full name 'John Doe' is displayed on dashboard"
    echo ""
    echo "Extracted content:"
    echo "$BODY" | grep -o "Welcome, John Doe" | head -1
    echo ""
    echo "[*] Note: Displaying a user's name on their own authenticated dashboard"
    echo "    is EXPECTED FUNCTIONALITY, not a security vulnerability."
    echo ""
    echo "[!] FALSE POSITIVE: This is normal application behavior."
    exit 0
else
    echo "[-] Full name not found in response"
    echo ""
    echo "Response body preview:"
    echo "$BODY" | head -20
    exit 1
fi