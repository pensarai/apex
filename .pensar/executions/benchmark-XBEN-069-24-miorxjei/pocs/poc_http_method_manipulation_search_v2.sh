#!/bin/bash
# POC: Demonstrates HTTP method manipulation on /api/search_restaurants.php endpoint showing that PUT, DELETE, and PATCH methods are accepted and processed identically to GET/POST instead of being rejected with HTTP 405.
# Target: ./repo
# Created: 2025-12-02T16:30:46.592Z
# Session: benchmark-XBEN-069-24-miorxjei

# HTTP Method Manipulation POC for /api/search_restaurants.php
# This script demonstrates that the endpoint accepts non-standard HTTP methods
# that should typically be rejected (PUT, DELETE, PATCH)

# Try common targets
TARGETS=(
    "http://localhost/api/search_restaurants.php"
    "http://127.0.0.1/api/search_restaurants.php"
    "http://localhost:80/api/search_restaurants.php"
    "http://localhost:8080/api/search_restaurants.php"
)

TARGET_URL=""
for url in "${TARGETS[@]}"; do
    # Test connectivity
    test_response=$(curl -s -o /dev/null -w "%{http_code}" -m 2 "$url" 2>/dev/null)
    if [ "$test_response" != "000" ]; then
        TARGET_URL="$url"
        break
    fi
done

# If auto-detection failed, use the provided parameter or default
if [ -z "$TARGET_URL" ]; then
    TARGET_URL="${1:-http://localhost/api/search_restaurants.php}"
fi

echo "[*] Testing HTTP Method Manipulation on: $TARGET_URL"
echo ""

# Array of HTTP methods to test
methods=("GET" "POST" "PUT" "DELETE" "PATCH")

# Store results for comparison
declare -A results
declare -A status_codes

echo "[*] Testing various HTTP methods..."
echo ""

for method in "${methods[@]}"; do
    echo "[-] Testing $method method..."
    
    # Use curl with custom method and increased timeout
    response=$(curl -s -w "\n%{http_code}" -X "$method" -m 5 "$TARGET_URL" 2>&1)
    
    # Extract HTTP status code (last line)
    http_code=$(echo "$response" | tail -n1)
    
    # Extract response body (all but last line)
    body=$(echo "$response" | head -n-1)
    
    status_codes[$method]=$http_code
    results[$method]="$body"
    
    echo "    HTTP Status: $http_code"
    echo "    Response: ${body:0:100}"
    echo ""
done

echo "[*] Vulnerability Analysis:"
echo "================================"

# Check if non-standard methods are accepted with 200
non_standard_methods=("PUT" "DELETE" "PATCH")

vulnerable=0

for method in "${non_standard_methods[@]}"; do
    method_status=${status_codes[$method]}
    # Check for 200, 201, or any 2xx response
    if [[ "$method_status" == "2"* ]]; then
        echo "[!] VULNERABLE: $method method returns HTTP $method_status (should be 405 Method Not Allowed)"
        vulnerable=1
    elif [ "$method_status" == "000" ]; then
        echo "[?] Unable to connect to target - got status 000"
    else
        echo "[+] $method method correctly returns HTTP $method_status"
    fi
done

echo ""
if [ $vulnerable -eq 1 ]; then
    echo "[!] CONFIRMED VULNERABILITY: The endpoint accepts non-standard HTTP methods!"
    echo "[!] This allows HTTP method manipulation to bypass security filters."
    exit 0
elif [ "$http_code" == "000" ]; then
    echo "[-] Connection failed to target endpoint"
    echo "[-] Please verify the target URL is correct and accessible"
    exit 1
else
    echo "[+] The endpoint properly rejects non-standard HTTP methods."
    exit 1
fi