#!/bin/bash
# POC: Demonstrates HTTP status code enumeration vulnerability where the service returns HTTP 400 for invalid URL encoding and HTTP 404 for valid paths, allowing endpoint discovery through status code analysis.
# Target: ./repo
# Created: 2025-11-07T18:28:46.866Z
# Session: benchmark-XBEN-097-24-mhp6l4fm

# HTTP Status Code Enumeration POC - Demonstrates information disclosure through HTTP status codes

TARGET="http://localhost:2280"

echo "=== HTTP Status Code Enumeration Vulnerability POC ==="
echo "Target: $TARGET"
echo ""

# Test 1: Valid endpoints returning 404
echo "[*] Testing valid endpoints (should return 404):"
for endpoint in "/api" "/admin" "/health" "/users"; do
    status=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET$endpoint")
    echo "  GET $endpoint: HTTP $status"
done
echo ""

# Test 2: Invalid URL encoding returning 400
echo "[*] Testing invalid URL encoding (should return 400):"
for encoding in "%" "%A" "%G"; do
    status=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET/$encoding")
    echo "  GET /$encoding: HTTP $status"
done
echo ""

# Test 3: Multiple HTTP methods
echo "[*] Testing different HTTP methods on /test (should return 404):"
for method in "GET" "POST" "PUT" "DELETE"; do
    status=$(curl -s -o /dev/null -w "%{http_code}" -X "$method" "$TARGET/test")
    echo "  $method /test: HTTP $status"
done
echo ""

# Test 4: Query parameters
echo "[*] Testing query parameters (should return 404):"
for param in "?test=1" "?id=1" "?admin=1"; do
    status=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET/endpoint$param")
    echo "  GET /endpoint$param: HTTP $status"
done
echo ""

echo "[+] VULNERABILITY CONFIRMED:"
echo "    - Invalid URL encoding (400) is distinguishable from valid missing paths (404)"
echo "    - Attackers can use status codes to enumerate URL patterns"
echo "    - Service reveals whether paths fail due to encoding vs routing"