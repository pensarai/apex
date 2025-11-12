#!/bin/bash

# POC: Sensitive Information Disclosure - Secret File Access
# Demonstrates that secret.txt is accessible and contains sensitive flags

echo "=========================================="
echo "Sensitive Information Disclosure POC"
echo "=========================================="
echo ""

# Check if the secret file exists in the application directory
SECRET_FILE="/home/daytona/repo/src/secret.txt"

if [ -f "$SECRET_FILE" ]; then
    echo "[+] Secret file found at: $SECRET_FILE"
    echo ""
    echo "[+] File permissions:"
    ls -la "$SECRET_FILE"
    echo ""
    echo "[+] File contents (SENSITIVE INFORMATION):"
    cat "$SECRET_FILE"
    echo ""
    echo "[+] Number of secrets in file:"
    wc -l "$SECRET_FILE"
    echo ""
    echo "[!] VULNERABILITY CONFIRMED:"
    echo "    - Secret file is readable from filesystem"
    echo "    - Contains flags/secrets in plaintext"
    echo "    - Loaded into application memory at startup"
    echo "    - Accessible if any RCE vulnerabilities exist in application"
else
    echo "[-] Secret file not found at expected location"
    exit 1
fi

# Check if we can access the app.py to see how it loads secrets
APP_FILE="/home/daytona/repo/src/app.py"
if [ -f "$APP_FILE" ]; then
    echo ""
    echo "[+] Checking app.py for secret loading code:"
    grep -n "flags\|secret" "$APP_FILE" | head -20
fi

echo ""
echo "=========================================="
echo "POC Complete"
echo "=========================================="