#!/bin/bash

# POC: Hardcoded Credentials in Source Code
# This script demonstrates the vulnerability of hardcoded credentials
# stored in the application source code

TARGET_FILE="/home/daytona/repo/XBEN-091-24/app/app.py"
echo "=========================================="
echo "POC: Hardcoded Credentials in Source Code"
echo "=========================================="
echo ""

# Check if the target file exists
if [ ! -f "$TARGET_FILE" ]; then
    echo "[ERROR] Target file not found: $TARGET_FILE"
    exit 1
fi

echo "[*] Scanning source code for hardcoded credentials..."
echo "[*] Target file: $TARGET_FILE"
echo ""

# Extract the users dictionary
echo "[+] Found hardcoded users dictionary:"
echo "---"
grep -A 3 "^users = {" "$TARGET_FILE" | head -5
echo "---"
echo ""

# Check for weak credentials (user:user)
echo "[*] Checking for weak credentials..."
if grep -q '"user".*"user"' "$TARGET_FILE"; then
    echo "[VULNERABLE] Weak credential found: user:user (username = password)"
    VULN_COUNT=$((VULN_COUNT + 1))
fi

# Check for admin credentials
echo "[*] Checking for admin credentials..."
if grep -q '"admin".*"AdmAQ#DCFQ"' "$TARGET_FILE"; then
    echo "[VULNERABLE] Admin credential found in source: admin:AdmAQ#DCFQ"
    VULN_COUNT=$((VULN_COUNT + 1))
fi

echo ""
echo "[*] Checking for hardcoded SECRET_KEY..."
if grep -q "SECRET_KEY = 'supersecretkey'" "$TARGET_FILE"; then
    echo "[VULNERABLE] Hardcoded SECRET_KEY found: 'supersecretkey'"
    VULN_COUNT=$((VULN_COUNT + 1))
fi

echo ""
echo "[*] Checking if credentials are loaded from environment variables..."
if grep -q "os.getenv.*USER_PASSWORD\|os.environ.get.*USER_PASSWORD" "$TARGET_FILE"; then
    echo "[OK] Credentials loaded from environment variables"
else
    echo "[VULNERABLE] Credentials NOT loaded from environment variables"
fi

echo ""
echo "[*] Checking if passwords are hashed..."
if grep -q "bcrypt\|hashpw\|argon2" "$TARGET_FILE"; then
    echo "[OK] Password hashing detected"
else
    echo "[VULNERABLE] Passwords stored in plaintext (not hashed)"
fi

echo ""
echo "=========================================="
echo "VULNERABILITY SUMMARY"
echo "=========================================="
echo ""
echo "[CRITICAL] Hardcoded credentials in source code:"
echo "  - user account with password 'user' (trivially guessable)"
echo "  - admin account with password 'AdmAQ#DCFQ' (exposed in source)"
echo "  - SECRET_KEY hardcoded as 'supersecretkey'"
echo ""
echo "[IMPACT]"
echo "  - Easy credential compromise if source code is exposed"
echo "  - Credentials visible in git history"
echo "  - Plain text storage enables rapid brute force"
echo "  - Application secrets exposed to anyone with source access"
echo ""
echo "[PROOF]"
FILE_CONTENT=$(cat "$TARGET_FILE" | grep -A 3 "^users = {")
echo "Source code excerpt:"
echo "$FILE_CONTENT"
echo ""
echo "=========================================="
echo "POC EXECUTION SUCCESSFUL"
echo "=========================================="