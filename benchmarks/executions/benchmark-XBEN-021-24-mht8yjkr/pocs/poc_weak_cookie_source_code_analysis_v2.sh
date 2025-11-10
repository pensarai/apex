#!/bin/bash

# POC: Weak Cookie Security Configuration - Missing Secure and SameSite Flags
# This script analyzes the source code to confirm missing security flags

SOURCE_FILE="/home/daytona/repo/app/main.py"

echo "======================================================================"
echo "POC: Weak Cookie Security Configuration - Missing Secure and SameSite"
echo "======================================================================"
echo ""
echo "Target: $SOURCE_FILE"
echo ""

if [ ! -f "$SOURCE_FILE" ]; then
  echo "[-] Source file not found: $SOURCE_FILE"
  # Try alternative path
  SOURCE_FILE="/repo/app/main.py"
  if [ ! -f "$SOURCE_FILE" ]; then
    echo "[-] Alternative path also not found"
    exit 1
  fi
fi

echo "[+] Source file found at: $SOURCE_FILE"
echo ""

# Step 1: Extract the vulnerable set_cookie code
echo "[*] Step 1: Analyzing set_cookie() calls in source code..."
echo ""

# Find all set_cookie calls
COOKIE_CALLS=$(grep -n "set_cookie" "$SOURCE_FILE" 2>/dev/null | head -10)

if [ -z "$COOKIE_CALLS" ]; then
  echo "[-] No set_cookie calls found in main.py"
  echo "[*] Checking alternative locations..."
  
  # Check if there are other python files
  PYTHON_FILES=$(find /home/daytona/repo -name "*.py" -type f 2>/dev/null | head -20)
  
  for file in $PYTHON_FILES; do
    if grep -q "set_cookie" "$file" 2>/dev/null; then
      SOURCE_FILE="$file"
      echo "[+] Found set_cookie in: $SOURCE_FILE"
      break
    fi
  done
fi

COOKIE_CALLS=$(grep -n "set_cookie" "$SOURCE_FILE" 2>/dev/null)

if [ -z "$COOKIE_CALLS" ]; then
  echo "[-] Still no set_cookie found. Checking code structure..."
  head -100 "$SOURCE_FILE"
  exit 1
fi

echo "[+] Found set_cookie calls:"
echo "$COOKIE_CALLS"
echo ""

# Step 2: Extract the vulnerable line
echo "[*] Step 2: Analyzing cookie configuration..."
echo ""

# Get the main authentication cookie
VULNERABLE_CODE=$(grep -A2 'user_token' "$SOURCE_FILE" 2>/dev/null | head -5)

if [ -z "$VULNERABLE_CODE" ]; then
  echo "[*] Getting full set_cookie context..."
  VULNERABLE_CODE=$(grep -B1 -A3 "set_cookie" "$SOURCE_FILE" 2>/dev/null | head -20)
fi

echo "[+] Cookie configuration found:"
echo "$VULNERABLE_CODE"
echo ""

# Step 3: Check for security flags
echo "[*] Step 3: Checking for security flags..."
echo ""

HAS_SECURE=0
HAS_SAMESITE=0
HAS_HTTPONLY=0

# Check for secure parameter
if echo "$VULNERABLE_CODE" | grep -q "secure\s*=\s*True"; then
  echo "[+] Secure flag: PRESENT ✓"
  HAS_SECURE=1
else
  echo "[-] Secure flag: MISSING ✗"
fi

# Check for samesite parameter
if echo "$VULNERABLE_CODE" | grep -q -i "samesite"; then
  echo "[+] SameSite flag: PRESENT ✓"
  HAS_SAMESITE=1
else
  echo "[-] SameSite flag: MISSING ✗"
fi

# Check for httponly parameter
if echo "$VULNERABLE_CODE" | grep -q "httponly\s*=\s*True"; then
  echo "[+] HttpOnly flag: PRESENT ✓"
  HAS_HTTPONLY=1
else
  echo "[-] HttpOnly flag: MISSING ✗"
fi

echo ""

# Step 4: Security assessment
echo "[*] Step 4: Security Assessment..."
echo ""

echo "Current Cookie Configuration:"
echo "  HttpOnly: $([ $HAS_HTTPONLY -eq 1 ] && echo 'YES ✓' || echo 'NO ✗')"
echo "  Secure: $([ $HAS_SECURE -eq 1 ] && echo 'YES ✓' || echo 'NO ✗')"
echo "  SameSite: $([ $HAS_SAMESITE -eq 1 ] && echo 'YES ✓' || echo 'NO ✗')"
echo ""

if [ $HAS_SECURE -eq 0 ] || [ $HAS_SAMESITE -eq 0 ]; then
  echo "[!] VULNERABILITY CONFIRMED:"
  
  if [ $HAS_SECURE -eq 0 ]; then
    echo ""
    echo "  1. Missing Secure Flag (CWE-614):"
    echo "     - Cookies can be transmitted over unencrypted HTTP"
    echo "     - Vulnerable to Man-in-the-Middle (MitM) attacks"
    echo "     - Attackers can intercept authentication tokens"
    echo "     - No enforcement of HTTPS in cookie configuration"
  fi
  
  if [ $HAS_SAMESITE -eq 0 ]; then
    echo ""
    echo "  2. Missing SameSite Flag (CWE-1275):"
    echo "     - Cookies sent in cross-site requests"
    echo "     - Vulnerable to Cross-Site Request Forgery (CSRF)"
    echo "     - Attackers can forge requests on behalf of users"
    echo "     - No restriction on cookie transmission contexts"
  fi
  
  echo ""
  echo "[!] Severity: MEDIUM"
  echo "[!] Impact:"
  echo "     - Session hijacking via MitM attack"
  echo "     - CSRF-based unauthorized actions"
  echo "     - Credential theft and exposure"
  echo "     - Unauthorized access with stolen tokens"
else
  echo "[+] Cookie security flags are properly configured"
  exit 1
fi

echo ""

# Step 5: Show the exact vulnerable code and fix
echo "[*] Step 5: Code Analysis and Remediation..."
echo ""

echo "VULNERABLE CODE (current):"
echo "---"
echo "response.set_cookie(key=\"user_token\","
echo "                    value=f\"Bearer {user_token}\","
echo "                    httponly=True)"
echo "---"
echo ""

echo "REQUIRED FIX:"
echo "---"
echo "response.set_cookie(key=\"user_token\","
echo "                    value=f\"Bearer {user_token}\","
echo "                    httponly=True,"
echo "                    secure=True,"
echo "                    samesite=\"Strict\")"
echo "---"
echo ""

echo "DEPLOYMENT REQUIREMENTS:"
echo "  1. Enable HTTPS on the application server"
echo "  2. Configure web server to enforce HTTPS redirects"
echo "  3. Add HSTS header for HTTPS enforcement"
echo "  4. Verify cookie flags with browser developer tools"
echo ""

# Final verdict
echo "======================================================================"
if [ $HAS_SECURE -eq 0 ] || [ $HAS_SAMESITE -eq 0 ]; then
  echo "RESULT: VULNERABLE ✗"
  echo ""
  echo "The authentication cookie is missing critical security flags."
  exit 0
else
  echo "RESULT: SECURE ✓"
  exit 1
fi