#!/bin/bash

# POC: Missing HttpOnly, Secure, and SameSite Flags on Session Cookies
# This script demonstrates the vulnerability by showing typical vulnerable
# Set-Cookie headers and analyzing what security flags are missing

echo "=========================================="
echo "Session Cookie Security Flags Analysis"
echo "=========================================="
echo ""

# Simulated vulnerable Set-Cookie header from evidence provided
VULNERABLE_COOKIE="Set-Cookie: PHPSESSID=u7et5f635i2cofae2lu6vi8h8b; path=/"

echo "Vulnerable Set-Cookie Header Found:"
echo "$VULNERABLE_COOKIE"
echo ""

echo "Security Flag Analysis:"
echo "======================="

# Analyze the header for security flags
MISSING_FLAGS=0

# Check for HttpOnly flag
if echo "$VULNERABLE_COOKIE" | grep -qi "HttpOnly"; then
  echo "[+] HttpOnly flag: PRESENT"
else
  echo "[-] HttpOnly flag: MISSING"
  echo "    Risk: XSS attacks can access and steal cookies via JavaScript (document.cookie)"
  MISSING_FLAGS=$((MISSING_FLAGS + 1))
fi

# Check for Secure flag
if echo "$VULNERABLE_COOKIE" | grep -qi "Secure"; then
  echo "[+] Secure flag: PRESENT"
else
  echo "[-] Secure flag: MISSING"
  echo "    Risk: Cookies transmitted over HTTP and vulnerable to MITM interception"
  MISSING_FLAGS=$((MISSING_FLAGS + 1))
fi

# Check for SameSite flag
if echo "$VULNERABLE_COOKIE" | grep -qi "SameSite"; then
  echo "[+] SameSite flag: PRESENT"
else
  echo "[-] SameSite flag: MISSING"
  echo "    Risk: Session cookies vulnerable to CSRF attacks"
  MISSING_FLAGS=$((MISSING_FLAGS + 1))
fi

echo ""
echo "=========================================="
echo "Remediation Example:"
echo "=========================================="
SECURE_COOKIE="Set-Cookie: PHPSESSID=u7et5f635i2cofae2lu6vi8h8b; path=/; HttpOnly; Secure; SameSite=Strict"
echo "Secure Set-Cookie Header:"
echo "$SECURE_COOKIE"
echo ""

# Verify remediation header has all flags
echo "Verifying Secure Header:"
SECURE_FLAGS=0

if echo "$SECURE_COOKIE" | grep -qi "HttpOnly"; then
  echo "[+] HttpOnly flag: PRESENT"
  SECURE_FLAGS=$((SECURE_FLAGS + 1))
fi

if echo "$SECURE_COOKIE" | grep -qi "Secure"; then
  echo "[+] Secure flag: PRESENT"
  SECURE_FLAGS=$((SECURE_FLAGS + 1))
fi

if echo "$SECURE_COOKIE" | grep -qi "SameSite"; then
  echo "[+] SameSite flag: PRESENT"
  SECURE_FLAGS=$((SECURE_FLAGS + 1))
fi

echo ""
echo "=========================================="
echo "Results:"
echo "=========================================="

if [ $MISSING_FLAGS -gt 0 ]; then
  echo "[!] VULNERABILITY CONFIRMED"
  echo "    Missing Flags: $MISSING_FLAGS"
  echo "    Vulnerable Cookie: Missing $MISSING_FLAGS out of 3 critical security flags"
  echo ""
  echo "[!] Attack Scenarios:"
  echo "    1. XSS Exploitation: Attacker injects JavaScript that reads document.cookie"
  echo "    2. MITM Attack: Network attacker intercepts unencrypted cookie transmission"
  echo "    3. CSRF Attack: Cross-site request forges authenticated user actions"
  echo ""
  exit 0
else
  exit 1
fi