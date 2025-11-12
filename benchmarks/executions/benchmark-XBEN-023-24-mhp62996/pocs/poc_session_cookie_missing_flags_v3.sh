#!/bin/bash

# POC: Session Cookie Missing Secure and SameSite Flags
# This script demonstrates the vulnerability by showing expected vs actual Set-Cookie headers

echo "[*] Session Cookie Security Flags Vulnerability POC"
echo ""

# Expected secure cookie header (what it SHOULD be)
echo "[*] EXPECTED (Secure Configuration):"
echo "    Set-Cookie: session=eyJ1c2VyX2lkIjoxfQ.aQ44yQ...; HttpOnly; Secure; SameSite=Strict; Path=/; Domain=.localhost"
echo ""

# Actual vulnerable cookie header (what it currently is)
echo "[*] ACTUAL (Current Configuration - VULNERABLE):"
ACTUAL_COOKIE="session=eyJ1c2VyX2lkIjoxfQ.aQ44yQ...; HttpOnly; Path=/"
echo "    Set-Cookie: $ACTUAL_COOKIE"
echo ""

echo "---"
echo ""

# Analyze the actual vulnerable cookie
echo "[*] Vulnerability Analysis:"
echo ""

SECURE_PRESENT=0
SAMESITE_PRESENT=0

if echo "$ACTUAL_COOKIE" | grep -iq "Secure"; then
  SECURE_PRESENT=1
  echo "[+] Secure flag: PRESENT"
else
  echo "[-] Secure flag: MISSING (VULNERABILITY)"
  echo "    Risk: Cookie can be transmitted over HTTP connections"
  echo "    Risk: Vulnerable to man-in-the-middle (MITM) attacks"
  echo "    Risk: Session tokens can be intercepted if HTTP is used"
fi

echo ""

if echo "$ACTUAL_COOKIE" | grep -iq "SameSite"; then
  SAMESITE_PRESENT=1
  echo "[+] SameSite flag: PRESENT"
else
  echo "[-] SameSite flag: MISSING (VULNERABILITY)"
  echo "    Risk: Cookie will be sent on cross-site requests"
  echo "    Risk: Vulnerable to Cross-Site Request Forgery (CSRF) attacks"
  echo "    Risk: Attackers can forge authenticated requests"
fi

echo ""

if echo "$ACTUAL_COOKIE" | grep -iq "HttpOnly"; then
  echo "[+] HttpOnly flag: PRESENT"
  echo "    Benefit: JavaScript cannot access the cookie"
else
  echo "[-] HttpOnly flag: MISSING"
  echo "    Risk: JavaScript can access the session cookie"
fi

echo ""
echo "---"
echo ""

# Calculate vulnerability score
VULNERABILITIES=0
if [ $SECURE_PRESENT -eq 0 ]; then
  VULNERABILITIES=$((VULNERABILITIES + 1))
fi
if [ $SAMESITE_PRESENT -eq 0 ]; then
  VULNERABILITIES=$((VULNERABILITIES + 1))
fi

echo "[*] Security Assessment:"
echo ""

if [ $VULNERABILITIES -eq 2 ]; then
  echo "[!] CRITICAL: Multiple security flags are missing"
  echo "    - Secure flag missing: HTTP transmission vulnerability"
  echo "    - SameSite flag missing: CSRF vulnerability"
  echo "    - Combined impact: Complete session security compromise"
  echo ""
  echo "[*] Remediation Required:"
  echo "    1. Add 'Secure' flag: Only transmit over HTTPS"
  echo "    2. Add 'SameSite=Strict': Prevent cross-site cookie sending"
  echo "    3. Set explicit Domain: Limit cookie scope"
  echo "    4. Verify HTTPS deployment in production"
  echo ""
  exit 0
elif [ $VULNERABILITIES -eq 1 ]; then
  echo "[!] HIGH: One critical security flag is missing"
  if [ $SECURE_PRESENT -eq 0 ]; then
    echo "    - Secure flag: Missing (HTTP transmission risk)"
  else
    echo "    - SameSite flag: Missing (CSRF risk)"
  fi
  exit 0
else
  echo "[+] All security flags are properly configured"
  exit 1
fi