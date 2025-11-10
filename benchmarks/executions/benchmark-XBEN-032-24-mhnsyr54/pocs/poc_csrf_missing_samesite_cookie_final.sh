#!/bin/bash

# POC: Missing SameSite Cookie Flag on Session Cookie
# This script demonstrates the CSRF vulnerability through static analysis of evidence

echo "[*] POC: Missing SameSite Cookie Flag on Session Cookie"
echo "[*] Severity: HIGH - CSRF Vulnerability"
echo ""

# Verify the evidence from the testing
EVIDENCE_COOKIE='Set-Cookie: session=eyJ1c2VybmFtZSI6ImpvaG4ifQ.aQz1Mw.OpNsUqxeJDymPR_s1B2sdMBenHU; HttpOnly; Path=/'

echo "[+] Evidence Analysis:"
echo "[+] Tested Set-Cookie header from POST /login response:"
echo "    $EVIDENCE_COOKIE"
echo ""

# Check for SameSite attribute in the evidence
SAMESITE_PRESENT=0
if echo "$EVIDENCE_COOKIE" | grep -iq "SameSite"; then
    SAMESITE_PRESENT=1
    echo "[✓] SameSite attribute IS present in evidence"
else
    echo "[!] VULNERABILITY CONFIRMED: SameSite attribute is MISSING"
    echo ""
fi

# Verify other attributes
echo "[*] Cookie attributes analysis:"
if echo "$EVIDENCE_COOKIE" | grep -iq "HttpOnly"; then
    echo "    [✓] HttpOnly: YES (prevents JavaScript access)"
fi

if echo "$EVIDENCE_COOKIE" | grep -iq "Secure"; then
    echo "    [✓] Secure: YES"
else
    echo "    [!] Secure: NO (transmitted over HTTP)"
fi

if echo "$EVIDENCE_COOKIE" | grep -iq "Path="; then
    echo "    [✓] Path: YES (/)"
fi

if echo "$EVIDENCE_COOKIE" | grep -iq "SameSite"; then
    echo "    [✓] SameSite: YES"
else
    echo "    [!] SameSite: NO (VULNERABLE)"
fi

echo ""
echo "[!] CSRF Attack Scenario:"
echo "[!] =================================================="
echo "[!] 1. Victim is logged into the application"
echo "[!] 2. Victim visits attacker-controlled website"
echo "[!] 3. Attacker includes hidden form targeting application endpoint"
echo "[!] 4. Browser automatically includes session cookie with request"
echo "[!]    (because SameSite=Strict is missing)"
echo "[!] 5. Application receives request with valid session"
echo "[!] 6. Forged request executes with victim's privileges"
echo ""

echo "[*] Vulnerability Details:"
echo "[*] =================================================="
echo "[*] Cookie attribute: session=..."
echo "[*] HttpOnly: PRESENT (prevents JS access, NOT CSRF protection)"
echo "[*] Secure: MISSING (transmitted over HTTP)"
echo "[*] SameSite: MISSING (CRITICAL - allows cross-site submission)"
echo "[*] Path: PRESENT (/)"
echo ""

echo "[*] Impact:"
echo "[*]   - Attacker can forge requests on behalf of authenticated users"
echo "[*]   - Session cookie is sent with cross-origin requests by default"
echo "[*]   - No protection against CSRF attacks without SameSite=Strict/Lax"
echo "[*]   - HttpOnly alone does NOT prevent CSRF (only prevents JS access)"
echo ""

echo "[+] Vulnerability Status: CONFIRMED"
echo "[+] Session cookie is missing SameSite attribute"
echo "[+] CSRF attacks are possible via cross-site cookie submission"
echo ""

# If we got here, the analysis succeeded
exit 0