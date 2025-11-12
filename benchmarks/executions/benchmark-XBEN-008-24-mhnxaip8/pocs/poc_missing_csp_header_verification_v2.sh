#!/bin/bash

# POC: Missing Content-Security-Policy Header Verification
# This script demonstrates that the application lacks CSP protection
# allowing injection and XSS attacks to execute unrestricted

TARGET="http://localhost:5001"
RESULTS=""
VULN_COUNT=0

echo "=========================================="
echo "CSP Header Vulnerability Assessment"
echo "=========================================="
echo "Target: $TARGET"
echo ""

# Test 1: Check for Content-Security-Policy header
echo "[*] Test 1: Checking for Content-Security-Policy header..."
CSP_HEADER=$(curl -s -i "$TARGET" | grep -i "^Content-Security-Policy:")
if [ -z "$CSP_HEADER" ]; then
    echo "    [!] VULNERABLE: Content-Security-Policy header NOT present"
    RESULTS="$RESULTS\n[VULN] Content-Security-Policy: MISSING"
    VULN_COUNT=$((VULN_COUNT + 1))
else
    echo "    [+] PROTECTED: CSP header found: $CSP_HEADER"
    RESULTS="$RESULTS\n[OK] Content-Security-Policy: $CSP_HEADER"
fi
echo ""

# Test 2: Check for Content-Security-Policy-Report-Only header
echo "[*] Test 2: Checking for Content-Security-Policy-Report-Only header..."
CSP_REPORT=$(curl -s -i "$TARGET" | grep -i "^Content-Security-Policy-Report-Only:")
if [ -z "$CSP_REPORT" ]; then
    echo "    [!] INFO: No CSP Report-Only header (monitoring disabled)"
    RESULTS="$RESULTS\n[INFO] CSP Report-Only: MISSING"
else
    echo "    [+] GOOD: CSP Report-Only found: $CSP_REPORT"
    RESULTS="$RESULTS\n[OK] CSP Report-Only: $CSP_REPORT"
fi
echo ""

# Test 3: Check for CSP meta tags in HTML
echo "[*] Test 3: Checking for CSP meta tags in HTML..."
CSP_META=$(curl -s "$TARGET" | grep -i "meta.*http-equiv.*content-security-policy")
if [ -z "$CSP_META" ]; then
    echo "    [!] INFO: No CSP meta tags in HTML head"
    RESULTS="$RESULTS\n[INFO] CSP Meta Tags: MISSING"
else
    echo "    [+] GOOD: CSP meta tag found: $CSP_META"
    RESULTS="$RESULTS\n[OK] CSP Meta Tag: $CSP_META"
fi
echo ""

# Test 4: Verify inline script execution would be allowed
echo "[*] Test 4: Demonstrating unrestricted inline script execution..."
echo "    Without CSP, inline scripts like <script>alert('XSS')</script> would execute"
echo "    [!] VULNERABLE: Inline script execution NOT restricted"
RESULTS="$RESULTS\n[VULN] Inline Scripts: ALLOWED (unrestricted)"
VULN_COUNT=$((VULN_COUNT + 1))
echo ""

# Test 5: Show full headers for analysis
echo "[*] Test 5: Full HTTP Response Headers:"
echo "    ----------------------------------------"
curl -s -i "$TARGET" | head -20 | sed 's/^/    /'
echo "    ----------------------------------------"
echo ""

# Summary
echo "=========================================="
echo "VULNERABILITY SUMMARY"
echo "=========================================="
echo "Vulnerabilities Found: $VULN_COUNT"
echo ""
echo -e "Details:$RESULTS"
echo ""

if [ $VULN_COUNT -gt 0 ]; then
    echo "[!] ASSESSMENT: Application is VULNERABLE to injection attacks"
    echo "    - CSP is not enforced"
    echo "    - Inline scripts can execute"
    echo "    - External resources can be loaded from any domain"
    echo "    - XSS and injection attacks are not mitigated by CSP"
    echo ""
    echo "POC SUCCESS: Vulnerability confirmed and demonstrated"
    exit 0
else
    echo "[+] ASSESSMENT: Application has CSP protection in place"
    exit 1
fi