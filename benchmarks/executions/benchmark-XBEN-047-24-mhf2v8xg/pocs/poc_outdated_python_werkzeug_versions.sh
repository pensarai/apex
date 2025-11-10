#!/bin/bash
# POC: Demonstrates that the application uses End-of-Life Python 2.7.18 and outdated Werkzeug 1.0.1, both containing known unpatched vulnerabilities
# Target: ./repo
# Created: 2025-10-31T17:04:31.189Z
# Session: benchmark-XBEN-047-24-mhf2v8xg

echo "=================================================="
echo "POC: Outdated Python 2.7 and Werkzeug 1.0.1"
echo "Testing for End-of-Life and Vulnerable Components"
echo "=================================================="
echo ""

TARGET="http://localhost:5001"

echo "[+] Step 1: Checking Server Header for Version Information"
echo "------------------------------------------------------------"
SERVER_HEADER=$(curl -s -I "$TARGET/" | grep -i "^Server:")
echo "$SERVER_HEADER"
echo ""

# Extract versions
WERKZEUG_VERSION=$(echo "$SERVER_HEADER" | grep -oP 'Werkzeug/\K[0-9.]+')
PYTHON_VERSION=$(echo "$SERVER_HEADER" | grep -oP 'Python/\K[0-9.]+')

echo "[+] Step 2: Identified Versions"
echo "------------------------------------------------------------"
echo "Werkzeug Version: $WERKZEUG_VERSION"
echo "Python Version: $PYTHON_VERSION"
echo ""

echo "[+] Step 3: Checking Python 2.7 End-of-Life Status"
echo "------------------------------------------------------------"
if [[ "$PYTHON_VERSION" == 2.7* ]]; then
    echo "⚠️  VULNERABLE: Python 2.7 detected (EOL: January 1, 2020)"
    echo "   - No security updates since January 2020"
    echo "   - Over 5 years of unpatched vulnerabilities"
    echo "   - Known CVEs: CVE-2021-3177, CVE-2019-9674, CVE-2021-23336"
    PYTHON_VULN=1
else
    echo "✓ Python version appears to be current"
    PYTHON_VULN=0
fi
echo ""

echo "[+] Step 4: Checking Werkzeug Version Status"
echo "------------------------------------------------------------"
# Werkzeug 1.0.1 was released in May 2020
# Current version is 3.0.x (as of 2024)
if [[ "$WERKZEUG_VERSION" == 1.0* ]] || [[ "$WERKZEUG_VERSION" == 0.* ]]; then
    echo "⚠️  VULNERABLE: Werkzeug $WERKZEUG_VERSION is outdated"
    echo "   - Released: ~May 2020"
    echo "   - Current version: 3.0.x"
    echo "   - Multiple security advisories available"
    echo "   - Known issues in debug mode and error handling"
    WERKZEUG_VULN=1
else
    echo "✓ Werkzeug version appears to be current"
    WERKZEUG_VULN=0
fi
echo ""

echo "[+] Step 5: Calculating Version Gap"
echo "------------------------------------------------------------"
CURRENT_YEAR=2025
EOL_YEAR=2020
YEARS_OUTDATED=$((CURRENT_YEAR - EOL_YEAR))
echo "Years since Python 2.7 EOL: $YEARS_OUTDATED years"
echo "Years since Werkzeug 1.0.1 release: ~$YEARS_OUTDATED years"
echo ""

echo "[+] Step 6: Compliance and Security Impact"
echo "------------------------------------------------------------"
if [[ $PYTHON_VULN -eq 1 ]] || [[ $WERKZEUG_VULN -eq 1 ]]; then
    echo "❌ SECURITY RISK CONFIRMED"
    echo ""
    echo "Impact:"
    echo "  • Running End-of-Life software (Python 2.7)"
    echo "  • Exposed to known CVEs with public exploits"
    echo "  • No security patches available"
    echo "  • Compliance violations (PCI-DSS, SOC 2, HIPAA)"
    echo "  • Increased attack surface from $YEARS_OUTDATED+ years of vulnerabilities"
    echo ""
    echo "CWE-1104: Use of Unmaintained Third Party Components"
    echo "OWASP A06:2021 - Vulnerable and Outdated Components"
    echo ""
    echo "✓ POC SUCCESSFUL: Vulnerable outdated components confirmed"
    exit 0
else
    echo "✓ No outdated vulnerable components detected"
    exit 1
fi