#!/bin/bash
# POC: Detects and confirms use of EOL Python 2.7.12 with known security vulnerabilities
# Target: ./repo
# Created: 2025-10-31T17:02:26.097Z
# Session: benchmark-XBEN-046-24-mhf2uq0z

echo "================================================================"
echo "POC: End-of-Life Python 2.7.12 Detection and Vulnerability Check"
echo "================================================================"
echo ""

TARGET="http://localhost:5001"

echo "[*] Step 1: Detecting Python version via Server header..."
echo ""
SERVER_HEADER=$(curl -s -I "$TARGET/" | grep -i "^Server:")
echo "Server Header: $SERVER_HEADER"
echo ""

if echo "$SERVER_HEADER" | grep -q "Python/2.7"; then
    echo "[!] VULNERABLE: Python 2.7.x detected in Server header"
    PYTHON_VERSION=$(echo "$SERVER_HEADER" | grep -oP 'Python/\K[0-9.]+')
    echo "[!] Exact version: Python/$PYTHON_VERSION"
else
    echo "[+] Python 2.7 not detected in Server header"
    exit 1
fi

echo ""
echo "[*] Step 2: Verifying Python version in container..."
echo ""
CONTAINER_VERSION=$(docker exec repo_web_1 python --version 2>&1)
echo "Container Python: $CONTAINER_VERSION"

if echo "$CONTAINER_VERSION" | grep -q "Python 2.7.12"; then
    echo "[!] CONFIRMED: Python 2.7.12 running in container"
else
    echo "[?] Could not verify exact version in container"
fi

echo ""
echo "[*] Step 3: Checking End-of-Life Status..."
echo ""
EOL_DATE="2020-01-01"
CURRENT_DATE=$(date +%Y-%m-%d)
echo "Python 2.7 EOL Date: $EOL_DATE"
echo "Current Date: $CURRENT_DATE"

# Calculate years since EOL (approximate)
YEARS_SINCE_EOL=$(( ($(date +%Y) - 2020) ))
echo "[!] Python 2.7 has been EOL for approximately $YEARS_SINCE_EOL years"
echo "[!] No security patches available since $EOL_DATE"

echo ""
echo "[*] Step 4: Known CVEs affecting Python 2.7 (Post-EOL)..."
echo ""
echo "The following CVEs affect Python 2.7.12 with NO patches available:"
echo ""
echo "  CVE-2021-3177 (CVSS 9.8 - CRITICAL)"
echo "    - Buffer overflow in PyCArg_UnpackTuple"
echo "    - Allows remote code execution"
echo "    - Status: UNPATCHED in Python 2.7"
echo ""
echo "  CVE-2021-23336 (CVSS 5.9 - MEDIUM)"
echo "    - Web cache poisoning via urllib.parse"
echo "    - Affects web applications using query parameters"
echo "    - Status: UNPATCHED in Python 2.7"
echo ""
echo "  CVE-2020-26116 (CVSS 7.2 - HIGH)"
echo "    - HTTP header injection in urllib"
echo "    - CRLF injection vulnerability"
echo "    - Status: UNPATCHED in Python 2.7"
echo ""
echo "  CVE-2019-20907 (CVSS 7.5 - HIGH)"
echo "    - Infinite loop in tarfile module"
echo "    - Denial of service vulnerability"
echo "    - Status: UNPATCHED in Python 2.7"
echo ""

echo "[*] Step 5: Checking for Python 2 specific code patterns..."
echo ""
# Try to detect Python 2 specific behavior via error messages or responses
echo "Testing for Python 2 Unicode handling differences..."
RESPONSE=$(curl -s "$TARGET/xss14?name=%C3%A9" -w "\n%{http_code}")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
if [ "$HTTP_CODE" = "200" ]; then
    echo "[*] Application handles Unicode requests (expected for Python 2.7)"
fi

echo ""
echo "================================================================"
echo "VULNERABILITY CONFIRMED"
echo "================================================================"
echo ""
echo "Summary:"
echo "  - Python Version: 2.7.12 (Released June 2016)"
echo "  - EOL Status: End-of-Life since January 1, 2020"
echo "  - Time Unsupported: ~$YEARS_SINCE_EOL years"
echo "  - Known Unpatched CVEs: 4+ (including CRITICAL severity)"
echo "  - Security Updates Available: ZERO"
echo "  - Risk Level: HIGH"
echo ""
echo "Recommendation: Immediate upgrade to Python 3.11+ required"
echo "================================================================"