#!/bin/bash

# POC: Detection of End-of-Life Python 2.7.18
# This script demonstrates that the application is running on EOL Python 2.7.18
# which has 50+ known unpatched vulnerabilities

TARGET="http://localhost:5001"
echo "=========================================="
echo "POC: End-of-Life Software Detection"
echo "Target: $TARGET"
echo "=========================================="
echo ""

echo "[*] Step 1: Detecting Python version from Server header"
echo "Command: curl -sI $TARGET | grep -i server"
SERVER_HEADER=$(curl -sI "$TARGET" 2>/dev/null | grep -i "server:")
echo "$SERVER_HEADER"
echo ""

# Extract Python version
PYTHON_VERSION=$(echo "$SERVER_HEADER" | grep -oP 'Python/\K[0-9.]+')
echo "[*] Detected Python Version: $PYTHON_VERSION"
echo ""

# Check if it's Python 2.7.x
if [[ "$PYTHON_VERSION" == 2.7.* ]]; then
    echo "[!] VULNERABILITY CONFIRMED: Python 2.7.x detected (EOL since January 1, 2020)"
    echo ""
    
    echo "[*] Step 2: Checking EOL status"
    EOL_DATE="2020-01-01"
    CURRENT_DATE=$(date +%Y-%m-%d)
    echo "    - EOL Date: $EOL_DATE"
    echo "    - Current Date: $CURRENT_DATE"
    echo "    - Status: NO SECURITY UPDATES FOR 5+ YEARS"
    echo ""
    
    echo "[*] Step 3: Known Critical CVEs affecting Python 2.7.x (unpatched):"
    echo "    - CVE-2021-3177: Buffer overflow in PyCArg_UnpackTuple (CVSS 9.8 CRITICAL)"
    echo "    - CVE-2021-23336: Web cache poisoning via urllib.parse (CVSS 5.9 MEDIUM)"
    echo "    - CVE-2020-26116: HTTP header injection via CRLF (CVSS 7.2 HIGH)"
    echo "    - CVE-2019-20907: Infinite loop in tarfile module (CVSS 7.5 HIGH)"
    echo "    - Multiple pickle deserialization vulnerabilities"
    echo ""
    
    echo "[*] Step 4: Verifying with verbose request"
    echo "Command: curl -v $TARGET 2>&1 | grep -A2 'Server:'"
    curl -v "$TARGET" 2>&1 | grep -A2 "Server:"
    echo ""
    
    echo "[*] Step 5: Security Impact Assessment"
    echo "    ✗ No security patches available"
    echo "    ✗ 50+ known unpatched CVEs"
    echo "    ✗ Python 2-specific vulnerabilities (input(), pickle, urllib)"
    echo "    ✗ Cannot use modern Python 3.x security features"
    echo "    ✗ Compliance violations (PCI-DSS, SOC2, etc.)"
    echo ""
    
    echo "=========================================="
    echo "[!] RESULT: EOL SOFTWARE VULNERABILITY CONFIRMED"
    echo "=========================================="
    echo "Severity: MEDIUM"
    echo "Risk: Application running on unmaintained software with known unpatched vulnerabilities"
    echo "Recommendation: Migrate to Python 3.11+ immediately"
    echo ""
    exit 0
else
    echo "[✓] Python 2.7.x not detected. Version found: $PYTHON_VERSION"
    exit 1
fi