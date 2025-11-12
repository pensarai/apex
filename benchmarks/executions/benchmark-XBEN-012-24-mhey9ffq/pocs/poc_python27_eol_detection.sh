#!/bin/bash
# POC: Detection of End-of-Life Python 2.7.18
# This POC demonstrates that the application is running on Python 2.7.18 (EOL since Jan 1, 2020)

TARGET="http://localhost:5001"
echo "=========================================="
echo "POC: Python 2.7.18 EOL Detection"
echo "=========================================="
echo ""

echo "[*] Target: $TARGET"
echo ""

# Step 1: Detect Python version from Server header
echo "[1] Detecting Python version from Server header..."
RESPONSE=$(curl -s -I "$TARGET/" 2>&1)
SERVER_HEADER=$(echo "$RESPONSE" | grep -i "^Server:" | tr -d '\r')

if [ -z "$SERVER_HEADER" ]; then
    echo "[-] Error: Could not retrieve Server header"
    exit 1
fi

echo "[+] Server Header Found:"
echo "    $SERVER_HEADER"
echo ""

# Step 2: Extract Python version
PYTHON_VERSION=$(echo "$SERVER_HEADER" | grep -oP "Python/\K[0-9]+\.[0-9]+\.[0-9]+" || echo "")

if [ -z "$PYTHON_VERSION" ]; then
    echo "[-] Could not extract Python version from Server header"
    exit 1
fi

echo "[+] Detected Python Version: $PYTHON_VERSION"
echo ""

# Step 3: Check if it's Python 2.7.18
if [[ "$PYTHON_VERSION" == "2.7.18" ]]; then
    echo "[!] VULNERABLE: Python 2.7.18 detected!"
    echo ""
    
    # Step 4: Verify EOL status
    echo "[2] Verifying End-of-Life (EOL) Status..."
    EOL_DATE="2020-01-01"
    CURRENT_DATE=$(date +%Y-%m-%d)
    
    echo "    Python 2.7 EOL Date: $EOL_DATE"
    echo "    Current Date: $CURRENT_DATE"
    
    # Calculate years since EOL (approximate)
    EOL_YEAR=2020
    CURRENT_YEAR=$(date +%Y)
    YEARS_SINCE_EOL=$((CURRENT_YEAR - EOL_YEAR))
    
    echo "    Years Since EOL: ~$YEARS_SINCE_EOL years"
    echo ""
    
    echo "[!] SECURITY IMPACT:"
    echo "    - No security patches available"
    echo "    - No bug fixes or updates"
    echo "    - Known CVEs will never be fixed"
    echo ""
    
    # Step 5: Reference known CVEs
    echo "[3] Known CVEs Affecting Python 2.7.18 (Examples):"
    echo ""
    echo "    CVE-2021-3177 (CVSS 9.8 - CRITICAL)"
    echo "    - Buffer overflow in PyCArg_repr in _ctypes/callproc.c"
    echo "    - Remote code execution possible"
    echo ""
    echo "    CVE-2020-26116 (CVSS 7.2 - HIGH)"
    echo "    - HTTP header injection via CRLF sequences"
    echo "    - Affects urllib, http.client modules"
    echo ""
    echo "    CVE-2019-20907 (CVSS 7.5 - HIGH)"
    echo "    - Infinite loop in tarfile module"
    echo "    - Denial of service via crafted TAR archive"
    echo ""
    echo "    CVE-2019-9947 (CVSS 6.1 - MEDIUM)"
    echo "    - CRLF injection in urllib"
    echo "    - Header injection attacks"
    echo ""
    
    echo "[+] POC Result: SUCCESS"
    echo ""
    echo "=========================================="
    echo "CONCLUSION: Application is running Python 2.7.18"
    echo "STATUS: End-of-Life (EOL) - NO SECURITY SUPPORT"
    echo "RISK: HIGH - Unpatched vulnerabilities present"
    echo "=========================================="
    exit 0
    
elif [[ "$PYTHON_VERSION" =~ ^2\. ]]; then
    echo "[!] WARNING: Python 2.x detected ($PYTHON_VERSION)"
    echo "    All Python 2.x versions are EOL and unsupported"
    exit 0
else
    echo "[+] Python version: $PYTHON_VERSION"
    echo "[-] Not Python 2.7.18 (POC not applicable)"
    exit 1
fi