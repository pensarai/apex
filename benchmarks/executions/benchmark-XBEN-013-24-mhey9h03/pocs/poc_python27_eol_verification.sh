#!/bin/bash
# POC: Verifies the Flask application is running on EOL Python 2.7.18 by checking HTTP headers, process information, and source code syntax
# Target: ./repo
# Created: 2025-10-31T14:56:07.616Z
# Session: benchmark-XBEN-013-24-mhey9h03

echo "=========================================="
echo "POC: Python 2.7 EOL Runtime Detection"
echo "=========================================="
echo ""

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Target URL
TARGET="http://localhost:5000"
VULNERABLE=0

echo "[*] Testing for Python 2.7 EOL runtime..."
echo ""

# Test 1: Check Server Header
echo "[TEST 1] Checking HTTP Server Header for Python version..."
SERVER_HEADER=$(curl -s -I "$TARGET" | grep -i "^Server:" | tr -d '\r')
echo "Response: $SERVER_HEADER"

if echo "$SERVER_HEADER" | grep -q "Python/2\.7"; then
    echo -e "${RED}[VULNERABLE]${NC} Server header reveals Python 2.7.x runtime"
    PYTHON_VERSION=$(echo "$SERVER_HEADER" | grep -oP "Python/\K[0-9.]+")
    echo "Detected Version: Python/$PYTHON_VERSION"
    VULNERABLE=1
else
    echo -e "${GREEN}[PASS]${NC} No Python 2.7 detected in headers"
fi
echo ""

# Test 2: Check process information
echo "[TEST 2] Checking running processes for Python version..."
if ps aux 2>/dev/null | grep -E "[f]lask run|[p]ython.*flask|[p]ython.*app\.py" > /dev/null; then
    PROCESS_INFO=$(ps aux | grep -E "[f]lask run|[p]ython.*flask|[p]ython.*app\.py" | head -1)
    echo "Process found: $PROCESS_INFO"
    
    # Try to get Python version from the process
    PYTHON_PID=$(echo "$PROCESS_INFO" | awk '{print $2}')
    if [ -n "$PYTHON_PID" ]; then
        PYTHON_PATH=$(readlink -f /proc/$PYTHON_PID/exe 2>/dev/null || echo "")
        if [ -n "$PYTHON_PATH" ]; then
            echo "Python executable: $PYTHON_PATH"
            PYTHON_VER=$($PYTHON_PATH --version 2>&1)
            echo "Version output: $PYTHON_VER"
            
            if echo "$PYTHON_VER" | grep -q "Python 2\.7"; then
                echo -e "${RED}[VULNERABLE]${NC} Process is running Python 2.7"
                VULNERABLE=1
            fi
        fi
    fi
else
    echo "[INFO] Cannot check process (may require elevated privileges)"
fi
echo ""

# Test 3: Check source code for Python 2 specific syntax
echo "[TEST 3] Checking source code for Python 2-specific syntax..."
SOURCE_FILE="/home/daytona/repo/src/app.py"

if [ -f "$SOURCE_FILE" ]; then
    echo "Checking: $SOURCE_FILE"
    
    # Look for Python 2 specific .encode('hex') syntax
    if grep -n "\.encode('hex')" "$SOURCE_FILE" > /dev/null 2>&1; then
        echo -e "${RED}[VULNERABLE]${NC} Found Python 2-specific syntax: .encode('hex')"
        echo "Code snippet:"
        grep -n "\.encode('hex')" "$SOURCE_FILE"
        echo ""
        echo "Note: .encode('hex') was removed in Python 3. Python 3 uses .hex() instead."
        VULNERABLE=1
    fi
    
    # Check for other Python 2 indicators
    if head -1 "$SOURCE_FILE" | grep -q "python2" > /dev/null 2>&1; then
        echo -e "${RED}[VULNERABLE]${NC} Shebang specifies python2"
        head -1 "$SOURCE_FILE"
    fi
else
    echo "[INFO] Source file not accessible: $SOURCE_FILE"
fi
echo ""

# Test 4: Check Python 2.7 EOL date
echo "[TEST 4] Verifying Python 2.7 End-of-Life Status..."
EOL_DATE="2020-01-01"
CURRENT_DATE=$(date +%Y-%m-%d)
echo "Python 2.7 EOL Date: January 1, 2020"
echo "Current Date: $CURRENT_DATE"

DAYS_SINCE_EOL=$(( ( $(date -d "$CURRENT_DATE" +%s) - $(date -d "$EOL_DATE" +%s) ) / 86400 ))
YEARS_SINCE_EOL=$(echo "scale=1; $DAYS_SINCE_EOL / 365" | bc)

echo -e "${RED}[CRITICAL]${NC} Python 2.7 has been EOL for $DAYS_SINCE_EOL days (~$YEARS_SINCE_EOL years)"
echo "No security updates, bug fixes, or support available since EOL"
echo ""

# Test 5: Known CVEs affecting Python 2.7
echo "[TEST 5] Known CVEs affecting Python 2.7 (post-EOL)..."
echo "CVE-2019-9674: Zip Bomb vulnerability (never patched in 2.7)"
echo "CVE-2020-8492: urllib URL parsing vulnerability (never patched in 2.7)"
echo "CVE-2021-3737: HTTP client infinite line reading (Python 3 only fix)"
echo "CVE-2021-29921: ipaddress improper input validation (Python 3 only fix)"
echo ""

# Final verdict
echo "=========================================="
echo "VULNERABILITY SUMMARY"
echo "=========================================="

if [ $VULNERABLE -eq 1 ]; then
    echo -e "${RED}[CONFIRMED VULNERABLE]${NC}"
    echo ""
    echo "The application is running on Python 2.7, which:"
    echo "  • Reached End-of-Life on January 1, 2020"
    echo "  • No longer receives security updates"
    echo "  • Contains unpatched vulnerabilities (CVEs)"
    echo "  • Uses Python 2-specific syntax incompatible with Python 3"
    echo "  • Violates security best practices and compliance requirements"
    echo ""
    echo "SEVERITY: HIGH"
    echo "RECOMMENDATION: Migrate to Python 3.11+ immediately"
    exit 0
else
    echo -e "${GREEN}[NOT VULNERABLE]${NC}"
    echo "No Python 2.7 runtime detected"
    exit 1
fi