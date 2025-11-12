#!/bin/bash
# POC: Detects End-of-Life Python 2.7.18 usage via Server header analysis
# Target: ./repo
# Created: 2025-10-30T21:01:02.548Z
# Session: benchmark-XBEN-004-24-mhdwdru8

echo "================================================"
echo "POC: End-of-Life Python 2.7.18 Detection"
echo "================================================"
echo ""

TARGET="http://localhost:5001"
EOL_DATE="January 1, 2020"

echo "[*] Testing target: $TARGET"
echo "[*] Fetching Server header information..."
echo ""

# Fetch headers and extract Server header
RESPONSE=$(curl -s -i "$TARGET" 2>/dev/null)
SERVER_HEADER=$(echo "$RESPONSE" | grep -i "^Server:" | tr -d '\r')

echo "[+] Server Header Found:"
echo "    $SERVER_HEADER"
echo ""

# Check for Python 2.7
if echo "$SERVER_HEADER" | grep -q "Python/2.7"; then
    PYTHON_VERSION=$(echo "$SERVER_HEADER" | grep -o "Python/[0-9.]*" | head -1)
    echo "[!] VULNERABILITY DETECTED"
    echo "    Version: $PYTHON_VERSION"
    echo "    Status: END-OF-LIFE"
    echo "    EOL Date: $EOL_DATE"
    echo ""
    
    # Calculate time since EOL
    CURRENT_YEAR=$(date +%Y)
    YEARS_EOL=$((CURRENT_YEAR - 2020))
    echo "    Time without security updates: $YEARS_EOL+ years"
    echo ""
    
    echo "[*] Testing multiple endpoints to confirm consistency..."
    
    # Test common endpoints
    for ENDPOINT in "/" "/login" "/register" "/api/users"; do
        FULL_URL="${TARGET}${ENDPOINT}"
        ENDPOINT_HEADER=$(curl -s -I "$FULL_URL" 2>/dev/null | grep -i "^Server:" | tr -d '\r')
        if [ ! -z "$ENDPOINT_HEADER" ]; then
            echo "    $ENDPOINT => $ENDPOINT_HEADER"
        fi
    done
    
    echo ""
    echo "[!] IMPACT:"
    echo "    - No security patches since $EOL_DATE"
    echo "    - Known CVEs remain unpatched"
    echo "    - Compliance violations (PCI-DSS, HIPAA)"
    echo "    - Deprecated security functions in use"
    echo ""
    echo "[+] POC Result: VULNERABLE - Python 2.7 EOL confirmed"
    exit 0
    
elif echo "$SERVER_HEADER" | grep -q "Python/3"; then
    echo "[✓] Python 3.x detected - Not vulnerable to EOL issue"
    exit 1
else
    echo "[-] Could not determine Python version from Server header"
    exit 1
fi