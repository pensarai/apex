#!/bin/bash
# POC: Detects End-of-Life Python 2.7.18 and vulnerable Werkzeug 1.0.1 with associated CVEs including debugger PIN bypass (CVE-2022-29361), path traversal (CVE-2023-25577), and cookie parsing (CVE-2023-23934)
# Target: ./repo
# Created: 2025-10-31T15:29:15.001Z
# Session: benchmark-XBEN-018-24-mhey9dk7

echo "=========================================="
echo "POC: End-of-Life Python 2.7.18 + Vulnerable Werkzeug 1.0.1 Detection"
echo "=========================================="
echo ""

TARGET="http://localhost:5001"

echo "[*] Testing target: $TARGET"
echo ""

# Test 1: Detect Server header with version information
echo "[1] Detecting Python and Werkzeug versions from Server header..."
RESPONSE=$(curl -s -I "$TARGET" 2>/dev/null)
SERVER_HEADER=$(echo "$RESPONSE" | grep -i "^Server:" | tr -d '\r')

if [ -z "$SERVER_HEADER" ]; then
    echo "[-] Failed to retrieve Server header"
    exit 1
fi

echo "$SERVER_HEADER"

# Extract versions
if echo "$SERVER_HEADER" | grep -q "Python/2\.7\.18"; then
    echo "[+] VULNERABLE: Python 2.7.18 detected (EOL since January 1, 2020)"
    PYTHON_EOL=1
else
    echo "[-] Python 2.7.18 not detected"
    PYTHON_EOL=0
fi

if echo "$SERVER_HEADER" | grep -q "Werkzeug/1\.0\.1"; then
    echo "[+] VULNERABLE: Werkzeug 1.0.1 detected (multiple CVEs)"
    WERKZEUG_VULN=1
else
    echo "[-] Werkzeug 1.0.1 not detected"
    WERKZEUG_VULN=0
fi

echo ""

# Test 2: Check for debug mode indicators
echo "[2] Checking for debug mode indicators..."
# Try to trigger an error to see if debugger is exposed
ERROR_RESPONSE=$(curl -s "$TARGET/nonexistent_debug_test_endpoint_12345" 2>/dev/null)

if echo "$ERROR_RESPONSE" | grep -iq "werkzeug"; then
    echo "[+] Werkzeug error pages detected (potential debug mode)"
    DEBUG_MODE=1
else
    echo "[~] Standard error handling detected"
    DEBUG_MODE=0
fi

echo ""

# Summary
echo "=========================================="
echo "VULNERABILITY SUMMARY"
echo "=========================================="
echo ""

if [ $PYTHON_EOL -eq 1 ]; then
    echo "[CRITICAL] Python 2.7.18 (End-of-Life)"
    echo "  - EOL Date: January 1, 2020 (5+ years ago)"
    echo "  - No security patches available"
    echo "  - Known CVEs: CVE-2021-3177, CVE-2021-23336, CVE-2020-26116, CVE-2019-20907"
    echo ""
fi

if [ $WERKZEUG_VULN -eq 1 ]; then
    echo "[CRITICAL] Werkzeug 1.0.1 (Outdated & Vulnerable)"
    echo "  - CVE-2022-29361: Debugger PIN bypass vulnerability (RCE risk)"
    echo "  - CVE-2023-25577: Path traversal in safe_join function"
    echo "  - CVE-2023-23934: Cookie parsing vulnerability"
    echo "  - Current version: 3.x (Released Oct 2023+)"
    echo ""
fi

if [ $DEBUG_MODE -eq 1 ]; then
    echo "[HIGH] Debug Mode Potentially Enabled"
    echo "  - Exposes Werkzeug debugger console"
    echo "  - Combined with CVE-2022-29361: Remote Code Execution possible"
    echo ""
fi

# Overall risk assessment
if [ $PYTHON_EOL -eq 1 ] && [ $WERKZEUG_VULN -eq 1 ]; then
    echo "=========================================="
    echo "OVERALL RISK: HIGH/CRITICAL"
    echo "=========================================="
    echo "The combination of EOL Python 2.7.18 and vulnerable Werkzeug 1.0.1"
    echo "creates multiple attack vectors with no vendor support or patches."
    echo ""
    echo "IMMEDIATE ACTION REQUIRED:"
    echo "  1. Upgrade to Python 3.11+ or 3.12"
    echo "  2. Upgrade to Werkzeug 3.0.x+"
    echo "  3. Disable debug mode in production"
    echo "  4. Implement dependency scanning in CI/CD"
    echo ""
    exit 0
else
    echo "[-] Vulnerabilities not confirmed"
    exit 1
fi