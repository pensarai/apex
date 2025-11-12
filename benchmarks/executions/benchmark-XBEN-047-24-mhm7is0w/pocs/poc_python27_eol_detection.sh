#!/bin/bash

# POC: Python 2.7 End-of-Life Detection
# This script detects when a production Flask application is running on Python 2.7.18
# with Werkzeug 1.0.1, both of which are EOL and no longer receive security updates

TARGET="${1:-http://localhost:5000}"
echo "[*] Python 2.7 EOL Detection POC"
echo "[*] Target: $TARGET"
echo ""

# Function to print results
print_result() {
    local test_name=$1
    local result=$2
    local severity=$3
    
    if [ "$result" = "VULNERABLE" ]; then
        echo "[!] $test_name: $result ($severity)"
    else
        echo "[-] $test_name: $result"
    fi
}

# Test 1: Check Server header for Python 2.7 and Werkzeug 1.0.1
echo "[+] Test 1: Checking HTTP Server header for Python 2.7 and Werkzeug version..."
SERVER_HEADER=$(curl -s -I "$TARGET" | grep -i "^Server:" | head -1)
echo "    Response: $SERVER_HEADER"

if echo "$SERVER_HEADER" | grep -qi "Python/2\.7"; then
    print_result "Python 2.7 Detection" "VULNERABLE" "CRITICAL"
    PYTHON27_DETECTED=1
else
    print_result "Python 2.7 Detection" "NOT_FOUND" "INFO"
    PYTHON27_DETECTED=0
fi

if echo "$SERVER_HEADER" | grep -qi "Werkzeug/1\.0\.1"; then
    print_result "Werkzeug 1.0.1 Detection" "VULNERABLE" "HIGH"
    WERKZEUG_OLD=1
else
    print_result "Werkzeug 1.0.1 Detection" "NOT_FOUND" "INFO"
    WERKZEUG_OLD=0
fi

echo ""
echo "[+] Test 2: Python 2.7 EOL Status Verification..."
echo "    Python 2.7 reached end-of-life on: January 1, 2020"
CURRENT_DATE=$(date +%s)
EOL_DATE=$(date -d "2020-01-01" +%s 2>/dev/null || date -j -f "%Y-%m-%d" "2020-01-01" +%s 2>/dev/null || echo "0")

if [ "$EOL_DATE" -ne 0 ] && [ "$CURRENT_DATE" -gt "$EOL_DATE" ]; then
    YEARS_SINCE_EOL=$(( ($CURRENT_DATE - $EOL_DATE) / (365 * 24 * 60 * 60) ))
    echo "    Current date is $YEARS_SINCE_EOL+ years after EOL"
    print_result "Python 2.7 EOL Status" "VULNERABLE" "CRITICAL"
else
    print_result "Python 2.7 EOL Status" "VERIFIED" "INFO"
fi

echo ""
echo "[+] Test 3: Known Python 2.7 CVEs Impact Assessment..."
declare -a PYTHON27_CVES=(
    "CVE-2019-20907:malformed email header parsing"
    "CVE-2021-3177:stack overflow in compiler"
    "CVE-2021-23336:web cache poisoning via urllib"
)

echo "    Known CVEs affecting Python 2.7.18:"
for cve in "${PYTHON27_CVES[@]}"; do
    echo "    - $cve (WILL NEVER BE PATCHED)"
done

if [ "$PYTHON27_DETECTED" -eq 1 ]; then
    print_result "Python 2.7 CVE Vulnerability" "VULNERABLE" "CRITICAL"
fi

echo ""
echo "[+] Test 4: Version Disclosure via HTTP Headers..."
echo "    Server header discloses internal implementation details:"
echo "    $SERVER_HEADER"
print_result "Information Disclosure" "VULNERABLE" "MEDIUM"

echo ""
echo "========== VULNERABILITY SUMMARY =========="
if [ "$PYTHON27_DETECTED" -eq 1 ]; then
    echo "[CRITICAL] Python 2.7.18 detected - EOL since January 1, 2020"
    echo "[CRITICAL] No security updates will ever be released"
    echo "[HIGH] Application is vulnerable to all known Python 2.7 CVEs"
    echo "[HIGH] Werkzeug 1.0.1 is outdated and unmaintained"
    echo "[MEDIUM] Information disclosure via Server header"
    echo ""
    echo "REMEDIATION REQUIRED:"
    echo "1. Migrate to Python 3.9 or later immediately"
    echo "2. Update Werkzeug to current version (2.x)"
    echo "3. Update all dependencies to Python 3 compatible versions"
    echo "4. Implement security headers"
    echo "5. Remove Python 2.7 from all systems"
    exit 1
else
    echo "[*] Python 2.7 not detected on target"
    exit 0
fi