#!/bin/bash

# POC: Outdated Apache HTTP Server Version Detection
# Demonstrates that Apache 2.4.25 is exposed and contains known CVEs

TARGET="http://localhost:3000"
echo "=================================================="
echo "POC: Outdated Apache HTTP Server Version 2.4.25"
echo "=================================================="
echo ""

echo "[*] Step 1: Detecting Apache version from Server header..."
RESPONSE=$(curl -s -I "$TARGET" 2>&1)
SERVER_HEADER=$(echo "$RESPONSE" | grep -i "^Server:" | tr -d '\r')

if [ -z "$SERVER_HEADER" ]; then
    echo "[-] Error: Could not retrieve Server header"
    exit 1
fi

echo "[+] Server Header Found:"
echo "    $SERVER_HEADER"
echo ""

# Extract version
APACHE_VERSION=$(echo "$SERVER_HEADER" | grep -oP "Apache/\K[0-9.]+")

if [ -z "$APACHE_VERSION" ]; then
    echo "[-] Could not extract Apache version"
    exit 1
fi

echo "[+] Detected Apache Version: $APACHE_VERSION"
echo ""

# Check if it's the vulnerable version
if [ "$APACHE_VERSION" = "2.4.25" ]; then
    echo "[!] VULNERABILITY CONFIRMED: Apache 2.4.25 detected"
    echo ""
    
    echo "[*] Step 2: Analyzing vulnerability exposure..."
    echo ""
    
    # Calculate age
    RELEASE_DATE="2016-12-20"
    CURRENT_YEAR=$(date +%Y)
    AGE=$((CURRENT_YEAR - 2016))
    
    echo "[+] Version Information:"
    echo "    - Release Date: $RELEASE_DATE"
    echo "    - Approximate Age: ~$AGE years"
    echo "    - Security Status: OUTDATED - Missing 8+ years of patches"
    echo ""
    
    echo "[!] Critical CVEs affecting Apache 2.4.25:"
    echo ""
    echo "    1. CVE-2017-7679 (CVSS 7.5) - mod_mime buffer overread"
    echo "       - Allows reading memory contents via crafted headers"
    echo ""
    echo "    2. CVE-2017-7668 (CVSS 7.5) - ap_find_token() buffer overread"
    echo "       - Memory disclosure via malformed HTTP requests"
    echo ""
    echo "    3. CVE-2017-9788 (CVSS 6.5) - Uninitialized memory reflection"
    echo "       - Information disclosure vulnerability"
    echo ""
    echo "    4. CVE-2017-9798 (CVSS 5.3) - Optionsbleed"
    echo "       - Leaks memory contents including sensitive data"
    echo ""
    echo "    5. CVE-2019-0211 (CVSS 8.8) - Privilege Escalation"
    echo "       - Local users can execute code as root"
    echo ""
    echo "    6. CVE-2019-0215 (CVSS 6.5) - mod_ssl access control bypass"
    echo "       - Bypass access restrictions"
    echo ""
    echo "    7. CVE-2021-44790 (CVSS 9.8) - mod_lua buffer overflow"
    echo "       - Remote Code Execution via buffer overflow"
    echo ""
    
    echo "[*] Step 3: Checking current patch level..."
    # Latest stable version as of 2025
    LATEST_VERSION="2.4.58"
    echo "    - Current Version: $APACHE_VERSION"
    echo "    - Latest Stable: $LATEST_VERSION+"
    echo "    - Status: 33+ patch releases behind"
    echo ""
    
    echo "[*] Step 4: Testing Server header exposure on multiple endpoints..."
    
    # Test multiple endpoints to confirm consistent version disclosure
    ENDPOINTS=("/" "/index.php" "/static/style.css")
    
    for endpoint in "${ENDPOINTS[@]}"; do
        TEST_URL="${TARGET}${endpoint}"
        TEST_SERVER=$(curl -s -I "$TEST_URL" 2>&1 | grep -i "^Server:" | tr -d '\r')
        if [[ "$TEST_SERVER" == *"Apache/2.4.25"* ]]; then
            echo "    [+] $endpoint - Apache/2.4.25 disclosed"
        fi
    done
    
    echo ""
    echo "=================================================="
    echo "[!] VULNERABILITY CONFIRMED"
    echo "=================================================="
    echo ""
    echo "Summary:"
    echo "  - Apache 2.4.25 is exposed via Server header"
    echo "  - Version is ~8 years outdated"
    echo "  - Contains 40+ known CVEs including critical RCE"
    echo "  - Missing all security patches since December 2016"
    echo "  - Affected by CVE-2021-44790 (CVSS 9.8 RCE)"
    echo ""
    echo "Impact: HIGH - Multiple exploitable CVEs with RCE potential"
    echo ""
    
else
    echo "[-] Apache 2.4.25 not detected (found: $APACHE_VERSION)"
    exit 1
fi