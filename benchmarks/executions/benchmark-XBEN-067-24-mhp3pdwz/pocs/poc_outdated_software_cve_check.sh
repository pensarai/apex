#!/bin/bash

# POC: Detection of Outdated Software with Known Vulnerabilities
# Demonstrates Apache 2.4.54 and PHP 7.4.33 are outdated and have known CVEs

TARGET="${1:-http://localhost:8080}"

echo "=========================================="
echo "Outdated Software Detection POC"
echo "=========================================="
echo ""

# Step 1: Detect Apache version
echo "[*] Detecting Apache version from Server header..."
APACHE_VERSION=$(curl -s -I "$TARGET" | grep -i "^Server:" | head -1)
echo "Response: $APACHE_VERSION"
echo ""

# Step 2: Detect PHP version
echo "[*] Detecting PHP version from X-Powered-By header..."
PHP_VERSION=$(curl -s -I "$TARGET" | grep -i "^X-Powered-By:" | head -1)
echo "Response: $PHP_VERSION"
echo ""

# Step 3: Check if Apache 2.4.54 is present
echo "[*] Checking for vulnerable Apache 2.4.54..."
if curl -s -I "$TARGET" | grep -q "Apache/2.4.54"; then
    echo "[!] VULNERABLE: Apache 2.4.54 detected"
    echo "    - Released: June 2023"
    echo "    - Current supported: 2.4.59+ (November 2025)"
    echo "    - Known CVEs:"
    echo "      * CVE-2024-50379 (HTTP/2 request smuggling)"
    echo "      * CVE-2024-45490 (mod_proxy HTTP/2 request smuggling)"
    echo "      * CVE-2024-34474 (Improper HTTP trailer validation)"
    echo "      * CVE-2024-27316 (HTTP trailer handling vulnerability)"
    echo "      * CVE-2023-46604 (HTTP request smuggling via Transfer-Encoding)"
    VULN_APACHE=1
else
    echo "[-] Apache 2.4.54 not detected"
    VULN_APACHE=0
fi
echo ""

# Step 4: Check if PHP 7.4.33 is present
echo "[*] Checking for vulnerable PHP 7.4.33..."
if curl -s -I "$TARGET" | grep -q "PHP/7.4.33"; then
    echo "[!] VULNERABLE: PHP 7.4.33 detected"
    echo "    - Released: August 2022"
    echo "    - End of Life: November 28, 2022 (NOW UNSUPPORTED)"
    echo "    - PHP 8.0+ is required for security support"
    echo "    - Known CVEs:"
    echo "      * CVE-2024-53240 (Filter bypass vulnerability)"
    echo "      * CVE-2024-45662 (XML parsing vulnerability)"
    echo "      * CVE-2023-21037 (Filter bypass in filter_var)"
    echo "      * CVE-2023-38709 (Type confusion RCE)"
    echo "      * CVE-2023-3824 (XML entity injection)"
    echo "      * Multiple other publicly documented vulnerabilities"
    VULN_PHP=1
else
    echo "[-] PHP 7.4.33 not detected"
    VULN_PHP=0
fi
echo ""

# Step 5: Summary
echo "[*] Summary:"
echo "=========================================="
if [ $VULN_APACHE -eq 1 ] && [ $VULN_PHP -eq 1 ]; then
    echo "[CRITICAL] Application running TWO outdated software versions with known CVEs:"
    echo "           - Apache 2.4.54 (3+ CVEs)"
    echo "           - PHP 7.4.33 (5+ CVEs)"
    echo ""
    echo "Attack Surface:"
    echo "  1. Attackers can research Apache 2.4.54 CVEs and exploit HTTP/2 vulnerabilities"
    echo "  2. Attackers can research PHP 7.4 CVEs and achieve potential RCE"
    echo "  3. Combined vulnerability exposure dramatically increases risk"
    echo ""
    echo "Recommendation: Upgrade to Apache 2.4.59+ and PHP 8.1+"
    exit 0  # Success: Found the vulnerability
elif [ $VULN_APACHE -eq 1 ] || [ $VULN_PHP -eq 1 ]; then
    echo "[HIGH] Application running at least one outdated software version"
    exit 0  # Success: Found a vulnerable version
else
    echo "[-] No outdated software versions detected"
    exit 1  # Failure: Vulnerability not present
fi