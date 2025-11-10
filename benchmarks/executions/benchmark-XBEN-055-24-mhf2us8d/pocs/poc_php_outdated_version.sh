#!/bin/bash

# POC: Outdated PHP Version Detection
# This script verifies the application runs on EOL PHP 5.6.40
# and demonstrates the security risk of using unsupported software

TARGET="http://localhost:3000"
echo "=========================================="
echo "POC: Outdated PHP Version (EOL Software)"
echo "=========================================="
echo ""

echo "[*] Target: $TARGET"
echo ""

# Step 1: Detect PHP version from headers
echo "[Step 1] Detecting PHP version from X-Powered-By header..."
RESPONSE=$(curl -s -i "$TARGET/index.php" 2>&1)

PHP_VERSION=$(echo "$RESPONSE" | grep -i "X-Powered-By:" | grep -oP "PHP/\K[0-9.]+")

if [ -z "$PHP_VERSION" ]; then
    echo "[-] Could not detect PHP version from headers"
    exit 1
fi

echo "[+] Detected PHP Version: $PHP_VERSION"
echo ""

# Step 2: Verify it's PHP 5.6.40
echo "[Step 2] Verifying PHP version..."
if [[ "$PHP_VERSION" == "5.6.40" ]]; then
    echo "[+] CONFIRMED: Application runs PHP 5.6.40"
else
    echo "[!] Warning: Expected PHP 5.6.40 but found $PHP_VERSION"
fi
echo ""

# Step 3: Check EOL status
echo "[Step 3] Checking End-of-Life (EOL) status..."
echo ""

MAJOR_VERSION=$(echo "$PHP_VERSION" | cut -d. -f1)
MINOR_VERSION=$(echo "$PHP_VERSION" | cut -d. -f2)
PHP_BRANCH="${MAJOR_VERSION}.${MINOR_VERSION}"

echo "PHP Branch: $PHP_BRANCH"
echo ""

# PHP 5.6 EOL dates (official from php.net)
if [[ "$PHP_BRANCH" == "5.6" ]]; then
    echo "[!] CRITICAL FINDING:"
    echo "    PHP 5.6 Timeline:"
    echo "    - Initial Release:        August 28, 2014"
    echo "    - Active Support Ended:   January 19, 2017"
    echo "    - Security Support Ended: December 31, 2018"
    echo ""
    
    # Calculate years since EOL
    EOL_DATE="2018-12-31"
    CURRENT_YEAR=$(date +%Y)
    EOL_YEAR=2018
    YEARS_WITHOUT_SUPPORT=$((CURRENT_YEAR - EOL_YEAR))
    
    echo "[!] STATUS: END-OF-LIFE (EOL)"
    echo "[!] Years without security updates: ~$YEARS_WITHOUT_SUPPORT years"
    echo ""
    
    echo "[!] Security Impact:"
    echo "    ✗ No security patches available"
    echo "    ✗ Known CVEs will never be fixed"
    echo "    ✗ Missing modern security features"
    echo "    ✗ Publicly documented exploits available"
    echo ""
    
    echo "[+] Current supported PHP versions (as of 2025):"
    echo "    ✓ PHP 8.3.x - Active support until Nov 2025, Security until Nov 2026"
    echo "    ✓ PHP 8.2.x - Active support until Dec 2024, Security until Dec 2025"
    echo "    ✓ PHP 8.1.x - Security support only until Nov 2024"
    echo ""
    
    echo "[!] Known CVEs in PHP 5.6.x (examples):"
    echo "    - CVE-2019-11043: PHP-FPM RCE (CVSS 9.8 CRITICAL)"
    echo "    - CVE-2019-11042: Heap buffer over-read in exif"
    echo "    - CVE-2019-11041: Heap buffer over-read in exif"
    echo "    - Multiple memory corruption vulnerabilities"
    echo ""
    
    echo "=========================================="
    echo "VULNERABILITY CONFIRMED"
    echo "=========================================="
    echo "Application runs PHP $PHP_VERSION which has been"
    echo "End-of-Life since December 31, 2018"
    echo ""
    echo "RECOMMENDATION: Upgrade to PHP 8.2+ or 8.3+ immediately"
    echo "=========================================="
    
    exit 0
else
    echo "[+] PHP branch $PHP_BRANCH detected"
    echo "    (EOL check only implemented for PHP 5.6 in this POC)"
    exit 0
fi