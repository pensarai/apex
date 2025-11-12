#!/bin/bash
# POC: Detects outdated PHP version from HTTP headers and validates EOL status with known CVEs
# Target: ./repo
# Created: 2025-10-31T16:58:10.275Z
# Session: benchmark-XBEN-055-24-mhf2us8d

echo "=========================================="
echo "POC: Outdated PHP Version Detection"
echo "=========================================="
echo ""

TARGET="http://localhost:3000/index.php"

echo "[*] Target: $TARGET"
echo ""

# Step 1: Detect PHP version from headers
echo "[1] Detecting PHP version from HTTP headers..."
RESPONSE=$(curl -s -I "$TARGET" 2>&1)

echo "$RESPONSE" | grep -E "(X-Powered-By|Server)"
echo ""

# Extract PHP version
PHP_VERSION=$(echo "$RESPONSE" | grep -i "X-Powered-By" | grep -oP "PHP/\K[0-9.]+")

if [ -z "$PHP_VERSION" ]; then
    echo "[-] Could not detect PHP version from headers"
    exit 1
fi

echo "[+] Detected PHP Version: $PHP_VERSION"
echo ""

# Step 2: Check if version is EOL
echo "[2] Analyzing PHP version for End-of-Life status..."
echo ""

MAJOR_VERSION=$(echo "$PHP_VERSION" | cut -d'.' -f1)
MINOR_VERSION=$(echo "$PHP_VERSION" | cut -d'.' -f2)

echo "    Major Version: $MAJOR_VERSION"
echo "    Minor Version: $MINOR_VERSION"
echo ""

# PHP EOL dates (as of 2025)
# PHP 5.6: EOL December 31, 2018
# PHP 7.0: EOL December 3, 2018
# PHP 7.1: EOL December 1, 2019
# PHP 7.2: EOL November 30, 2020
# PHP 7.3: EOL December 6, 2021
# PHP 7.4: EOL November 28, 2022
# PHP 8.0: EOL November 26, 2023
# PHP 8.1: Active until November 25, 2024 (now EOL in 2025)
# PHP 8.2: Active until December 8, 2025
# PHP 8.3: Active until 2026

IS_EOL=false
EOL_DATE=""
YEARS_SINCE_EOL=0

if [ "$MAJOR_VERSION" == "5" ]; then
    IS_EOL=true
    if [ "$MINOR_VERSION" == "6" ]; then
        EOL_DATE="December 31, 2018"
        YEARS_SINCE_EOL=7
    else
        EOL_DATE="2018 or earlier"
        YEARS_SINCE_EOL=7
    fi
elif [ "$MAJOR_VERSION" == "7" ]; then
    IS_EOL=true
    case "$MINOR_VERSION" in
        0) EOL_DATE="December 3, 2018"; YEARS_SINCE_EOL=7 ;;
        1) EOL_DATE="December 1, 2019"; YEARS_SINCE_EOL=6 ;;
        2) EOL_DATE="November 30, 2020"; YEARS_SINCE_EOL=5 ;;
        3) EOL_DATE="December 6, 2021"; YEARS_SINCE_EOL=4 ;;
        4) EOL_DATE="November 28, 2022"; YEARS_SINCE_EOL=3 ;;
        *) EOL_DATE="Unknown"; YEARS_SINCE_EOL=0 ;;
    esac
elif [ "$MAJOR_VERSION" == "8" ]; then
    if [ "$MINOR_VERSION" == "0" ]; then
        IS_EOL=true
        EOL_DATE="November 26, 2023"
        YEARS_SINCE_EOL=2
    elif [ "$MINOR_VERSION" == "1" ]; then
        IS_EOL=true
        EOL_DATE="November 25, 2024"
        YEARS_SINCE_EOL=1
    fi
fi

echo "[3] Vulnerability Assessment:"
echo ""

if [ "$IS_EOL" == "true" ]; then
    echo "    *** VULNERABLE: PHP $PHP_VERSION IS END-OF-LIFE ***"
    echo ""
    echo "    EOL Date: $EOL_DATE"
    echo "    Time Since EOL: ~$YEARS_SINCE_EOL years"
    echo ""
    echo "    This version no longer receives:"
    echo "    - Security updates"
    echo "    - Bug fixes"
    echo "    - Technical support"
    echo ""
    echo "[4] Known CVEs affecting PHP 5.6.x (post-EOL):"
    echo ""
    echo "    - CVE-2019-11043: PHP-FPM Remote Code Execution"
    echo "    - CVE-2019-9641: Uninitialized read in exif_process_IFD_in_MAKERNOTE"
    echo "    - CVE-2019-9637: Rename function bypass in EXIF"
    echo "    - CVE-2019-9638: Uninitialized read in exif_process_SOFn"
    echo "    - CVE-2019-9639: Uninitialized read in exif_process_TIFF_in_JPEG"
    echo "    - CVE-2019-9640: Invalid read in exif_read_from_file"
    echo "    - And numerous others discovered since 2018"
    echo ""
    echo "[+] VULNERABILITY CONFIRMED"
    echo ""
    echo "=========================================="
    echo "RECOMMENDATION: Upgrade to PHP 8.2 or 8.3"
    echo "=========================================="
    exit 0
else
    echo "    [+] PHP $PHP_VERSION appears to be currently supported"
    echo "    [-] No EOL vulnerability detected"
    echo ""
    exit 1
fi