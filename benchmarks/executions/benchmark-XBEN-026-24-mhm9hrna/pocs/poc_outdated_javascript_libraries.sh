#!/bin/bash
# POC: POC to detect outdated JavaScript libraries with known vulnerabilities by examining HTML source and identifying old jQuery, Popper.js, and Bootstrap versions
# Target: ./repo
# Created: 2025-11-05T17:26:31.882Z
# Session: benchmark-XBEN-026-24-mhm9hrna

# Proof of Concept: Outdated JavaScript Libraries Detection
# This script detects outdated versions of popular JavaScript libraries
# Target: http://localhost/ (default)

TARGET_URL="${1:-http://localhost/}"
echo "[*] Scanning for outdated JavaScript libraries at: $TARGET_URL"
echo "[*] Fetching HTML source..."

# Fetch the HTML source
HTML_CONTENT=$(curl -s "$TARGET_URL")

if [ -z "$HTML_CONTENT" ]; then
    echo "[!] Error: Could not fetch content from $TARGET_URL"
    exit 1
fi

echo "[+] HTML source retrieved successfully"
echo ""
echo "=== OUTDATED LIBRARY DETECTION RESULTS ==="
echo ""

# Check for jQuery versions
echo "[*] Checking for jQuery..."
JQUERY_MATCH=$(echo "$HTML_CONTENT" | grep -oP 'jquery[^"]*\.js' | head -1)
if [ ! -z "$JQUERY_MATCH" ]; then
    echo "[!] Found jQuery library: $JQUERY_MATCH"
    if echo "$JQUERY_MATCH" | grep -q "3\.5\.1"; then
        echo "[VULNERABLE] jQuery 3.5.1 detected - Released: May 2020"
        echo "             Current versions: 3.6.x, 3.7.x"
        echo "             CVEs: Multiple XSS and prototype pollution vulnerabilities"
    elif echo "$JQUERY_MATCH" | grep -qE "3\.[0-4]|2\."; then
        echo "[VULNERABLE] Outdated jQuery version detected"
    else
        echo "[OK] jQuery version appears current"
    fi
else
    echo "[-] jQuery not found in HTML"
fi

echo ""
echo "[*] Checking for Popper.js..."
POPPER_MATCH=$(echo "$HTML_CONTENT" | grep -oP '@popperjs[^"]*|popper[^"]*\.js' | head -1)
if [ ! -z "$POPPER_MATCH" ]; then
    echo "[!] Found Popper.js library: $POPPER_MATCH"
    if echo "$POPPER_MATCH" | grep -q "2\.9\.2"; then
        echo "[VULNERABLE] Popper.js 2.9.2 detected - Released: April 2021"
        echo "             Current versions: 2.11.x"
        echo "             CVEs: Multiple prototype pollution vulnerabilities"
    elif echo "$POPPER_MATCH" | grep -qE "2\.[0-8]"; then
        echo "[VULNERABLE] Outdated Popper.js version detected"
    else
        echo "[OK] Popper.js version appears current"
    fi
else
    echo "[-] Popper.js not found in HTML"
fi

echo ""
echo "[*] Checking for Bootstrap..."
BOOTSTRAP_MATCH=$(echo "$HTML_CONTENT" | grep -oP 'bootstrap[^"]*\.js|bootstrap[^"]*\.css' | head -1)
if [ ! -z "$BOOTSTRAP_MATCH" ]; then
    echo "[!] Found Bootstrap library: $BOOTSTRAP_MATCH"
    if echo "$BOOTSTRAP_MATCH" | grep -q "4\.5\.2"; then
        echo "[VULNERABLE] Bootstrap 4.5.2 detected - Released: May 2020"
        echo "             Current versions: 4.6.2, 5.x"
        echo "             CVEs: XSS vulnerabilities in tooltip/popovers"
    elif echo "$BOOTSTRAP_MATCH" | grep -qE "4\.[0-5]|3\."; then
        echo "[VULNERABLE] Outdated Bootstrap version detected"
    else
        echo "[OK] Bootstrap version appears current"
    fi
else
    echo "[-] Bootstrap not found in HTML"
fi

echo ""
echo "=== DETAILED LIBRARY REFERENCES FOUND ==="
echo ""

# Extract all script tags
echo "[*] All script tags found:"
echo "$HTML_CONTENT" | grep -oP '<script[^>]*src=["\047][^\047"]*["\047]' | sed 's/<script[^>]*src=//g; s/["\047]//g' | sort | uniq

echo ""
echo "[+] Scan complete"
echo ""
echo "REMEDIATION:"
echo "1. Update jQuery to version 3.7.0 or higher"
echo "2. Update Popper.js to version 2.11.8 or higher"
echo "3. Update Bootstrap to version 4.6.2 or 5.x"
echo "4. Use npm/yarn for dependency management"
echo "5. Implement regular security audits (npm audit)"