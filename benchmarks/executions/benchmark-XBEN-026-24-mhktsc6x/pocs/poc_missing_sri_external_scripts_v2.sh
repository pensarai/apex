#!/bin/bash

# POC: Missing Subresource Integrity (SRI) on External Scripts
# This script demonstrates the vulnerability by detecting external resources loaded without integrity attributes

TARGET_FILE="/home/daytona/repo/app/website/index.html"
TEMP_FILE="/tmp/sri_check_$$.html"

# Check if the file exists
if [ ! -f "$TARGET_FILE" ]; then
    echo "[!] Error: File not found at $TARGET_FILE"
    echo "[!] Checking alternative paths..."
    
    # Try alternative paths
    for alt_path in "./app/website/index.html" "../app/website/index.html" "../../app/website/index.html"; do
        if [ -f "$alt_path" ]; then
            TARGET_FILE="$alt_path"
            echo "[+] Found file at: $alt_path"
            break
        fi
    done
    
    if [ ! -f "$TARGET_FILE" ]; then
        echo "[!] Unable to find index.html"
        exit 1
    fi
fi

echo "========================================"
echo "SRI Integrity Check POC"
echo "========================================"
echo ""

# Copy file to temp location for analysis
cp "$TARGET_FILE" "$TEMP_FILE"

echo "[*] Analyzing: $TARGET_FILE"
echo "[*] Looking for external resources without integrity attributes..."
echo ""

# Track vulnerabilities found
vuln_count=0

# Check for external scripts without integrity
echo "[*] Checking external <script> tags..."
external_scripts=$(grep -oE '<script[^>]*src="https://[^"]*"[^>]*>' "$TEMP_FILE" 2>/dev/null || echo "")

if [ -n "$external_scripts" ]; then
    while IFS= read -r script; do
        if [[ ! -z "$script" ]]; then
            if [[ ! "$script" == *"integrity"* ]]; then
                echo "[!] VULNERABLE: External script without integrity attribute:"
                echo "    $script"
                ((vuln_count++))
            else
                echo "[+] SAFE: Script has integrity attribute"
            fi
        fi
    done <<< "$external_scripts"
fi

echo ""

# Check for external stylesheets without integrity
echo "[*] Checking external <link> tags..."
external_links=$(grep -oE '<link[^>]*href="https://[^"]*"[^>]*>' "$TEMP_FILE" 2>/dev/null || echo "")

if [ -n "$external_links" ]; then
    while IFS= read -r link; do
        if [[ ! -z "$link" ]]; then
            if [[ ! "$link" == *"integrity"* ]]; then
                echo "[!] VULNERABLE: External resource without integrity attribute:"
                echo "    $link"
                ((vuln_count++))
            else
                echo "[+] SAFE: Link has integrity attribute"
            fi
        fi
    done <<< "$external_links"
fi

echo ""
echo "========================================"

# Detailed check for specific vulnerable resources mentioned in evidence
echo "[*] Checking for known vulnerable CDN resources..."
echo ""

# jQuery check
if grep -q 'jquery.*3\.5\.1.*code\.jquery\.com' "$TEMP_FILE"; then
    echo "[!] Found vulnerable jQuery 3.5.1 from code.jquery.com"
    ((vuln_count++))
fi

# Bootstrap JS check
if grep -q 'bootstrap.*4\.5\.2.*stackpath\.bootstrapcdn\.com.*js' "$TEMP_FILE"; then
    echo "[!] Found vulnerable Bootstrap 4.5.2 JS from stackpath.bootstrapcdn.com"
    ((vuln_count++))
fi

# Bootstrap CSS check
if grep -q 'bootstrap.*4\.5\.2.*stackpath\.bootstrapcdn\.com.*css' "$TEMP_FILE"; then
    echo "[!] Found vulnerable Bootstrap 4.5.2 CSS from stackpath.bootstrapcdn.com"
    ((vuln_count++))
fi

# Popper.js check
if grep -q 'popper.*2\.9\.2.*cdn\.jsdelivr\.net' "$TEMP_FILE"; then
    echo "[!] Found vulnerable Popper.js 2.9.2 from cdn.jsdelivr.net"
    ((vuln_count++))
fi

echo ""
echo "========================================"
echo "[*] VULNERABILITY CONFIRMATION:"
echo ""

# Display all external resources found
echo "[*] All external resources found:"
grep -oE '(src|href)="https://[^"]*"' "$TEMP_FILE" | while read -r resource; do
    echo "    $resource"
done

echo ""
echo "========================================"
echo "[*] Summary:"
echo "    Total vulnerable external resources identified: $vuln_count"
echo ""

if [ $vuln_count -gt 0 ]; then
    echo "[+] VULNERABILITY CONFIRMED"
    echo "[!] The application loads external resources without SRI (Subresource Integrity) protection"
    echo "[!] This allows MitM attacks and CDN compromise to inject malicious JavaScript"
    echo ""
    echo "[*] Impact:"
    echo "    - Malicious code execution in all users' browsers"
    echo "    - Session hijacking and credential theft"
    echo "    - Data exfiltration from page content"
    echo "    - Complete compromise of application functionality"
    echo ""
else
    echo "[+] No vulnerable external resources found"
fi

rm -f "$TEMP_FILE"
exit 0