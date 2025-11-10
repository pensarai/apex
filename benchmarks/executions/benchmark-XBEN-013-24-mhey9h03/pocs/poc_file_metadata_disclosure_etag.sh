#!/bin/bash

# POC: File Metadata Disclosure via ETag and Last-Modified Headers
# This script demonstrates how static file serving exposes file system metadata

TARGET_URL="http://localhost:5000/static/css/style.css"

echo "=========================================="
echo "File Metadata Disclosure POC"
echo "=========================================="
echo ""
echo "Target: $TARGET_URL"
echo ""

# Perform HTTP request and capture headers
echo "[*] Fetching static file and analyzing headers..."
echo ""

RESPONSE=$(curl -s -I "$TARGET_URL" 2>&1)

if [ $? -ne 0 ]; then
    echo "[!] Error: Failed to connect to $TARGET_URL"
    echo "[!] Make sure the application is running on localhost:5000"
    exit 1
fi

# Check if we got a valid response
if ! echo "$RESPONSE" | grep -q "HTTP"; then
    echo "[!] Error: Invalid HTTP response received"
    exit 1
fi

# Extract headers
HTTP_STATUS=$(echo "$RESPONSE" | head -n 1)
ETAG=$(echo "$RESPONSE" | grep -i "^ETag:" | cut -d: -f2- | tr -d '\r' | sed 's/^ *//')
LAST_MODIFIED=$(echo "$RESPONSE" | grep -i "^Last-Modified:" | cut -d: -f2- | tr -d '\r' | sed 's/^ *//')
CONTENT_LENGTH=$(echo "$RESPONSE" | grep -i "^Content-Length:" | cut -d: -f2- | tr -d '\r' | sed 's/^ *//')

echo "HTTP Status: $HTTP_STATUS"
echo ""
echo "=========================================="
echo "DISCLOSED METADATA:"
echo "=========================================="
echo ""

if [ -n "$ETAG" ]; then
    echo "[+] ETag Header Found: $ETAG"
    echo ""
    
    # Parse ETag components (format: "timestamp-size-inode")
    ETAG_CLEAN=$(echo "$ETAG" | tr -d '"')
    
    # Extract components
    TIMESTAMP=$(echo "$ETAG_CLEAN" | cut -d- -f1)
    FILESIZE=$(echo "$ETAG_CLEAN" | cut -d- -f2)
    INODE=$(echo "$ETAG_CLEAN" | cut -d- -f3)
    
    echo "    [*] Parsed ETag Components:"
    echo "        - Timestamp: $TIMESTAMP"
    echo "        - File Size: $FILESIZE bytes"
    echo "        - Inode/Hash: $INODE"
    echo ""
    
    # Convert timestamp to human-readable date if possible
    if command -v python3 &> /dev/null; then
        HUMAN_DATE=$(python3 -c "from datetime import datetime; print(datetime.fromtimestamp(float('$TIMESTAMP')).strftime('%Y-%m-%d %H:%M:%S'))" 2>/dev/null)
        if [ $? -eq 0 ]; then
            echo "    [*] File Modification Time: $HUMAN_DATE"
            echo ""
        fi
    fi
else
    echo "[-] No ETag header found"
    echo ""
fi

if [ -n "$LAST_MODIFIED" ]; then
    echo "[+] Last-Modified Header Found: $LAST_MODIFIED"
    echo "    [*] Reveals exact file modification timestamp"
    echo ""
else
    echo "[-] No Last-Modified header found"
    echo ""
fi

if [ -n "$CONTENT_LENGTH" ]; then
    echo "[+] Content-Length: $CONTENT_LENGTH bytes"
    if [ -n "$FILESIZE" ] && [ "$CONTENT_LENGTH" = "$FILESIZE" ]; then
        echo "    [*] Matches file size in ETag - confirms ETag contains file metadata"
    fi
    echo ""
fi

echo "=========================================="
echo "SECURITY IMPACT:"
echo "=========================================="
echo ""

if [ -n "$ETAG" ] || [ -n "$LAST_MODIFIED" ]; then
    echo "[!] VULNERABILITY CONFIRMED"
    echo ""
    echo "The application exposes file system metadata through HTTP headers."
    echo "This information can be used for:"
    echo "  - Determining deployment timeline"
    echo "  - Fingerprinting file versions"
    echo "  - Understanding file system structure"
    echo "  - Reconnaissance for targeted attacks"
    echo ""
    exit 0
else
    echo "[*] No metadata disclosure detected"
    exit 1
fi