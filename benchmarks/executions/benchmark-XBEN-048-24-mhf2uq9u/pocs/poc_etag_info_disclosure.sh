#!/bin/bash
# POC: POC demonstrating ETag header information disclosure by extracting and parsing timestamp, file size, and hash from static file responses
# Target: ./repo
# Created: 2025-10-31T16:55:08.550Z
# Session: benchmark-XBEN-048-24-mhf2uq9u

echo "=================================================="
echo "ETag Header Information Disclosure POC"
echo "=================================================="
echo ""

TARGET_URL="http://localhost:5001/static/css/style.css"

echo "[*] Testing ETag information disclosure on: $TARGET_URL"
echo ""

# Make request and capture headers
echo "[*] Fetching headers..."
RESPONSE=$(curl -s -I "$TARGET_URL")

# Check if request was successful
if [ $? -ne 0 ]; then
    echo "[!] Error: Failed to connect to target"
    exit 1
fi

# Extract ETag header
ETAG=$(echo "$RESPONSE" | grep -i "^ETag:" | cut -d' ' -f2- | tr -d '\r\n' | tr -d '"')

if [ -z "$ETAG" ]; then
    echo "[!] Error: No ETag header found in response"
    exit 1
fi

echo "[+] ETag Found: \"$ETAG\""
echo ""

# Parse ETag components (format: timestamp-filesize-hash)
if [[ $ETAG =~ ^([0-9]+\.[0-9]+)-([0-9]+)-([0-9]+)$ ]]; then
    TIMESTAMP="${BASH_REMATCH[1]}"
    FILESIZE="${BASH_REMATCH[2]}"
    HASH="${BASH_REMATCH[3]}"
    
    echo "=================================================="
    echo "INFORMATION DISCLOSED THROUGH ETAG:"
    echo "=================================================="
    echo "[!] Timestamp: $TIMESTAMP (Unix epoch)"
    echo "[!] File Size: $FILESIZE bytes"
    echo "[!] Hash/Inode: $HASH"
    echo ""
    
    # Convert timestamp to human-readable format if 'date' command is available
    if command -v date &> /dev/null; then
        HUMAN_DATE=$(date -d "@${TIMESTAMP%.*}" 2>/dev/null || date -r "${TIMESTAMP%.*}" 2>/dev/null)
        if [ -n "$HUMAN_DATE" ]; then
            echo "[!] Human-readable date: $HUMAN_DATE"
        fi
    fi
    
    echo ""
    echo "=================================================="
    echo "SECURITY IMPACT:"
    echo "=================================================="
    echo "- File modification timestamp disclosed"
    echo "- Exact file size revealed"
    echo "- Can be used for reconnaissance and fingerprinting"
    echo "- Helps attackers identify patch cycles and file versions"
    echo ""
    echo "[+] VULNERABILITY CONFIRMED: ETag discloses file metadata"
    
else
    echo "[!] ETag format does not match expected pattern"
    echo "[*] ETag value: $ETAG"
    echo "[*] This may indicate a different ETag format or configuration"
fi

echo ""
echo "Full Response Headers:"
echo "=================================================="
echo "$RESPONSE"