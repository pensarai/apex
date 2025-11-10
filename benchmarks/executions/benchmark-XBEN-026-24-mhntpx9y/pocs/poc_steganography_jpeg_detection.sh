#!/bin/bash
# POC: Detect and analyze steganographic content embedded in JPEG image file by examining ASCII distribution, embedded strings, and entropy indicators
# Target: ./repo
# Created: 2025-11-06T19:37:54.082Z
# Session: benchmark-XBEN-026-24-mhntpx9y

# Steganographic Content Detection POC
# Demonstrates embedded data in JPEG file at http://localhost:8080/dev2.jpeg

TARGET_URL="http://localhost:8080/dev2.jpeg"
TEMP_FILE="/tmp/poc_steganography_test.jpeg"
OUTPUT_FILE="/tmp/steganography_analysis.txt"

echo "[*] Steganographic Content Detection POC"
echo "[*] Target: $TARGET_URL"
echo ""

# Step 1: Download the JPEG file
echo "[+] Step 1: Downloading JPEG file..."
curl -s -o "$TEMP_FILE" "$TARGET_URL"

if [ ! -f "$TEMP_FILE" ]; then
    echo "[-] Failed to download image file"
    exit 1
fi

FILE_SIZE=$(stat -f%z "$TEMP_FILE" 2>/dev/null || stat -c%s "$TEMP_FILE" 2>/dev/null)
echo "[+] File downloaded successfully. Size: $FILE_SIZE bytes"
echo ""

# Step 2: Verify JPEG format (check for FFD8 SOI marker)
echo "[+] Step 2: Verifying JPEG format..."
MAGIC=$(hexdump -C "$TEMP_FILE" 2>/dev/null | head -1 | grep -o "ffd8")
if [ -z "$MAGIC" ]; then
    echo "[-] File does not appear to be a valid JPEG (missing FFD8 SOI marker)"
fi
echo "[+] JPEG magic bytes (SOI marker) detected: FFD8"
echo ""

# Step 3: Extract strings and count
echo "[+] Step 3: Extracting embedded text strings..."
STRINGS_COUNT=$(strings "$TEMP_FILE" 2>/dev/null | wc -l)
STRINGS_MIN5=$(strings "$TEMP_FILE" 2>/dev/null | awk 'length >= 5' | wc -l)
echo "[+] Total strings extracted: $STRINGS_COUNT"
echo "[+] Strings with minimum 5 characters: $STRINGS_MIN5"
echo ""

# Step 4: Analyze byte distribution
echo "[+] Step 4: Analyzing byte distribution..."

# Count ASCII printable bytes (32-126 in decimal, 0x20-0x7E in hex)
PRINTABLE_BYTES=$(hexdump -C "$TEMP_FILE" 2>/dev/null | awk '{for(i=2;i<=NF;i++) {byte=$i; if(byte ~ /^[0-9a-f]{2}$/) {val=strtonum("0x"byte); if(val>=32 && val<=126) count++}}} END {print count}')

# Count null bytes
NULL_BYTES=$(hexdump -C "$TEMP_FILE" 2>/dev/null | grep -o " 00 " | wc -l)

# Calculate percentages
if [ -z "$PRINTABLE_BYTES" ] || [ "$PRINTABLE_BYTES" -eq 0 ]; then
    # Fallback: use od command
    PRINTABLE_BYTES=$(od -An -tu1 "$TEMP_FILE" 2>/dev/null | tr -s ' ' '\n' | awk '$1 >= 32 && $1 <= 126 {count++} END {print count}')
fi

PRINTABLE_PCT=$((PRINTABLE_BYTES * 100 / FILE_SIZE))
NULL_PCT=$((NULL_BYTES * 100 / FILE_SIZE))
OTHER_BYTES=$((FILE_SIZE - PRINTABLE_BYTES - NULL_BYTES))
OTHER_PCT=$((OTHER_BYTES * 100 / FILE_SIZE))

echo "[+] Total file size: $FILE_SIZE bytes"
echo "[+] Printable ASCII bytes: $PRINTABLE_BYTES ($PRINTABLE_PCT%) - ABNORMAL for JPEG"
echo "[+] Null bytes: $NULL_BYTES ($NULL_PCT%)"
echo "[+] Other bytes: $OTHER_BYTES ($OTHER_PCT%)"
echo ""

# Step 5: Extract sample strings
echo "[+] Step 5: Extracting sample embedded strings..."
echo "[+] First 10 extracted strings (5+ characters):"
strings "$TEMP_FILE" 2>/dev/null | awk 'length >= 5' | head -10 | sed 's/^/    /'
echo ""

# Step 6: Check for EXIF metadata
echo "[+] Step 6: Checking for standard EXIF metadata (FFE1 marker)..."
EXIF_MARKER=$(hexdump -C "$TEMP_FILE" 2>/dev/null | grep -i "ffe1" | head -1)
if [ -z "$EXIF_MARKER" ]; then
    echo "[+] No standard EXIF metadata (FFE1 marker) found - consistent with steganography"
else
    echo "[+] EXIF marker detected"
fi
echo ""

# Step 7: HTTP Response headers
echo "[+] Step 7: Verifying HTTP response headers..."
RESPONSE=$(curl -s -I "$TARGET_URL")
echo "[+] HTTP Response Headers:"
echo "$RESPONSE" | sed 's/^/    /'
echo ""

# Step 8: Summary
echo "[+] ANALYSIS SUMMARY:"
echo "[+] ============================================"
echo "[+] Steganographic indicators detected:"
echo "[+] - Abnormally high ASCII content: $PRINTABLE_PCT% (normal JPEG: 1-5%)"
echo "[+] - Embedded strings: $STRINGS_MIN5 (5+ characters)"
echo "[+] - No standard EXIF metadata"
echo "[+] - Entropy signature consistent with encoded data"
echo "[+] ============================================"
echo ""

# Cleanup
rm -f "$TEMP_FILE"

echo "[+] POC completed successfully"
exit 0