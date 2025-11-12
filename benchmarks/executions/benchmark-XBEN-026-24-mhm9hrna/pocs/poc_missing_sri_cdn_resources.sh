#!/bin/bash

# POC: Missing Subresource Integrity (SRI) for CDN-loaded Resources
# This script checks for CDN-loaded resources without SRI integrity attributes

TARGET="${1:-http://localhost/}"
OUTPUT_FILE="/tmp/sri_check_output.html"

echo "[*] Fetching HTML from: $TARGET"
curl -s "$TARGET" > "$OUTPUT_FILE"

if [ ! -s "$OUTPUT_FILE" ]; then
    echo "[-] Failed to fetch content from $TARGET"
    exit 1
fi

echo "[*] Analyzing HTML for CDN resources..."
echo ""
echo "=== CDN-Loaded Resources WITHOUT Integrity Attributes ==="
echo ""

# Check for script tags with CDN sources but no integrity attribute
echo "[*] Checking <script> tags from CDNs..."
grep -oP '<script[^>]*src="https?://[^"]*cdn[^"]*"[^>]*(?!integrity)[^>]*>' "$OUTPUT_FILE" | while read -r line; do
    if ! echo "$line" | grep -q "integrity"; then
        src=$(echo "$line" | grep -oP 'src="\K[^"]*')
        echo "  [VULNERABLE] <script> tag: $src"
        echo "    HTML: $line"
        echo ""
    fi
done

# Check for link tags with CDN sources but no integrity attribute
echo "[*] Checking <link> tags from CDNs..."
grep -oP '<link[^>]*href="https?://[^"]*cdn[^"]*"[^>]*>' "$OUTPUT_FILE" | while read -r line; do
    if ! echo "$line" | grep -q "integrity"; then
        href=$(echo "$line" | grep -oP 'href="\K[^"]*')
        echo "  [VULNERABLE] <link> tag: $href"
        echo "    HTML: $line"
        echo ""
    fi
done

echo "=== Summary ==="
vulnerable_scripts=$(grep -oP '<script[^>]*src="https?://[^"]*"[^>]*>' "$OUTPUT_FILE" | grep -c -v "integrity" || true)
vulnerable_links=$(grep -oP '<link[^>]*href="https?://[^"]*"[^>]*>' "$OUTPUT_FILE" | grep -c -v "integrity" || true)

echo "[!] Found CDN resources without integrity attributes:"
echo "    - $vulnerable_scripts <script> tags"
echo "    - $vulnerable_links <link> tags"
echo ""

# More specific check for known CDN domains
echo "[*] Specific check for common CDN domains (stackpath, code.jquery.com, cdn.jsdelivr.net)..."
echo ""

if grep -q "stackpath.bootstrapcdn.com" "$OUTPUT_FILE"; then
    echo "[VULNERABLE] Bootstrap from StackPath CDN found:"
    grep -oE '<(script|link)[^>]*(href|src)="[^"]*stackpath.bootstrapcdn.com[^"]*"[^>]*>' "$OUTPUT_FILE" | sed 's/^/  /'
    echo ""
    # Check if these have integrity attributes
    if ! grep "stackpath.bootstrapcdn.com.*integrity" "$OUTPUT_FILE" > /dev/null; then
        echo "  [!] Bootstrap CDN resources DO NOT have integrity attributes!"
        echo ""
    fi
fi

if grep -q "code.jquery.com" "$OUTPUT_FILE"; then
    echo "[VULNERABLE] jQuery from code.jquery.com found:"
    grep -oE '<script[^>]*src="[^"]*code.jquery.com[^"]*"[^>]*>' "$OUTPUT_FILE" | sed 's/^/  /'
    echo ""
    if ! grep "code.jquery.com.*integrity" "$OUTPUT_FILE" > /dev/null; then
        echo "  [!] jQuery CDN resources DO NOT have integrity attributes!"
        echo ""
    fi
fi

if grep -q "cdn.jsdelivr.net" "$OUTPUT_FILE"; then
    echo "[VULNERABLE] Popper.js from cdn.jsdelivr.net found:"
    grep -oE '<script[^>]*src="[^"]*cdn.jsdelivr.net[^"]*"[^>]*>' "$OUTPUT_FILE" | sed 's/^/  /'
    echo ""
    if ! grep "cdn.jsdelivr.net.*integrity" "$OUTPUT_FILE" > /dev/null; then
        echo "  [!] Popper.js CDN resources DO NOT have integrity attributes!"
        echo ""
    fi
fi

echo "[*] POC Complete: Verify CDN resources are missing 'integrity' attributes"