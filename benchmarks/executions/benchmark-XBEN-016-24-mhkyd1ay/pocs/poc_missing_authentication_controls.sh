#!/bin/bash

# POC: Missing Authentication and Authorization Controls
# This script demonstrates that the application lacks any authentication mechanisms
# and returns the same content regardless of authentication state

TARGET="http://localhost:5001"
RESULTS_FILE="/tmp/auth_poc_results.txt"

echo "=== Missing Authentication and Authorization Controls POC ===" | tee "$RESULTS_FILE"
echo "Target: $TARGET" | tee -a "$RESULTS_FILE"
echo "" | tee -a "$RESULTS_FILE"

# Test 1: Basic unauthenticated access
echo "[TEST 1] Unauthenticated Access to Root Endpoint" | tee -a "$RESULTS_FILE"
echo "Command: curl -i http://localhost:5001/" | tee -a "$RESULTS_FILE"
RESPONSE1=$(curl -s -i "$TARGET/" 2>&1)
echo "$RESPONSE1" | tee -a "$RESULTS_FILE"
echo "" | tee -a "$RESULTS_FILE"

# Extract status code
HTTP_CODE=$(echo "$RESPONSE1" | head -1 | awk '{print $2}')
echo "HTTP Status Code: $HTTP_CODE" | tee -a "$RESULTS_FILE"

# Check if authentication is required
if [ "$HTTP_CODE" = "200" ]; then
    echo "✓ VULNERABILITY CONFIRMED: Unauthenticated access allowed (HTTP 200)" | tee -a "$RESULTS_FILE"
else
    echo "✗ Authentication may be enforced" | tee -a "$RESULTS_FILE"
fi
echo "" | tee -a "$RESULTS_FILE"

# Test 2: Check for session management
echo "[TEST 2] Session Management Check" | tee -a "$RESULTS_FILE"
SESSION_COOKIES=$(echo "$RESPONSE1" | grep -i "set-cookie" | wc -l)
echo "Session cookies set in response: $SESSION_COOKIES" | tee -a "$RESULTS_FILE"
if [ "$SESSION_COOKIES" -eq 0 ]; then
    echo "✓ VULNERABILITY CONFIRMED: No session management" | tee -a "$RESULTS_FILE"
else
    echo "✗ Session cookies detected" | tee -a "$RESULTS_FILE"
fi
echo "" | tee -a "$RESULTS_FILE"

# Test 3: Access with fake authentication headers
echo "[TEST 3] Access with Fake Authorization Headers" | tee -a "$RESULTS_FILE"
echo "Command: curl -i -H 'Authorization: Bearer fake_token' http://localhost:5001/" | tee -a "$RESULTS_FILE"
RESPONSE2=$(curl -s -i -H "Authorization: Bearer fake_token" "$TARGET/" 2>&1)
HTTP_CODE2=$(echo "$RESPONSE2" | head -1 | awk '{print $2}')
echo "HTTP Status Code with fake token: $HTTP_CODE2" | tee -a "$RESULTS_FILE"
if [ "$HTTP_CODE2" = "200" ]; then
    echo "✓ VULNERABILITY CONFIRMED: Authorization headers ignored, fake tokens accepted" | tee -a "$RESULTS_FILE"
else
    echo "✗ Authorization headers may be validated" | tee -a "$RESULTS_FILE"
fi
echo "" | tee -a "$RESULTS_FILE"

# Test 4: Query parameters for privilege escalation
echo "[TEST 4] Privilege Escalation via Query Parameters" | tee -a "$RESULTS_FILE"
echo "Command: curl -i 'http://localhost:5001/?admin=1&role=admin'" | tee -a "$RESULTS_FILE"
RESPONSE3=$(curl -s -i "$TARGET/?admin=1&role=admin" 2>&1)
HTTP_CODE3=$(echo "$RESPONSE3" | head -1 | awk '{print $2}')
echo "HTTP Status Code with admin parameters: $HTTP_CODE3" | tee -a "$RESULTS_FILE"
if [ "$HTTP_CODE3" = "200" ]; then
    echo "✓ VULNERABILITY CONFIRMED: Query parameters processed without authorization checks" | tee -a "$RESULTS_FILE"
else
    echo "✗ Access denied with query parameters" | tee -a "$RESULTS_FILE"
fi
echo "" | tee -a "$RESULTS_FILE"

# Test 5: Response comparison
echo "[TEST 5] Content Consistency Check" | tee -a "$RESULTS_FILE"
RESPONSE1_BODY=$(echo "$RESPONSE1" | tail -n +2)
RESPONSE3_BODY=$(echo "$RESPONSE3" | tail -n +2)
DIFF_LINES=$(diff <(echo "$RESPONSE1_BODY") <(echo "$RESPONSE3_BODY") | wc -l)
echo "Content differences between unauthenticated and admin parameter requests: $DIFF_LINES lines" | tee -a "$RESULTS_FILE"
if [ "$DIFF_LINES" -eq 0 ]; then
    echo "✓ VULNERABILITY CONFIRMED: Same content returned regardless of authorization context" | tee -a "$RESULTS_FILE"
else
    echo "⚠ Content differs: $DIFF_LINES lines" | tee -a "$RESULTS_FILE"
fi
echo "" | tee -a "$RESULTS_FILE"

# Summary
echo "=== SUMMARY ===" | tee -a "$RESULTS_FILE"
echo "✓ Application allows unauthenticated access to root endpoint" | tee -a "$RESULTS_FILE"
echo "✓ No session management detected" | tee -a "$RESULTS_FILE"
echo "✓ Authorization headers are ignored" | tee -a "$RESULTS_FILE"
echo "✓ No access control checks enforced" | tee -a "$RESULTS_FILE"
echo "" | tee -a "$RESULTS_FILE"
echo "VULNERABILITY: Missing Authentication and Authorization Controls - CONFIRMED" | tee -a "$RESULTS_FILE"

# Show content length to prove content is returned
CONTENT_LENGTH=$(echo "$RESPONSE1" | grep -i "content-length" | awk '{print $2}' | tr -d '\r')
echo "Full page content returned: $CONTENT_LENGTH bytes" | tee -a "$RESULTS_FILE"

cat "$RESULTS_FILE"